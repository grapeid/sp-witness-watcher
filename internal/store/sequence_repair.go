package store

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/grapeid/sp-witness-watcher/internal/digest"
)

// SequenceRepair is what one identity's stored key log looks like when its
// sequence numbers are read as KERI writes them, in hexadecimal.
//
// Before that was fixed they were read as decimal: an event "a" to "f" read as
// 0 and was refused as conflicting with the inception, writing a
// digest_conflicts row; an event "10" or later was stored at the wrong place,
// and every rolling digest from there on was computed over the wrong events.
type SequenceRepair struct {
	AID string
	// Misplaced is how many stored events sit at a place other than their own.
	Misplaced int
	// Conflicts is how many digest_conflicts rows this identity has. Those
	// written by the misreading are not told apart from real ones here: a
	// person decides, and nothing deletes them.
	Conflicts int
	// Missing are the places, read correctly, that hold no event: the ones
	// refused while misread. The controller re-sends them.
	Missing []int
}

// RepairSequences reports every identity whose stored events are misplaced,
// and, when apply is true, moves each to its own place and recomputes the
// rolling digests. Nothing else is changed: conflict rows stay for a person
// to judge, and observed times are kept.
func (s *ServiceStore) RepairSequences(apply bool) ([]SequenceRepair, error) {
	rows, err := s.db.Query(`SELECT DISTINCT aid FROM kel_events`)
	if err != nil {
		return nil, err
	}
	var aids []string
	for rows.Next() {
		var aid string
		if err := rows.Scan(&aid); err != nil {
			rows.Close()
			return nil, err
		}
		aids = append(aids, aid)
	}
	rows.Close()
	var out []SequenceRepair
	for _, aid := range aids {
		r, events, err := s.sequenceRepairOf(aid)
		if err != nil {
			return nil, err
		}
		if r.Misplaced == 0 && r.Conflicts == 0 && len(r.Missing) == 0 {
			continue
		}
		out = append(out, r)
		if apply && r.Misplaced > 0 {
			if err := s.renumber(aid, events); err != nil {
				return out, fmt.Errorf("%s: %w", aid, err)
			}
		}
	}
	return out, nil
}

type storedEvent struct {
	stored     int
	event      map[string]interface{}
	raw        string
	receivedAt string
}

func (s *ServiceStore) sequenceRepairOf(aid string) (SequenceRepair, []storedEvent, error) {
	r := SequenceRepair{AID: aid}
	rows, err := s.db.Query(`SELECT sequence_num, event_json, received_at FROM kel_events WHERE aid=? ORDER BY sequence_num`, aid)
	if err != nil {
		return r, nil, err
	}
	var events []storedEvent
	held := map[int]bool{}
	max := -1
	for rows.Next() {
		var e storedEvent
		if err := rows.Scan(&e.stored, &e.raw, &e.receivedAt); err != nil {
			rows.Close()
			return r, nil, err
		}
		if err := json.Unmarshal([]byte(e.raw), &e.event); err != nil {
			rows.Close()
			return r, nil, err
		}
		sn := digest.EventSeq(e.event)
		if sn != e.stored {
			r.Misplaced++
		}
		held[sn] = true
		if sn > max {
			max = sn
		}
		events = append(events, e)
	}
	rows.Close()
	for sn := 0; sn <= max; sn++ {
		if !held[sn] {
			r.Missing = append(r.Missing, sn)
		}
	}
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM digest_conflicts WHERE aid=?`, aid).Scan(&r.Conflicts); err != nil {
		return r, nil, err
	}
	return r, events, nil
}

// renumber stores aid's events at their own places, with the rolling digest
// recomputed over the events as they really are, keeping when each was
// received and when each place was first observed.
func (s *ServiceStore) renumber(aid string, events []storedEvent) error {
	sort.Slice(events, func(i, j int) bool { return digest.EventSeq(events[i].event) < digest.EventSeq(events[j].event) })
	parsed := make([]map[string]interface{}, 0, len(events))
	for _, e := range events {
		parsed = append(parsed, e.event)
	}
	observed := map[int]string{}
	orows, err := s.db.Query(`SELECT sequence_num, observed_at FROM observations WHERE aid=?`, aid)
	if err != nil {
		return err
	}
	for orows.Next() {
		var sn int
		var at string
		if err := orows.Scan(&sn, &at); err == nil {
			observed[sn] = at
		}
	}
	orows.Close()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM kel_events WHERE aid=?`, aid); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM observations WHERE aid=?`, aid); err != nil {
		return err
	}
	for _, e := range events {
		sn := digest.EventSeq(e.event)
		if sn < 0 {
			return fmt.Errorf("an event with no readable sequence number")
		}
		d, err := digest.KelDigestAtSeq(parsed, sn)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO kel_events (aid, sequence_num, event_json, event_digest, received_at) VALUES (?,?,?,?,?)`,
			aid, sn, e.raw, d, e.receivedAt); err != nil {
			return err
		}
		at := observed[e.stored]
		if at == "" {
			at = e.receivedAt
		}
		if _, err := tx.Exec(`INSERT INTO observations (aid, sequence_num, kel_digest, observed_at) VALUES (?,?,?,?)`,
			aid, sn, d, at); err != nil {
			return err
		}
	}
	return tx.Commit()
}
