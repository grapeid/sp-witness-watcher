package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"time"

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
	// refused while misread. The controller sends them again from the
	// unbroken tip this witness reports.
	Missing []int
}

// RepairSequences reports every identity whose stored events are misplaced,
// and, when apply is true, moves each to its own place and recomputes the
// rolling digests. Each identity is read and rewritten in one transaction
// that holds the write lock, and every row it moves, with its digest before
// and after and a copy of the row as it was, is kept in sequence_repairs.
// Conflict rows stay for a person to judge, and observed times are kept.
//
// Apply only while nothing else writes: the server runs it at start, before
// it listens (WW_REPAIR_SEQUENCES=apply).
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
		var r SequenceRepair
		err := s.immediately(func(ctx context.Context, c *sql.Conn) error {
			var events []storedEvent
			var err error
			r, events, err = sequenceRepairOf(ctx, c, aid)
			if err != nil || !apply || r.Misplaced == 0 {
				return err
			}
			return renumber(ctx, c, aid, events)
		})
		if err != nil {
			return out, fmt.Errorf("%s: %w", aid, err)
		}
		if r.Misplaced > 0 || r.Conflicts > 0 || len(r.Missing) > 0 {
			out = append(out, r)
		}
	}
	return out, nil
}

type storedEvent struct {
	stored     int
	event      map[string]interface{}
	raw        string
	digest     string
	receivedAt string
}

func sequenceRepairOf(ctx context.Context, c *sql.Conn, aid string) (SequenceRepair, []storedEvent, error) {
	r := SequenceRepair{AID: aid}
	rows, err := c.QueryContext(ctx, `SELECT sequence_num, event_json, event_digest, received_at FROM kel_events WHERE aid=? ORDER BY sequence_num`, aid)
	if err != nil {
		return r, nil, err
	}
	var events []storedEvent
	held := map[int]bool{}
	max := -1
	for rows.Next() {
		var e storedEvent
		if err := rows.Scan(&e.stored, &e.raw, &e.digest, &e.receivedAt); err != nil {
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
	if err := c.QueryRowContext(ctx, `SELECT COUNT(*) FROM digest_conflicts WHERE aid=?`, aid).Scan(&r.Conflicts); err != nil {
		return r, nil, err
	}
	return r, events, nil
}

// renumber stores aid's events at their own places, with the rolling digest
// recomputed over the events as they really are, keeping when each was
// received and when each place was first observed, and recording each move.
func renumber(ctx context.Context, c *sql.Conn, aid string, events []storedEvent) error {
	sort.Slice(events, func(i, j int) bool { return digest.EventSeq(events[i].event) < digest.EventSeq(events[j].event) })
	parsed := make([]map[string]interface{}, 0, len(events))
	for _, e := range events {
		parsed = append(parsed, e.event)
	}
	type observation struct{ digest, at string }
	observed := map[int]observation{}
	orows, err := c.QueryContext(ctx, `SELECT sequence_num, kel_digest, observed_at FROM observations WHERE aid=?`, aid)
	if err != nil {
		return err
	}
	for orows.Next() {
		var sn int
		var o observation
		if err := orows.Scan(&sn, &o.digest, &o.at); err != nil {
			orows.Close()
			return err
		}
		observed[sn] = o
	}
	orows.Close()
	now := time.Now().UTC().Format(time.RFC3339)
	record := func(kind string, before, after int, digestBefore, digestAfter, rowBefore string) error {
		_, err := c.ExecContext(ctx, `INSERT INTO sequence_repairs (aid, kind, seq_before, seq_after, digest_before, digest_after, row_before, repaired_at) VALUES (?,?,?,?,?,?,?,?)`,
			aid, kind, before, after, digestBefore, digestAfter, rowBefore, now)
		return err
	}
	if _, err := c.ExecContext(ctx, `DELETE FROM kel_events WHERE aid=?`, aid); err != nil {
		return err
	}
	if _, err := c.ExecContext(ctx, `DELETE FROM observations WHERE aid=?`, aid); err != nil {
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
		if _, err := c.ExecContext(ctx, `INSERT INTO kel_events (aid, sequence_num, event_json, event_digest, received_at) VALUES (?,?,?,?,?)`,
			aid, sn, e.raw, d, e.receivedAt); err != nil {
			return err
		}
		row, _ := json.Marshal(map[string]interface{}{"sequence_num": e.stored, "event_json": e.raw, "event_digest": e.digest, "received_at": e.receivedAt})
		if err := record("event", e.stored, sn, e.digest, d, string(row)); err != nil {
			return err
		}
		o := observed[e.stored]
		at := o.at
		if at == "" {
			at = e.receivedAt
		}
		if _, err := c.ExecContext(ctx, `INSERT INTO observations (aid, sequence_num, kel_digest, observed_at) VALUES (?,?,?,?)`,
			aid, sn, d, at); err != nil {
			return err
		}
		orow, _ := json.Marshal(map[string]interface{}{"sequence_num": e.stored, "kel_digest": o.digest, "observed_at": o.at})
		if err := record("observation", e.stored, sn, o.digest, d, string(orow)); err != nil {
			return err
		}
	}
	return nil
}
