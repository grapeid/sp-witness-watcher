package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/grapeid/sp-witness-watcher/internal/digest"
)

// ErrConflict is an event at a place this witness already holds something
// else at: a second history.
var ErrConflict = fmt.Errorf("conflicting event")

// immediately runs fn in one transaction that takes the write lock at once,
// so what it reads is what it writes over: nothing else writes between.
func (s *ServiceStore) immediately(fn func(ctx context.Context, c *sql.Conn) error) error {
	ctx := context.Background()
	c, err := s.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer c.Close()
	if _, err := c.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return err
	}
	if err := fn(ctx, c); err != nil {
		_, _ = c.ExecContext(ctx, "ROLLBACK")
		return err
	}
	_, err = c.ExecContext(ctx, "COMMIT")
	return err
}

func eventsIn(ctx context.Context, c *sql.Conn, aid string) ([]map[string]interface{}, error) {
	rows, err := c.QueryContext(ctx, `SELECT event_json FROM kel_events WHERE aid=? ORDER BY sequence_num`, aid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]interface{}
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var ev map[string]interface{}
		if err := json.Unmarshal([]byte(raw), &ev); err != nil {
			return nil, err
		}
		out = append(out, ev)
	}
	return out, rows.Err()
}

// AcceptEvent stores an event at its place and returns the rolling digest
// there. An event already held at that place, the same one, is answered with
// what is held: duplicate is true and nothing is written. Something else at
// that place is a conflict, recorded as one. An event that fills a place left
// empty moves every later rolling digest, so each is recomputed.
func (s *ServiceStore) AcceptEvent(aid string, seq int, event map[string]interface{}, rawB64, sig string) (kelDigest string, duplicate bool, err error) {
	said, _ := event["d"].(string)
	var existing, theirs string
	err = s.immediately(func(ctx context.Context, c *sql.Conn) error {
		held, err := eventsIn(ctx, c, aid)
		if err != nil {
			return err
		}
		for _, ev := range held {
			if digest.EventSeq(ev) != seq {
				continue
			}
			if heldSaid, _ := ev["d"].(string); heldSaid == said && said != "" {
				duplicate = true
				return c.QueryRowContext(ctx, `SELECT event_digest FROM kel_events WHERE aid=? AND sequence_num=?`, aid, seq).Scan(&kelDigest)
			}
			_ = c.QueryRowContext(ctx, `SELECT event_digest FROM kel_events WHERE aid=? AND sequence_num=?`, aid, seq).Scan(&existing)
			theirs, _ = digest.KelDigestAtSeq(append(withoutSeq(held, seq), event), seq)
			return fmt.Errorf("%w at seq %d", ErrConflict, seq)
		}
		all := append(held, event)
		b, _ := json.Marshal(event)
		now := Now().UTC().Format(time.RFC3339)
		d, err := digest.KelDigestAtSeq(all, seq)
		if err != nil {
			return err
		}
		kelDigest = d
		if _, err := c.ExecContext(ctx, `INSERT INTO kel_events (aid, sequence_num, event_json, event_digest, received_at, raw_b64, cesr_signature) VALUES (?,?,?,?,?,?,?)`,
			aid, seq, string(b), d, now, rawB64, sig); err != nil {
			return err
		}
		if _, err := c.ExecContext(ctx, `INSERT INTO observations (aid, sequence_num, kel_digest, observed_at) VALUES (?,?,?,?)
			ON CONFLICT(aid, sequence_num) DO UPDATE SET kel_digest=excluded.kel_digest`, aid, seq, d, now); err != nil {
			return err
		}
		if err := advanceUnbrokenTip(ctx, c, aid, all); err != nil {
			return err
		}
		// Every later place's rolling digest covers this event now.
		for _, ev := range held {
			later := digest.EventSeq(ev)
			if later <= seq {
				continue
			}
			ld, err := digest.KelDigestAtSeq(all, later)
			if err != nil {
				return err
			}
			// A published digest is not overwritten unrecorded: what it was,
			// what it becomes, and the row as it stood are kept first.
			var oldDigest, observedAt string
			_ = c.QueryRowContext(ctx, `SELECT kel_digest, observed_at FROM observations WHERE aid=? AND sequence_num=?`, aid, later).Scan(&oldDigest, &observedAt)
			if oldDigest != ld {
				row, _ := json.Marshal(map[string]interface{}{"sequence_num": later, "kel_digest": oldDigest, "observed_at": observedAt})
				if _, err := c.ExecContext(ctx, `INSERT INTO sequence_repairs (aid, kind, seq_before, seq_after, digest_before, digest_after, row_before, repaired_at) VALUES (?,?,?,?,?,?,?,?)`,
					aid, "digest-recomputed", later, later, oldDigest, ld, string(row), now); err != nil {
					return err
				}
			}
			if _, err := c.ExecContext(ctx, `UPDATE kel_events SET event_digest=? WHERE aid=? AND sequence_num=?`, ld, aid, later); err != nil {
				return err
			}
			if _, err := c.ExecContext(ctx, `UPDATE observations SET kel_digest=? WHERE aid=? AND sequence_num=?`, ld, aid, later); err != nil {
				return err
			}
		}
		return nil
	})
	if errors.Is(err, ErrConflict) {
		// Recorded once the transaction that found it has ended, which undoes
		// anything written inside it.
		if _, rerr := s.db.Exec(`INSERT INTO digest_conflicts (aid, sequence_num, digest_a, digest_b, detected_at) VALUES (?,?,?,?,?)`,
			aid, seq, existing, theirs, time.Now().UTC().Format(time.RFC3339)); rerr != nil {
			return "", false, rerr
		}
	}
	return kelDigest, duplicate, err
}

func withoutSeq(events []map[string]interface{}, seq int) []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(events))
	for _, ev := range events {
		if digest.EventSeq(ev) != seq {
			out = append(out, ev)
		}
	}
	return out
}

// UnbrokenTip is the highest place this witness holds with nothing missing
// below it, and the event there; -1 and "" when it holds no inception. A
// controller sends from the place after it, so a place left empty is filled
// rather than stepped over. It is kept as events arrive, not worked out from
// the log each time it is asked.
func (s *ServiceStore) UnbrokenTip(aid string) (int, string, error) {
	var sn int
	var said string
	err := s.db.QueryRow(`SELECT sequence_num, said FROM unbroken_tips WHERE aid=?`, aid).Scan(&sn, &said)
	if err == nil {
		return sn, said, nil
	}
	if err != sql.ErrNoRows {
		return -1, "", err
	}
	// Nothing held for it: answered so, without writing anything, since
	// anybody may ask about any identifier.
	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM kel_events WHERE aid=?`, aid).Scan(&count); err != nil {
		return -1, "", err
	}
	if count == 0 {
		return -1, "", nil
	}
	// Held before tips were kept: worked out once, and kept.
	var tip int
	var tipSAID string
	err = s.immediately(func(ctx context.Context, c *sql.Conn) error {
		held, err := eventsIn(ctx, c, aid)
		if err != nil {
			return err
		}
		for _, ev := range held {
			if digest.EventSeq(ev) < 0 {
				return fmt.Errorf("an event held for %s has no readable place in its log", aid)
			}
		}
		if err := advanceUnbrokenTip(ctx, c, aid, held); err != nil {
			return err
		}
		return c.QueryRowContext(ctx, `SELECT sequence_num, said FROM unbroken_tips WHERE aid=?`, aid).Scan(&tip, &tipSAID)
	})
	if err != nil {
		return -1, "", err
	}
	return tip, tipSAID, nil
}

// advanceUnbrokenTip sets aid's unbroken tip from the events held.
func advanceUnbrokenTip(ctx context.Context, c *sql.Conn, aid string, held []map[string]interface{}) error {
	at := map[int]string{}
	for _, ev := range held {
		said, _ := ev["d"].(string)
		at[digest.EventSeq(ev)] = said
	}
	tip, said := -1, ""
	for {
		next, ok := at[tip+1]
		if !ok {
			break
		}
		tip, said = tip+1, next
	}
	_, err := c.ExecContext(ctx, `INSERT INTO unbroken_tips (aid, sequence_num, said) VALUES (?,?,?)
		ON CONFLICT(aid) DO UPDATE SET sequence_num=excluded.sequence_num, said=excluded.said`, aid, tip, said)
	return err
}
