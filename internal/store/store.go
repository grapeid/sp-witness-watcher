package store

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

// ServiceStore holds witness KEL replicas, watcher observations, and enrollments.
type ServiceStore struct {
	db *sql.DB
}

func Open(dir string) (*ServiceStore, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}
	// The wait for a busy database is set on every connection the pool opens:
	// a PRAGMA run once applies to one connection only.
	db, err := sql.Open("sqlite", filepath.Join(dir, "witness-watcher.db")+"?_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	for _, p := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA busy_timeout=5000",
		"PRAGMA foreign_keys=ON",
	} {
		if _, err := db.Exec(p); err != nil {
			db.Close()
			return nil, err
		}
	}
	s := &ServiceStore{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *ServiceStore) Close() error { return s.db.Close() }

func (s *ServiceStore) migrate() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS enrollments (
    aid TEXT PRIMARY KEY,
    controller_aid TEXT NOT NULL,
    enrolled_at TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    observed_since TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS kel_events (
    aid TEXT NOT NULL,
    sequence_num INTEGER NOT NULL,
    event_json TEXT NOT NULL,
    event_digest TEXT NOT NULL,
    received_at TEXT NOT NULL,
    PRIMARY KEY (aid, sequence_num)
);
CREATE TABLE IF NOT EXISTS observations (
    aid TEXT NOT NULL,
    sequence_num INTEGER NOT NULL,
    kel_digest TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    PRIMARY KEY (aid, sequence_num)
);
-- The highest place each identity's log is held with nothing missing below
-- it, kept as events arrive, so the tip is answered without reading the log.
CREATE TABLE IF NOT EXISTS unbroken_tips (
    aid TEXT PRIMARY KEY,
    sequence_num INTEGER NOT NULL,
    said TEXT NOT NULL
);
-- Events held back because the event before them had not arrived: taken up,
-- in order, once it does. Bounded per identity, and expired.
CREATE TABLE IF NOT EXISTS escrowed_events (
    aid TEXT NOT NULL,
    sequence_num INTEGER NOT NULL,
    said TEXT NOT NULL,
    raw_b64 TEXT NOT NULL,
    cesr_signature TEXT NOT NULL,
    received_at TEXT NOT NULL,
    PRIMARY KEY (aid, said)
);
-- Every row moved by a repair of sequence numbers, before and after, with a
-- copy of the row as it was.
CREATE TABLE IF NOT EXISTS sequence_repairs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    aid TEXT NOT NULL,
    kind TEXT NOT NULL,
    seq_before INTEGER NOT NULL,
    seq_after INTEGER NOT NULL,
    digest_before TEXT NOT NULL,
    digest_after TEXT NOT NULL,
    row_before TEXT NOT NULL,
    repaired_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS digest_conflicts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    aid TEXT NOT NULL,
    sequence_num INTEGER NOT NULL,
    digest_a TEXT NOT NULL,
    digest_b TEXT NOT NULL,
    detected_at TEXT NOT NULL
);
`)
	if err != nil {
		return err
	}
	// Each event as its controller published and signed it, so it can be
	// handed back exactly (GET /witness/kel/{aid}/event/{sn}); and who sent
	// each event held back, so one sender cannot fill the escrow.
	for _, col := range []struct{ table, name string }{
		{"kel_events", "raw_b64"}, {"kel_events", "cesr_signature"}, {"escrowed_events", "client_ip"},
	} {
		if err := s.addColumn(col.table, col.name); err != nil {
			return err
		}
	}
	return nil
}

// addColumn adds a text column to a table that lacks it.
func (s *ServiceStore) addColumn(table, name string) error {
	rows, err := s.db.Query(`SELECT name FROM pragma_table_info(?)`, table)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var have string
		if err := rows.Scan(&have); err != nil {
			return err
		}
		if have == name {
			return nil
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	rows.Close()
	_, err = s.db.Exec(`ALTER TABLE ` + table + ` ADD COLUMN ` + name + ` TEXT NOT NULL DEFAULT ''`)
	return err
}

// EventAt is the event held at sn of aid's log as its controller published
// and signed it; ok is false when none is held there, or it was held before
// witnesses kept the bytes.
func (s *ServiceStore) EventAt(aid string, sn int) (rawB64, sig string, ok bool, err error) {
	err = s.db.QueryRow(`SELECT raw_b64, cesr_signature FROM kel_events WHERE aid=? AND sequence_num=?`, aid, sn).Scan(&rawB64, &sig)
	if err == sql.ErrNoRows {
		return "", "", false, nil
	}
	if err != nil {
		return "", "", false, err
	}
	return rawB64, sig, rawB64 != "" && sig != "", nil
}

// PublishedLogBefore is aid's log from its inception up to, but not including,
// sn, as its controller published each event, in order.
//
// It is all or nothing. A place below sn that is not held, or an event held
// before witnesses kept the bytes, makes it an error rather than a shorter
// log: what the caller checks against it (a rotation's commitment) is only
// sound against the whole history, and a log with a hole in it would answer a
// narrower question than the one asked.
func (s *ServiceStore) PublishedLogBefore(aid string, sn int) ([][]byte, error) {
	rows, err := s.db.Query(`SELECT sequence_num, raw_b64 FROM kel_events WHERE aid=? AND sequence_num>=0 AND sequence_num<? ORDER BY sequence_num`, aid, sn)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([][]byte, 0, sn)
	for rows.Next() {
		var at int
		var rawB64 string
		if err := rows.Scan(&at, &rawB64); err != nil {
			return nil, err
		}
		if at != len(out) {
			return nil, fmt.Errorf("this witness does not hold place %d of the log", len(out))
		}
		if rawB64 == "" {
			return nil, fmt.Errorf("this witness holds place %d of the log without the bytes it "+
				"was published as", at)
		}
		raw, err := base64.StdEncoding.DecodeString(rawB64)
		if err != nil {
			return nil, fmt.Errorf("place %d of the log is held unreadably: %w", at, err)
		}
		out = append(out, raw)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) != sn {
		return nil, fmt.Errorf("this witness does not hold place %d of the log", len(out))
	}
	return out, nil
}

func (s *ServiceStore) Enroll(aid, controllerAID string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	// observed_since is first-wins and is never moved forward.
	//
	// It used to be overwritten on conflict, so a second enrolment for an AID
	// already enrolled reset it to the present. That field is handed back as
	// part of this service's answer — it is the watcher's testimony about how
	// long it has been looking, which is most of what the opinion is worth —
	// and /enroll takes any AID from anyone. So a stranger could take a witness
	// that had observed an identity for a year and reset it to five seconds
	// ago, discarding exactly the window in which a fork would have shown.
	//
	// Re-enrolling still reactivates a withdrawn enrolment, because that is a
	// real thing a controller may want. It just cannot rewrite history.
	_, err := s.db.Exec(`
		INSERT INTO enrollments (aid, controller_aid, enrolled_at, status, observed_since)
		VALUES (?, ?, ?, 'active', ?)
		ON CONFLICT(aid) DO UPDATE SET status='active'`,
		aid, controllerAID, now, now)
	return err
}

func (s *ServiceStore) IsEnrolled(aid string) (bool, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(1) FROM enrollments WHERE aid=? AND status='active'`, aid).Scan(&n)
	return n > 0, err
}

func (s *ServiceStore) ObservedSince(aid string) (string, error) {
	var ts string
	err := s.db.QueryRow(`SELECT observed_since FROM enrollments WHERE aid=?`, aid).Scan(&ts)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return ts, err
}

// StoreEvent stores a witness KEL event; returns conflict if same seq different digest.
func (s *ServiceStore) GetKELEvents(aid string) ([]map[string]interface{}, error) {
	rows, err := s.db.Query(`SELECT event_json FROM kel_events WHERE aid=? ORDER BY sequence_num`, aid)
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

func (s *ServiceStore) GetObservationDigest(aid string, seq int) (digest string, ok bool, err error) {
	err = s.db.QueryRow(`SELECT kel_digest FROM observations WHERE aid=? AND sequence_num=?`, aid, seq).Scan(&digest)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return digest, true, nil
}
