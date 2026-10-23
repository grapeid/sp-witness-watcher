package store

import (
	"database/sql"
	"encoding/json"
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
	return err
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
