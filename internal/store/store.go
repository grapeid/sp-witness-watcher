package store

import (
	"database/sql"
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
	db, err := sql.Open("sqlite", filepath.Join(dir, "witness-watcher.db"))
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
	_, err := s.db.Exec(`
		INSERT INTO enrollments (aid, controller_aid, enrolled_at, status, observed_since)
		VALUES (?, ?, ?, 'active', ?)
		ON CONFLICT(aid) DO UPDATE SET status='active', observed_since=excluded.observed_since`,
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
func (s *ServiceStore) StoreEvent(aid string, seq int, event map[string]interface{}, digest string) error {
	var existingDigest string
	err := s.db.QueryRow(`SELECT event_digest FROM kel_events WHERE aid=? AND sequence_num=?`, aid, seq).Scan(&existingDigest)
	if err == nil && existingDigest != digest {
		_, _ = s.db.Exec(`INSERT INTO digest_conflicts (aid, sequence_num, digest_a, digest_b, detected_at) VALUES (?,?,?,?,?)`,
			aid, seq, existingDigest, digest, time.Now().UTC().Format(time.RFC3339))
		return fmt.Errorf("conflicting event at seq %d", seq)
	}
	if err == nil {
		return nil // idempotent same event
	}
	b, _ := json.Marshal(event)
	now := time.Now().UTC().Format(time.RFC3339)
	_, err = s.db.Exec(`INSERT INTO kel_events (aid, sequence_num, event_json, event_digest, received_at) VALUES (?,?,?,?,?)`,
		aid, seq, string(b), digest, now)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`
		INSERT INTO observations (aid, sequence_num, kel_digest, observed_at) VALUES (?,?,?,?)
		ON CONFLICT(aid, sequence_num) DO UPDATE SET kel_digest=excluded.kel_digest, observed_at=excluded.observed_at`,
		aid, seq, digest, now)
	return err
}

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