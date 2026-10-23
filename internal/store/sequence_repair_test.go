package store

import (
	"fmt"
	"testing"
)

// Events stored while sequence numbers were read as decimal are found, and
// moved to their own places; the conflict row the misreading wrote is
// reported and kept; the events refused then are reported missing.
func TestEventsStoredAtTheWrongPlaceAreRepaired(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	aid := "EOld"
	put := func(stored int, s string) {
		ev := fmt.Sprintf(`{"t":"ixn","d":"E%s","i":"%s","s":"%s"}`, s, aid, s)
		if s == "0" {
			ev = fmt.Sprintf(`{"t":"icp","d":"E0","i":"%s","s":"0"}`, aid)
		}
		if _, err := st.db.Exec(`INSERT INTO kel_events (aid, sequence_num, event_json, event_digest, received_at) VALUES (?,?,?,?,?)`,
			aid, stored, ev, "Ewrong", "2026-01-01T00:00:00Z"); err != nil {
			t.Fatal(err)
		}
		st.db.Exec(`INSERT INTO observations (aid, sequence_num, kel_digest, observed_at) VALUES (?,?,?,?)`, aid, stored, "Ewrong", fmt.Sprintf("2026-01-01T00:00:%02dZ", stored))
	}
	// As the decimal reading left it: 0-9 right, "a"-"f" refused (one wrote a
	// conflict), "10" and "11" stored at 10 and 11.
	for sn := 0; sn <= 9; sn++ {
		put(sn, fmt.Sprintf("%x", sn))
	}
	put(10, "10")
	put(11, "11")
	st.db.Exec(`INSERT INTO digest_conflicts (aid, sequence_num, digest_a, digest_b, detected_at) VALUES (?,?,?,?,?)`, aid, 0, "Ea", "Eb", "2026-01-01T00:00:00Z")

	found, err := st.RepairSequences(false)
	if err != nil || len(found) != 1 {
		t.Fatalf("report: %v %+v", err, found)
	}
	r := found[0]
	if r.Misplaced != 2 || r.Conflicts != 1 || fmt.Sprint(r.Missing) != "[10 11 12 13 14 15]" {
		t.Fatalf("the report reads %+v", r)
	}
	if again, _ := st.RepairSequences(false); again[0].Misplaced != 2 {
		t.Fatal("a report changed something")
	}
	if _, err := st.RepairSequences(true); err != nil {
		t.Fatal(err)
	}
	events, _ := st.GetKELEvents(aid)
	if len(events) != 12 || events[len(events)-1]["s"] != "11" {
		t.Fatalf("after repair the log is %v", events)
	}
	var at17 string
	if err := st.db.QueryRow(`SELECT sequence_num FROM kel_events WHERE aid=? AND event_json LIKE '%"s":"11"%'`, aid).Scan(&at17); err != nil || at17 != "17" {
		t.Fatalf("event 11 is at %s", at17)
	}
	d, ok, _ := st.GetObservationDigest(aid, 17)
	if !ok || d == "Ewrong" {
		t.Fatal("the rolling digest was not recomputed")
	}
	var conflicts int
	st.db.QueryRow(`SELECT COUNT(*) FROM digest_conflicts WHERE aid=?`, aid).Scan(&conflicts)
	if conflicts != 1 {
		t.Fatal("a conflict row was removed")
	}
	if after, _ := st.RepairSequences(false); len(after) != 1 || after[0].Misplaced != 0 {
		t.Fatalf("after repair the report reads %+v", after)
	}
}
