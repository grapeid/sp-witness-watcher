package store

import (
	"fmt"
	"testing"
	"time"

	"github.com/grapeid/sp-witness-watcher/internal/digest"
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
		if _, err := st.db.Exec(`INSERT INTO kel_events (aid, sequence_num, event_json, event_digest, received_at, raw_b64, cesr_signature) VALUES (?,?,?,?,?,?,?)`,
			aid, stored, ev, "Ewrong", "2026-01-01T00:00:00Z", "cmF3"+s, "sig"+s); err != nil {
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
	// Each event keeps the bytes and signature it was published with.
	if raw, sig, ok, _ := st.EventAt(aid, 17); !ok || raw != "cmF311" || sig != "sig11" {
		t.Fatalf("the event moved to 17 lost what it was published as: %q %q", raw, sig)
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
	// Every moved row is recorded, before and after, with a copy of the old
	// row: two events and their two observations.
	var moved, kept int
	st.db.QueryRow(`SELECT COUNT(*) FROM sequence_repairs WHERE aid=? AND seq_before != seq_after`, aid).Scan(&moved)
	st.db.QueryRow(`SELECT COUNT(*) FROM sequence_repairs WHERE aid=? AND kind='event' AND seq_before=10 AND seq_after=16 AND digest_before='Ewrong' AND row_before LIKE '%"s\":\"10\"%'`, aid).Scan(&kept)
	if moved != 4 || kept != 1 {
		t.Fatalf("the repair recorded %d moves, and the old row of event 10 %d times", moved, kept)
	}
	if after, _ := st.RepairSequences(false); len(after) != 1 || after[0].Misplaced != 0 {
		t.Fatalf("after repair the report reads %+v", after)
	}
}

// An event written while a repair runs is neither lost nor misplaced: the
// repair holds the write lock while it reads and rewrites, and the write
// waits for it.
func TestAWriteDuringARepairIsKept(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	aid := "EBusy"
	for sn := 0; sn <= 9; sn++ {
		ev := fmt.Sprintf(`{"t":"ixn","d":"E%x","i":"%s","s":"%x"}`, sn, aid, sn)
		st.db.Exec(`INSERT INTO kel_events (aid, sequence_num, event_json, event_digest, received_at) VALUES (?,?,?,?,?)`, aid, sn, ev, "Ewrong", "t")
	}
	for _, sn := range []int{0x10, 0x11, 0x12} {
		ev := fmt.Sprintf(`{"t":"ixn","d":"E%x","i":"%s","s":"%x"}`, sn, aid, sn)
		st.db.Exec(`INSERT INTO kel_events (aid, sequence_num, event_json, event_digest, received_at) VALUES (?,?,?,?,?)`, aid, 10+sn-0x10, ev, "Ewrong", "t")
	}
	done := make(chan error, 1)
	go func() {
		for i := 0; i < 20; i++ {
			ev := map[string]interface{}{"t": "ixn", "d": fmt.Sprintf("EOther%d", i), "i": "EOther", "s": fmt.Sprintf("%x", i)}
			if _, _, err := st.AcceptEvent("EOther", i, ev, "", ""); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	if _, err := st.RepairSequences(true); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("a write during the repair failed: %v", err)
	}
	other, _ := st.GetKELEvents("EOther")
	busy, _ := st.GetKELEvents(aid)
	if len(other) != 20 || len(busy) != 13 {
		t.Fatalf("after the repair: %d of 20 written meanwhile, %d of 13 repaired", len(other), len(busy))
	}
	if r, _ := st.RepairSequences(false); len(r) != 1 || r[0].Misplaced != 0 {
		t.Fatalf("after the repair the report reads %+v", r)
	}
}

// The same event again is answered with what is held and writes no conflict;
// something else at the place is a conflict, recorded.
func TestTheSameEventAgainIsNoConflict(t *testing.T) {
	st, _ := Open(t.TempDir())
	defer st.Close()
	ev := map[string]interface{}{"t": "icp", "d": "E0", "i": "EAid", "s": "0"}
	d1, dup1, err := st.AcceptEvent("EAid", 0, ev, "", "")
	if err != nil || dup1 {
		t.Fatal(err)
	}
	d2, dup2, err := st.AcceptEvent("EAid", 0, ev, "", "")
	if err != nil || !dup2 || d2 != d1 {
		t.Fatalf("the same event again: %v %v %v", err, dup2, d2 == d1)
	}
	var conflicts int
	st.db.QueryRow(`SELECT COUNT(*) FROM digest_conflicts`).Scan(&conflicts)
	if conflicts != 0 {
		t.Fatal("the same event again wrote a conflict")
	}
	other := map[string]interface{}{"t": "icp", "d": "E0other", "i": "EAid", "s": "0"}
	if _, _, err := st.AcceptEvent("EAid", 0, other, "", ""); err == nil {
		t.Fatal("a different event at a held place was accepted")
	}
	st.db.QueryRow(`SELECT COUNT(*) FROM digest_conflicts`).Scan(&conflicts)
	if conflicts != 1 {
		t.Fatal("a conflict was not recorded")
	}
}

// The tip is the highest place with nothing missing below, and filling a
// place left empty recomputes every later rolling digest.
func TestFillingAHoleMovesTheTipAndTheLaterDigests(t *testing.T) {
	st, _ := Open(t.TempDir())
	defer st.Close()
	ev := func(sn int) map[string]interface{} {
		return map[string]interface{}{"t": "ixn", "d": fmt.Sprintf("E%x", sn), "i": "EAid", "s": fmt.Sprintf("%x", sn)}
	}
	for _, sn := range []int{0, 1, 3} {
		if _, _, err := st.AcceptEvent("EAid", sn, ev(sn), "", ""); err != nil {
			t.Fatal(err)
		}
	}
	if tip, said, _ := st.UnbrokenTip("EAid"); tip != 1 || said != "E1" {
		t.Fatalf("with place 2 empty the tip is %d %s", tip, said)
	}
	before, _, _ := st.GetObservationDigest("EAid", 3)
	if _, _, err := st.AcceptEvent("EAid", 2, ev(2), "", ""); err != nil {
		t.Fatal(err)
	}
	if tip, _, _ := st.UnbrokenTip("EAid"); tip != 3 {
		t.Fatalf("with the hole filled the tip is %d", tip)
	}
	after, _, _ := st.GetObservationDigest("EAid", 3)
	all, _ := st.GetKELEvents("EAid")
	want, _ := digest.KelDigestAtSeq(all, 3)
	var stored string
	st.db.QueryRow(`SELECT event_digest FROM kel_events WHERE aid='EAid' AND sequence_num=3`).Scan(&stored)
	if after == before || after != want || stored != want {
		t.Fatal("the rolling digest after the filled place was not recomputed")
	}
	var recorded int
	st.db.QueryRow(`SELECT COUNT(*) FROM sequence_repairs WHERE aid='EAid' AND kind='digest-recomputed' AND seq_before=3 AND digest_before=? AND digest_after=?`, before, after).Scan(&recorded)
	if recorded != 1 {
		t.Fatal("the published digest was overwritten without a record of what it was")
	}
}

// Held back events are bounded per identity and expire.
func TestTheEscrowIsBoundedAndExpires(t *testing.T) {
	st, _ := Open(t.TempDir())
	defer st.Close()
	for i := 0; i < EscrowLimit; i++ {
		if err := st.EscrowEvent("EAid", 10+i, fmt.Sprintf("E%d", i), "cmF3", "sig", "", false); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.EscrowEvent("EAid", 999, "Emore", "cmF3", "sig", "", false); err != ErrEscrowFull {
		t.Fatalf("past the bound: %v", err)
	}
	if err := st.EscrowEvent("EOther", 5, "Eother", "cmF3", "sig", "", false); err != nil {
		t.Fatalf("another identity is bounded on its own: %v", err)
	}
	st.db.Exec(`UPDATE escrowed_events SET received_at = ? WHERE aid = 'EAid'`, time.Now().UTC().Add(-2*EscrowLife).Format(time.RFC3339))
	if err := st.EscrowEvent("EAid", 999, "Emore", "cmF3", "sig", "", false); err != nil {
		t.Fatalf("after the held back events expired: %v", err)
	}
	if got, _ := st.EscrowedAt("EAid", 10); len(got) != 0 {
		t.Fatal("an expired event is still held back")
	}
}

// The tip is kept as events arrive and answered without reading the log.
func TestTheTipIsKeptNotReadFromTheLog(t *testing.T) {
	st, _ := Open(t.TempDir())
	defer st.Close()
	for sn := 0; sn <= 3; sn++ {
		ev := map[string]interface{}{"t": "ixn", "d": fmt.Sprintf("E%x", sn), "i": "EAid", "s": fmt.Sprintf("%x", sn)}
		if _, _, err := st.AcceptEvent("EAid", sn, ev, "", ""); err != nil {
			t.Fatal(err)
		}
	}
	// Were the tip worked out from the log, a log emptied underneath would
	// change it.
	st.db.Exec(`DELETE FROM kel_events WHERE aid='EAid'`)
	if tip, said, _ := st.UnbrokenTip("EAid"); tip != 3 || said != "E3" {
		t.Fatalf("the tip kept is %d %s", tip, said)
	}
}

// Held back events are capped across every identity, not only per identity.
func TestTheEscrowIsCappedOverall(t *testing.T) {
	st, _ := Open(t.TempDir())
	defer st.Close()
	for i := 0; i < EscrowTotalLimit; i++ {
		st.db.Exec(`INSERT INTO escrowed_events (aid, sequence_num, said, raw_b64, cesr_signature, received_at) VALUES (?,?,?,?,?,?)`,
			fmt.Sprintf("E%d", i), 1, fmt.Sprintf("S%d", i), "cmF3", "sig", time.Now().UTC().Format(time.RFC3339))
	}
	if err := st.EscrowEvent("ENew", 3, "Enew", "cmF3", "sig", "", false); err != ErrEscrowFull {
		t.Fatalf("past the overall cap: %v", err)
	}
}

// The last EscrowReserved places are kept for identities with history here
// beyond their inception.
func TestEscrowRoomIsKeptForEstablishedIdentities(t *testing.T) {
	st, _ := Open(t.TempDir())
	defer st.Close()
	for i := 0; i < EscrowTotalLimit-EscrowReserved; i++ {
		st.db.Exec(`INSERT INTO escrowed_events (aid, sequence_num, said, raw_b64, cesr_signature, received_at) VALUES (?,?,?,?,?,?)`,
			fmt.Sprintf("E%d", i), 1, fmt.Sprintf("S%d", i), "cmF3", "sig", time.Now().UTC().Format(time.RFC3339))
	}
	if err := st.EscrowEvent("EFresh", 3, "Efresh", "cmF3", "sig", "", false); err != ErrEscrowFull {
		t.Fatalf("a fresh identity took reserved room: %v", err)
	}
	if err := st.EscrowEvent("EEstablished", 3, "Eest", "cmF3", "sig", "", true); err != nil {
		t.Fatalf("an established identity found no room: %v", err)
	}
}

// One sender may have only EscrowPerSender events held back at once.
func TestOneSenderCannotFillTheEscrow(t *testing.T) {
	st, _ := Open(t.TempDir())
	defer st.Close()
	for i := 0; i < EscrowPerSender; i++ {
		if err := st.EscrowEvent(fmt.Sprintf("E%d", i), 3, fmt.Sprintf("S%d", i), "cmF3", "sig", "10.0.0.1", false); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.EscrowEvent("EOne", 3, "Eone", "cmF3", "sig", "10.0.0.1", false); err != ErrEscrowFull {
		t.Fatalf("past the sender's cap: %v", err)
	}
	if err := st.EscrowEvent("ETwo", 3, "Etwo", "cmF3", "sig", "10.0.0.2", false); err != nil {
		t.Fatalf("another sender: %v", err)
	}
}

// A tip asked for an identity nothing is held of is answered -1 and writes
// nothing.
func TestATipForAnUnknownIdentityWritesNothing(t *testing.T) {
	st, _ := Open(t.TempDir())
	defer st.Close()
	if sn, said, err := st.UnbrokenTip("ENobody"); sn != -1 || said != "" || err != nil {
		t.Fatalf("%d %q %v", sn, said, err)
	}
	var n int
	st.db.QueryRow(`SELECT COUNT(*) FROM unbroken_tips`).Scan(&n)
	if n != 0 {
		t.Fatalf("%d tips written for an identity nothing is held of", n)
	}
}

// An event held whose place cannot be read is reported, not read as place 0.
func TestATipOverAnUnreadablePlaceIsAnError(t *testing.T) {
	st, _ := Open(t.TempDir())
	defer st.Close()
	st.db.Exec(`INSERT INTO kel_events (aid, sequence_num, event_json, event_digest, received_at) VALUES ('EAid', 0, '{"d":"E0","s":"zz"}', 'x', 'now')`)
	if _, _, err := st.UnbrokenTip("EAid"); err == nil {
		t.Fatal("a tip was worked out over an event with no readable place")
	}
}
