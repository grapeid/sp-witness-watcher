package store

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

// The log below a place is handed back whole, in order, as published, or not
// at all: a hole, or an event held without its published bytes, is an error
// naming the place, never a shorter log.
func TestThePublishedLogIsWholeOrRefused(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	put := func(aid string, sn int, raw string) {
		if _, err := st.db.Exec(`INSERT INTO kel_events (aid, sequence_num, event_json, event_digest, received_at, raw_b64, cesr_signature) VALUES (?,?,?,?,?,?,?)`,
			aid, sn, fmt.Sprintf(`{"s":"%x"}`, sn), "E", "2026-01-01T00:00:00Z", raw, "sig"); err != nil {
			t.Fatal(err)
		}
	}
	b64 := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

	put("Ewhole", 0, b64("zero"))
	put("Ewhole", 1, b64("one"))
	put("Ewhole", 2, b64("two"))
	log, err := st.PublishedLogBefore("Ewhole", 2)
	if err != nil || len(log) != 2 || string(log[0]) != "zero" || string(log[1]) != "one" {
		t.Fatalf("the log below place 2 was %q, %v", log, err)
	}

	put("Egap", 0, b64("zero"))
	put("Egap", 2, b64("two"))
	if _, err := st.PublishedLogBefore("Egap", 3); err == nil || !strings.Contains(err.Error(), "place 1") {
		t.Fatalf("a log with a hole at place 1 was not refused for it: %v", err)
	}
	if _, err := st.PublishedLogBefore("Egap", 5); err == nil {
		t.Fatal("a log shorter than asked for was handed back")
	}

	put("Elegacy", 0, b64("zero"))
	put("Elegacy", 1, "")
	if _, err := st.PublishedLogBefore("Elegacy", 2); err == nil || !strings.Contains(err.Error(), "without the bytes") {
		t.Fatalf("a log held without its published bytes was not refused for it: %v", err)
	}
}
