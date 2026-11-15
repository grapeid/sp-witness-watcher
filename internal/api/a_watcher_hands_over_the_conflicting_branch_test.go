package api

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	keri "github.com/grapeid/keri-go"

	"github.com/grapeid/sp-witness-watcher/internal/store"
)

func indexed(t *testing.T, priv ed25519.PrivateKey, raw []byte) string {
	t.Helper()
	sig, err := keri.EncodeIndexedSignature(ed25519.Sign(priv, raw), keri.SignaturePlace{Index: 0, Ondex: 0})
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

type servedLog struct {
	AID         string                   `json:"aid"`
	KEL         []map[string]interface{} `json:"kel"`
	Conflicting []map[string]interface{} `json:"conflicting"`
}

func getLog(t *testing.T, router http.Handler, aid string) servedLog {
	t.Helper()
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/witness/kel/"+aid, nil))
	wantStatus(t, rec, 200, "the served log")
	var out servedLog
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func decodeB64(t *testing.T, v interface{}) []byte {
	t.Helper()
	s, _ := v.(string)
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) == 0 {
		t.Fatalf("not bytes: %v %v", v, err)
	}
	return b
}

// A watcher that saw two correctly signed events at one place keeps both, and
// hands both over, so whoever asks can verify the fork itself. The first one
// seen stays where it was ("nothing rewritten").
//
// Fails when the conflict is only counted (the digest_conflicts row), as it was:
// the second event is then not served, and a verifier holding the first history
// can never be shown the second.
func TestAWatcherKeepsAndServesTheConflictingBranchItSaw(t *testing.T) {
	router, _ := hexWorld(t)
	c := newController(t)
	icp := c.log[0]
	wantStatus(t, postSigned(t, router, c.aid, icp, indexed(t, c.priv, icp)), 200, "the inception")
	first := c.interact(t)
	wantStatus(t, postSigned(t, router, c.aid, first, indexed(t, c.priv, first)), 200, "the first history")

	other, err := keri.BuildInteraction(keri.InteractionInput{
		Prefix: c.aid, PriorSAID: c.said[0], SN: 1, Data: []json.RawMessage{json.RawMessage(`{"d":"another-history"}`)},
	})
	if err != nil {
		t.Fatal(err)
	}
	wantStatus(t, postSigned(t, router, c.aid, other, indexed(t, c.priv, other)), 409, "the second history")
	// Said again, it is still one.
	wantStatus(t, postSigned(t, router, c.aid, other, indexed(t, c.priv, other)), 409, "the second history again")

	got := getLog(t, router, c.aid)
	if len(got.KEL) != 2 || len(got.Conflicting) != 1 {
		t.Fatalf("served %d events and %d conflicting", len(got.KEL), len(got.Conflicting))
	}
	// The first history is what is still held, as published.
	if string(decodeB64(t, got.KEL[1]["raw_bytes_b64"])) != string(first) {
		t.Fatal("the held event at place 1 is not the first one seen")
	}
	if string(decodeB64(t, got.Conflicting[0]["raw_bytes_b64"])) != string(other) {
		t.Fatal("the conflicting event was not served as published")
	}
	// What is served is enough to verify both on their own: the held log as a
	// signed log, and the rival against the state before its place.
	var msgs [][]byte
	for _, ev := range got.KEL {
		msgs = append(msgs, attach(t, ev))
	}
	if _, err := keri.ValidateSignedKEL(msgs); err != nil {
		t.Fatalf("the served log does not verify: %v", err)
	}
	// The rival is a log of its own that verifies: the same inception, then the
	// other event.
	if _, err := keri.ValidateSignedKEL([][]byte{msgs[0], attach(t, got.Conflicting[0])}); err != nil {
		t.Fatalf("the served conflicting event does not verify: %v", err)
	}
}

func attach(t *testing.T, ev map[string]interface{}) []byte {
	t.Helper()
	raw := decodeB64(t, ev["raw_bytes_b64"])
	group, err := keri.AttachControllerSigs([]string{ev["cesr_signature"].(string)})
	if err != nil {
		t.Fatal(err)
	}
	return append(append([]byte(nil), raw...), group...)
}

// An event nobody signed is not kept as a rival: nobody can fill the store with
// conflicts the controller never made.
func TestAnUnsignedConflictingEventIsNotKept(t *testing.T) {
	router, _ := hexWorld(t)
	c := newController(t)
	wantStatus(t, postSigned(t, router, c.aid, c.log[0], indexed(t, c.priv, c.log[0])), 200, "the inception")
	first := c.interact(t)
	wantStatus(t, postSigned(t, router, c.aid, first, indexed(t, c.priv, first)), 200, "the first history")
	other, _ := keri.BuildInteraction(keri.InteractionInput{
		Prefix: c.aid, PriorSAID: c.said[0], SN: 1, Data: []json.RawMessage{json.RawMessage(`{"d":"forged"}`)},
	})
	_, stranger, _ := ed25519.GenerateKey(nil)
	if rec := postSigned(t, router, c.aid, other, indexed(t, stranger, other)); rec.Code == 200 || rec.Code == 409 {
		t.Fatalf("an event signed by a stranger: %d", rec.Code)
	}
	if got := getLog(t, router, c.aid); len(got.Conflicting) != 0 {
		t.Fatalf("a forged event was kept: %v", got.Conflicting)
	}
}

// first_seen_at is when this service saw the log through that place, from its
// own observation, not the time the identity was enrolled.
//
// Fails when first_seen_at is the enrolment time again.
func TestFirstSeenAtComesFromTheObservationNotTheEnrolment(t *testing.T) {
	router, _ := hexWorld(t)
	c := newController(t)
	enrol := httptest.NewRecorder()
	router.ServeHTTP(enrol, httptest.NewRequest(http.MethodPost, "/enroll", bytes.NewReader(mustJSON(t, map[string]string{"aid": c.aid, "controller_aid": c.aid}))))
	wantStatus(t, enrol, 200, "enrolment")

	was := store.Now
	t.Cleanup(func() { store.Now = was })
	seenAt := time.Now().UTC().Add(48 * time.Hour).Truncate(time.Second)
	store.Now = func() time.Time { return seenAt }
	wantStatus(t, postSigned(t, router, c.aid, c.log[0], indexed(t, c.priv, c.log[0])), 200, "the inception")

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/public/kel-digest?aid="+c.aid+"&seq=0", nil))
	var out map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out["digest"] == nil {
		t.Fatalf("no digest: %v", out)
	}
	if out["first_seen_at"] != seenAt.Format(time.RFC3339) {
		t.Fatalf("first_seen_at %v, want the observation time %s", out["first_seen_at"], seenAt.Format(time.RFC3339))
	}
	if out["observed_since"] == out["first_seen_at"] {
		t.Fatal("observed_since (how long it has looked) and first_seen_at (when it saw this) are the same")
	}
}

func mustJSON(t *testing.T, v interface{}) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The cross-check says when this service first saw the log through the place
// asked about, not when it began looking at the identity.
//
// Fails when /public/kel-check reports the enrolment time as our_first_seen_at.
func TestTheCrossCheckDatesTheFirstSightingNotTheEnrolment(t *testing.T) {
	router, _ := hexWorld(t)
	c := newController(t)
	enrol := httptest.NewRecorder()
	router.ServeHTTP(enrol, httptest.NewRequest(http.MethodPost, "/enroll", bytes.NewReader(mustJSON(t, map[string]string{"aid": c.aid, "controller_aid": c.aid}))))
	wantStatus(t, enrol, 200, "enrolment")

	was := store.Now
	t.Cleanup(func() { store.Now = was })
	seenAt := time.Now().UTC().Add(48 * time.Hour).Truncate(time.Second)
	store.Now = func() time.Time { return seenAt }
	wantStatus(t, postSigned(t, router, c.aid, c.log[0], indexed(t, c.priv, c.log[0])), 200, "the inception")

	dig := httptest.NewRecorder()
	router.ServeHTTP(dig, httptest.NewRequest(http.MethodGet, "/public/kel-digest?aid="+c.aid+"&seq=0", nil))
	var held map[string]interface{}
	if err := json.Unmarshal(dig.Body.Bytes(), &held); err != nil || held["digest"] == nil {
		t.Fatalf("no digest to check against: %s", dig.Body.String())
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/public/kel-check",
		bytes.NewReader(mustJSON(t, map[string]interface{}{"aid": c.aid, "seq": 0, "digest": held["digest"]}))))
	var out map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out["match"] != true {
		t.Fatalf("the check of the digest it holds did not match: %v", out)
	}
	if out["our_first_seen_at"] != seenAt.Format(time.RFC3339) {
		t.Fatalf("our_first_seen_at %v, want the observation time %s (not the enrolment's)", out["our_first_seen_at"], seenAt.Format(time.RFC3339))
	}
}
