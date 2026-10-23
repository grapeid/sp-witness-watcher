package api

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	keri "github.com/grapeid/keri-go"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/grapeid/sp-witness-watcher/internal/signer"
	"github.com/grapeid/sp-witness-watcher/internal/store"
)

func TestWitnessWatcherFlow(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	id, err := signer.LoadOrCreate(filepath.Join(dir, "id"))
	if err != nil {
		t.Fatal(err)
	}
	srv := New(st, id)
	router := srv.Router()

	// Enroll
	alice := newController(t)
	enrollBody, _ := json.Marshal(map[string]string{"aid": alice.aid, "controller_aid": alice.aid})
	enrollReq := httptest.NewRequest(http.MethodPost, "/enroll", bytes.NewReader(enrollBody))
	enrollRec := httptest.NewRecorder()
	router.ServeHTTP(enrollRec, enrollReq)
	if enrollRec.Code != http.StatusOK {
		t.Fatalf("enroll: %d %s", enrollRec.Code, enrollRec.Body.String())
	}

	// Witness event seq 0.
	//
	// Sent as published bytes with the controller's signature over them,
	// because that is now the only form a witness will receipt. The parsed
	// form this test used to send was never checked against anything, and
	// storing an unchecked event moves the digest this service reports.
	alicePriv := alice.priv
	icpRaw := alice.log[0]
	evBody, _ := json.Marshal(map[string]interface{}{
		"aid":            alice.aid,
		"event_b64":      base64.StdEncoding.EncodeToString(icpRaw),
		"cesr_signature": cesrSig(ed25519.Sign(alicePriv, icpRaw)),
	})
	evReq := httptest.NewRequest(http.MethodPost, "/witness/event", bytes.NewReader(evBody))
	evRec := httptest.NewRecorder()
	router.ServeHTTP(evRec, evReq)
	if evRec.Code != http.StatusOK {
		t.Fatalf("witness event: %d %s", evRec.Code, evRec.Body.String())
	}

	// Conflicting event at the same seq — must reject (C3). Properly signed by
	// Alice, so what is being tested is the fork detection and not the
	// signature check that now precedes it.
	// Two different interactions at the same place, both following the
	// inception and both signed by Alice: a second history.
	evOne := alice.interact(t)
	oneBody, _ := json.Marshal(map[string]interface{}{
		"aid": alice.aid, "event_b64": base64.StdEncoding.EncodeToString(evOne),
		"cesr_signature": cesrSig(ed25519.Sign(alicePriv, evOne)),
	})
	oneRec := httptest.NewRecorder()
	router.ServeHTTP(oneRec, httptest.NewRequest(http.MethodPost, "/witness/event", bytes.NewReader(oneBody)))
	if oneRec.Code != http.StatusOK {
		t.Fatalf("first interaction: %d %s", oneRec.Code, oneRec.Body.String())
	}
	forkRaw, _ := keri.BuildInteraction(keri.InteractionInput{Prefix: alice.aid, PriorSAID: alice.said[0], SN: 1,
		Data: []json.RawMessage{json.RawMessage(`{"d":"` + alice.said[0] + `","forked":"yes"}`)}})
	ev2Body, _ := json.Marshal(map[string]interface{}{
		"aid":            alice.aid,
		"event_b64":      base64.StdEncoding.EncodeToString(forkRaw),
		"cesr_signature": cesrSig(ed25519.Sign(alicePriv, forkRaw)),
	})
	ev2Req := httptest.NewRequest(http.MethodPost, "/witness/event", bytes.NewReader(ev2Body))
	ev2Rec := httptest.NewRecorder()
	router.ServeHTTP(ev2Rec, ev2Req)
	if ev2Rec.Code != http.StatusConflict {
		t.Fatalf("expected conflict, got %d", ev2Rec.Code)
	}

	// Kel digest (C5)
	digReq := httptest.NewRequest(http.MethodGet, "/public/kel-digest?aid="+alice.aid+"&seq=0", nil)
	digRec := httptest.NewRecorder()
	router.ServeHTTP(digRec, digReq)
	if digRec.Code != http.StatusOK {
		t.Fatalf("kel-digest: %d %s", digRec.Code, digRec.Body.String())
	}
	var digResp map[string]interface{}
	json.Unmarshal(digRec.Body.Bytes(), &digResp)
	if digResp["digest"] == nil {
		t.Fatal("expected digest for enrolled AID")
	}
	if digResp["signature"] == "" {
		t.Fatal("expected signed digest response (C7)")
	}

	// Unknown AID — null digest (C5-b)
	unkReq := httptest.NewRequest(http.MethodGet, "/public/kel-digest?aid=EUnknown&seq=0", nil)
	unkRec := httptest.NewRecorder()
	router.ServeHTTP(unkRec, unkReq)
	var unkResp map[string]interface{}
	json.Unmarshal(unkRec.Body.Bytes(), &unkResp)
	if unkResp["digest"] != nil {
		t.Fatal("unknown AID should return null digest")
	}

	// Serve KEL (C2)
	kelReq := httptest.NewRequest(http.MethodGet, "/witness/kel/"+alice.aid, nil)
	kelRec := httptest.NewRecorder()
	router.ServeHTTP(kelRec, kelReq)
	if kelRec.Code != http.StatusOK {
		t.Fatalf("witness kel: %d", kelRec.Code)
	}
}

// Health answers on both paths. The agent's heartbeat builds /api/health, and
// when only /health existed every probe 404'd and counted as a failure.
func TestHealthAnswersOnBothPaths(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	id, err := signer.LoadOrCreate(filepath.Join(dir, "id"))
	if err != nil {
		t.Fatal(err)
	}
	router := New(st, id).Router()
	for _, path := range []string{"/health", "/api/health"} {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", path, rec.Code, rec.Body.String())
		}
	}
}

// Re-enrolling must not move observed_since. It is this service's testimony
// about how long it has been watching, /enroll takes any AID from anyone, and
// resetting it discards the window a fork would have shown in.
func TestReEnrollingDoesNotResetObservedSince(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Enroll("EAlice", "EAlice"); err != nil {
		t.Fatal(err)
	}
	first, err := st.ObservedSince("EAlice")
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond) // the column has second resolution
	if err := st.Enroll("EAlice", "EAlice"); err != nil {
		t.Fatal(err)
	}
	again, err := st.ObservedSince("EAlice")
	if err != nil {
		t.Fatal(err)
	}
	if again != first {
		t.Fatalf("observed_since moved on re-enrolment: %q then %q", first, again)
	}
}
