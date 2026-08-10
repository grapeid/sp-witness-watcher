package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

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
	enrollBody, _ := json.Marshal(map[string]string{"aid": "EAlice", "controller_aid": "EAlice"})
	enrollReq := httptest.NewRequest(http.MethodPost, "/enroll", bytes.NewReader(enrollBody))
	enrollRec := httptest.NewRecorder()
	router.ServeHTTP(enrollRec, enrollReq)
	if enrollRec.Code != http.StatusOK {
		t.Fatalf("enroll: %d %s", enrollRec.Code, enrollRec.Body.String())
	}

	// Witness event seq 0
	ev := map[string]interface{}{
		"event": map[string]interface{}{
			"v": "KERI10JSON000256_", "t": "icp", "d": "EAliceEvent0000000000000000000000000000000x",
			"i": "EAlice", "s": "0",
			"k": []string{"Dkey1"},
		},
		"aid": "EAlice",
	}
	evBody, _ := json.Marshal(ev)
	evReq := httptest.NewRequest(http.MethodPost, "/witness/event", bytes.NewReader(evBody))
	evRec := httptest.NewRecorder()
	router.ServeHTTP(evRec, evReq)
	if evRec.Code != http.StatusOK {
		t.Fatalf("witness event: %d %s", evRec.Code, evRec.Body.String())
	}

	// Conflicting event at same seq — must reject (C3)
	ev2 := map[string]interface{}{
		"event": map[string]interface{}{
			"v": "KERI10JSON000256_", "t": "icp", "d": "EAliceForked000000000000000000000000000000x",
			"i": "EAlice", "s": "0",
			"k": []string{"DkeyFORK"},
		},
		"aid": "EAlice",
	}
	ev2Body, _ := json.Marshal(ev2)
	ev2Req := httptest.NewRequest(http.MethodPost, "/witness/event", bytes.NewReader(ev2Body))
	ev2Rec := httptest.NewRecorder()
	router.ServeHTTP(ev2Rec, ev2Req)
	if ev2Rec.Code != http.StatusConflict {
		t.Fatalf("expected conflict, got %d", ev2Rec.Code)
	}

	// Kel digest (C5)
	digReq := httptest.NewRequest(http.MethodGet, "/public/kel-digest?aid=EAlice&seq=0", nil)
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
	kelReq := httptest.NewRequest(http.MethodGet, "/witness/kel/EAlice", nil)
	kelRec := httptest.NewRecorder()
	router.ServeHTTP(kelRec, kelReq)
	if kelRec.Code != http.StatusOK {
		t.Fatalf("witness kel: %d", kelRec.Code)
	}
}
