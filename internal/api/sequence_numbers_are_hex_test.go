package api

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/grapeid/sp-witness-watcher/internal/signer"
	"github.com/grapeid/sp-witness-watcher/internal/store"
)

func hexWorld(t *testing.T) (http.Handler, *signer.Identity) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	id, err := signer.LoadOrCreate(filepath.Join(dir, "id"))
	if err != nil {
		t.Fatal(err)
	}
	return New(st, id).Router(), id
}

func postEvent(t *testing.T, router http.Handler, aid string, raw []byte, priv ed25519.PrivateKey) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(map[string]interface{}{
		"aid": aid, "event_b64": base64.StdEncoding.EncodeToString(raw),
		"cesr_signature": cesrSig(ed25519.Sign(priv, raw)),
	})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/witness/event", bytes.NewReader(body)))
	return rec
}

// A key event's sequence number is hexadecimal. A key log past its tenth and
// sixteenth events is witnessed in order, each at its own place: read as
// decimal, event "a" became 0 and was refused as a conflicting inception.
func TestAKeyLogPastItsSixteenthEventIsWitnessed(t *testing.T) {
	router, id := hexWorld(t)
	pub, priv, _ := ed25519.GenerateKey(nil)
	aid := "EHexAlice"
	icp := []byte(`{"v":"KERI10JSON000256_","t":"icp","d":"EHexEvent00","i":"` + aid + `","s":"0","k":["` + qb64Key(pub) + `"]}`)
	if rec := postEvent(t, router, aid, icp, priv); rec.Code != http.StatusOK {
		t.Fatalf("inception: %d %s", rec.Code, rec.Body.String())
	}
	last := ""
	for sn := 1; sn <= 17; sn++ {
		last = fmt.Sprintf("EHexEvent%02x", sn)
		ixn := []byte(fmt.Sprintf(`{"v":"KERI10JSON000100_","t":"ixn","d":"%s","i":"%s","s":"%x","a":[]}`, last, aid, sn))
		if rec := postEvent(t, router, aid, ixn, priv); rec.Code != http.StatusOK {
			t.Fatalf("event %x was refused: %d %s", sn, rec.Code, rec.Body.String())
		}
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/witness/kel/"+aid+"/tip?nonce=n-1", nil))
	var tip struct {
		AID, Nonce, SAID, Signature string
		SN                          int
		WitnessAID                  string `json:"witness_aid"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &tip); err != nil || rec.Code != http.StatusOK {
		t.Fatalf("tip: %d %s", rec.Code, rec.Body.String())
	}
	if tip.SN != 17 || tip.SAID != last || tip.Nonce != "n-1" || tip.WitnessAID != id.AID {
		t.Fatalf("the witness says it holds %+v", tip)
	}
	sig, err := base64.RawURLEncoding.DecodeString("AA" + tip.Signature[2:])
	if err != nil || !ed25519.Verify(id.PublicKey, []byte(tipStatement(aid, "n-1", 17, last)), sig[2:]) {
		t.Fatal("the tip is not signed by the witness over what it says")
	}
}

// The tip of a key log this witness holds nothing of is -1, still signed, and
// a tip asked for without a nonce is refused.
func TestATipIsAskedForWithANonce(t *testing.T) {
	router, _ := hexWorld(t)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/witness/kel/ENobody/tip?nonce=x", nil))
	var tip struct {
		SN        int    `json:"sn"`
		Signature string `json:"signature"`
	}
	json.Unmarshal(rec.Body.Bytes(), &tip)
	if rec.Code != http.StatusOK || tip.SN != -1 || tip.Signature == "" {
		t.Fatalf("an empty key log's tip: %d %s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/witness/kel/ENobody/tip", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("a tip asked for without a nonce was answered %d", rec.Code)
	}
}

// What this witness signs about its tip is the Identity Agent core's
// TipStatement byte for byte, or no Identity Agent believes its answers.
func TestTheTipStatementMatchesTheCore(t *testing.T) {
	if got := tipStatement("EAid", "n-1", 17, "ESaid"); got != "witness-kel-tip/v1\nEAid\nn-1\n17\nESaid" {
		t.Fatalf("the tip statement is %q", got)
	}
}
