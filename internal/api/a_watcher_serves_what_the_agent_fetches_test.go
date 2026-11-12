package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/witnessproto"
	keri "github.com/grapeid/keri-go"
	"github.com/grapeid/sp-common/decode"
)

func getJSON(t *testing.T, router http.Handler, path string, into interface{}) int {
	t.Helper()
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	if err := json.Unmarshal(rec.Body.Bytes(), into); err != nil {
		t.Fatalf("%s: %v: %s", path, err, rec.Body.String())
	}
	return rec.Code
}

// The contract between this service's GET /witness/kel/{aid} and an Identity
// Agent's FetchLog: one committed fixture (witnessproto.KelLogContractFixture),
// tested by both, in place of a fake each wrote for itself. A multi-key identity
// is sent in order, every event signed by two of its three keys, and a second
// validly signed event at place 2 is held beside the first; what is served back
// is the fixture's, event for event and signature for signature, and the digest
// answers are the protocol's statement, signed, with the rival flag.
func TestWhatIsServedIsExactlyWhatTheSharedFixtureSays(t *testing.T) {
	c, err := witnessproto.ReadKelLogContract()
	if err != nil {
		t.Fatal(err)
	}
	router, id := hexWorld(t)
	for i, s := range c.Submissions {
		body, _ := json.Marshal(s)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/witness/event", bytes.NewReader(body)))
		want := http.StatusOK
		if i == len(c.Submissions)-1 {
			want = http.StatusConflict // the rival: a second history at a held place
		}
		if rec.Code != want {
			t.Fatalf("submission %d: %d %s, want %d", i, rec.Code, rec.Body.String(), want)
		}
	}

	var served struct {
		AID         string                   `json:"aid"`
		KEL         []map[string]interface{} `json:"kel"`
		Conflicting []map[string]interface{} `json:"conflicting"`
		Count       int                      `json:"count"`
	}
	if code := getJSON(t, router, "/witness/kel/"+c.AID, &served); code != http.StatusOK {
		t.Fatalf("GET kel: %d", code)
	}
	if served.Count != c.Served.Count || len(served.KEL) != len(c.Served.KEL) || len(served.Conflicting) != len(c.Served.Conflicting) {
		t.Fatalf("served %d events and %d rivals, the fixture has %d and %d", len(served.KEL), len(served.Conflicting), len(c.Served.KEL), len(c.Served.Conflicting))
	}
	same := func(what string, got, want map[string]interface{}, keys ...string) {
		for _, k := range keys {
			g, _ := json.Marshal(got[k])
			w, _ := json.Marshal(want[k])
			if !bytes.Equal(g, w) {
				t.Errorf("%s: %s is %s, the fixture says %s", what, k, g, w)
			}
		}
	}
	for i := range served.KEL {
		same("event "+string(rune('0'+i)), served.KEL[i], c.Served.KEL[i], "raw_bytes_b64", "cesr_signature", "cesr_signatures")
	}
	same("the rival", served.Conflicting[0], c.Served.Conflicting[0], "sequence_number", "said", "raw_bytes_b64", "cesr_signature", "cesr_signatures")

	// What is served is a log an agent can verify as signed, threshold and all.
	var msgs [][]byte
	for _, rec := range served.KEL {
		raw, _ := base64.StdEncoding.DecodeString(rec["raw_bytes_b64"].(string))
		var sigs []string
		for _, s := range rec["cesr_signatures"].([]interface{}) {
			sigs = append(sigs, s.(string))
		}
		m, err := signedMessage(raw, sigs)
		if err != nil {
			t.Fatal(err)
		}
		msgs = append(msgs, m)
	}
	if _, err := keri.ValidateSignedKEL(msgs); err != nil {
		t.Fatalf("the served log does not verify as served: %v", err)
	}

	// The digest answers: the digest, the rival flag, and a signature over the
	// protocol's statement built from the fields of the answer, which is what
	// the client rebuilds and checks.
	for _, d := range c.Digests {
		var raw map[string]interface{}
		if code := getJSON(t, router, "/public/kel-digest?aid="+c.AID+"&seq="+string(rune('0'+d.Seq)), &raw); code != http.StatusOK {
			t.Fatalf("digest at %d: %d", d.Seq, code)
		}
		if raw["digest"] != d.Digest {
			t.Errorf("digest at %d is %v, the fixture says %s", d.Seq, raw["digest"], d.Digest)
		}
		rival, _ := raw["rival_at_or_below"].(bool)
		if rival != d.RivalAtOrBelow {
			t.Errorf("rival flag at %d is %v, the fixture says %v", d.Seq, rival, d.RivalAtOrBelow)
		}
		opt := func(k string) *string {
			if s, ok := raw[k].(string); ok && s != "" {
				return &s
			}
			return nil
		}
		dg := opt("digest")
		stmt, err := witnessproto.DigestStatementWithRival(c.AID, d.Seq, dg, opt("first_seen_at"), opt("observed_since"), rival)
		if err != nil {
			t.Fatal(err)
		}
		sig, err := decode.Ed25519SignatureQB64(raw["signature"].(string))
		if err != nil {
			t.Fatalf("digest at %d: the signature is not a CESR signature: %v", d.Seq, err)
		}
		if keri.VerifyUnderKey(id.AID, []byte(stmt), "", sig) != nil {
			t.Errorf("digest at %d: the signature is not over the shared statement", d.Seq)
		}
		if raw["signed_by"] != id.AID {
			t.Errorf("digest at %d is signed_by %v", d.Seq, raw["signed_by"])
		}
	}
}

// recovery: icp (key a, next b), an interaction, and the two ways the same
// place can be contested: the retired key signs an interaction at the place the
// recovery rotation takes.
func recoveryWorld(t *testing.T) (router http.Handler, aid string, a, b keyPair, ixn1 []byte, said1 string) {
	t.Helper()
	router, _ = hexWorld(t)
	a, b = newKeyPair(t), newKeyPair(t)
	raw, err := keri.BuildInception(keri.InceptionInput{Keys: pubs(a), NextDigests: digs(b), Derivation: "self-addressing"})
	if err != nil {
		t.Fatal(err)
	}
	ev, _ := keri.ParseEvent(raw)
	aid = ev.Identifier
	wantStatus(t, postEvent(t, router, aid, raw, a.priv), 200, "the inception")
	ixn1, _ = keri.BuildInteraction(keri.InteractionInput{Prefix: aid, PriorSAID: ev.SAID, SN: 1})
	e1, _ := keri.ParseEvent(ixn1)
	wantStatus(t, postEvent(t, router, aid, ixn1, a.priv), 200, "the first interaction")
	return router, aid, a, b, ixn1, e1.SAID
}

type rivalsServed struct {
	Conflicting []map[string]interface{} `json:"conflicting"`
}

func rivalFlagAt(t *testing.T, router http.Handler, aid string, seq string) bool {
	t.Helper()
	var raw map[string]interface{}
	getJSON(t, router, "/public/kel-digest?aid="+aid+"&seq="+seq, &raw)
	v, _ := raw["rival_at_or_below"].(bool)
	return v
}

// An interaction the retired key signs at the place a recovery rotation holds
// is what the recovery replaces, not a second history: it is neither kept nor
// served as a conflict, and no digest answer says a rival is held, so no agent
// is then shown two validly signed events at place 2 and refuses the honestly
// recovered identity. Fails when the retired interaction is kept as a rival.
func TestAnInteractionTheRetiredKeySignsAtARecoveryRotationsPlaceIsNotKeptAsAConflict(t *testing.T) {
	router, aid, a, b, _, said1 := recoveryWorld(t)
	rot, err := keri.BuildRotation(keri.RotationInput{Prefix: aid, PriorSAID: said1, SN: 2, Keys: pubs(b), NextDigests: digs(newKeyPair(t))})
	if err != nil {
		t.Fatal(err)
	}
	wantStatus(t, postEvent(t, router, aid, rot, b.priv), 200, "the recovery rotation")

	thief, _ := keri.BuildInteraction(keri.InteractionInput{Prefix: aid, PriorSAID: said1, SN: 2,
		Data: []json.RawMessage{json.RawMessage(`{"d":"thief"}`)}})
	rec := postEvent(t, router, aid, thief, a.priv)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "recovery rotation") {
		t.Fatalf("the retired key's interaction: %d %s", rec.Code, rec.Body.String())
	}
	var log rivalsServed
	getJSON(t, router, "/witness/kel/"+aid, &log)
	if len(log.Conflicting) != 0 {
		t.Fatalf("the retired interaction is served as a conflict: %v", log.Conflicting)
	}
	if rivalFlagAt(t, router, aid, "2") {
		t.Fatal("a digest answer says a rival is held after a recovery replaced it")
	}

	// Control: with no recovery at the place, a second validly signed event still is a conflict.
	router2, aid2, a2, _, _, said2 := recoveryWorld(t)
	first, _ := keri.BuildInteraction(keri.InteractionInput{Prefix: aid2, PriorSAID: said2, SN: 2, Data: []json.RawMessage{json.RawMessage(`{"d":"x"}`)}})
	second, _ := keri.BuildInteraction(keri.InteractionInput{Prefix: aid2, PriorSAID: said2, SN: 2, Data: []json.RawMessage{json.RawMessage(`{"d":"y"}`)}})
	wantStatus(t, postEvent(t, router2, aid2, first, a2.priv), 200, "the first event at place 2")
	wantStatus(t, postEvent(t, router2, aid2, second, a2.priv), 409, "a second event at place 2")
	getJSON(t, router2, "/witness/kel/"+aid2, &log)
	if len(log.Conflicting) != 1 || !rivalFlagAt(t, router2, aid2, "2") || rivalFlagAt(t, router2, aid2, "1") {
		t.Fatalf("a real second history is not kept and flagged from its place: %v", log.Conflicting)
	}
}

// The other order: the retired key's interaction was seen first and the recovery
// rotation then arrives at its place. The first-seen event is never rewritten,
// so the recovery is kept beside it, as published, for an agent to judge.
func TestARecoveryRotationAfterTheRetiredKeysInteractionIsKeptBesideIt(t *testing.T) {
	router, aid, a, b, _, said1 := recoveryWorld(t)
	thief, _ := keri.BuildInteraction(keri.InteractionInput{Prefix: aid, PriorSAID: said1, SN: 2})
	wantStatus(t, postEvent(t, router, aid, thief, a.priv), 200, "the retired key's interaction, first")
	rot, _ := keri.BuildRotation(keri.RotationInput{Prefix: aid, PriorSAID: said1, SN: 2, Keys: pubs(b), NextDigests: digs(newKeyPair(t))})
	wantStatus(t, postEvent(t, router, aid, rot, b.priv), 409, "the recovery rotation at the held place")
	var log rivalsServed
	getJSON(t, router, "/witness/kel/"+aid, &log)
	if len(log.Conflicting) != 1 {
		t.Fatalf("the recovery rotation is not kept beside the held event: %v", log.Conflicting)
	}
}
