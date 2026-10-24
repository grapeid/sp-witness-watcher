package api

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	keri "github.com/grapeid/keri-go"
)

// Events captured from keripy 1.3.6 (keri-go vectors/keri_vectors_v2_keripy-1.3.6.json,
// cases icp/single-key/no-witnesses and rot/single-key, CESR 1.0). The keys
// come from keripy's fixed seeds, the tag letter repeated to 32 bytes: the
// inception is signed by "a", and rotates to "b".
//
// They are here because the commitment check is exact-serialisation work: the
// inception's `n` is keripy's digest of key b, so this witness accepting the
// rotation is what shows its digest of a next key agrees with the reference.
const (
	keripyIcpB64 = "eyJ2IjoiS0VSSTEwSlNPTjAwMDEyYl8iLCJ0IjoiaWNwIiwiZCI6IkVOQTk5d0lMek1UZWhQVHZjcGVNbHJkLTZOd2tBZmw4TFZSRzZYNkh5Qk9TIiwiaSI6IkRLOEdvLU1wRnhUazgxYkJuSnNWelJsUjdHNW1ZcXAzdmdkVWZ5aVRnelFkIiwicyI6IjAiLCJrdCI6IjEiLCJrIjpbIkRLOEdvLU1wRnhUazgxYkJuSnNWelJsUjdHNW1ZcXAzdmdkVWZ5aVRnelFkIl0sIm50IjoiMSIsIm4iOlsiRUVYZWtVWXd5ZjRCbHYxVV9XRk1MN1lsaUJSOUdKWGZsM29zS3RJZXZLUU4iXSwiYnQiOiIwIiwiYiI6W10sImMiOltdLCJhIjpbXX0="
	keripyRotB64 = "eyJ2IjoiS0VSSTEwSlNPTjAwMDE2MF8iLCJ0Ijoicm90IiwiZCI6IkVLTjJSRUk1OVR4Rm1TVDRZUWhYa2VhRTBpZVFybGVKTERhMmEzY2xWZVZQIiwiaSI6IkRLOEdvLU1wRnhUazgxYkJuSnNWelJsUjdHNW1ZcXAzdmdkVWZ5aVRnelFkIiwicyI6IjEiLCJwIjoiRU5BOTl3SUx6TVRlaFBUdmNwZU1scmQtNk53a0FmbDhMVlJHNlg2SHlCT1MiLCJrdCI6IjEiLCJrIjpbIkRDM3dRU1h3QVZyN1I4NkZPdS1IY2dsUC1VbU1GTXNibmhLWFBDa24yZy1tIl0sIm50IjoiMSIsIm4iOlsiRUtvZS1QUWx4eG9Yd3hITUc3T3RCLVhya2RvTjBYOV9MNG8tdlFEcERLLVAiXSwiYnQiOiIwIiwiYnIiOltdLCJiYSI6W10sImEiOltdfQ=="
	keripyAID    = "DK8Go-MpFxTk81bBnJsVzRlR7G5mYqp3vgdUfyiTgzQd"
)

func keripySeed(t *testing.T, tag string, want string) ed25519.PrivateKey {
	t.Helper()
	priv := ed25519.NewKeyFromSeed([]byte(strings.Repeat(tag, 32))[:32])
	if got := qb64Key(priv.Public().(ed25519.PublicKey)); got != want {
		t.Fatalf("seed %q gives %s, and keripy's vector says %s", tag, got, want)
	}
	return priv
}

func mustB64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func wantStatus(t *testing.T, rec *httptest.ResponseRecorder, code int, what string) {
	t.Helper()
	if rec.Code != code {
		t.Fatalf("%s: got %d, want %d: %s", what, rec.Code, code, rec.Body.String())
	}
}

func tipOf(t *testing.T, router http.Handler, aid string) int {
	t.Helper()
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/witness/kel/"+aid+"/tip?nonce=n", nil))
	var out struct {
		SN int `json:"sn"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out.SN
}

// A rotation keripy produced, signed by the key it rotates to, is witnessed, and
// so is the interaction after it, signed by the new key. That interaction is
// the event that used to be lost: the agent sends its log in order and stops at
// the first refusal, so a refused rotation meant nothing after it was ever
// confirmed.
func TestARotationKeripyProducedIsWitnessedAndSoIsWhatFollows(t *testing.T) {
	router, _ := hexWorld(t)
	a := keripySeed(t, "a", keripyAID)
	b := keripySeed(t, "b", "DC3wQSXwAVr7R86FOu-HcglP-UmMFMsbnhKXPCkn2g-m")
	icp, rot := mustB64(t, keripyIcpB64), mustB64(t, keripyRotB64)

	wantStatus(t, postEvent(t, router, keripyAID, icp, a), 200, "the inception")
	// Signed by the old key, the rotation is refused: the old key is exactly
	// what a thief would hold.
	wantStatus(t, postEvent(t, router, keripyAID, rot, a), 400, "the rotation signed by the key it replaces")
	wantStatus(t, postEvent(t, router, keripyAID, rot, b), 200, "the rotation")
	// Sent again, it is answered with its receipt, as any event already held is.
	wantStatus(t, postEvent(t, router, keripyAID, rot, b), 200, "the rotation sent again")

	ev, _ := keri.ParseEvent(rot)
	ixn, err := keri.BuildInteraction(keri.InteractionInput{Prefix: keripyAID, PriorSAID: ev.SAID, SN: 2})
	if err != nil {
		t.Fatal(err)
	}
	wantStatus(t, postEvent(t, router, keripyAID, ixn, a), 400, "the interaction signed by the retired key")
	wantStatus(t, postEvent(t, router, keripyAID, ixn, b), 200, "the interaction after the rotation")
	if sn := tipOf(t, router, keripyAID); sn != 2 {
		t.Fatalf("the witness holds the log to %d, want 2", sn)
	}
}

// keyPair is a key and its qb64 public form.
type keyPair struct {
	priv ed25519.PrivateKey
	pub  string
	dig  string
}

func newKeyPair(t *testing.T) keyPair {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(nil)
	q := qb64Key(pub)
	d, err := keri.NextDigest(q)
	if err != nil {
		t.Fatal(err)
	}
	return keyPair{priv: priv, pub: q, dig: d}
}

func pubs(ks ...keyPair) (out []string) {
	for _, k := range ks {
		out = append(out, k.pub)
	}
	return out
}

func digs(ks ...keyPair) (out []string) {
	for _, k := range ks {
		out = append(out, k.dig)
	}
	return out
}

// incept files an inception with one key, committing to next with threshold nt.
func incept(t *testing.T, router http.Handler, nt string, next ...keyPair) (aid, said string) {
	t.Helper()
	cur := newKeyPair(t)
	raw, err := keri.BuildInception(keri.InceptionInput{
		Keys: pubs(cur), NextDigests: digs(next...), Nsith: json.RawMessage(fmt.Sprintf("%q", nt)),
		Derivation: "self-addressing",
	})
	if err != nil {
		t.Fatal(err)
	}
	ev, _ := keri.ParseEvent(raw)
	wantStatus(t, postEvent(t, router, ev.Identifier, raw, cur.priv), 200, "the inception")
	return ev.Identifier, ev.SAID
}

func rotation(t *testing.T, aid, prior string, kt string, keys ...keyPair) []byte {
	t.Helper()
	raw, err := keri.BuildRotation(keri.RotationInput{
		Prefix: aid, PriorSAID: prior, SN: 1, Keys: pubs(keys...),
		NextDigests: digs(newKeyPair(t)), Isith: json.RawMessage(fmt.Sprintf("%q", kt)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// A rotation to keys the identity never committed to is the attack the
// commitment exists to stop: whoever sends it chose those keys.
func TestARotationToKeysNeverCommittedToIsRefused(t *testing.T) {
	router, _ := hexWorld(t)
	committed, chosen := newKeyPair(t), newKeyPair(t)
	aid, said := incept(t, router, "1", committed)

	rec := postEvent(t, router, aid, rotation(t, aid, said, "1", chosen), chosen.priv)
	wantStatus(t, rec, 400, "a rotation to an uncommitted key")
	if !strings.Contains(rec.Body.String(), "committed") {
		t.Fatalf("the refusal does not say why: %s", rec.Body.String())
	}
	if sn := tipOf(t, router, aid); sn != 0 {
		t.Fatalf("a refused rotation moved the held log to %d", sn)
	}
}

// One signature under a rotation that sets a threshold of two keys does not
// authorise it.
func TestARotationUnderItsOwnThresholdIsRefused(t *testing.T) {
	router, _ := hexWorld(t)
	b, c := newKeyPair(t), newKeyPair(t)
	aid, said := incept(t, router, "1", b, c)

	rec := postEvent(t, router, aid, rotation(t, aid, said, "2", b, c), b.priv)
	wantStatus(t, rec, 400, "a rotation signed by one key of a threshold of two")
	if !strings.Contains(rec.Body.String(), "threshold") {
		t.Fatalf("the refusal does not say why: %s", rec.Body.String())
	}
}

// The previous establishment event's threshold for its next keys binds too: an
// identity that said two of its next keys must agree to a rotation is not
// rotated by one of them, whatever the rotation itself sets.
func TestARotationUnderThePriorNextThresholdIsRefused(t *testing.T) {
	router, _ := hexWorld(t)
	b, c := newKeyPair(t), newKeyPair(t)
	aid, said := incept(t, router, "2", b, c)

	rec := postEvent(t, router, aid, rotation(t, aid, said, "1", b, c), b.priv)
	wantStatus(t, rec, 400, "a rotation signed by one of two required next keys")
	if !strings.Contains(rec.Body.String(), "threshold 2") {
		t.Fatalf("the refusal does not say why: %s", rec.Body.String())
	}
}

// Any committed key can be the one that signs, not only the first.
func TestARotationSignedByItsSecondKeyIsWitnessed(t *testing.T) {
	router, _ := hexWorld(t)
	b, c := newKeyPair(t), newKeyPair(t)
	aid, said := incept(t, router, "1", b, c)
	wantStatus(t, postEvent(t, router, aid, rotation(t, aid, said, "1", b, c), c.priv), 200,
		"a rotation signed by its second key")
}

// A delegated identity rotates under the same rule: its own commitment.
func TestADelegatedRotationKeepsItsCommitment(t *testing.T) {
	router, _ := hexWorld(t)
	cur, next, stranger := newKeyPair(t), newKeyPair(t), newKeyPair(t)
	delegator, _ := incept(t, router, "1", newKeyPair(t))
	dip, err := keri.BuildDelegatedInception(keri.DelegationInput{
		Delegator: delegator, Keys: pubs(cur), NextDigests: digs(next),
	})
	if err != nil {
		t.Fatal(err)
	}
	dev, _ := keri.ParseEvent(dip)
	wantStatus(t, postEvent(t, router, dev.Identifier, dip, cur.priv), 200, "the delegated inception")

	drt := func(to keyPair) []byte {
		raw, err := keri.BuildDelegatedRotation(keri.DelegationInput{
			Prefix: dev.Identifier, PriorSAID: dev.SAID, SN: 1, Keys: pubs(to), NextDigests: digs(newKeyPair(t)),
		})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	wantStatus(t, postEvent(t, router, dev.Identifier, drt(stranger), stranger.priv), 400,
		"a delegated rotation to an uncommitted key")
	wantStatus(t, postEvent(t, router, dev.Identifier, drt(next), next.priv), 200, "the delegated rotation")
}

// A rotation arriving before the event it follows cannot be checked against the
// log, so it is refused rather than held back, and its controller sends again
// in order.
func TestARotationPastAGapIsRefused(t *testing.T) {
	router, _ := hexWorld(t)
	next := newKeyPair(t)
	aid, said := incept(t, router, "1", next)
	ixn, _ := keri.BuildInteraction(keri.InteractionInput{Prefix: aid, PriorSAID: said, SN: 1})
	iev, _ := keri.ParseEvent(ixn)
	rot, err := keri.BuildRotation(keri.RotationInput{
		Prefix: aid, PriorSAID: iev.SAID, SN: 2, Keys: pubs(next), NextDigests: digs(newKeyPair(t)),
	})
	if err != nil {
		t.Fatal(err)
	}
	rec := postEvent(t, router, aid, rot, next.priv)
	wantStatus(t, rec, 400, "a rotation past a gap")
}
