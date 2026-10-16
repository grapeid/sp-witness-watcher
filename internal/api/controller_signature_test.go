package api

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"testing"
)

// qb64Key encodes a raw Ed25519 key the way an event carries it.
func qb64Key(pub ed25519.PublicKey) string {
	padded := make([]byte, 1+len(pub))
	copy(padded[1:], pub)
	return "D" + base64.RawURLEncoding.EncodeToString(padded)[1:]
}

// cesrSig encodes a signature the way a controller sends one.
func cesrSig(sig []byte) string {
	padded := make([]byte, 2+len(sig))
	copy(padded[2:], sig)
	return "0B" + base64.RawURLEncoding.EncodeToString(padded)[2:]
}

// signedEvent returns canonical event bytes and a controller signature over
// them, plus the parsed form.
func signedEvent(t *testing.T) (raw []byte, parsed map[string]interface{}, sig string, other ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	_, otherPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	raw = []byte(`{"v":"KERI10JSON000120_","t":"icp","d":"EAAAtestevent","i":"EAAAtestevent","s":"0","k":["` + qb64Key(pub) + `"]}`)
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatal(err)
	}
	return raw, parsed, cesrSig(ed25519.Sign(priv, raw)), otherPriv
}

// The ordinary case: an event signed by the key it declares.
func TestAnEventSignedByItsOwnKeyIsAccepted(t *testing.T) {
	raw, parsed, sig, _ := signedEvent(t)
	if err := verifyControllerSignature(raw, parsed, sig, nil); err != nil {
		t.Fatalf("a correctly signed event was refused: %v", err)
	}
}

// The case this exists for. Without it a witness attests to events submitted by
// anybody, and its receipts stop separating a real history from an invented one.
func TestAnEventSignedByAStrangerIsRefused(t *testing.T) {
	raw, parsed, _, other := signedEvent(t)
	if err := verifyControllerSignature(raw, parsed, cesrSig(ed25519.Sign(other, raw)), nil); err == nil {
		t.Fatal("an event signed by a key it does not declare was accepted for witnessing")
	}
}

// Altering any byte changes what was signed.
func TestATamperedEventIsRefused(t *testing.T) {
	raw, parsed, sig, _ := signedEvent(t)
	tampered := append([]byte(nil), raw...)
	tampered[len(tampered)-3] ^= 0x01
	if err := verifyControllerSignature(tampered, parsed, sig, nil); err == nil {
		t.Fatal("an altered event was accepted for witnessing")
	}
}

// An interaction event carries no `k` of its own: it is signed by whatever the
// last establishment event put in force. This is the case that used to be
// refused outright with "this event declares no key", which meant nothing
// could ever be anchored through this witness.
func TestAnInteractionIsCheckedAgainstTheStoredKeyState(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	var icp map[string]interface{}
	icpRaw := []byte(`{"v":"KERI10JSON000120_","t":"icp","d":"EAAAicp","i":"EAAAicp","s":"0","k":["` + qb64Key(pub) + `"]}`)
	if err := json.Unmarshal(icpRaw, &icp); err != nil {
		t.Fatal(err)
	}

	ixnRaw := []byte(`{"v":"KERI10JSON000098_","t":"ixn","d":"EAAAixn","i":"EAAAicp","s":"1"}`)
	var ixn map[string]interface{}
	if err := json.Unmarshal(ixnRaw, &ixn); err != nil {
		t.Fatal(err)
	}

	prior := []map[string]interface{}{icp}
	if err := verifyControllerSignature(ixnRaw, ixn, cesrSig(ed25519.Sign(priv, ixnRaw)), prior); err != nil {
		t.Fatalf("an interaction signed by the key in force was refused: %v", err)
	}

	// And a stranger still cannot anchor against somebody else's key state.
	_, otherPriv, _ := ed25519.GenerateKey(nil)
	if err := verifyControllerSignature(ixnRaw, ixn, cesrSig(ed25519.Sign(otherPriv, ixnRaw)), prior); err == nil {
		t.Fatal("an interaction signed by a stranger was accepted")
	}
}

// With no establishment event on file there is no key to check against, and
// guessing is not an option — the witness must refuse rather than attest.
func TestAnInteractionWithNoKnownKeyStateIsRefused(t *testing.T) {
	ixnRaw := []byte(`{"v":"KERI10JSON000098_","t":"ixn","d":"EAAAixn","i":"EAAAicp","s":"1"}`)
	var ixn map[string]interface{}
	if err := json.Unmarshal(ixnRaw, &ixn); err != nil {
		t.Fatal(err)
	}
	if err := verifyControllerSignature(ixnRaw, ixn, cesrSig(make([]byte, 64)), nil); err == nil {
		t.Fatal("an interaction was attested to with no key state to check it against")
	}
}

// The parsed-only form is no longer receipted: it cannot be verified, and
// storing it would move the digest this service reports for that identity.
func TestTheParsedOnlyFormIsRefused(t *testing.T) {
	req := witnessEventRequest{AID: "EAAAicp", Event: map[string]interface{}{"t": "icp", "d": "EAAAicp"}}
	if _, _, err := req.event(); err == nil {
		t.Fatal("an event with no published bytes was accepted")
	}
}
