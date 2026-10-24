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
	if err := verifyControllerSignature(raw, parsed, sig, nil, nil); err != nil {
		t.Fatalf("a correctly signed event was refused: %v", err)
	}
}

// The case this exists for. Without it a witness attests to events submitted by
// anybody, and its receipts stop separating a real history from an invented one.
func TestAnEventSignedByAStrangerIsRefused(t *testing.T) {
	raw, parsed, _, other := signedEvent(t)
	if err := verifyControllerSignature(raw, parsed, cesrSig(ed25519.Sign(other, raw)), nil, nil); err == nil {
		t.Fatal("an event signed by a key it does not declare was accepted for witnessing")
	}
}

// Altering any byte changes what was signed.
func TestATamperedEventIsRefused(t *testing.T) {
	raw, parsed, sig, _ := signedEvent(t)
	tampered := append([]byte(nil), raw...)
	tampered[len(tampered)-3] ^= 0x01
	if err := verifyControllerSignature(tampered, parsed, sig, nil, nil); err == nil {
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
	if err := verifyControllerSignature(ixnRaw, ixn, cesrSig(ed25519.Sign(priv, ixnRaw)), prior, nil); err != nil {
		t.Fatalf("an interaction signed by the key in force was refused: %v", err)
	}

	// And a stranger still cannot anchor against somebody else's key state.
	_, otherPriv, _ := ed25519.GenerateKey(nil)
	if err := verifyControllerSignature(ixnRaw, ixn, cesrSig(ed25519.Sign(otherPriv, ixnRaw)), prior, nil); err == nil {
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
	if err := verifyControllerSignature(ixnRaw, ixn, cesrSig(make([]byte, 64)), nil, nil); err == nil {
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

// A rotation is never trusted on the strength of its own declared key, which
// would let anyone who can reach the witness rotate anyone's key state. With no
// log to check its commitment against, it is refused.
func TestARotationWithNoLogToCheckIsRefused(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	rotRaw := []byte(`{"v":"KERI10JSON000160_","t":"rot","d":"EAAArot","i":"EAAAicp","s":"1","k":["` + qb64Key(pub) + `"]}`)
	var rot map[string]interface{}
	if err := json.Unmarshal(rotRaw, &rot); err != nil {
		t.Fatal(err)
	}
	// Even signed by the key it declares, it must not be accepted.
	if err := verifyControllerSignature(rotRaw, rot, cesrSig(ed25519.Sign(priv, rotRaw)), nil, nil); err == nil {
		t.Fatal("a rotation was attested to without pre-rotation validation")
	}
}

// Key state is resolved at the submitted event's sequence, not at the tail, so
// a backfilled interaction before a (hypothetical) later establishment event
// is checked against the key that was actually in force when it was signed.
func TestKeyStateIsResolvedAtTheEventsSequence(t *testing.T) {
	k0pub, k0priv, _ := ed25519.GenerateKey(nil)
	k1pub, _, _ := ed25519.GenerateKey(nil)

	var icp, laterEstablishment map[string]interface{}
	json.Unmarshal([]byte(`{"t":"icp","d":"EAAAicp","i":"EAAAicp","s":"0","k":["`+qb64Key(k0pub)+`"]}`), &icp)
	// A second establishment event at s=5 under a different key, already on
	// file: signingKeyFor must resolve correctly around it.
	json.Unmarshal([]byte(`{"t":"rot","d":"EAAArot","i":"EAAAicp","s":"5","k":["`+qb64Key(k1pub)+`"]}`), &laterEstablishment)
	prior := []map[string]interface{}{icp, laterEstablishment}

	// An interaction at s=2 is signed by k0 (in force at s=2), not k1.
	ixnRaw := []byte(`{"t":"ixn","d":"EAAAixn2","i":"EAAAicp","s":"2"}`)
	var ixn map[string]interface{}
	json.Unmarshal(ixnRaw, &ixn)
	if err := verifyControllerSignature(ixnRaw, ixn, cesrSig(ed25519.Sign(k0priv, ixnRaw)), prior, nil); err != nil {
		t.Fatalf("an interaction at s=2 was not checked against the key in force at s=2: %v", err)
	}
}
