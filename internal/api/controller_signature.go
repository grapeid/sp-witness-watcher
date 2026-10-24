package api

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"strconv"
)

// Checking that a controller authorised the event it is asking to have
// witnessed.
//
// A receipt is worth exactly what it establishes, and what it is read as
// establishing is that this witness saw this event from this identity. The
// second half needs checking, or a witness attests to whatever it is sent — and
// receipts stop distinguishing a real history from an invented one.
//
// Only the controller's own declared key is used. That is not the same as
// deciding the identity is genuine, and it is not meant to be: a witness's job
// is to record what it saw and who signed it, not to adjudicate. What this
// rules out is somebody submitting events under an identity whose keys they do
// not hold.

// isEstablishment reports whether an event sets the key state rather than
// inheriting it. Only these carry a `k` field of their own.
func isEstablishment(event map[string]interface{}) bool {
	switch t, _ := event["t"].(string); t {
	case "icp", "rot", "dip", "drt":
		return true
	}
	return false
}

// eventSeqOf reads the integer sequence number from an event's hex `s` field.
func eventSeqOf(event map[string]interface{}) (int, bool) {
	sv, ok := event["s"].(string)
	if !ok {
		return 0, false
	}
	n, err := strconv.ParseInt(sv, 16, 64)
	if err != nil {
		return 0, false
	}
	return int(n), true
}

// signingKeyFor returns the key that must have signed this event, and refuses
// rather than guess.
//
// An inception (icp) or delegated inception (dip) is self-certifying: the
// identifier IS the digest of the event, so one cannot be filed under an AID
// whose controller did not produce it (the handler also checks i == aid), and
// its own `k` is authoritative.
//
// Anything that merely inherits key state — an interaction — is signed by the
// key the newest establishment event IN FORCE AT THIS EVENT'S SEQUENCE put
// there. Resolving at the tail instead was wrong twice: a backfilled event
// before a rotation would be checked against the post-rotation key and
// wrongly refused, and a gap could let the wrong key through.
//
// A rotation (rot/drt) has no single key to return: its own keys are the ones
// whoever wrote it chose, so trusting them would let anyone who can reach the
// witness rotate anyone's key state. It is checked against the commitment the
// identity made earlier instead, by verifyRotation, and refused here so that
// nothing can reach this function with one and come away with a key.
func signingKeyFor(event map[string]interface{}, prior []map[string]interface{}) (ed25519.PublicKey, error) {
	switch t, _ := event["t"].(string); t {
	case "icp", "dip":
		return signingKeyOf(event)
	case "rot", "drt":
		return nil, fmt.Errorf("a rotation is checked against the identity's commitment to its " +
			"next keys, not against a key it declares")
	}

	seq, ok := eventSeqOf(event)
	if !ok {
		return nil, fmt.Errorf("event has no readable sequence number")
	}
	for i := len(prior) - 1; i >= 0; i-- {
		pseq, ok := eventSeqOf(prior[i])
		if !ok || pseq >= seq {
			continue // only key state established strictly before this event counts
		}
		if isEstablishment(prior[i]) {
			return signingKeyOf(prior[i])
		}
	}
	return nil, fmt.Errorf("this event inherits its key from an establishment event, and this " +
		"witness holds none at an earlier sequence for that identity — submit the inception first")
}

// verifyControllerSignature checks that the identity an event claims to come
// from authorised it: an inception against its own key, an interaction against
// the key in force at its place in the log, and a rotation against the
// commitment the identity made to its next keys, using the log before it as
// published.
func verifyControllerSignature(raw []byte, event map[string]interface{}, cesrSig string, prior []map[string]interface{}, published publishedLog) error {
	switch t, _ := event["t"].(string); t {
	case "rot", "drt":
		return verifyRotation(raw, cesrSig, published)
	}
	key, err := signingKeyFor(event, prior)
	if err != nil {
		return err
	}
	sig, err := decodeCesrSignature(cesrSig)
	if err != nil {
		return err
	}
	if !ed25519.Verify(key, raw, sig) {
		return fmt.Errorf("the event is not signed by the key it declares, so the identity " +
			"it claims to come from did not authorise it")
	}
	return nil
}

// signingKeyOf returns the verifying key an event declares.
//
// An establishment event carries its own keys; anything else is signed by
// whatever is currently in force, which a witness holding no prior state cannot
// resolve. Those are accepted without a signature check rather than refused,
// because refusing them would make a witness useless for interactions — and the
// response records which of the two happened.
func signingKeyOf(event map[string]interface{}) (ed25519.PublicKey, error) {
	keys, ok := event["k"].([]interface{})
	if !ok || len(keys) == 0 {
		return nil, fmt.Errorf("this event declares no key, so there is nothing to check its " +
			"signature against")
	}
	qb64, ok := keys[0].(string)
	if !ok || len(qb64) != 44 {
		return nil, fmt.Errorf("the event's key is not a qb64 Ed25519 key")
	}
	// qb64 for a 1-character code: the code replaces the first character of the
	// base64 of a one-byte-padded key, so restoring that byte recovers the key.
	raw, err := base64.RawURLEncoding.DecodeString("A" + qb64[1:])
	if err != nil {
		return nil, fmt.Errorf("the event's key does not decode: %w", err)
	}
	if len(raw) != 33 {
		return nil, fmt.Errorf("the event's key decodes to %d bytes, not 33", len(raw))
	}
	return ed25519.PublicKey(raw[1:]), nil
}

// decodeCesrSignature accepts the CESR "0B" form a controller signs with.
func decodeCesrSignature(sig string) ([]byte, error) {
	if len(sig) != 88 || sig[:2] != "0B" {
		return nil, fmt.Errorf("the controller signature is not a CESR Ed25519 signature")
	}
	// A 2-character code stands in for two leading pad bytes.
	raw, err := base64.RawURLEncoding.DecodeString("AA" + sig[2:])
	if err != nil {
		return nil, fmt.Errorf("the controller signature does not decode: %w", err)
	}
	if len(raw) != 66 {
		return nil, fmt.Errorf("the controller signature decodes to %d bytes, not 66", len(raw))
	}
	return raw[2:], nil
}
