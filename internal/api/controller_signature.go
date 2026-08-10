package api

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
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

// verifyControllerSignature checks a CESR signature over an event's canonical
// bytes against the key the event itself declares.
func verifyControllerSignature(raw []byte, event map[string]interface{}, cesrSig string) error {
	key, err := signingKeyOf(event)
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
