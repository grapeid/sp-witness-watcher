package api

import (
	"crypto/ed25519"
	"fmt"
	"strconv"

	keri "github.com/grapeid/keri-go"
	"github.com/grapeid/sp-common/decode"
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
	sig, err := readControllerSignature(cesrSig)
	if err != nil {
		return err
	}
	// The key used is the first one, so only a signature naming it is hers.
	if sig.At.Index != 0 || !ed25519.Verify(key, raw, sig.Raw) {
		return fmt.Errorf("the event is not signed by the key it declares, so the identity " +
			"it claims to come from did not authorise it")
	}
	return nil
}

// signingKeyOf returns the verifying key an event declares.
//
// An establishment event carries its own keys, and its first is the one read.
// Anything else is signed by whatever is in force, which signingKeyFor
// resolves from the held log before calling this.
//
// Read by sp-common's decoder, which checks the derivation code and the lead
// bits. Reading the key by its length alone took a Blake3 digest (code E) for
// an Ed25519 key, and four strings for every key.
func signingKeyOf(event map[string]interface{}) (ed25519.PublicKey, error) {
	keys, ok := event["k"].([]interface{})
	if !ok || len(keys) == 0 {
		return nil, fmt.Errorf("this event declares no key, so there is nothing to check its " +
			"signature against")
	}
	qb64, ok := keys[0].(string)
	if !ok {
		return nil, fmt.Errorf("the event's key is not a qb64 Ed25519 key")
	}
	pub, _, err := decode.Ed25519KeyQB64(qb64)
	if err != nil {
		return nil, fmt.Errorf("the event's key is not a qb64 Ed25519 key: %w", err)
	}
	return pub, nil
}

// controllerSignature is a controller signature as KERI attaches it: the
// indexed form, and where it counts.
type controllerSignature struct {
	keri.IndexedSignature
	QB64 string
}

// readControllerSignature reads a controller signature in either form a
// controller sends. The unindexed "0B" form, through sp-common's decoder (its
// lead bits must be zero, so a signature has one string, not sixteen), is a
// signature by the first key, opening the first commitment. An indexed form
// (A, B, 2A or 2B, as keripy 1.3.6 writes them) is read by keri-go and carries
// its own places.
func readControllerSignature(sig string) (controllerSignature, error) {
	if raw, err := decode.Ed25519SignatureQB64(sig); err == nil {
		qb64, err := keri.EncodeIndexedSignature(raw, keri.SamePlace(0))
		if err != nil {
			return controllerSignature{}, err
		}
		return controllerSignature{IndexedSignature: keri.IndexedSignature{
			Code: "A", At: keri.SamePlace(0), Raw: raw}, QB64: qb64}, nil
	}
	parsed, err := keri.ParseIndexedSignature(sig)
	if err != nil {
		return controllerSignature{}, fmt.Errorf("the controller signature is not a CESR "+
			"Ed25519 signature, indexed or not: %w", err)
	}
	return controllerSignature{IndexedSignature: parsed, QB64: sig}, nil
}
