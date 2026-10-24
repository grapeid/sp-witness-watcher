package api

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	keri "github.com/grapeid/keri-go"
)

// Witnessing a rotation.
//
// A rotation (rot, or drt for a delegated identity) replaces an identity's
// keys, so the one thing it cannot be checked against is the key it declares:
// whoever wrote it chose that key. What it is checked against is the
// commitment the identity made earlier. Every establishment event publishes
// digests of the keys that will come next (its `n`), never the keys, so only
// whoever generated those keys can present ones that match.
//
// A rotation is witnessed when all of this holds, as KERI requires:
//   - it is a valid next event in the log this witness holds, from the
//     inception on: its sequence number follows, it names the event before it,
//     and every key it presents digests to one the previous establishment event
//     committed to (keri.ValidateKEL, which also checks the witness changes);
//   - its signature is by one of the keys it presents and meets the signing
//     threshold it sets (`kt`, checked by keri.ValidateStream);
//   - that same signature meets the threshold the previous establishment event
//     set for its next keys (`nt`), counted over the committed digests.
//
// The last is checked here rather than by the library, because keri-go reads
// `nt` only against which keys a rotation PRESENTS, not which of them SIGNED.
// For the single signature an event carries to this witness that comes down to
// two facts: the signing key is one that was committed to, and one committed
// key is enough. Anything needing more than one signature is refused: this
// witness takes one signature per event, so it cannot see such a threshold
// met, and a witness that receipted it anyway would attest to a rotation the
// identity's own rules do not authorise.

// publishedLog returns an identity's log before sn, as published.
type publishedLog func(sn int) ([][]byte, error)

func verifyRotation(raw []byte, cesrSig string, published publishedLog) error {
	ev, err := keri.ParseEvent(raw)
	if err != nil {
		return fmt.Errorf("the rotation does not parse: %w", err)
	}
	if ev.SN == 0 {
		return fmt.Errorf("a rotation cannot be an identity's first event")
	}
	if published == nil {
		return fmt.Errorf("this witness cannot read the log a rotation extends, so it will not attest to one")
	}
	held, err := published(int(ev.SN))
	if err != nil {
		return fmt.Errorf("a rotation is checked against the whole log before it, and %v; "+
			"send the log from its inception", err)
	}

	log := append(append([][]byte(nil), held...), raw)
	if err := keri.ValidateKEL(log); err != nil {
		return fmt.Errorf("the rotation is not a valid next step in this identity's log: %w", err)
	}

	sig, err := decodeCesrSignature(cesrSig)
	if err != nil {
		return err
	}
	signer := -1
	for i, k := range ev.Keys {
		if keri.VerifySignature(k, raw, sig) == nil {
			signer = i
			break
		}
	}
	if signer < 0 {
		return fmt.Errorf("the rotation is not signed by any of the keys it rotates to, so " +
			"whoever sent it does not hold the identity's next keys")
	}

	// The rotation's own threshold, by the library, from the signature as an
	// indexed attachment naming the key that made it.
	stream, err := withIndexedSignature(raw, signer, cesrSig)
	if err != nil {
		return err
	}
	if err := keri.ValidateStream(stream); err != nil {
		return fmt.Errorf("the rotation's signature does not meet the signing threshold it "+
			"sets: %w", err)
	}

	// The previous establishment event's threshold for its next keys.
	committed, nt, err := priorCommitment(held)
	if err != nil {
		return err
	}
	digest, err := keri.NextDigest(ev.Keys[signer])
	if err != nil {
		return fmt.Errorf("the signing key cannot be digested: %w", err)
	}
	found := false
	for _, d := range committed {
		if d == digest {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("the rotation is signed by %s, which the identity never committed to "+
			"as a next key", ev.Keys[signer])
	}
	if !oneSignatureMeets(nt) {
		return fmt.Errorf("the identity's previous establishment event requires its next keys "+
			"to sign with threshold %s; this witness takes one signature per event, so it cannot "+
			"see that met and will not attest to the rotation", strings.Trim(nt, `"`))
	}
	return nil
}

// withIndexedSignature attaches a controller signature to an event as KERI
// carries it on the wire: a controller-signatures group of one, the signature
// indexed by the position of the key that made it.
//
// The unindexed form a controller sends ("0B" then 86 characters) and the
// indexed one ("A", one character of index, then the same 86) differ only in
// that two-character code, because both encode 64 bytes behind two pad bytes.
func withIndexedSignature(raw []byte, index int, cesrSig string) ([]byte, error) {
	const b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	if index < 0 || index >= len(b64) {
		return nil, fmt.Errorf("the rotation is signed by key %d, past the %d a one-character "+
			"index can name", index, len(b64))
	}
	if len(cesrSig) != 88 || cesrSig[:2] != "0B" {
		return nil, fmt.Errorf("the controller signature is not a CESR Ed25519 signature")
	}
	out := make([]byte, 0, len(raw)+4+88)
	out = append(out, raw...)
	out = append(out, "-AAB"...)
	out = append(out, 'A', b64[index])
	out = append(out, cesrSig[2:]...)
	return out, nil
}

// priorCommitment is the next-key digests and their threshold from the newest
// establishment event in a log, as published.
func priorCommitment(log [][]byte) (digests []string, nt string, err error) {
	for i := len(log) - 1; i >= 0; i-- {
		ev, err := keri.ParseEvent(log[i])
		if err != nil {
			return nil, "", fmt.Errorf("event %d of the held log does not parse: %w", i, err)
		}
		if !ev.Establishment() {
			continue
		}
		var fields struct {
			NT json.RawMessage `json:"nt"`
		}
		if err := json.Unmarshal(ev.Raw, &fields); err != nil {
			return nil, "", fmt.Errorf("event %d of the held log does not read: %w", i, err)
		}
		return ev.NextDigest, string(fields.NT), nil
	}
	return nil, "", fmt.Errorf("the held log has no establishment event before the rotation")
}

// oneSignatureMeets reports whether a single committed key signing satisfies a
// next-key threshold, as it appears in the event: a hexadecimal count of at
// most one. A weighted threshold is answered no, which refuses rather than
// guesses; reading weights belongs in the KERI library, not here.
func oneSignatureMeets(nt string) bool {
	var count string
	if err := json.Unmarshal([]byte(nt), &count); err != nil {
		return false // absent, or weighted (a list)
	}
	n, err := strconv.ParseUint(count, 16, 32)
	return err == nil && n <= 1
}
