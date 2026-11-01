package api

import (
	"encoding/json"
	"fmt"
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
// A rotation is witnessed when all of this holds:
//   - it is a valid next event in the log this witness holds, from the
//     inception on: its sequence number follows, it names the event before it,
//     and the keys it presents could open enough of the previous establishment
//     event's commitment (keri.ValidateKEL, which also checks the witness
//     changes);
//   - its signature is by one of the keys it presents and meets the signing
//     threshold it sets (`kt`, checked by keri.ValidateStream);
//   - the key that signed opens the commitment its signature names: the
//     prior-next place an indexed signature carries (A, or 2A when the key sits
//     at a different place in `k` than its commitment in `n`), and that place
//     alone meets the threshold the previous establishment event set for its
//     next keys (`nt`, judged by keri.SatisfiesThreshold, nested and weighted
//     thresholds included). A current-only signature (B, 2B) opens nothing.
//
// The last is checked here from the one signature this witness is sent,
// because keri.ValidateKEL can only ask which keys a rotation PRESENTS, not
// which of them SIGNED. The signature must also be by the rotation's first key,
// the key everything after it is checked against. Anything needing more than
// one signature is refused: this witness takes one signature per event, so it
// cannot see such a threshold met, and a witness that receipted it anyway would
// attest to a rotation the identity's own rules do not authorise.
//
// Not checked: that a delegated rotation (drt) is anchored by its delegator,
// which KERI also requires. A delegated inception is not checked for it either;
// both wait on the witness holding the delegator's log.

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

	sig, err := readControllerSignature(cesrSig)
	if err != nil {
		return err
	}
	// The signature must be by the first key. Everything after a rotation is
	// checked against the first key in force (signingKeyOf), and so is the
	// rotation itself in the Identity Agent core's own log check; accepting a
	// rotation signed by another key would witness a log that its controller's
	// next interaction, and the core, then refuse.
	const signer = 0
	if sig.At.Index != signer || len(ev.Keys) == 0 ||
		keri.VerifySignature(ev.Keys[signer], raw, sig.Raw) != nil {
		return fmt.Errorf("the rotation is not signed by the first of the keys it rotates to, " +
			"so whoever sent it has not been shown to hold the identity's next keys")
	}

	// The rotation's own threshold, by the library, from the signature as an
	// indexed attachment naming the key that made it.
	group, err := keri.AttachControllerSigs([]string{sig.QB64})
	if err != nil {
		return err
	}
	if err := keri.ValidateStream(append(append([]byte(nil), raw...), group...)); err != nil {
		return fmt.Errorf("the rotation's signature does not meet the signing threshold it "+
			"sets: %w", err)
	}

	// The previous establishment event's commitment, opened by the signing key
	// at the place its signature names.
	committed, nt, err := priorCommitment(held)
	if err != nil {
		return err
	}
	if sig.At.CurrentOnly {
		return fmt.Errorf("the rotation is signed with a current-only signature (%s), which "+
			"opens none of the identity's committed next keys", sig.Code)
	}
	digest, err := keri.NextDigest(ev.Keys[signer])
	if err != nil {
		return fmt.Errorf("the signing key cannot be digested: %w", err)
	}
	if sig.At.Ondex < 0 || sig.At.Ondex >= len(committed) || committed[sig.At.Ondex] != digest {
		return fmt.Errorf("the rotation is signed by %s, which the identity did not commit to "+
			"as next key %d, the place its signature names", ev.Keys[signer], sig.At.Ondex)
	}
	met, err := keri.SatisfiesThreshold(nt, []int{sig.At.Ondex})
	if err != nil {
		return fmt.Errorf("the identity's previous establishment event sets a next-key "+
			"threshold that cannot be read: %w", err)
	}
	if !met {
		return fmt.Errorf("the identity's previous establishment event requires its next keys "+
			"to sign with threshold %s; this witness takes one signature per event, and one "+
			"committed key does not meet it, so it will not attest to the rotation",
			strings.Trim(string(nt), `"`))
	}
	return nil
}

// priorCommitment is the next-key digests and their threshold from the newest
// establishment event in a log, as published.
func priorCommitment(log [][]byte) (digests []string, nt json.RawMessage, err error) {
	for i := len(log) - 1; i >= 0; i-- {
		ev, err := keri.ParseEvent(log[i])
		if err != nil {
			return nil, nil, fmt.Errorf("event %d of the held log does not parse: %w", i, err)
		}
		if !ev.Establishment() {
			continue
		}
		var fields struct {
			NT json.RawMessage `json:"nt"`
		}
		if err := json.Unmarshal(ev.Raw, &fields); err != nil {
			return nil, nil, fmt.Errorf("event %d of the held log does not read: %w", i, err)
		}
		return ev.NextDigest, fields.NT, nil
	}
	return nil, nil, fmt.Errorf("the held log has no establishment event before the rotation")
}
