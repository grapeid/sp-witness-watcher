package api

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	keri "github.com/grapeid/keri-go"
	"github.com/grapeid/sp-witness-watcher/internal/store"
)

// qb64Key encodes a raw Ed25519 key the way an event carries it.
func qb64Key(pub ed25519.PublicKey) string {
	padded := make([]byte, 1+len(pub))
	copy(padded[1:], pub)
	return "D" + base64.RawURLEncoding.EncodeToString(padded)[1:]
}

// cesrSig encodes a signature the way a controller sends an unindexed one.
func cesrSig(sig []byte) string {
	padded := make([]byte, 2+len(sig))
	copy(padded[2:], sig)
	return "0B" + base64.RawURLEncoding.EncodeToString(padded)[2:]
}

const qb64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

// flipChar flips the given bits of the i'th character of a qb64 value.
func flipChar(s string, i, bits int) string {
	return s[:i] + string(qb64Alphabet[strings.IndexByte(qb64Alphabet, s[i])^bits]) + s[i+1:]
}

func noTip() (int, error) { return -1, nil }

// held is a log as this witness holds it published: each event with the
// signatures it was kept with.
type held []store.PublishedEvent

func (h held) before(sn int) ([]store.PublishedEvent, error) {
	if sn > len(h) {
		return nil, fmt.Errorf("this witness does not hold place %d of the log", len(h))
	}
	return h[:sn], nil
}

func (h held) tip() (int, error) { return len(h) - 1, nil }

// A founding event for one key, committing to a next one, a real one: keri-go
// judges events whole, so what is tested here is real events.
func inceptionOf(t *testing.T, keys []keyPair, kt string, next ...keyPair) (raw []byte, aid string) {
	t.Helper()
	raw, err := keri.BuildInception(keri.InceptionInput{
		Keys: pubs(keys...), NextDigests: digs(next...), Isith: json.RawMessage(fmt.Sprintf("%q", kt)),
		Nsith: json.RawMessage(`"1"`), Derivation: "self-addressing",
	})
	if err != nil {
		t.Fatal(err)
	}
	ev, _ := keri.ParseEvent(raw)
	return raw, ev.Identifier
}

func sigsBy(t *testing.T, raw []byte, signers map[int]keyPair) []string {
	t.Helper()
	var out []string
	for at := 0; at < 16; at++ {
		if k, ok := signers[at]; ok {
			out = append(out, signedAt(t, k, raw, keri.SamePlace(at)))
		}
	}
	return out
}

// The ordinary case: an event signed by the key it declares.
func TestAnEventSignedByItsOwnKeyIsAccepted(t *testing.T) {
	k, n := newKeyPair(t), newKeyPair(t)
	raw, _ := inceptionOf(t, []keyPair{k}, "1", n)
	got, err := verifyControllerSignatures(raw, []string{cesrSig(ed25519.Sign(k.priv, raw))}, nil, noTip)
	if err != nil || len(got) != 1 {
		t.Fatalf("a correctly signed event was refused: %v %v", err, got)
	}
}

// The case this exists for. Without it a witness attests to events submitted by
// anybody, and its receipts stop separating a real history from an invented one.
func TestAnEventSignedByAStrangerIsRefused(t *testing.T) {
	k, n, stranger := newKeyPair(t), newKeyPair(t), newKeyPair(t)
	raw, _ := inceptionOf(t, []keyPair{k}, "1", n)
	if _, err := verifyControllerSignatures(raw, []string{cesrSig(ed25519.Sign(stranger.priv, raw))}, nil, noTip); err == nil {
		t.Fatal("an event signed by a key it does not declare was accepted for witnessing")
	}
}

// Altering any byte changes what was signed.
func TestATamperedEventIsRefused(t *testing.T) {
	k, n := newKeyPair(t), newKeyPair(t)
	raw, _ := inceptionOf(t, []keyPair{k}, "1", n)
	sig := cesrSig(ed25519.Sign(k.priv, raw))
	tampered := append([]byte(nil), raw...)
	tampered[len(tampered)-3] ^= 0x01
	if _, err := verifyControllerSignatures(tampered, []string{sig}, nil, noTip); err == nil {
		t.Fatal("an altered event was accepted for witnessing")
	}
}

// The code 0B stands for two zero bytes, and covers 12 of their 16 bits; the
// other 4 are in the third character. Unchecked, every signature had sixteen
// spellings, each stored as a different string.
func TestASignatureWithLeadBitsIsRefused(t *testing.T) {
	k, n := newKeyPair(t), newKeyPair(t)
	raw, _ := inceptionOf(t, []keyPair{k}, "1", n)
	sig := cesrSig(ed25519.Sign(k.priv, raw))
	for bits := 0x04; bits < 0x40; bits += 0x04 {
		if _, err := verifyControllerSignatures(raw, []string{flipChar(sig, 2, bits)}, nil, noTip); err == nil {
			t.Fatalf("a signature with lead bits %x was accepted", bits)
		}
	}
}

// A key that is not an Ed25519 key spelt as one is not the identity's key: a
// Blake3 digest (code E) read by its length alone was one, and a key with lead
// bits had four spellings.
func TestAKeyThatIsNotWhatItsCodeSaysIsNotAnEventsKey(t *testing.T) {
	good, n := newKeyPair(t), newKeyPair(t)
	for name, key := range map[string]string{
		"a digest":       "E" + good.pub[1:],
		"lead bits 0x10": flipChar(good.pub, 1, 0x10),
		"lead bits 0x30": flipChar(good.pub, 1, 0x30),
	} {
		raw, err := keri.BuildInception(keri.InceptionInput{Keys: []string{key}, NextDigests: digs(n),
			Nsith: json.RawMessage(`"1"`), Derivation: "self-addressing"})
		if err != nil {
			continue // not even built: nothing to witness
		}
		if _, err := verifyControllerSignatures(raw, []string{cesrSig(ed25519.Sign(good.priv, raw))}, nil, noTip); err == nil {
			t.Errorf("%s: an event declaring it as its key was witnessed", name)
		}
	}
}

// An interaction carries no keys of its own: it is signed by whatever the last
// establishment event put in force, and a stranger cannot anchor against it.
func TestAnInteractionIsCheckedAgainstTheStoredKeyState(t *testing.T) {
	k, n, stranger := newKeyPair(t), newKeyPair(t), newKeyPair(t)
	icp, aid := inceptionOf(t, []keyPair{k}, "1", n)
	ev, _ := keri.ParseEvent(icp)
	log := held{{Raw: icp, Sigs: []string{signedAt(t, k, icp, keri.SamePlace(0))}}}
	ixn, err := keri.BuildInteraction(keri.InteractionInput{Prefix: aid, PriorSAID: ev.SAID, SN: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyControllerSignatures(ixn, []string{signedAt(t, k, ixn, keri.SamePlace(0))}, log.before, log.tip); err != nil {
		t.Fatalf("an interaction signed by the key in force was refused: %v", err)
	}
	if _, err := verifyControllerSignatures(ixn, []string{signedAt(t, stranger, ixn, keri.SamePlace(0))}, log.before, log.tip); err == nil {
		t.Fatal("an interaction signed by a stranger was accepted")
	}
}

// With no log on file there is no key to check against, and guessing is not an
// option: the witness refuses rather than attests.
func TestAnInteractionWithNoKnownKeyStateIsRefused(t *testing.T) {
	k, n := newKeyPair(t), newKeyPair(t)
	_, aid := inceptionOf(t, []keyPair{k}, "1", n)
	ixn, _ := keri.BuildInteraction(keri.InteractionInput{Prefix: aid, PriorSAID: aid, SN: 1})
	none := held{}
	if _, err := verifyControllerSignatures(ixn, []string{signedAt(t, k, ixn, keri.SamePlace(0))}, none.before, none.tip); err == nil {
		t.Fatal("an interaction was attested to with no key state to check it against")
	}
	if _, err := verifyControllerSignatures(ixn, []string{signedAt(t, k, ixn, keri.SamePlace(0))}, nil, noTip); err == nil {
		t.Fatal("an interaction was attested to with no log to read")
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

// A rotation is never trusted on the strength of its own declared key: it is
// judged against the commitment the identity made, which needs the log.
func TestARotationWithNoLogToCheckIsRefused(t *testing.T) {
	k, n := newKeyPair(t), newKeyPair(t)
	_, aid := inceptionOf(t, []keyPair{k}, "1", n)
	rot := rotation(t, aid, aid, "1", n)
	if _, err := verifyControllerSignatures(rot, []string{signedAt(t, n, rot, keri.SamePlace(0))}, nil, noTip); err == nil {
		t.Fatal("a rotation was attested to without its log")
	}
}

// An interaction that comes after a place this witness does not hold is checked
// against the key state at the end of the log it holds: by the threshold in
// force, from the signatures offered, and not by a key that merely appears in
// a later event. An event that changes the keys is refused there.
func TestAnInteractionPastAGapIsCheckedAgainstTheKeysInForceAtTheEndOfTheLogHeld(t *testing.T) {
	k, n, stranger := newKeyPair(t), newKeyPair(t), newKeyPair(t)
	icp, aid := inceptionOf(t, []keyPair{k}, "1", n)
	log := held{{Raw: icp, Sigs: []string{signedAt(t, k, icp, keri.SamePlace(0))}}}
	ixn, _ := keri.BuildInteraction(keri.InteractionInput{Prefix: aid, PriorSAID: "Eunknown", SN: 3})
	if _, err := verifyControllerSignatures(ixn, []string{signedAt(t, k, ixn, keri.SamePlace(0))}, log.before, log.tip); err != nil {
		t.Fatalf("an interaction past a gap signed by the key in force was refused: %v", err)
	}
	if _, err := verifyControllerSignatures(ixn, []string{signedAt(t, stranger, ixn, keri.SamePlace(0))}, log.before, log.tip); err == nil {
		t.Fatal("an interaction past a gap signed by a stranger was accepted")
	}
	rot, _ := keri.BuildRotation(keri.RotationInput{Prefix: aid, PriorSAID: "Eunknown", SN: 3, Keys: pubs(n),
		NextDigests: digs(newKeyPair(t)), Isith: json.RawMessage(`"1"`)})
	if _, err := verifyControllerSignatures(rot, []string{signedAt(t, n, rot, keri.SamePlace(0))}, log.before, log.tip); err == nil {
		t.Fatal("a rotation past a gap was checked without the event it follows")
	}
}

// Item 8: an identity with several keys signs with a threshold of them, and is
// checked against it. One signature of a 2-of-3 is refused, two are accepted,
// every one that verified is kept, and one that does not verify is dropped
// without refusing the rest.
func TestAnEventOfAnIdentityWithSeveralKeysIsCheckedAgainstItsThreshold(t *testing.T) {
	ks := []keyPair{newKeyPair(t), newKeyPair(t), newKeyPair(t)}
	raw, _ := inceptionOf(t, ks, "2", newKeyPair(t))
	if _, err := verifyControllerSignatures(raw, sigsBy(t, raw, map[int]keyPair{0: ks[0]}), nil, noTip); err == nil {
		t.Fatal("one signature of a two-of-three threshold was accepted")
	}
	got, err := verifyControllerSignatures(raw, sigsBy(t, raw, map[int]keyPair{0: ks[0], 2: ks[2]}), nil, noTip)
	if err != nil || len(got) != 2 {
		t.Fatalf("two signatures of a two-of-three threshold: %v %v", err, got)
	}
	forged := signedAt(t, newKeyPair(t), raw, keri.SamePlace(1))
	got, err = verifyControllerSignatures(raw, append(sigsBy(t, raw, map[int]keyPair{0: ks[0], 2: ks[2]}), forged), nil, noTip)
	if err != nil || len(got) != 2 {
		t.Fatalf("a forged signature beside two real ones: %v, kept %d, want the two that verified", err, len(got))
	}
	// The same threshold from a key that is not in the list does not count.
	if _, err := verifyControllerSignatures(raw, sigsBy(t, raw, map[int]keyPair{0: ks[0], 1: newKeyPair(t)}), nil, noTip); err == nil {
		t.Fatal("a signature by a key outside the list met the threshold")
	}
}
