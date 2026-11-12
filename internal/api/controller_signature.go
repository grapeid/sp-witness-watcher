package api

import (
	"encoding/json"
	"fmt"
	"strconv"

	keri "github.com/grapeid/keri-go"
	"github.com/grapeid/sp-common/decode"
	"github.com/grapeid/sp-witness-watcher/internal/store"
)

// Checking that a controller authorised the event it is asking to have
// witnessed.
//
// A receipt is worth exactly what it establishes, and what it is read as
// establishing is that this witness saw this event from this identity. The
// second half needs checking, or a witness attests to whatever it is sent — and
// receipts stop distinguishing a real history from an invented one.
//
// The identity's own key state is used, from the log this witness holds. That is
// not the same as deciding the identity is genuine, and it is not meant to be: a
// witness's job is to record what it saw and who signed it, not to adjudicate.
// What this rules out is somebody submitting events under an identity whose keys
// they do not hold.

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

// publishedLog returns an identity's log before sn, as published and signed.
type publishedLog func(sn int) ([]store.PublishedEvent, error)

// signedMessage is an event followed by its controller signatures, as it
// travels, which is what keri-go judges.
func signedMessage(raw []byte, sigs []string) ([]byte, error) {
	if len(sigs) == 0 {
		return nil, fmt.Errorf("an event must carry the controller signature over its published bytes")
	}
	qb := make([]string, 0, len(sigs))
	for _, s := range sigs {
		cs, err := readControllerSignature(s)
		if err != nil {
			return nil, err
		}
		qb = append(qb, cs.QB64)
	}
	group, err := keri.AttachControllerSigs(qb)
	if err != nil {
		return nil, err
	}
	return append(append([]byte(nil), raw...), group...), nil
}

// verifyControllerSignatures checks that the identity an event claims to come
// from authorised it, and returns the signatures that did, as they are to be
// kept and served.
//
// The judge is keri-go's VerifyEvent, against the key state in force as this
// witness holds the log: an inception against its own keys (it is
// self-certifying), a rotation against the commitment the identity made to its
// next keys, and an interaction against the keys of the newest establishment
// event, each against the signing threshold in force. So an identity with
// several keys is checked as keripy checks it: enough of them, by weight or
// count, signed; and a signature that does not verify is dropped and the rest
// are judged, as there.
//
// An event whose predecessor this witness does not yet hold is checked only if
// it is an interaction, against the key state at the end of the log it holds
// (checkPastAGap); a rotation there is refused, because what it rotates from is
// not known.
func verifyControllerSignatures(raw []byte, offered []string, published publishedLog, tip func() (int, error)) ([]string, error) {
	ev, err := keri.ParseEvent(raw)
	if err != nil {
		return nil, fmt.Errorf("the event does not parse: %w", err)
	}
	msg, err := signedMessage(raw, offered)
	if err != nil {
		return nil, err
	}
	if ev.SN == 0 {
		v, err := keri.VerifyEvent(nil, msg)
		if err != nil {
			return nil, fmt.Errorf("the event is not authorised by the identity it claims to come from: %w", err)
		}
		return v.Signatures, nil
	}
	if published == nil {
		return nil, fmt.Errorf("this witness cannot read the log an event extends, so it will not attest to one")
	}
	if n, terr := tip(); terr == nil && int(ev.SN) > n+1 {
		return checkPastAGap(ev, raw, offered, published, n)
	}
	held, err := published(int(ev.SN))
	if err != nil {
		return nil, fmt.Errorf("an event is checked against the whole log before it, and %v; "+
			"send the log from its inception", err)
	}
	log, err := keri.ValidateSignedKEL(messagesOf(held))
	if err != nil {
		return nil, fmt.Errorf("the log this witness holds before place %d does not verify: %w", ev.SN, err)
	}
	v, err := keri.VerifyEvent(log.State(), msg)
	if err != nil {
		return nil, fmt.Errorf("the event is not a valid next step in this identity's log, or its "+
			"signatures do not meet the threshold in force: %w", err)
	}
	return v.Signatures, nil
}

// checkPastAGap checks an interaction that comes after a place this witness
// does not hold: its signatures against the keys, and the signing threshold,
// of the newest establishment event in the log held up to tip. Whether it
// belongs at that place is not known until the places before it arrive, when
// it is checked again. A rotation cannot be judged without the event it follows,
// so it is refused.
func checkPastAGap(ev *keri.Event, raw []byte, offered []string, published publishedLog, tip int) ([]string, error) {
	if ev.Establishment() {
		return nil, fmt.Errorf("an event that changes the keys cannot be checked while this witness "+
			"does not hold place %d of the log; send the log in order", tip+1)
	}
	if tip < 0 {
		return nil, fmt.Errorf("this event inherits its key from an establishment event, and this " +
			"witness holds none at an earlier sequence for that identity — submit the inception first")
	}
	held, err := published(tip + 1)
	if err != nil {
		return nil, fmt.Errorf("an event is checked against the whole log before it, and %v; "+
			"send the log from its inception", err)
	}
	log, err := keri.ValidateSignedKEL(messagesOf(held))
	if err != nil {
		return nil, fmt.Errorf("the log this witness holds does not verify: %w", err)
	}
	keys := log.State().Keys()
	var threshold json.RawMessage
	for i := len(held) - 1; i >= 0; i-- {
		hev, err := keri.ParseEvent(held[i].Raw)
		if err != nil {
			return nil, err
		}
		if hev.Establishment() {
			var f struct {
				KT json.RawMessage `json:"kt"`
			}
			if err := json.Unmarshal(hev.Raw, &f); err != nil || len(f.KT) == 0 {
				return nil, fmt.Errorf("the signing threshold in force cannot be read")
			}
			threshold = f.KT
			break
		}
	}
	var kept []string
	var places []int
	seen := map[int]bool{}
	for _, o := range offered {
		cs, err := readControllerSignature(o)
		if err != nil {
			continue
		}
		at := cs.At.Index
		if at < 0 || at >= len(keys) || seen[at] || keri.VerifySignature(keys[at], raw, cs.Raw) != nil {
			continue // dropped, as keri-go drops one that does not verify
		}
		seen[at] = true
		places = append(places, at)
		kept = append(kept, cs.QB64)
	}
	met, err := keri.SatisfiesThreshold(threshold, places)
	if err != nil || !met {
		return nil, fmt.Errorf("the event is not signed by enough of the keys in force to meet the " +
			"signing threshold, so the identity it claims to come from did not authorise it")
	}
	return kept, nil
}

func messagesOf(held []store.PublishedEvent) [][]byte {
	out := make([][]byte, 0, len(held))
	for _, h := range held {
		m, err := signedMessage(h.Raw, h.Sigs)
		if err != nil {
			m = h.Raw // unreadable signatures make the log fail to verify, which is the answer
		}
		out = append(out, m)
	}
	return out
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
