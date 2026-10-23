package api

import (
	"errors"
	"fmt"

	keri "github.com/grapeid/keri-go"

	"github.com/grapeid/sp-witness-watcher/internal/digest"
)

// eventBelongsHere checks a key event against itself and against the key log
// this witness holds for its identity, using the same KERI validation the
// Identity Agent core applies to a whole log:
//   - it is well formed and its contents digest to the identifier it claims;
//   - an inception derives the identity's identifier from itself;
//   - any later event follows the event held one place before it, naming it
//     as its prior. An event at a place already held is left to the caller,
//     which answers the same event with its receipt and anything else as a
//     conflict.
//
// errNoPredecessor is an event whose predecessor this witness does not hold
// yet: kept in escrow until it does, as KERI witnesses do, rather than refused.
var errNoPredecessor = errors.New("this witness does not hold the event before this one yet")

// errNextDisagrees is an event filling a place whose successor, already held,
// names another event as its prior: a second history at that place.
var errNextDisagrees = errors.New("the event held after this place names another event before it")

func eventBelongsHere(raw []byte, held []map[string]interface{}) error {
	if err := keri.ValidateEvent(raw); err != nil {
		return fmt.Errorf("the event is not what it says it is: %w", err)
	}
	ev, err := keri.ParseEvent(raw)
	if err != nil {
		return fmt.Errorf("the event does not parse: %w", err)
	}
	sn := int(ev.SN)
	switch ev.Ilk {
	case "icp", "dip":
		if err := keri.ValidateKEL([][]byte{raw}); err != nil {
			return fmt.Errorf("the inception does not establish the identifier it names: %w", err)
		}
		return nil
	}
	if sn == 0 {
		return fmt.Errorf("an identity's first event is its inception")
	}
	for _, h := range held {
		if digest.EventSeq(h) == sn {
			return nil // held already: the same event, or a conflict
		}
	}
	// Filling a place left empty: the event held after it must name this one
	// as its prior, or this is another history at that place.
	for _, h := range held {
		if digest.EventSeq(h) != sn+1 {
			continue
		}
		if next, _ := h["p"].(string); next != ev.SAID {
			return errNextDisagrees
		}
	}
	for _, h := range held {
		if digest.EventSeq(h) != sn-1 {
			continue
		}
		if prior, _ := h["d"].(string); prior != ev.PriorSAID {
			return fmt.Errorf("the event does not follow the event held before it")
		}
		return nil
	}
	return errNoPredecessor
}
