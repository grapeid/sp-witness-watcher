package api

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"testing"

	keri "github.com/grapeid/keri-go"
)

// controller is an identity with a real key log, built by the KERI library a
// controller uses, so this witness is tested against events as they are
// published rather than stand-ins it would rightly refuse.
type controller struct {
	priv ed25519.PrivateKey
	aid  string
	log  [][]byte
	said []string
}

func newController(t *testing.T) *controller {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(nil)
	nextPub, _, _ := ed25519.GenerateKey(nil)
	next, err := keri.NextDigest(qb64Key(nextPub))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := keri.BuildInception(keri.InceptionInput{Keys: []string{qb64Key(pub)}, NextDigests: []string{next}, Derivation: "self-addressing"})
	if err != nil {
		t.Fatal(err)
	}
	ev, err := keri.ParseEvent(raw)
	if err != nil {
		t.Fatal(err)
	}
	return &controller{priv: priv, aid: ev.Identifier, log: [][]byte{raw}, said: []string{ev.SAID}}
}

// interact appends an interaction to the controller's log and returns it.
func (c *controller) interact(t *testing.T) []byte {
	t.Helper()
	sn := len(c.log)
	seal := json.RawMessage(fmt.Sprintf(`{"d":"%s"}`, c.said[sn-1]))
	raw, err := keri.BuildInteraction(keri.InteractionInput{Prefix: c.aid, PriorSAID: c.said[sn-1], SN: sn, Data: []json.RawMessage{seal}})
	if err != nil {
		t.Fatal(err)
	}
	ev, err := keri.ParseEvent(raw)
	if err != nil {
		t.Fatal(err)
	}
	c.log, c.said = append(c.log, raw), append(c.said, ev.SAID)
	return raw
}
