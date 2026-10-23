package api

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	keri "github.com/grapeid/keri-go"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/grapeid/sp-witness-watcher/internal/signer"
	"github.com/grapeid/sp-witness-watcher/internal/store"
)

func hexWorld(t *testing.T) (http.Handler, *signer.Identity) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	id, err := signer.LoadOrCreate(filepath.Join(dir, "id"))
	if err != nil {
		t.Fatal(err)
	}
	return New(st, id).Router(), id
}

func postEvent(t *testing.T, router http.Handler, aid string, raw []byte, priv ed25519.PrivateKey) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(map[string]interface{}{
		"aid": aid, "event_b64": base64.StdEncoding.EncodeToString(raw),
		"cesr_signature": cesrSig(ed25519.Sign(priv, raw)),
	})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/witness/event", bytes.NewReader(body)))
	return rec
}

// The tip of a key log this witness holds nothing of is -1, still signed, and
// a tip asked for without a nonce is refused.
func TestATipIsAskedForWithANonce(t *testing.T) {
	router, _ := hexWorld(t)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/witness/kel/ENobody/tip?nonce=x", nil))
	var tip struct {
		SN        int    `json:"sn"`
		Signature string `json:"signature"`
	}
	json.Unmarshal(rec.Body.Bytes(), &tip)
	if rec.Code != http.StatusOK || tip.SN != -1 || tip.Signature == "" {
		t.Fatalf("an empty key log's tip: %d %s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/witness/kel/ENobody/tip", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("a tip asked for without a nonce was answered %d", rec.Code)
	}
}

// What this witness signs about its tip is the Identity Agent core's
// TipStatement byte for byte, or no Identity Agent believes its answers.
func TestTheTipStatementMatchesTheCore(t *testing.T) {
	if got := tipStatement("EAid", "n-1", 17, "ESaid"); got != "witness-kel-tip/v1\nEAid\nn-1\n17\nESaid" {
		t.Fatalf("the tip statement is %q", got)
	}
}

// A key event's sequence number is hexadecimal. A real key log past its tenth
// and sixteenth events is witnessed in order, each at its own place: read as
// decimal, event "a" became 0 and was refused as a conflicting inception.
func TestAKeyLogPastItsSixteenthEventIsWitnessed(t *testing.T) {
	router, id := hexWorld(t)
	c := newController(t)
	if rec := postEvent(t, router, c.aid, c.log[0], c.priv); rec.Code != http.StatusOK {
		t.Fatalf("inception: %d %s", rec.Code, rec.Body.String())
	}
	for sn := 1; sn <= 17; sn++ {
		if rec := postEvent(t, router, c.aid, c.interact(t), c.priv); rec.Code != http.StatusOK {
			t.Fatalf("event %x was refused: %d %s", sn, rec.Code, rec.Body.String())
		}
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/witness/kel/"+c.aid+"/tip?nonce=n-1", nil))
	var tip struct {
		AID, Nonce, SAID, Signature string
		SN                          int
		WitnessAID                  string `json:"witness_aid"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &tip); err != nil || rec.Code != http.StatusOK {
		t.Fatalf("tip: %d %s", rec.Code, rec.Body.String())
	}
	last := c.said[len(c.said)-1]
	if tip.SN != 17 || tip.SAID != last || tip.Nonce != "n-1" || tip.WitnessAID != id.AID {
		t.Fatalf("the witness says it holds %+v", tip)
	}
	sig, err := base64.RawURLEncoding.DecodeString("AA" + tip.Signature[2:])
	if err != nil || !ed25519.Verify(id.PublicKey, []byte(tipStatement(c.aid, "n-1", 17, last)), sig[2:]) {
		t.Fatal("the tip is not signed by the witness over what it says")
	}
}

// The same event sent again is answered with its receipt, not a conflict, so
// a controller sending from where it thinks the witness stopped carries on.
func TestTheSameEventAgainIsReceipted(t *testing.T) {
	router, _ := hexWorld(t)
	c := newController(t)
	first := postEvent(t, router, c.aid, c.log[0], c.priv)
	again := postEvent(t, router, c.aid, c.log[0], c.priv)
	if first.Code != http.StatusOK || again.Code != http.StatusOK {
		t.Fatalf("the same event again: %d then %d %s", first.Code, again.Code, again.Body.String())
	}
	var a, b map[string]interface{}
	json.Unmarshal(first.Body.Bytes(), &a)
	json.Unmarshal(again.Body.Bytes(), &b)
	if a["cesr_signature"] != b["cesr_signature"] || a["event_said"] != b["event_said"] {
		t.Fatal("the same event again was not answered with its receipt")
	}
}

// An event whose predecessor has not arrived is held back, not refused; one
// naming another prior than the event held before it is refused.
func TestAnEventOutOfOrderIsRefused(t *testing.T) {
	router, _ := hexWorld(t)
	c := newController(t)
	postEvent(t, router, c.aid, c.log[0], c.priv)
	first := c.interact(t)
	second := c.interact(t)
	if rec := postEvent(t, router, c.aid, second, c.priv); rec.Code != http.StatusAccepted {
		t.Fatalf("an event with the one before it missing was answered %d, not held back", rec.Code)
	}
	if rec := postEvent(t, router, c.aid, first, c.priv); rec.Code != http.StatusOK {
		t.Fatalf("the next event: %d %s", rec.Code, rec.Body.String())
	}
	other := newController(t)
	stray, _ := keri.BuildInteraction(keri.InteractionInput{Prefix: c.aid, PriorSAID: other.said[0], SN: 3,
		Data: []json.RawMessage{json.RawMessage(`{"d":"` + other.said[0] + `"}`)}})
	if rec := postEvent(t, router, c.aid, stray, c.priv); rec.Code != http.StatusBadRequest {
		t.Fatalf("an event naming another prior was answered %d", rec.Code)
	}
}

// The attack this witness now refuses: an inception for an identifier nobody
// has sent yet, whose identifier is not derived from it, or whose contents do
// not digest to what it claims. Either would pre-empt the real identity.
func TestAForgedInceptionIsRefused(t *testing.T) {
	router, _ := hexWorld(t)
	real := newController(t)
	attacker := newController(t)
	pub, priv, _ := ed25519.GenerateKey(nil)
	// The attacker's own, valid, inception, filed under the real identifier
	// with the identifier rewritten to match.
	forged := []byte(strings.Replace(string(attacker.log[0]), attacker.aid, real.aid, -1))
	if rec := postEvent(t, router, real.aid, forged, attacker.priv); rec.Code != http.StatusBadRequest {
		t.Fatalf("an inception whose identifier is not derived from it was answered %d", rec.Code)
	}
	// A hand-made inception with a claimed digest.
	made := []byte(`{"v":"KERI10JSON000256_","t":"icp","d":"` + real.aid + `","i":"` + real.aid + `","s":"0","k":["` + qb64Key(pub) + `"]}`)
	if rec := postEvent(t, router, real.aid, made, priv); rec.Code != http.StatusBadRequest {
		t.Fatalf("a hand-made inception was answered %d", rec.Code)
	}
	if rec := postEvent(t, router, real.aid, real.log[0], real.priv); rec.Code != http.StatusOK {
		t.Fatalf("the real inception, after the forgeries: %d %s", rec.Code, rec.Body.String())
	}
}

// The log an older Identity Agent leaves: events its witnesses never got,
// then later ones. The later ones are held back, the tip stays below the gap,
// and once the missing events arrive everything held back is taken up in
// order.
func TestALogWithAGapIsTakenUpWhenTheGapFills(t *testing.T) {
	router, _ := hexWorld(t)
	c := newController(t)
	postEvent(t, router, c.aid, c.log[0], c.priv)
	for i := 0; i < 5; i++ {
		c.interact(t)
	}
	// Events 1 and 2 never sent; 3, 4 and 5 sent.
	for sn := 3; sn <= 5; sn++ {
		if rec := postEvent(t, router, c.aid, c.log[sn], c.priv); rec.Code != http.StatusAccepted {
			t.Fatalf("event %d past a gap was answered %d %s", sn, rec.Code, rec.Body.String())
		}
	}
	tipOf := func() int {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/witness/kel/"+c.aid+"/tip?nonce=n", nil))
		var tip struct {
			SN int `json:"sn"`
		}
		json.Unmarshal(rec.Body.Bytes(), &tip)
		return tip.SN
	}
	if tip := tipOf(); tip != 0 {
		t.Fatalf("with a gap the tip is %d", tip)
	}
	postEvent(t, router, c.aid, c.log[1], c.priv)
	if tip := tipOf(); tip != 1 {
		t.Fatalf("with the gap half filled the tip is %d", tip)
	}
	postEvent(t, router, c.aid, c.log[2], c.priv)
	if tip := tipOf(); tip != 5 {
		t.Fatalf("with the gap filled the tip is %d, not the last held back", tip)
	}
}

// An event past a gap whose signature does not hold is refused, not held
// back, and the genuine event takes its place once the gap fills.
func TestAWronglySignedEventPastAGapIsRefused(t *testing.T) {
	router, _ := hexWorld(t)
	c := newController(t)
	postEvent(t, router, c.aid, c.log[0], c.priv)
	one, two := c.interact(t), c.interact(t)
	_, other, _ := ed25519.GenerateKey(nil)
	if rec := postEvent(t, router, c.aid, two, other); rec.Code != http.StatusBadRequest {
		t.Fatalf("a wrongly signed event past a gap was answered %d", rec.Code)
	}
	postEvent(t, router, c.aid, one, c.priv)
	if rec := postEvent(t, router, c.aid, two, c.priv); rec.Code != http.StatusOK {
		t.Fatalf("the genuine event: %d %s", rec.Code, rec.Body.String())
	}
}

// Filling a place left empty under an event already held: the new event must
// be the one that event names before it, or it is another history there. It
// is held back and the conflict recorded; the right one fills the place.
func TestFillingAGapMustAgreeWithWhatFollows(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	id, _ := signer.LoadOrCreate(filepath.Join(dir, "id"))
	router := New(st, id).Router()
	c := newController(t)
	postEvent(t, router, c.aid, c.log[0], c.priv)
	one, two, three := c.interact(t), c.interact(t), c.interact(t)
	postEvent(t, router, c.aid, one, c.priv)
	// As an older witness left it: event 3 held, event 2 missing.
	var parsed map[string]interface{}
	json.Unmarshal(three, &parsed)
	if _, _, err := st.AcceptEvent(c.aid, 3, parsed, "", ""); err != nil {
		t.Fatal(err)
	}
	other, _ := keri.BuildInteraction(keri.InteractionInput{Prefix: c.aid, PriorSAID: c.said[1], SN: 2,
		Data: []json.RawMessage{json.RawMessage(`{"d":"` + c.said[1] + `","other":"history"}`)}})
	if rec := postEvent(t, router, c.aid, other, c.priv); rec.Code != http.StatusConflict {
		t.Fatalf("an event disagreeing with what follows it was answered %d %s", rec.Code, rec.Body.String())
	}
	if found, _ := st.RepairSequences(false); len(found) != 1 || found[0].Conflicts != 1 {
		t.Fatalf("the disagreement was not recorded: %+v", found)
	}
	if rec := postEvent(t, router, c.aid, two, c.priv); rec.Code != http.StatusOK {
		t.Fatalf("the event what follows names: %d %s", rec.Code, rec.Body.String())
	}
	events, _ := st.GetKELEvents(c.aid)
	if len(events) != 4 {
		t.Fatalf("%d events held", len(events))
	}
}

// Events a stranger signed are neither held back nor counted as conflicts:
// they could otherwise fill an identity's escrow, or accuse it of a second
// history, without its controller ever signing anything.
func TestAStrangersEventsTakeNoEscrowAndRecordNoConflict(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	id, _ := signer.LoadOrCreate(filepath.Join(dir, "id"))
	router := New(st, id).Router()
	c := newController(t)
	_, stranger, _ := ed25519.GenerateKey(nil)
	postEvent(t, router, c.aid, c.log[0], c.priv)
	one, two, three := c.interact(t), c.interact(t), c.interact(t)
	_ = one
	if rec := postEvent(t, router, c.aid, three, stranger); rec.Code != http.StatusBadRequest {
		t.Fatalf("a stranger's event past a gap was answered %d", rec.Code)
	}
	if held, _ := st.EscrowedAt(c.aid, 3); len(held) != 0 {
		t.Fatal("a stranger's event was held back")
	}
	// As an older witness left it: event 3 held, 2 missing; a stranger's
	// event for 2 that disagrees with it.
	var parsed map[string]interface{}
	json.Unmarshal(three, &parsed)
	st.AcceptEvent(c.aid, 3, parsed, "", "")
	postEvent(t, router, c.aid, one, c.priv)
	other, _ := keri.BuildInteraction(keri.InteractionInput{Prefix: c.aid, PriorSAID: c.said[1], SN: 2,
		Data: []json.RawMessage{json.RawMessage(`{"d":"` + c.said[1] + `","other":"history"}`)}})
	if rec := postEvent(t, router, c.aid, other, stranger); rec.Code != http.StatusBadRequest {
		t.Fatalf("a stranger's disagreeing event was answered %d", rec.Code)
	}
	if found, _ := st.RepairSequences(false); len(found) != 0 && found[0].Conflicts != 0 {
		t.Fatalf("a stranger's event recorded a conflict: %+v", found)
	}
	if rec := postEvent(t, router, c.aid, two, c.priv); rec.Code != http.StatusOK {
		t.Fatalf("the genuine event: %d %s", rec.Code, rec.Body.String())
	}
}

// The reviewer's flood: somebody without the identity's key sends it
// well-formed events. None is held back, and the identity's own event that
// arrives before its predecessor still is.
func TestAnEscrowCannotBeFloodedWithoutTheKey(t *testing.T) {
	router, _ := hexWorld(t)
	alice := newController(t)
	if rec := postEvent(t, router, alice.aid, alice.log[0], alice.priv); rec.Code != http.StatusOK {
		t.Fatalf("inception: %d %s", rec.Code, rec.Body.String())
	}
	_, mallory, _ := ed25519.GenerateKey(nil)
	for i := 0; i < 70; i++ {
		seal := json.RawMessage(fmt.Sprintf(`{"d":"Ejunk%04d"}`, i))
		raw, _ := keri.BuildInteraction(keri.InteractionInput{Prefix: alice.aid, PriorSAID: "Eunknownprior", SN: 5, Data: []json.RawMessage{seal}})
		if rec := postEvent(t, router, alice.aid, raw, mallory); rec.Code == http.StatusAccepted {
			t.Fatal("an event its controller never signed was held back")
		}
	}
	alice.interact(t)
	alice.interact(t)
	if rec := postEvent(t, router, alice.aid, alice.log[2], alice.priv); rec.Code != http.StatusAccepted {
		t.Fatalf("alice's own event before its predecessor was answered %d %s", rec.Code, rec.Body.String())
	}
}

// Nothing is held back for an identity whose inception this witness does not
// hold.
func TestNothingIsHeldBackForAnUnknownIdentity(t *testing.T) {
	router, _ := hexWorld(t)
	c := newController(t)
	c.interact(t)
	two := c.interact(t)
	if rec := postEvent(t, router, c.aid, two, c.priv); rec.Code == http.StatusAccepted {
		t.Fatal("an event was held back for an identity with no inception here")
	}
}

func postEventFrom(t *testing.T, router http.Handler, ip, aid string, raw []byte, priv ed25519.PrivateKey) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(map[string]interface{}{
		"aid": aid, "event_b64": base64.StdEncoding.EncodeToString(raw),
		"cesr_signature": cesrSig(ed25519.Sign(priv, raw)),
	})
	req := httptest.NewRequest(http.MethodPost, "/witness/event", bytes.NewReader(body))
	req.RemoteAddr = ip + ":1234"
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

// Identities made for the purpose, each holding events back from its own
// address, cannot fill the escrow so that an established identity's event,
// arriving before its predecessor, has nowhere to wait.
func TestFreshIdentitiesCannotCrowdOutAnEstablishedOne(t *testing.T) {
	total, reserved := store.EscrowTotalLimit, store.EscrowReserved
	store.EscrowTotalLimit, store.EscrowReserved = 30, 10
	t.Cleanup(func() { store.EscrowTotalLimit, store.EscrowReserved = total, reserved })
	router, _ := hexWorld(t)
	// Alice's history here is two days old.
	store.Now = func() time.Time { return time.Now().Add(-48 * time.Hour) }
	alice := newController(t)
	postEventFrom(t, router, "10.1.0.1", alice.aid, alice.log[0], alice.priv)
	postEventFrom(t, router, "10.1.0.1", alice.aid, alice.interact(t), alice.priv)
	store.Now = time.Now
	refused := 0
	// Forty addresses, each with a fresh identity holding one interaction
	// beyond its inception: none of them established.
	for i := 0; i < 40; i++ {
		ip := fmt.Sprintf("10.2.%d.%d", i/200, i%200+1)
		c := newController(t)
		if rec := postEventFrom(t, router, ip, c.aid, c.log[0], c.priv); rec.Code != http.StatusOK {
			t.Fatalf("inception: %d %s", rec.Code, rec.Body.String())
		}
		if rec := postEventFrom(t, router, ip, c.aid, c.interact(t), c.priv); rec.Code != http.StatusOK {
			t.Fatalf("interaction: %d %s", rec.Code, rec.Body.String())
		}
		c.interact(t)
		if rec := postEventFrom(t, router, ip, c.aid, c.interact(t), c.priv); rec.Code == http.StatusTooManyRequests {
			refused++
		}
	}
	if refused != 20 {
		t.Fatalf("%d of 40 fresh identities were refused, where 20 fit outside the reserve", refused)
	}
	alice.interact(t)
	alice.interact(t)
	if rec := postEventFrom(t, router, "10.1.0.1", alice.aid, alice.log[3], alice.priv); rec.Code != http.StatusAccepted {
		t.Fatalf("the established identity's early event was answered %d %s", rec.Code, rec.Body.String())
	}
}

// A witness hands back an event it holds exactly as published and signed.
func TestAWitnessHandsBackAnEvent(t *testing.T) {
	router, _ := hexWorld(t)
	c := newController(t)
	postEvent(t, router, c.aid, c.log[0], c.priv)
	one := c.interact(t)
	postEvent(t, router, c.aid, one, c.priv)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/witness/kel/"+c.aid+"/event/1", nil))
	var out struct {
		Raw string `json:"raw_bytes_b64"`
		Sig string `json:"cesr_signature"`
	}
	json.Unmarshal(rec.Body.Bytes(), &out)
	if rec.Code != http.StatusOK || out.Raw != base64.StdEncoding.EncodeToString(one) || out.Sig != cesrSig(ed25519.Sign(c.priv, one)) {
		t.Fatalf("handed back %d %s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/witness/kel/"+c.aid+"/event/5", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("an event not held was answered %d", rec.Code)
	}
}

// IPv6 senders are grouped by their /64 for the per-sender cap.
func TestAnIPv6SenderIsItsSlash64(t *testing.T) {
	if senderOf("2001:db8:1:2:aaaa::1") != senderOf("2001:db8:1:2:bbbb::9") {
		t.Fatal("two addresses in one /64 count as two senders")
	}
	if senderOf("2001:db8:1:2::1") == senderOf("2001:db8:1:3::1") {
		t.Fatal("two /64s count as one sender")
	}
	if senderOf("10.0.0.1") == senderOf("10.0.0.2") {
		t.Fatal("two IPv4 addresses count as one sender")
	}
}
