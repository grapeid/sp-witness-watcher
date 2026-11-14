package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/witnessproto"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	keri "github.com/grapeid/keri-go"
	"github.com/grapeid/sp-common/decode"
	"github.com/grapeid/sp-common/sign"
	"github.com/grapeid/sp-witness-watcher/internal/digest"
	"github.com/grapeid/sp-witness-watcher/internal/store"
)

type Server struct {
	Store    *store.ServiceStore
	Identity *sign.Identity
	lim      *ipLimiter
}

func New(st *store.ServiceStore, id *sign.Identity) *Server {
	return &Server{Store: st, Identity: id, lim: newIPLimiter(120, time.Minute)}
}

func (s *Server) Router() chi.Router {
	r := chi.NewRouter()
	r.Use(middleware.RequestID, middleware.Logger, middleware.Recoverer)

	r.Get("/health", s.handleHealth)
	// Also under /api, for the same reason the witness routes are: an Identity
	// Agent addresses everything under /api because it serves its own witness
	// routes there, and its heartbeat builds <base>/api/health. Without this
	// every heartbeat answered 404 and counted as a failure, so a perfectly
	// healthy witness marched towards being written off — 288 consecutive
	// failures, which is 72 hours at a 15 minute interval.
	//
	// Mounted here rather than inside the role gates below, because health is
	// not a role: a watcher-only instance still has to be able to say it is
	// alive, and it reports which roles it offers in the body.
	r.Get("/api/health", s.handleHealth)

	roles := RolesFromEnv()

	witnessRoutes := func(r chi.Router) {
		r.Post("/event", s.handleWitnessEvent)
		r.Get("/kel/{aid}", s.handleWitnessKel)
		r.Get("/kel/{aid}/tip", s.handleWitnessKelTip)
		r.Get("/kel/{aid}/event/{sn}", s.handleWitnessKelEvent)
	}
	if roles.Witness {
		r.Route("/witness", witnessRoutes)
		// Also under /api, which is where an Identity Agent serves its own
		// witness routes. Without this a controller has to know which kind of
		// witness it is talking to in order to address it, and the agent's own
		// broadcast builds the /api path — so every submission here answered
		// 404 and was recorded as the witness being offline.
		r.Route("/api/witness", witnessRoutes)
	}

	// The watcher side: what this service has seen of other identities' logs,
	// answered rather than pushed. A watcher never volunteers an alert; the
	// verifier compares and decides for itself, which is what makes a
	// fraudulent-report attack pointless.
	if roles.Watcher {
		watcherRoutes := func(r chi.Router) {
			r.Get("/kel-digest", s.handleKelDigest)
			r.Post("/kel-check", s.handleKelCheck)
		}
		r.Route("/public", watcherRoutes)
		r.Route("/api/public", watcherRoutes)
	}

	r.Post("/enroll", s.handleEnroll)

	return r
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, map[string]interface{}{
		"status": "active", "service": "sp-witness-watcher",
		"service_aid": s.Identity.AID,
		// What this instance actually offers, so an operator and a relying
		// party read the same answer rather than inferring it from a 404.
		"roles": RolesFromEnv().Enabled(),
	})
}

type witnessEventRequest struct {
	AID string `json:"aid"`
	// Event is the parsed form. Still read so that a caller sending it gets an
	// explanation rather than "no event was supplied", but it is no longer
	// accepted — see event().
	Event map[string]interface{} `json:"event"`
	// EventB64 is the event exactly as the controller published it, and
	// CesrSignature is the controller's signature over those bytes. Both are
	// required.
	//
	// It has to be the bytes, for a reason that goes to what a receipt is
	// worth. An identifier is a digest over an exact byte sequence in an exact
	// field order, so an event re-encoded from a parsed object is a different
	// event — and a witness handed only the parsed form cannot tell whether the
	// identity it is about to attest for actually authorised anything. It can
	// only report that somebody sent it a JSON object.
	EventB64      string `json:"event_b64"`
	CesrSignature string `json:"cesr_signature"`
	// CesrSignatures is every controller signature over the event, for an
	// identity with several keys, which signs with a threshold of them. When
	// present it is the whole list and CesrSignature is its first.
	CesrSignatures []string `json:"cesr_signatures"`
}

// signatures is every controller signature the request offers.
func (req witnessEventRequest) signatures() []string {
	var out []string
	for _, s := range req.CesrSignatures {
		if s != "" {
			out = append(out, s)
		}
	}
	if len(out) == 0 && req.CesrSignature != "" {
		out = []string{req.CesrSignature}
	}
	return out
}

// event returns the event to receipt, as bytes and parsed.
//
// The published bytes are now required. The parsed-only form used to be
// accepted and receipted "on weaker terms", which meant no signature check at
// all — and the terms were not recorded anywhere, so a caller could not tell a
// checked receipt from an unchecked one. Worse, the unchecked event was still
// stored, and storing it moves the digest this service reports for that
// identity, so anyone could make an identity look duplicitous to the watcher
// layer by getting there first with a junk event at a sequence number nobody
// had reached yet.
//
// No live caller is affected: the Identity Agent has always sent event_b64
// with a signature (see SubmitToWitness in identity-agent-core).
func (req witnessEventRequest) event() (raw []byte, parsed map[string]interface{}, err error) {
	if req.EventB64 == "" {
		if req.Event != nil {
			return nil, nil, fmt.Errorf("send the event as published bytes in event_b64 with " +
				"cesr_signature over them; the parsed form cannot be verified and is no longer receipted")
		}
		return nil, nil, fmt.Errorf("no event was supplied")
	}
	raw, err = decode.Base64(req.EventB64)
	if err != nil {
		return nil, nil, fmt.Errorf("event_b64 is not readable base64: %w", err)
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, nil, fmt.Errorf("event_b64 does not contain a KERI event: %w", err)
	}
	return raw, parsed, nil
}

func (s *Server) handleWitnessEvent(w http.ResponseWriter, r *http.Request) {
	// Writing paths are rate limited too. Only the read paths were, and this
	// one both stores state and spends a signature.
	if !s.lim.allow(clientIP(r)) {
		writeErr(w, http.StatusTooManyRequests, "slow down")
		return
	}
	var req witnessEventRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	if req.AID == "" {
		writeErr(w, http.StatusBadRequest, "aid required")
		return
	}
	rawEvent, event, err := req.event()
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	// The event must belong to the AID it is being filed under. Without this,
	// a genuine, correctly-signed event from identity X can be POSTed with
	// aid set to a victim: the signature verifies (it is real), the event is
	// stored at the victim's AID, and it moves the digest this service reports
	// for the victim — so the victim's own real event then collides and the
	// victim is recorded as equivocating. The signature check alone does not
	// stop this, because the signature is X's and it is valid; what stops it
	// is binding the stored AID to the event's own identifier.
	if i, _ := event["i"].(string); i != req.AID {
		writeErr(w, http.StatusBadRequest,
			"the event's identifier does not match the aid it is filed under")
		return
	}

	// Nothing is stored or receipted until the identity is shown to have
	// authorised it. A witness that attests to whatever it is sent is one
	// anybody can make say anything, and its receipts stop distinguishing a
	// real history from an invented one — and because a stored event moves the
	// digest this service reports, an unchecked write is also a way to accuse
	// an innocent identity of equivocating.
	offered := req.signatures()
	if len(offered) == 0 {
		writeErr(w, http.StatusBadRequest,
			"an event must carry the controller signature over its published bytes")
		return
	}
	// The event must be what it says it is before anything else is believed:
	// its contents digest to the identifier it claims, an inception derives
	// the identity's identifier from itself, and any later event names, as
	// its prior, the event this witness holds one place before it. Without
	// this anybody could plant an inception, under an identifier no witness
	// holds yet, that its real controller never made.
	events, _ := s.Store.GetKELEvents(req.AID)
	// The controller's signature, checked against the key in force as this
	// witness holds the log, before the event is held back or counted as a
	// conflict: otherwise anybody could fill an identity's escrow, or record
	// conflicts against it, with events its controller never signed. An event
	// whose signing key cannot be shown from what is held, such as one past a
	// gap that held a rotation, is refused, and its controller sends again in
	// order.
	verified, err := verifyControllerSignatures(rawEvent, offered, s.publishedLog(req.AID), s.tipOf(req.AID))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	// What is kept and served is the signatures that verified, as attached.
	sigField := store.EncodeSignatures(verified)
	switch err := eventBelongsHere(rawEvent, events); {
	case (errors.Is(err, errNoPredecessor) || errors.Is(err, errNextDisagrees)) && len(events) == 0:
		// Nothing held back for an identity this witness holds nothing of:
		// its controller sends its inception first.
		writeErr(w, http.StatusBadRequest, "this witness holds no inception for this identity; send the log from its inception")
		return
	case errors.Is(err, errNoPredecessor), errors.Is(err, errNextDisagrees):
		// Held back rather than refused: an event whose predecessor has not
		// arrived waits for it, and one that disagrees with what is held after
		// it waits too, with the disagreement recorded.
		if errors.Is(err, errNextDisagrees) {
			s.Store.RecordConflict(req.AID, seqOrMinus(event), "held-after-names-another", eventSAIDOf(event))
		}
		established, serr := s.Store.Established(req.AID)
		if serr != nil {
			writeErr(w, http.StatusInternalServerError, serr.Error())
			return
		}
		if eerr := s.Store.EscrowEvent(req.AID, seqOrMinus(event), eventSAIDOf(event),
			base64.StdEncoding.EncodeToString(rawEvent), sigField, senderOf(clientIP(r)), established); eerr != nil {
			writeErr(w, http.StatusTooManyRequests, eerr.Error())
			return
		}
		status := http.StatusAccepted
		if errors.Is(err, errNextDisagrees) {
			status = http.StatusConflict
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(map[string]interface{}{"escrowed": true, "reason": err.Error()})
		return
	case err != nil:
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	seq, ok := eventSeqOf(event)
	if !ok {
		writeErr(w, http.StatusBadRequest, "the event's sequence number is not readable")
		return
	}
	// An event already held at its place is answered with its receipt, as
	// though it had just arrived, so a controller sending from where it thinks
	// this witness stopped carries on. Something else there is a conflict.
	d, _, err := s.Store.AcceptEvent(req.AID, seq, event, base64.StdEncoding.EncodeToString(rawEvent), sigField)
	if errors.Is(err, store.ErrConflict) {
		// Correctly signed (checked above) and different from what is held: a second
		// history, unless what is held at that place is a recovery rotation that
		// replaces this event, which is what a recovery does to the interactions a
		// retired key signed: that is no second history and is not kept or served
		// as one (keripy does not call it duplicity either).
		if msg, merr := signedMessage(rawEvent, verified); merr == nil && s.retiredByHeldRecovery(req.AID, seq, msg) {
			writeErr(w, http.StatusConflict, "this place holds a recovery rotation that replaces this event")
			return
		}
		// Kept as published, beside the first, so this service can hand over both.
		// The first stays; nothing held is rewritten.
		if kerr := s.Store.KeepConflicting(req.AID, seq, eventSAIDOf(event),
			base64.StdEncoding.EncodeToString(rawEvent), sigField); kerr != nil {
			writeErr(w, http.StatusInternalServerError, kerr.Error())
			return
		}
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	// Events held back for this one are taken up now, in order, each checked
	// as though it had just arrived.
	s.promoteEscrowed(req.AID, seq)
	// A receipt covers the EVENT, and the event names itself: its `d` is a
	// digest of its own contents, so a signature over that identifier is a
	// signature over the event and nothing else.
	//
	// What stood here signed a JSON receipt body whose `d` was the rolling KEL
	// digest at this sequence number. That is a fine thing to compute — it is
	// what the watcher role compares — but it is not the event's identifier, so
	// a verifier asking "did a witness sign this event?" could never answer yes.
	eventSaid, _ := event["d"].(string)
	if eventSaid == "" {
		writeErr(w, http.StatusBadRequest, "event carries no identifier to receipt")
		return
	}
	cesrSig := s.Identity.CESRSignature([]byte(eventSaid))
	receiptBody, _ := json.Marshal(map[string]interface{}{
		"v": "KERI10JSON", "t": "rct", "d": eventSaid, "i": s.Identity.AID,
		"aid": req.AID, "seq": seq, "dt": time.Now().UTC().Format(time.RFC3339),
	})
	jsonOK(w, map[string]interface{}{
		"receipt": receiptBody,
		// The fields a controller needs to check this without asking anything
		// further: who witnessed, and the signature over the event identifier.
		"witness_aid":    s.Identity.AID,
		"cesr_signature": cesrSig,
		"event_said":     eventSaid,
		// The rolling digest still travels, because the watcher role is about
		// the log rather than one event, and both questions have callers.
		"kel_digest": d,
		// Retained so an existing caller is not broken by this change.
		"signature": s.Identity.Sign(receiptBody),
		"signed_by": s.Identity.AID,
	})
}

// tipStatement is what a witness signs when asked how far it holds an
// identity's key log. Its form is the Identity Agent core's TipStatement, in
// identity-agent-core/witness, and must stay byte-identical to it.
func tipStatement(aid, nonce string, sn int, said string) string {
	return fmt.Sprintf("witness-kel-tip/v1\n%s\n%s\n%d\n%s", aid, nonce, sn, said)
}

// handleWitnessKelTip answers how far this witness holds an identity's key
// log: the highest place it holds with nothing missing below, and the event
// there, or -1 and nothing,
// signed with this witness's key together with the asker's nonce, so the
// answer is fresh and its own. A controller asks this before sending, and
// sends only what the witness lacks, rather than its whole log every time.
func (s *Server) handleWitnessKelTip(w http.ResponseWriter, r *http.Request) {
	if !s.lim.allow(clientIP(r)) {
		writeErr(w, http.StatusTooManyRequests, "rate limited")
		return
	}
	nonce := r.URL.Query().Get("nonce")
	if nonce == "" || len(nonce) > 128 {
		writeErr(w, http.StatusBadRequest, "a nonce is required")
		return
	}
	aid := chi.URLParam(r, "aid")
	sn, said, err := s.Store.UnbrokenTip(aid)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	jsonOK(w, map[string]interface{}{
		"aid": aid, "nonce": nonce, "sn": sn, "said": said,
		"witness_aid": s.Identity.AID,
		"signature":   s.Identity.CESRSignature([]byte(tipStatement(aid, nonce, sn, said))),
	})
}

func (s *Server) handleWitnessKel(w http.ResponseWriter, r *http.Request) {
	if !s.lim.allow(clientIP(r)) {
		writeErr(w, http.StatusTooManyRequests, "rate limited")
		return
	}
	aid := chi.URLParam(r, "aid")
	events, err := s.Store.GetKELEvents(aid)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Each event goes out with the bytes it was published as and the controller's
	// signature over them, so whoever asks can verify the log for itself rather
	// than take this service's word for it. A log that cannot be verified cannot
	// prove anything, either way.
	published, err := s.Store.PublishedEvents(aid)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	for _, ev := range events {
		if p, ok := published[digest.EventSeq(ev)]; ok && p.RawB64 != "" && p.CesrSignature != "" {
			ev["raw_bytes_b64"] = p.RawB64
			ev["cesr_signature"], ev["cesr_signatures"] = servedSignatures(p.CesrSignature)
		}
	}
	// The other histories seen, which is what lets a verifier holding the first one
	// be shown the second, and the reverse.
	rivals, err := s.Store.ConflictingEvents(aid)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	conflicting := make([]map[string]interface{}, 0, len(rivals))
	for _, c := range rivals {
		first, all := servedSignatures(c.CesrSignature)
		conflicting = append(conflicting, map[string]interface{}{
			"sequence_number": c.SequenceNum, "said": c.SAID,
			"raw_bytes_b64": c.RawB64, "cesr_signature": first, "cesr_signatures": all,
		})
	}
	jsonOK(w, map[string]interface{}{"aid": aid, "kel": events, "conflicting": conflicting, "count": len(events)})
}

// servedSignatures is a kept signature field as served: the first signature,
// for a reader that takes one, and every signature, for one that checks a
// threshold.
func servedSignatures(stored string) (first string, all []string) {
	all = store.DecodeSignatures(stored)
	if len(all) > 0 {
		first = all[0]
	}
	return first, all
}

func (s *Server) handleKelDigest(w http.ResponseWriter, r *http.Request) {
	if !s.lim.allow(clientIP(r)) {
		writeErr(w, http.StatusTooManyRequests, "rate limited")
		return
	}
	aid := r.URL.Query().Get("aid")
	seqStr := r.URL.Query().Get("seq")
	seq, _ := strconv.Atoi(seqStr)
	resp := map[string]interface{}{
		"aid": aid, "sequence_number": seq,
		"digest": nil, "observed_since": nil, "first_seen_at": nil,
		"signed_by": s.Identity.AID,
	}
	var digestP, firstSeenP, sinceP *string
	rival := false
	if aid != "" && seqStr != "" {
		if d, ok, err := s.Store.GetObservationDigest(aid, seq); err == nil && ok {
			since, _ := s.Store.ObservedSince(aid)
			// first_seen_at is when this service saw the log through this place,
			// from its own observation: it dates the first digest it held at that
			// place, and a digest served later can be recomputed from what is held
			// (digest-recomputed), so the date is the first sighting's and not a
			// promise about this digest's history. observed_since is how long this
			// service has been looking at the identity.
			seenAt, _ := s.Store.ObservedAt(aid, seq)
			digestP = &d
			resp["digest"] = d
			resp["observed_since"] = since
			resp["first_seen_at"] = seenAt
			if since != "" {
				sinceP = &since
			}
			if seenAt != "" {
				firstSeenP = &seenAt
			}
		}
		// Whether a validly signed event that conflicts with a held one is kept at
		// or below this place, which a digest of the held branch cannot show. The
		// asker then fetches the log and judges both branches itself.
		if rivals, err := s.Store.ConflictingEvents(aid); err == nil {
			for _, c := range rivals {
				rival = rival || c.SequenceNum <= seq
			}
		}
	}
	if rival {
		resp["rival_at_or_below"] = true
	}
	// Signed over the one statement the protocol defines, the text the client
	// rebuilds from the fields of the answer (witnessproto.DigestStatementWithRival),
	// and not over this service's own rendering of them.
	if stmt, err := witnessproto.DigestStatementWithRival(aid, seq, digestP, firstSeenP, sinceP, rival); err == nil {
		resp["signature"] = s.Identity.CESRSignature([]byte(stmt))
	}
	signed, _ := json.Marshal(resp)
	w.Header().Set("Content-Type", "application/json")
	w.Write(signed)
}

func (s *Server) handleKelCheck(w http.ResponseWriter, r *http.Request) {
	if !s.lim.allow(clientIP(r)) {
		writeErr(w, http.StatusTooManyRequests, "rate limited")
		return
	}
	var req struct {
		AID    string `json:"aid"`
		Seq    int    `json:"seq"`
		Digest string `json:"digest"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	d, ok, _ := s.Store.GetObservationDigest(req.AID, req.Seq)
	match := ok && d == req.Digest
	out := map[string]interface{}{"match": match}
	if ok {
		out["our_digest"] = d
		// When this service first saw the log through this place, from its own
		// observation, as the digest answer says it: not how long it has been
		// looking at the identity.
		seenAt, _ := s.Store.ObservedAt(req.AID, req.Seq)
		out["our_first_seen_at"] = seenAt
	}
	jsonOK(w, out)
}

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	if !s.lim.allow(clientIP(r)) {
		writeErr(w, http.StatusTooManyRequests, "slow down")
		return
	}
	var req struct {
		AID           string `json:"aid"`
		ControllerAID string `json:"controller_aid"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	if req.AID == "" {
		writeErr(w, http.StatusBadRequest, "aid required")
		return
	}
	controller := req.ControllerAID
	if controller == "" {
		controller = req.AID
	}
	if err := s.Store.Enroll(req.AID, controller); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	jsonOK(w, map[string]interface{}{
		"enrolled": true, "aid": req.AID,
		"watcher_hint_url": watcherKelDigestURL(r),
		"witness_url":      witnessEventURL(r),
		"observed_since":   time.Now().UTC().Format(time.RFC3339),
	})
	log.Printf("[enroll] enrolled aid=%s controller=%s", req.AID, controller)
}

func jsonOK(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

type ipLimiter struct {
	mu     sync.Mutex
	hits   map[string][]time.Time
	limit  int
	window time.Duration
}

func newIPLimiter(limit int, window time.Duration) *ipLimiter {
	return &ipLimiter{hits: make(map[string][]time.Time), limit: limit, window: window}
}

func (l *ipLimiter) allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-l.window)
	prev := l.hits[ip]
	filt := prev[:0]
	for _, t := range prev {
		if t.After(cutoff) {
			filt = append(filt, t)
		}
	}
	if len(filt) >= l.limit {
		l.hits[ip] = filt
		return false
	}
	l.hits[ip] = append(filt, now)
	return true
}

// senderOf groups an address with the others one sender is likely to hold:
// an IPv6 address by its /64, which one host or network is usually given
// whole; an IPv4 address alone.
func senderOf(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() != nil {
		return ip
	}
	return (&net.IPNet{IP: parsed.Mask(net.CIDRMask(64, 128)), Mask: net.CIDRMask(64, 128)}).String()
}

func seqOrMinus(event map[string]interface{}) int {
	if n, ok := eventSeqOf(event); ok {
		return n
	}
	return -1
}

func eventSAIDOf(event map[string]interface{}) string {
	d, _ := event["d"].(string)
	return d
}

// publishedLog reads an identity's log as this witness holds it published,
// which is what a rotation is checked against.
func (s *Server) publishedLog(aid string) publishedLog {
	return func(sn int) ([]store.PublishedEvent, error) { return s.Store.PublishedLogBefore(aid, sn) }
}

// tipOf is the place of the newest event this witness holds with nothing
// missing below it, or -1.
func (s *Server) tipOf(aid string) func() (int, error) {
	return func() (int, error) {
		sn, _, err := s.Store.UnbrokenTip(aid)
		return sn, err
	}
}

// retiredByHeldRecovery says whether the event held at sn is a recovery
// rotation that replaces rival, an event at the same place: the log below sn
// and the rival, with the held event admitted to it, leave the rival
// superseded. Both are verified by keri-go, nothing on trust.
func (s *Server) retiredByHeldRecovery(aid string, sn int, rival []byte) bool {
	if sn == 0 {
		return false
	}
	prefix, err := s.Store.PublishedLogBefore(aid, sn)
	if err != nil {
		return false
	}
	rawB64, sig, ok, err := s.Store.EventAt(aid, sn)
	if err != nil || !ok {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(rawB64)
	if err != nil {
		return false
	}
	held, err := signedMessage(raw, store.DecodeSignatures(sig))
	if err != nil {
		return false
	}
	branch, err := keri.ValidateSignedKEL(append(messagesOf(prefix), rival))
	if err != nil {
		return false
	}
	adm, err := branch.Admit(held)
	return err == nil && adm.Supersedes > 0
}

// promoteEscrowed takes up, in order from after seq, the events held back
// waiting for their predecessors, accepting each that now follows what is
// held and is signed by the key in force, and stopping at the first place
// none does.
func (s *Server) promoteEscrowed(aid string, seq int) {
	for next := seq + 1; ; next++ {
		waiting, err := s.Store.EscrowedAt(aid, next)
		if err != nil || len(waiting) == 0 {
			return
		}
		taken := false
		for _, e := range waiting {
			raw, err := base64.StdEncoding.DecodeString(e.RawB64)
			if err != nil {
				s.Store.DropEscrowed(aid, e.SAID)
				continue
			}
			var event map[string]interface{}
			if json.Unmarshal(raw, &event) != nil {
				s.Store.DropEscrowed(aid, e.SAID)
				continue
			}
			held, _ := s.Store.GetKELEvents(aid)
			if err := eventBelongsHere(raw, held); err != nil {
				if !errors.Is(err, errNoPredecessor) && !errors.Is(err, errNextDisagrees) {
					s.Store.DropEscrowed(aid, e.SAID)
				}
				continue
			}
			verified, err := verifyControllerSignatures(raw, store.DecodeSignatures(e.Signature), s.publishedLog(aid), s.tipOf(aid))
			if err != nil {
				s.Store.DropEscrowed(aid, e.SAID)
				continue
			}
			if _, _, err := s.Store.AcceptEvent(aid, next, event, e.RawB64, store.EncodeSignatures(verified)); err != nil {
				continue
			}
			s.Store.DropEscrowed(aid, e.SAID)
			taken = true
			break
		}
		if !taken {
			return
		}
	}
}

// handleWitnessKelEvent hands back one event of an identity's log as its
// controller published and signed it: how an Identity Agent finds an event
// the device holding the identity's key signed, when the reply did not reach
// it.
func (s *Server) handleWitnessKelEvent(w http.ResponseWriter, r *http.Request) {
	if !s.lim.allow(clientIP(r)) {
		writeErr(w, http.StatusTooManyRequests, "rate limited")
		return
	}
	sn, err := strconv.Atoi(chi.URLParam(r, "sn"))
	if err != nil || sn < 0 {
		writeErr(w, http.StatusBadRequest, "a place in the log is a number")
		return
	}
	raw, sig, ok, err := s.Store.EventAt(chi.URLParam(r, "aid"), sn)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeErr(w, http.StatusNotFound, "no event is held there as it was published")
		return
	}
	first, all := servedSignatures(sig)
	jsonOK(w, map[string]interface{}{"raw_bytes_b64": raw, "cesr_signature": first, "cesr_signatures": all})
}
