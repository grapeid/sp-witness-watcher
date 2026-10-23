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

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/grapeid/sp-witness-watcher/internal/signer"
	"github.com/grapeid/sp-witness-watcher/internal/store"
)

type Server struct {
	Store    *store.ServiceStore
	Identity *signer.Identity
	lim      *ipLimiter
}

func New(st *store.ServiceStore, id *signer.Identity) *Server {
	return &Server{Store: st, Identity: id, lim: newIPLimiter(120, time.Minute)}
}

func (s *Server) Router() chi.Router {
	r := chi.NewRouter()
	r.Use(middleware.RequestID, middleware.RealIP, middleware.Logger, middleware.Recoverer)

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
	raw, err = base64.StdEncoding.DecodeString(req.EventB64)
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
	if req.CesrSignature == "" {
		writeErr(w, http.StatusBadRequest,
			"an event must carry the controller signature over its published bytes")
		return
	}
	// Prior events are read first because a non-establishment event is signed
	// by the key state they carry, not by anything in the event itself.
	events, _ := s.Store.GetKELEvents(req.AID)
	if err := verifyControllerSignature(rawEvent, event, req.CesrSignature, events); err != nil {
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
	d, _, err := s.Store.AcceptEvent(req.AID, seq, event)
	if errors.Is(err, store.ErrConflict) {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
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
	jsonOK(w, map[string]interface{}{"aid": aid, "kel": events, "count": len(events)})
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
	if aid != "" && seqStr != "" {
		if d, ok, err := s.Store.GetObservationDigest(aid, seq); err == nil && ok {
			since, _ := s.Store.ObservedSince(aid)
			resp["digest"] = d
			resp["observed_since"] = since
			resp["first_seen_at"] = since
		}
	}
	unsigned, _ := json.Marshal(resp)
	resp["signature"] = s.Identity.Sign(unsigned)
	signed, _ := json.Marshal(resp)
	w.Header().Set("Content-Type", "application/json")
	w.Write(signed)
}

func (s *Server) handleKelCheck(w http.ResponseWriter, r *http.Request) {
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
		since, _ := s.Store.ObservedSince(req.AID)
		out["our_first_seen_at"] = since
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

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
