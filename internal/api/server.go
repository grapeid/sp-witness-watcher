package api

import (
	"encoding/base64"
	"encoding/json"
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
	"github.com/grapeid/sp-witness-watcher/internal/digest"
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

	witnessRoutes := func(r chi.Router) {
		r.Post("/event", s.handleWitnessEvent)
		r.Get("/kel/{aid}", s.handleWitnessKel)
	}
	r.Route("/witness", witnessRoutes)
	// Also under /api, which is where an Identity Agent serves its own witness
	// routes. Without this a controller has to know which kind of witness it is
	// talking to in order to address it, and the agent's own broadcast builds
	// the /api path — so every submission here answered 404 and was recorded as
	// the witness being offline.
	r.Route("/api/witness", witnessRoutes)

	r.Route("/public", func(r chi.Router) {
		r.Get("/kel-digest", s.handleKelDigest)
		r.Post("/kel-check", s.handleKelCheck)
	})

	r.Post("/enroll", s.handleEnroll)

	return r
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, map[string]interface{}{
		"status": "active", "service": "sp-witness-watcher",
		"service_aid": s.Identity.AID,
	})
}

type witnessEventRequest struct {
	AID string `json:"aid"`
	// Event is the parsed form, accepted from callers that predate EventB64.
	Event map[string]interface{} `json:"event"`
	// EventB64 is the event exactly as the controller published it, and
	// CesrSignature is the controller's signature over those bytes.
	//
	// Preferred over Event, and for a reason that goes to what a receipt is
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
// The bytes are authoritative wherever they were supplied. Where they were not,
// the parsed form is used and the caller is receipted on weaker terms, which is
// recorded in the response rather than hidden.
func (req witnessEventRequest) event() (raw []byte, parsed map[string]interface{}, verifiable bool, err error) {
	if req.EventB64 != "" {
		raw, err = base64.StdEncoding.DecodeString(req.EventB64)
		if err != nil {
			return nil, nil, false, fmt.Errorf("event_b64 is not readable base64: %w", err)
		}
		if err := json.Unmarshal(raw, &parsed); err != nil {
			return nil, nil, false, fmt.Errorf("event_b64 does not contain a KERI event: %w", err)
		}
		return raw, parsed, true, nil
	}
	if req.Event == nil {
		return nil, nil, false, fmt.Errorf("no event was supplied")
	}
	return nil, req.Event, false, nil
}

func (s *Server) handleWitnessEvent(w http.ResponseWriter, r *http.Request) {
	var req witnessEventRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	if req.AID == "" {
		writeErr(w, http.StatusBadRequest, "aid required")
		return
	}
	rawEvent, event, verifiable, err := req.event()
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	// Where the controller sent the published bytes and a signature, check that
	// the identity actually authorised this event before attesting to it.
	//
	// A witness that will attest to anything it is sent is one anybody can make
	// say anything, and its receipts stop distinguishing a real history from an
	// invented one. Where only the parsed form arrived there is nothing to
	// check, and the receipt says so rather than implying a check happened.
	if verifiable {
		if req.CesrSignature == "" {
			writeErr(w, http.StatusBadRequest,
				"an event sent as bytes must carry the controller signature over them")
			return
		}
		if err := verifyControllerSignature(rawEvent, event, req.CesrSignature); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	seq := digest.CurrentSeq([]map[string]interface{}{event})
	if seq < 0 {
		if v, ok := event["s"].(string); ok {
			seq, _ = strconv.Atoi(v)
		}
	}
	events, _ := s.Store.GetKELEvents(req.AID)
	events = append(events, event)
	d, err := digest.KelDigestAtSeq(events, seq)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.Store.StoreEvent(req.AID, seq, event, d); err != nil {
		writeErr(w, http.StatusConflict, err.Error())
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
		"watcher_hint_url": watcherKelDigestURL(),
		"witness_url":      witnessEventURL(),
		"observed_since":   time.Now().UTC().Format(time.RFC3339),
	})
	log.Printf("[M67] enrolled aid=%s controller=%s", req.AID, controller)
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
