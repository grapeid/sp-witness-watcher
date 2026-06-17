package api

import (
	"encoding/json"
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

	r.Route("/witness", func(r chi.Router) {
		r.Post("/event", s.handleWitnessEvent)
		r.Get("/kel/{aid}", s.handleWitnessKel)
	})

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
		"service_aid": s.Identity.AID, "seam": "M67",
	})
}

type witnessEventRequest struct {
	AID   string                 `json:"aid"`
	Event map[string]interface{} `json:"event"`
}

func (s *Server) handleWitnessEvent(w http.ResponseWriter, r *http.Request) {
	var req witnessEventRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	if req.AID == "" || req.Event == nil {
		writeErr(w, http.StatusBadRequest, "aid and event required")
		return
	}
	seq := digest.CurrentSeq([]map[string]interface{}{req.Event})
	if seq < 0 {
		if v, ok := req.Event["s"].(string); ok {
			seq, _ = strconv.Atoi(v)
		}
	}
	events, _ := s.Store.GetKELEvents(req.AID)
	events = append(events, req.Event)
	d, err := digest.KelDigestAtSeq(events, seq)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.Store.StoreEvent(req.AID, seq, req.Event, d); err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	receiptBody, _ := json.Marshal(map[string]interface{}{
		"v": "KERI10JSON", "t": "rct", "d": d, "i": s.Identity.AID,
		"aid": req.AID, "seq": seq, "dt": time.Now().UTC().Format(time.RFC3339),
	})
	sig := s.Identity.Sign(receiptBody)
	jsonOK(w, map[string]interface{}{
		"receipt": receiptBody, "signature": sig, "signed_by": s.Identity.AID,
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
	watcherURL := "https://watcher.grapeid.org/public/kel-digest"
	jsonOK(w, map[string]interface{}{
		"enrolled": true, "aid": req.AID,
		"watcher_hint_url": watcherURL,
		"witness_url": "https://witness.grapeid.org/witness/event",
		"observed_since": time.Now().UTC().Format(time.RFC3339),
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