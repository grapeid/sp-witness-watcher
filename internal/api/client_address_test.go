package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A caller cannot choose the address it is counted as by writing a header.
//
// Fails when the router believes True-Client-IP, X-Real-IP or X-Forwarded-For
// from a caller that is not a trusted proxy (chi's RealIP middleware did).
func TestAForwardingHeaderFromAStrangerIsNotBelieved(t *testing.T) {
	t.Setenv("TRUSTED_PROXIES", "")
	for _, h := range []string{"True-Client-IP", "X-Real-IP", "X-Forwarded-For"} {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = "203.0.113.9:4000"
		r.Header.Set(h, "198.51.100.7")
		if got := clientIP(r); got != "203.0.113.9" {
			t.Fatalf("%s moved the caller to %s", h, got)
		}
	}
}

func TestAForwardingHeaderIsBelievedOnlyFromATrustedProxy(t *testing.T) {
	t.Setenv("TRUSTED_PROXIES", "10.0.0.0/8")
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.1.2.3:4000"
	r.Header.Set("X-Forwarded-For", "6.6.6.6, 198.51.100.7, 10.9.9.9")
	if got := clientIP(r); got != "198.51.100.7" {
		t.Fatalf("through a trusted proxy the caller is %s, want the nearest address that is not a proxy", got)
	}
	r.RemoteAddr = "203.0.113.9:4000"
	if got := clientIP(r); got != "203.0.113.9" {
		t.Fatalf("a stranger writing X-Forwarded-For was believed: %s", got)
	}
}

// The whole router counts the connection, not the header, and the cross-check
// is limited like every other public route.
//
// Fails when a header can name a fresh caller for each request, or when
// /public/kel-check has no limit.
func TestAHeaderCannotGetPastTheLimitOnTheCrossCheck(t *testing.T) {
	t.Setenv("TRUSTED_PROXIES", "")
	router, _ := hexWorld(t)
	limited := false
	for i := 0; i < 200 && !limited; i++ {
		req := httptest.NewRequest(http.MethodPost, "/public/kel-check", strings.NewReader(`{"aid":"EAlice","seq":0,"digest":"Ex"}`))
		req.RemoteAddr = "203.0.113.9:4000"
		req.Header.Set("X-Forwarded-For", fmt.Sprintf("198.51.100.%d", i%250))
		req.Header.Set("X-Real-IP", fmt.Sprintf("192.0.2.%d", i%250))
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		limited = rec.Code == http.StatusTooManyRequests
	}
	if !limited {
		t.Fatal("200 cross-checks from one connection were never limited")
	}
}
