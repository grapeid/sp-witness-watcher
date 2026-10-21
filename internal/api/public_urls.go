package api

import (
	"net/http"
	"os"
	"strings"
)

// The public URLs /enroll hands back, so a controller knows where to send its
// events and where to ask for the digest this service reports.
//
// An operator names them with WW_WITNESS_PUBLIC_URL and WW_WATCHER_PUBLIC_URL
// (the base URL each role is reachable at; the path is appended here). When an
// operator has not, the URL the request arrived on is used. That is right for
// the ordinary single-host deployment and needs no configuration; an operator
// who serves the two roles on different hosts, or behind a proxy that rewrites
// the host, sets the variables.

func witnessEventURL(r *http.Request) string {
	return publicBase("WW_WITNESS_PUBLIC_URL", r) + "/witness/event"
}

func watcherKelDigestURL(r *http.Request) string {
	return publicBase("WW_WATCHER_PUBLIC_URL", r) + "/public/kel-digest"
}

func publicBase(envVar string, r *http.Request) string {
	if base := strings.TrimRight(strings.TrimSpace(os.Getenv(envVar)), "/"); base != "" {
		return base
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	// A TLS-terminating proxy in front of the service says what the caller used.
	if p := strings.ToLower(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto"))); p == "https" || p == "http" {
		scheme = p
	}
	return scheme + "://" + r.Host
}
