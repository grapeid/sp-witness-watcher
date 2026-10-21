package api

import (
	"net/http/httptest"
	"testing"
)

// An operator that names its public URLs gets exactly those back.
func TestConfiguredPublicURLsAreUsed(t *testing.T) {
	t.Setenv("WW_WITNESS_PUBLIC_URL", "https://witness.example.net/")
	t.Setenv("WW_WATCHER_PUBLIC_URL", "https://watcher.example.net")
	r := httptest.NewRequest("POST", "http://internal:8092/enroll", nil)
	if got := witnessEventURL(r); got != "https://witness.example.net/witness/event" {
		t.Fatalf("witness url = %q", got)
	}
	if got := watcherKelDigestURL(r); got != "https://watcher.example.net/public/kel-digest" {
		t.Fatalf("watcher url = %q", got)
	}
}

// With nothing configured, the service names the host it was reached on, so a
// new operator's enrolment hints point at that operator and nobody else.
func TestUnconfiguredPublicURLsFollowTheRequest(t *testing.T) {
	t.Setenv("WW_WITNESS_PUBLIC_URL", "")
	t.Setenv("WW_WATCHER_PUBLIC_URL", "")
	r := httptest.NewRequest("POST", "http://ww.example.org/enroll", nil)
	r.Header.Set("X-Forwarded-Proto", "https")
	if got := witnessEventURL(r); got != "https://ww.example.org/witness/event" {
		t.Fatalf("witness url = %q", got)
	}
	if got := watcherKelDigestURL(r); got != "https://ww.example.org/public/kel-digest" {
		t.Fatalf("watcher url = %q", got)
	}
}
