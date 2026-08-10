package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/grapeid/sp-witness-watcher/internal/signer"
	"github.com/grapeid/sp-witness-watcher/internal/store"
)

// An operator that has said nothing has not asked to be restricted, and a
// service silently offering nothing would look identical to a broken one.
func TestSayingNothingOffersBothRoles(t *testing.T) {
	t.Setenv("WW_ROLES", "")
	r := RolesFromEnv()
	if !r.Witness || !r.Watcher {
		t.Fatalf("an unconfigured service offered %v", r.Enabled())
	}
}

// A typo in a deployment variable must not quietly take a live service off the
// air — the failure would look like an outage with no cause.
func TestAnUnrecognisedRoleDoesNotDisableEverything(t *testing.T) {
	t.Setenv("WW_ROLES", "wittness")
	r := RolesFromEnv()
	if !r.Witness || !r.Watcher {
		t.Fatalf("a misspelt role list left the service offering %v", r.Enabled())
	}
}

func TestASingleRoleCanBeOffered(t *testing.T) {
	t.Setenv("WW_ROLES", "watcher")
	r := RolesFromEnv()
	if r.Witness || !r.Watcher {
		t.Fatalf("expected watcher only, got %v", r.Enabled())
	}
}

// The routes follow the roles: a service offering only one must not answer for
// the other, or an operator's choice means nothing.
func TestDisabledRoleRoutesAreNotServed(t *testing.T) {
	t.Setenv("WW_ROLES", "watcher")
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	id, err := signer.LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	router := New(st, id).Router()

	// The watcher side answers.
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/public/kel-digest?aid=EAlice&seq=0", nil))
	if rec.Code == http.StatusNotFound {
		t.Error("the enabled watcher role did not answer")
	}

	// The witness side does not.
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/witness/event", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("a disabled witness role answered with %d", rec.Code)
	}

	// Health still says what it offers, so nobody has to infer it from a 404.
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("health answered %d", rec.Code)
	}
	if body := rec.Body.String(); !contains(body, "watcher") || contains(body, "\"witness\"") {
		t.Errorf("health does not report the roles honestly: %s", body)
	}
	_ = os.Getenv
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}
