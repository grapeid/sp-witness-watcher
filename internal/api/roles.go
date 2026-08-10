package api

import (
	"os"
	"strings"
)

// Which roles this instance offers.
//
// Both ship in one build. The two share almost everything that is hard —
// identity, key handling, storage, the HTTP surface, rate limiting, deployment
// — and the difference between them is a few endpoints. Splitting them into
// separate builds would duplicate all of the difficult part and double the
// places a mistake can be made, and would leave a relying party with two
// attestations to check instead of one.
//
// An operator who wants to offer only one turns the other off. That is a flag,
// and a flag is far less error-prone than a fork.
//
// Nothing in the protocol requires an operator to offer both, and nothing
// prohibits it. Running both is the ordinary case: a witness sees key events as
// they are published, which is precisely what a watcher needs to answer about.

// Roles reports which roles are enabled.
type Roles struct {
	Witness bool
	Watcher bool
}

// RolesFromEnv reads WW_ROLES.
//
// Empty means both, because an operator that has said nothing has not asked to
// be restricted, and a service that silently offered nothing would look
// identical to one that was broken.
func RolesFromEnv() Roles {
	raw := strings.TrimSpace(os.Getenv("WW_ROLES"))
	if raw == "" {
		return Roles{Witness: true, Watcher: true}
	}
	var r Roles
	for _, part := range strings.Split(raw, ",") {
		switch strings.ToLower(strings.TrimSpace(part)) {
		case "witness":
			r.Witness = true
		case "watcher":
			r.Watcher = true
		}
	}
	// Neither recognised. Treated as both rather than as nothing: a typo in a
	// deployment variable should not quietly take a live service off the air.
	if !r.Witness && !r.Watcher {
		return Roles{Witness: true, Watcher: true}
	}
	return r
}

// Enabled renders the roles for the health response, so an operator and a
// relying party read the same answer about what this instance does.
func (r Roles) Enabled() []string {
	var out []string
	if r.Witness {
		out = append(out, "witness")
	}
	if r.Watcher {
		out = append(out, "watcher")
	}
	return out
}
