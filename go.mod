module github.com/grapeid/sp-witness-watcher

go 1.25.0

require (
	github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/witnessproto v0.0.0
	github.com/go-chi/chi/v5 v5.2.5
	github.com/grapeid/keri-go v0.5.1-0.20261108070129-11308439ee52
	github.com/grapeid/sp-common v0.0.0-20261031192253-65359a6496f4
	github.com/zeebo/blake3 v0.2.4
	modernc.org/sqlite v1.46.1
)

require (
	filippo.io/edwards25519 v1.2.0 // indirect
	github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/relayproto v0.0.0-20261022154728-134689791b1a // indirect
	github.com/cloudflare/circl v1.6.3 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/gorilla/websocket v1.5.3 // indirect
	github.com/hashicorp/yamux v0.1.2 // indirect
	github.com/klauspost/cpuid/v2 v2.0.12 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	golang.org/x/exp v0.0.0-20251023183803-a4bb9ffd2546 // indirect
	golang.org/x/sys v0.37.0 // indirect
	modernc.org/libc v1.67.6 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
)

// TEMPORARY, until identity-bot's "rival_at_or_below" digest field is merged:
// the shared statement is read from the checkout of that change. Re-pin this to
// the merged commit (go get ...witnessproto@<commit>) and delete this line
// before this branch is merged; a build outside this machine does not have it.
replace github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/witnessproto => ../../workspace/identity-bot/identity-agent-core/witnessproto
