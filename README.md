# sp-witness-watcher

A KERI witness and watcher service for Identity Agents.

- As a **witness**, it receives an identity's key events, checks that the
  identity's controller signed each one, stores a replica of the key event log,
  and returns a signed receipt. Receipts from independent witnesses are what stop
  an identity from later presenting two different histories.
- As a **watcher**, it reports a signed digest of the key event log it has
  observed for an identity, and when it first observed it, and answers peer
  cross-checks. A relying party compares these against what it has seen itself to
  detect duplicity.

One build offers both roles; either can be switched off. Grape ID operates
instances of this implementation, and anyone may run their own. The more
independent operators there are, the more a witness receipt is worth.

## The protocol it implements

The Identity Agent side of these roles is the open-source
[Identity Agent](https://github.com/LF-Decentralized-Trust-labs/identity-bot) core. The protocol is
described in its architecture decision records:

- **ADR-024 — KERI Network Participation: Witness, Watcher, Relay, did:webs
  Publisher.** The witness and watcher roles, and the three watcher layers: this
  service answers the shared-watcher standing digest (`/public/kel-digest`) and
  peer cross-checks (`/public/kel-check`).
- **ADR-031 — Who witnesses what.** Why a new identity, and every pairwise
  identifier, relies on independently operated witnesses such as this one.
- **ADR-016 — Witness Protocol.** The witness exchange between Identity Agents.

## API

| Method | Path | Role | Purpose |
|---|---|---|---|
| `POST` | `/witness/event` | witness | Verify and store a key event, return a signed receipt |
| `GET` | `/witness/kel/{aid}` | witness | Serve the stored key event log replica |
| `GET` | `/witness/kel/{aid}/tip?nonce=` | witness | How far the replica goes: the newest event's sequence number and identifier, signed with this witness's key together with the nonce |
| `GET` | `/public/kel-digest?aid=&seq=` | watcher | Signed digest at a sequence number, with `observed_since` |
| `POST` | `/public/kel-check` | watcher | Peer cross-check: does your digest match mine? |
| `POST` | `/enroll` | both | Start witnessing and watching an identity; returns where to send events |
| `GET` | `/health` | — | Liveness |

The witness and watcher routes are also served under `/api` (`/api/witness/...`,
`/api/public/...`, `/api/health`), which is where an Identity Agent addresses
them.

Sequence numbers are read as KERI writes them, in hexadecimal. A witness that
stored events before this read them as decimal: `go run ./cmd/repair-sequences
-data <dir>` reports any identity whose events sit at the wrong place, and
`-apply` moves them and recomputes the digests. Conflict rows are reported and
never deleted.

`POST /witness/event` requires the event's published bytes (`event_b64`) and the
controller's signature over them (`cesr_signature`). Nothing is stored or
receipted unverified. Rotation events are refused until pre-rotation commitments
are validated. Write and read paths are rate limited per client IP.

## Build and run

Requires Go 1.24 or later.

```bash
go run ./cmd/server
# listening on http://0.0.0.0:8092
```

Test:

```bash
go build ./... && go vet ./... && go test ./...
```

Docker:

```bash
docker build -t sp-witness-watcher .
docker run -p 8092:8092 -v ww-data:/data sp-witness-watcher
```

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `WW_DATA_DIR` | `./data` (`/data` in the image) | SQLite database and the service identity |
| `PORT` | `8092` | Listen port |
| `HOST` | `0.0.0.0` | Listen address |
| `WW_ROLES` | both | `witness`, `watcher`, or `witness,watcher` |
| `WW_WITNESS_PUBLIC_URL` | the host the request arrived on | Public base URL of the witness role, returned by `/enroll` |
| `WW_WATCHER_PUBLIC_URL` | the host the request arrived on | Public base URL of the watcher role, returned by `/enroll` |

## Running it in production

**The service identity is the witness.** On first start the service generates
an Ed25519 key and writes it to `service_identity.json` in `WW_DATA_DIR`. Every
receipt it issues is signed by that key. Keep the data directory on durable
storage and back it up: a witness that comes back with a new identity has
invalidated every receipt it ever issued.

**One identity per instance.** Running several instances to give controllers
several witnesses only works if each has its own data directory, and so its own
identity. Several processes sharing one identity are one witness, however many
addresses it answers on.

Put the service behind a TLS-terminating proxy. If the proxy rewrites the host,
or the two roles are served on different hosts, set the two public URL variables.

## Licence

Apache License 2.0. See [LICENSE](LICENSE). Contributions require a DCO sign-off;
see [CONTRIBUTING.md](CONTRIBUTING.md). Report vulnerabilities privately, as
described in [SECURITY.md](SECURITY.md).
