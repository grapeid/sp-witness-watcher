# sp-witness-watcher

M67 Commercial Witness + Watcher Service — hosted implementation of M11 witness protocol and M12 watcher protocol.

One codebase, two API surfaces, shared KEL observation store. Grape ID operates the default instance (`witness.grapeid.org` / `watcher.grapeid.org`); this repo is the reference implementation Rob deploys (~3 instances for the live witness pool).

## APIs

| Method | Path | Role |
|--------|------|------|
| `POST` | `/witness/event` | Receipt key event → signed receipt |
| `GET` | `/witness/kel/{aid}` | Serve KEL replica |
| `GET` | `/public/kel-digest?aid&seq` | Watcher digest + `observed_since` (signed) |
| `POST` | `/public/kel-check` | Peer cross-check (L3) |
| `POST` | `/enroll` | Begin witnessing + watching from enrollment |
| `GET` | `/health` | Liveness |

## Run locally

```bash
go run ./cmd/server
# → http://0.0.0.0:8092
```

Environment:

- `WW_DATA_DIR` — SQLite + service identity (default `./data`)
- `PORT` / `HOST` — bind address

## Test

```bash
go test ./...
```

## Docker

```bash
docker build -t sp-witness-watcher .
docker run -p 8092:8092 -v ww-data:/data sp-witness-watcher
```

## Topology

Deploy **~3 independent instances** behind load balancers for the default witness pool (T-142). Each instance holds its own service KERI AID; verifiers cross-check via M12 L2/L3 for plurality.

## Deploy targets

| Target | Path | Runtime |
|--------|------|---------|
| Docker / Linux VPS | repo root (`go run ./cmd/server`) | Go + SQLite |
| Replit Autoscale | [`deploy/replit/`](deploy/replit/) → hoisted to root at publish | Node.js + PostgreSQL |

Replit playbook (all Grape ID services): [`deploy/REPLIT_DEPLOY_PLAYBOOK.md`](deploy/REPLIT_DEPLOY_PLAYBOOK.md)

The Node.js build uses the same HTTP API and Postgres schema. Set production secret `WW_SERVICE_IDENTITY_JSON` on Replit so the witness AID stays stable across deploys.

## Related

- M11 witness protocol — `identity-bot/identity-agent-core`
- M12 watcher protocol — `identity-bot/identity-agent-core/watcher/`
- M29 login golden vector — `identity-bot/packages/login-verify/golden_vectors.json`