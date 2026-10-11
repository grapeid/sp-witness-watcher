# sp-witness-watcher

M67 Commercial Witness + Watcher Service — hosted implementation of M11 witness protocol and M12 watcher protocol.

One codebase, two API surfaces, shared KEL observation store. Grape ID operates a pool of numbered instances (`witness1`–`witness3` / `watcher1`–`watcher3` at `*.grapeid.org`); set `WW_INSTANCE=1|2|3` per deployment (or `WW_WITNESS_PUBLIC_URL` / `WW_WATCHER_PUBLIC_URL`).

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
| Fly.io | `fly.toml`, `fly.witness2.toml`, `fly.witness3.toml` | Go + SQLite on a volume |

One app per instance on Fly, because each instance is a separate witness with
its own AID, and that AID lives on the mounted volume. The instances scale to
zero when idle and the Fly proxy starts one on the next request, which costs
about 1.8s cold and returns the same AID it had before.

`WW_ROLES` selects which roles an instance offers (`witness`, `watcher`, or
both; empty means both), so a deployment can run the two separately without a
separate build.

## Related

- M11 witness protocol — `identity-bot/identity-agent-core`
- M12 watcher protocol — `identity-bot/identity-agent-core/watcher/`
- M29 login golden vector — `identity-bot/packages/login-verify/golden_vectors.json`