# Replit Deploy Playbook — Grape ID Services

Canonical checklist for shipping a Grape ID backend on **Replit Autoscale**. Proven on `witness.grapeid.org`, `watcher.grapeid.org`, and `brr.grapeid.org` (June 2026).

Copy this file into any new service repo as `deploy/REPLIT_DEPLOY_PLAYBOOK.md`.

---

## Architecture pattern

Every service uses **two implementations**:

| Layer | Location | Purpose |
|-------|----------|---------|
| **Canonical** | repo root (`cmd/`, `internal/`) | Go + Docker + self-hosted Linux |
| **Replit** | `deploy/replit/` → hoisted to root at publish | Node.js + PostgreSQL + Autoscale |

Do **not** replace the Go implementation. The Node port is a deployment adapter, not a rewrite of protocol logic.

---

## Phase 1 — Implement `deploy/replit/`

### Required files

```
deploy/replit/
├── package.json          # fastify, pg, @noble/hashes, @noble/curves
├── tsconfig.json
├── src/
│   ├── index.ts          # listen() BEFORE store.migrate()
│   ├── server.ts         # HTTP routes (same contract as Go)
│   ├── store.ts          # PostgreSQL only — DATABASE_URL
│   └── signer.ts         # load from {SVC}_SERVICE_IDENTITY_JSON
├── scripts/generate-identity.mjs
├── REPLIT_AGENT_SETUP.md # service-specific steps
└── .replit               # autoscale template
```

### Crypto rule

Use `@noble/hashes` (BLAKE3) and `@noble/curves` (Ed25519). Port minimal digest/signing from Go — **no KERI framework dependency**. Lock parity with Go golden tests.

### Database rule

**PostgreSQL only** on Replit. Never SQLite — published filesystem is ephemeral.

Schema: port Go Postgres tables verbatim (`$1` placeholders, `BIGSERIAL`, etc.).

### Startup rule (critical)

```typescript
await app.listen({ port, host });   // /health must answer within 5 seconds
store.migrate().catch(() => process.exit(1));  // after listen, not before
```

Do **not** call `pool.query('SELECT 1')` before listen — Neon cold start blocks the health probe.

---

## Phase 2 — Replit Agent setup

Give the Agent **`deploy/replit/REPLIT_AGENT_SETUP.md`** and this playbook.

### Agent checklist (in order)

1. **Pull from GitHub** — branch `main`
2. **Enable Replit SQL Database** — confirms `DATABASE_URL` in Secrets
3. **Hoist Node app to workspace root** (required — see below)
4. **Set production Secret** — `{PREFIX}_SERVICE_IDENTITY_JSON` (generate once, never regenerate)
5. **Configure `.replit`** — Autoscale, port 5000 → 80
6. **Publish** — verify `GET /health` on public URL
7. **Custom domain** — CNAME → `<slug>.<owner>.replit.app`

### Hoist to workspace root (mandatory)

Replit Autoscale expects `package.json` at the **workspace root**, not in a subdirectory.

After hoist, root layout:

```
.replit
package.json
tsconfig.json
src/
scripts/
dist/          # from npm run build
cmd/           # Go (unchanged, ignored by Node runtime)
internal/
```

Root `.replit` deployment section:

```toml
[deployment]
deploymentTarget = "autoscale"
build = ["npm", "run", "build"]
run = ["node", "dist/index.js"]

[[ports]]
localPort = 5000
externalPort = 80

[env]
PORT = "5000"
HOST = "0.0.0.0"
```

Keep `deploy/replit/` in git as the **source of truth**; sync hoisted copies back after Agent edits.

---

## Phase 3 — Secrets

| Secret | Required | Notes |
|--------|----------|-------|
| `DATABASE_URL` | Yes | Auto-injected by Replit SQL Database |
| `{SVC}_SERVICE_IDENTITY_JSON` | Yes | Single-line JSON: `aid`, `public_key_b64`, `private_seed_b64` |
| `{SVC}_DEV_SKIP_SIG` | Dev only | Skip issuer signature verify during testing |
| `{SVC}_ANCHORING_ENABLED` | Optional | BRR only; default `false` |

Generate identity once:

```bash
node scripts/generate-identity.mjs
```

Paste output into **Tools → Secrets**. Same name in dev and published Autoscale.

---

## Phase 4 — Verify production

### Smoke (all services)

```bash
curl https://<domain>/health
```

### Service-specific steel thread

**Witness/Watcher** (`sp-witness-watcher`):

```bash
# enroll → witness/event → kel-digest → kel-check (match: true)
# conflict at same seq → HTTP 409
```

**BRR** (`sp-blind-revocation-registry`):

```bash
# enroll (issuer-signed) → iss event → rev event → bulk-proof
# revoked_ids must contain blinded_id; brr_signature present
```

Run `deploy/replit/scripts/live-verify.mjs` if provided, or use the Node one-liner in `REPLIT_AGENT_SETUP.md`.

**Relay** (`sp-url-relay`) — different profile; see §Exceptions below.

---

## Horizontal scaling (Autoscale)

**Witness, Watcher, BRR — scales horizontally:**

- Shared PostgreSQL → all instances see same state
- Same `{SVC}_SERVICE_IDENTITY_JSON` → all instances sign with same service AID
- Stateless HTTP (except per-instance in-memory rate limits)

**Witness pool plurality (T-142):** multiple *different* witness AIDs = multiple Replit *deployments*, not multiple Autoscale replicas of one deployment.

**Relay — do not Autoscale without design work:**

- WebSocket tunnel hub is in-memory per instance
- Currently on **Reserved VM** + pre-built Go binary
- Horizontal scale needs sticky sessions or external tunnel state (Redis)

---

## Exceptions — services that differ

### sp-url-relay (live: relay.grapeid.org)

| Aspect | Value |
|--------|-------|
| Runtime | **Go** (not Node) |
| Deployment | **Reserved VM** (`deploymentTarget = "vm"`) |
| Build | `CGO_ENABLED=0 go build -o bin/api ./cmd/api` in `deployment.build` |
| Why VM | WebSocket tunnels + Go compile time |

`/allocate` without enrollment token → **403** (expected).  
`/enroll` without resolvable OOBI → **401** (expected; supply `public_key_b64` in dev).  
Old `/status` path → **404** (removed in M35; use `/health`).

**Node port for relay:** optional future work. Not required while VM + Go publishes successfully. Autoscale would still need sticky WebSocket routing.

---

## What Replit Agent added beyond initial commits

Documented from `sp-witness-watcher` and `sp-blind-revocation-registry` publish diffs:

| Change | Why |
|--------|-----|
| Hoist `src/`, `package.json` to repo root | Replit only auto-detects root `package.json` |
| `.replit` build/run without `cd deploy/replit` | Deployment runner cwd is workspace root |
| `BRR_/WW_SERVICE_IDENTITY_JSON` in Secrets UI | Stable AID across deploys (not in git) |
| PostgreSQL integration enabled | `DATABASE_URL` in prod |
| `listen()` before `migrate()` | 5-second health probe passes |
| `@replit/connectors-sdk` (witness only) | Replit platform integration — optional |
| Publish checkpoint commits | `Published your App` — metadata only, no logic changes |

**No protocol changes** were required in Agent publish commits — only workspace layout and secrets.

---

## New service template (mailbox, etc.)

1. Build Go service at repo root (canonical)
2. Copy `deploy/replit/` structure from `sp-witness-watcher` or `sp-blind-revocation-registry`
3. Port HTTP routes + Postgres store + noble crypto
4. Write `REPLIT_AGENT_SETUP.md` with domain name and secret prefix
5. Add golden tests vs Go
6. Hand Agent this playbook + setup doc
7. After publish: run steel-thread verification script
8. Add row to **Deployed services** table below

---

## Deployed services (June 2026)

| Domain | Repo | Runtime | Replit target | Identity secret |
|--------|------|---------|---------------|-----------------|
| witness.grapeid.org | sp-witness-watcher | Node.js | Autoscale | `WW_SERVICE_IDENTITY_JSON` |
| watcher.grapeid.org | sp-witness-watcher | Node.js | Autoscale | (same deployment) |
| brr.grapeid.org | sp-blind-revocation-registry | Node.js | Autoscale | `BRR_SERVICE_IDENTITY_JSON` |
| relay.grapeid.org | sp-url-relay | Go | Reserved VM | (relay AID in env/config) |

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| Publish fails at final step | `listen()` before DB; check port 5000 / `externalPort=80` |
| New AID every deploy | Set `{SVC}_SERVICE_IDENTITY_JSON` in **Publishing** secrets |
| Data lost on republish | Using SQLite or local files — switch to PostgreSQL |
| `npm run build` not found | Hoist `package.json` to workspace root |
| Neon slow first query | OK after publish — health check only hits `/health` |