# Deploy adaptation plan — sp-witness-watcher

## Decision

- **Canonical implementation:** Go at repo root (Docker, VPS, witness pool).
- **Replit Autoscale:** Node.js/TypeScript in `deploy/replit/` (implemented).
- **Future targets:** add `deploy/<target>/` siblings (e.g. `deploy/fly/`, `deploy/railway/`).

## Task status

| Task | Est. effort | Risk | Status |
|------|-------------|------|--------|
| Repo scaffold + `.replit` | 30 min | Low | Done |
| BLAKE3 + Matter qb64 digest parity | 2–4 hrs | **High** | Done (golden test passes) |
| Ed25519 signer + identity from Secret | 1 hr | Medium | Done |
| PostgreSQL store (schema port) | 1–2 hrs | Low | Done |
| HTTP API (6 endpoints) | 2–3 hrs | Low | Done |
| Contract test vs Go golden vector | 1 hr | Medium | Done (digest) |
| Replit publish + custom domains | 30 min–2 hrs | **High** | **You / Replit Agent** |
| Stable `WW_SERVICE_IDENTITY_JSON` in prod Secrets | 15 min | **High** if skipped | **You** |

## Longest / highest-risk items

### 1. BLAKE3 digest byte-parity (was highest risk)

Go and Node must produce identical `E...` Matter qb64 digests. Failure breaks witness receipts and watcher cross-checks.

**Mitigation:** Golden test locked to Go output `EIL7184M0CepkyBvLnW5amSFHgSSmRTLCHfmEMsFL8l-`. Required sorted JSON keys (Go `encoding/json` behavior).

**Avoid:** Do not swap hash libraries or canonicalization without re-running the golden test.

### 2. Replit publish (platform-specific)

Not fully verifiable locally. Remaining unknowns: Neon cold start vs 5s health check, `npm install` in build image, production Secrets visibility.

**Ask Replit Agent:** see [`deploy/replit/REPLIT_AGENT_QUESTIONS.md`](replit/REPLIT_AGENT_QUESTIONS.md).

### 3. Stable witness AID across deploys

Ephemeral Replit filesystem regenerates identity without `WW_SERVICE_IDENTITY_JSON`.

**You:** Run `node deploy/replit/scripts/generate-identity.mjs` once, save output as production Secret.

## What we deliberately did NOT rewrite

- Full KERI framework / CESR codec
- Witness receipt verification logic (clients verify; server only signs)
- New database schema (identical Postgres tables to Go Replit port)

## Crypto libraries (no custom KERI crypto)

| Primitive | Library |
|-----------|---------|
| BLAKE3-256 | `@noble/hashes` |
| Ed25519 sign | `@noble/curves` |
| SQL | `pg` |
| HTTP | `fastify` |