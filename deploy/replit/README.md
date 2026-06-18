# sp-witness-watcher — Replit (Node.js / Autoscale)

JavaScript/TypeScript implementation of the M67 witness + watcher service for **Replit Autoscale** deployments. The canonical Go implementation remains at the repo root for Docker and self-hosted Linux.

## APIs

Same contract as the Go service:

| Method | Path |
|--------|------|
| `POST` | `/witness/event` |
| `GET` | `/witness/kel/:aid` |
| `GET` | `/public/kel-digest?aid&seq` |
| `POST` | `/public/kel-check` |
| `POST` | `/enroll` |
| `GET` | `/health` |

## Replit setup

1. Enable **Replit SQL Database** (PostgreSQL) — `DATABASE_URL` is injected automatically.
2. In **Publishing → Secrets**, set production `WW_SERVICE_IDENTITY_JSON` with a stable witness AID (generate once locally, never regenerate in prod).
3. Publish with **Autoscale** (configured in `.replit`).

### Stable service identity (required in production)

```json
{
  "aid": "E...",
  "public_key_b64": "...",
  "private_seed_b64": "..."
}
```

Set as secret `WW_SERVICE_IDENTITY_JSON` (single-line JSON string). Without this, a new AID is generated on every cold start when `./data` is ephemeral.

## Local dev

```bash
cd deploy/replit
npm install
DATABASE_URL=postgres://... npm run dev
```

## Test

```bash
npm test
```

Digest output is verified against the Go golden vector (`EIL7184M0CepkyBvLnW5amSFHgSSmRTLCHfmEMsFL8l-`).

## Stack

- **Fastify** — HTTP server
- **pg** — PostgreSQL (Replit Neon)
- **@noble/hashes** — BLAKE3 (KEL digest)
- **@noble/curves** — Ed25519 (receipts + watcher signatures)

No KERI framework dependency — only the minimal digest and signing primitives ported from Go.