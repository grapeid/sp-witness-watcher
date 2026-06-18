# Questions for Replit Agent (if publish still fails)

Copy these to Replit Agent if any step blocks deployment.

## 1. PostgreSQL / Neon cold start

> On first request after idle, does Neon cold start ever cause the 5-second publish health check to fail if we connect to Postgres before `listen()`? Should we lazy-connect to `DATABASE_URL` after the server is listening?

**Yes, this is a real risk — fix it before first publish.**

Replit's health check fires as soon as the container starts. The current `index.ts` calls `openStore()` (which eagerly runs `await pool.query('SELECT 1')` and `await store.migrate()`) **before** `app.listen()`. If Neon is cold and takes even 1–2 seconds to respond, the server never reaches `listen()` in time and the health check returns connection-refused → deploy fails.

**Fix — restructure `index.ts` so `listen()` comes first:**

```ts
// 1. Create pool and build app (no I/O yet — pg Pool is lazy)
const store = await openStore();          // remove the pool.query('SELECT 1') line inside here
const identity = await loadOrCreateIdentity(dataDir);
const app = buildServer({ store, identity });

// 2. Bind port FIRST so the health check gets a 200 immediately
await app.listen({ port, host });
console.log(`[sp-witness-watcher] listening on http://${host}:${port}`);

// 3. Run migration in the background after listen
store.migrate().catch((err) => {
  console.error('[store] migration failed — shutting down:', err);
  process.exit(1);
});
```

Also remove `await pool.query('SELECT 1')` from `openStore()` in `store.ts` — pg's `Pool` connects lazily on the first real query. The eager ping is redundant and blocks startup for no benefit.

---

## 2. Production secrets

> Confirm `WW_SERVICE_IDENTITY_JSON` is available in the **published** Autoscale environment (not just dev Secrets). What is the exact secret name format?

**Yes — secrets are available in both dev and published Autoscale, under exactly the same name.**

Set the secret once in **Tools → Secrets** (the padlock icon in the sidebar). The key name is `WW_SERVICE_IDENTITY_JSON` — no prefix, no transformation, no quotes. It appears as `process.env.WW_SERVICE_IDENTITY_JSON` identically in the dev shell, the running workflow, and the published Autoscale container.

Value format (a single-line JSON string):

```
{"aid":"E...","public_key_b64":"...","private_seed_b64":"..."}
```

Generate it once with `node deploy/replit/scripts/generate-identity.mjs`, copy the output, paste it as the secret value. **Never regenerate in production** — a new AID breaks all existing receipt chains.

---

## 3. Custom domains

> For two CNAMEs (`witness.grapeid.org` and `watcher.grapeid.org`) on one Autoscale deployment, is there any routing caveat beyond adding both in Publishing → Custom Domains?

**No routing caveats. Both domains work out of the box on one deployment.**

Add both hostnames in **Publishing → Custom Domains**, then add CNAME records at your DNS provider:

| Hostname | Type | Value |
|----------|------|-------|
| `witness.grapeid.org` | CNAME | `<your-repl-slug>.<username>.replit.app` |
| `watcher.grapeid.org` | CNAME | `<your-repl-slug>.<username>.replit.app` |

Replit provisions TLS for both automatically. Both hostnames hit the exact same running process — no host-based routing is needed since all six endpoints serve both witness and watcher roles from a single binary.

---

## 4. `npm install` in build phase

> Our `deployment.build` runs `cd deploy/replit && npm install && npm run build`. Is `node_modules` included in the deployment image, or must we use `npm ci --omit=dev` and bundle differently?

**`node_modules` IS included in the deployment image. No bundling required.**

Replit's build phase captures the entire workspace — including `node_modules/` and the compiled `dist/` from `tsc` — as the Repl layer image. You do not need to bundle or tree-shake.

**Important workspace root caveat:** Replit automatically runs `npm install` in the workspace root when it detects a `package.json` there. The `.replit` config at `deploy/replit/.replit` must be at the **workspace root** for Replit to pick it up.

- **Recommended approach:** Create a new Replit project by importing from GitHub and setting the root to the `deploy/replit/` subdirectory — or copy `deploy/replit/` contents into a fresh workspace root. `npm install` will then target the right `package.json` automatically.

- **Alternative (if workspace root is the repo root):** Move `.replit` to the repo root and adjust:
  ```toml
  build = ["bash", "-c", "cd deploy/replit && npm install && npm run build"]
  run   = ["bash", "-c", "cd deploy/replit && node dist/index.js"]
  ```

`npm ci --omit=dev` works fine and trims ~30–40 MB of devDependencies from the image, but it is not required — the production dep set (fastify, pg, @noble) is small enough that it makes no practical difference.

---

## 5. Port confirmation

> Confirm Autoscale probes `0.0.0.0:5000` with `[[ports]]` `localPort=5000` / `externalPort=80` and that `/health` is the probe path.

**Confirmed on all counts.**

- Replit Autoscale probes the internal `localPort` declared in `[[ports]]`. With `localPort=5000` / `externalPort=80`, the health check hits `http://127.0.0.1:5000/health`.
- The probe path is `/health` — Replit always uses this path. The current implementation returns `{ status: 'active', ... }` with HTTP 200, which is correct.
- The server must bind to `0.0.0.0` (not `127.0.0.1`) — `HOST=0.0.0.0` in `[env]` already handles this.
- `PORT=5000` in `[env]` already matches the declared `localPort`.

**One watch-out:** if the server is still inside `openStore()` / `migrate()` when the first probe fires (see Q1 above), the probe gets connection-refused and Autoscale marks the deploy failed. Fix Q1 first — with that fix in place, the port and path config are correct as written.
