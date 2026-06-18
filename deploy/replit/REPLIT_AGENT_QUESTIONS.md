# Questions for Replit Agent (if publish still fails)

Copy these to Replit Agent if any step blocks deployment.

## 1. PostgreSQL / Neon cold start

> On first request after idle, does Neon cold start ever cause the 5-second publish health check to fail if we connect to Postgres before `listen()`? Should we lazy-connect to `DATABASE_URL` after the server is listening?

## 2. Production secrets

> Confirm `WW_SERVICE_IDENTITY_JSON` is available in the **published** Autoscale environment (not just dev Secrets). What is the exact secret name format?

## 3. Custom domains

> For two CNAMEs (`witness.grapeid.org` and `watcher.grapeid.org`) on one Autoscale deployment, is there any routing caveat beyond adding both in Publishing → Custom Domains?

## 4. `npm install` in build phase

> Our `deployment.build` runs `cd deploy/replit && npm install && npm run build`. Is `node_modules` included in the deployment image, or must we use `npm ci --omit=dev` and bundle differently?

## 5. Port confirmation

> Confirm Autoscale probes `0.0.0.0:5000` with `[[ports]]` `localPort=5000` / `externalPort=80` and that `/health` is the probe path.