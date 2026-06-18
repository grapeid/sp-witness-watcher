import Fastify, { type FastifyInstance } from 'fastify';
import { currentSeq, kelDigestAtSeq } from './digest.js';
import { marshalSorted } from './json-canonical.js';
import { IpLimiter } from './rate-limit.js';
import { witnessEventUrl, watcherKelDigestUrl } from './public-urls.js';
import { sign, type ServiceIdentity } from './signer.js';
import { ConflictError, type WitnessStore } from './store.js';

export interface AppContext {
  store: WitnessStore;
  identity: ServiceIdentity;
}

export function buildServer(ctx: AppContext): FastifyInstance {
  const app = Fastify({ logger: true });
  const limiter = new IpLimiter(120, 60_000);

  app.get('/health', async () => ({
    status: 'active',
    service: 'sp-witness-watcher',
    service_aid: ctx.identity.aid,
    seam: 'M67',
    runtime: 'nodejs',
  }));

  app.post<{ Body: { aid?: string; event?: Record<string, unknown> } }>(
    '/witness/event',
    async (req, reply) => {
      const aid = req.body?.aid;
      const event = req.body?.event;
      if (!aid || !event) {
        return reply.code(400).send({ error: 'aid and event required' });
      }
      let seq = currentSeq([event]);
      if (seq < 0) {
        const s = event['s'];
        if (typeof s === 'string') seq = parseInt(s, 10) || 0;
      }
      const events = await ctx.store.getKelEvents(aid);
      events.push(event);
      let digest: string;
      try {
        digest = kelDigestAtSeq(events, seq);
      } catch (err) {
        return reply.code(400).send({ error: (err as Error).message });
      }
      try {
        await ctx.store.storeEvent(aid, seq, event, digest);
      } catch (err) {
        if (err instanceof ConflictError) {
          return reply.code(409).send({ error: err.message });
        }
        throw err;
      }
      const receiptBody = marshalSorted({
        v: 'KERI10JSON',
        t: 'rct',
        d: digest,
        i: ctx.identity.aid,
        aid,
        seq,
        dt: new Date().toISOString(),
      });
      const receiptBytes = new TextEncoder().encode(receiptBody);
      return {
        receipt: JSON.parse(receiptBody) as Record<string, unknown>,
        signature: sign(ctx.identity, receiptBytes),
        signed_by: ctx.identity.aid,
      };
    },
  );

  app.get<{ Params: { aid: string } }>('/witness/kel/:aid', async (req, reply) => {
    if (!limiter.allow(clientIp(req))) {
      return reply.code(429).send({ error: 'rate limited' });
    }
    const events = await ctx.store.getKelEvents(req.params.aid);
    return { aid: req.params.aid, kel: events, count: events.length };
  });

  app.get<{ Querystring: { aid?: string; seq?: string } }>(
    '/public/kel-digest',
    async (req, reply) => {
      if (!limiter.allow(clientIp(req))) {
        return reply.code(429).send({ error: 'rate limited' });
      }
      const aid = req.query.aid ?? '';
      const seqStr = req.query.seq ?? '';
      const seq = parseInt(seqStr, 10);
      const resp: Record<string, unknown> = {
        aid,
        sequence_number: Number.isFinite(seq) ? seq : 0,
        digest: null,
        observed_since: null,
        first_seen_at: null,
        signed_by: ctx.identity.aid,
      };
      if (aid && seqStr) {
        const { digest, ok } = await ctx.store.getObservationDigest(aid, seq);
        if (ok) {
          const since = await ctx.store.observedSince(aid);
          resp.digest = digest;
          resp.observed_since = since || null;
          resp.first_seen_at = since || null;
        }
      }
      const unsigned = marshalSorted(resp);
      resp.signature = sign(ctx.identity, new TextEncoder().encode(unsigned));
      return JSON.parse(marshalSorted(resp));
    },
  );

  app.post<{ Body: { aid?: string; seq?: number; digest?: string } }>(
    '/public/kel-check',
    async (req, reply) => {
      const { aid = '', seq = 0, digest = '' } = req.body ?? {};
      const { digest: ours, ok } = await ctx.store.getObservationDigest(aid, seq);
      const match = ok && ours === digest;
      const out: Record<string, unknown> = { match };
      if (ok) {
        out.our_digest = ours;
        const since = await ctx.store.observedSince(aid);
        out.our_first_seen_at = since;
      }
      return out;
    },
  );

  app.post<{ Body: { aid?: string; controller_aid?: string } }>('/enroll', async (req, reply) => {
    const aid = req.body?.aid;
    if (!aid) return reply.code(400).send({ error: 'aid required' });
    const controller = req.body?.controller_aid || aid;
    await ctx.store.enroll(aid, controller);
    req.log.info({ aid, controller }, '[M67] enrolled');
    return {
      enrolled: true,
      aid,
      watcher_hint_url: watcherKelDigestUrl(),
      witness_url: witnessEventUrl(),
      observed_since: new Date().toISOString(),
    };
  });

  return app;
}

function clientIp(req: { ip: string; headers: Record<string, string | string[] | undefined> }): string {
  const xff = req.headers['x-forwarded-for'];
  if (typeof xff === 'string' && xff.length > 0) {
    return xff.split(',')[0]?.trim() || req.ip;
  }
  return req.ip;
}
