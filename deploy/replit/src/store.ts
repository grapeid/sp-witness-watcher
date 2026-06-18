import pg from 'pg';

export interface WitnessStore {
  migrate(): Promise<void>;
  close(): Promise<void>;
  enroll(aid: string, controllerAid: string): Promise<void>;
  isEnrolled(aid: string): Promise<boolean>;
  observedSince(aid: string): Promise<string>;
  storeEvent(
    aid: string,
    seq: number,
    event: Record<string, unknown>,
    digest: string,
  ): Promise<void>;
  getKelEvents(aid: string): Promise<Record<string, unknown>[]>;
  getObservationDigest(aid: string, seq: number): Promise<{ digest: string; ok: boolean }>;
}

export async function openStore(): Promise<WitnessStore> {
  const dsn = process.env.DATABASE_URL;
  if (!dsn) {
    throw new Error('DATABASE_URL is not set — Replit PostgreSQL integration required');
  }
  const pool = new pg.Pool({
    connectionString: dsn,
    ssl: dsn.includes('localhost') ? undefined : { rejectUnauthorized: false },
  });
  return new PostgresStore(pool);
}

class PostgresStore implements WitnessStore {
  constructor(private readonly pool: pg.Pool) {}

  async migrate(): Promise<void> {
    await this.pool.query(`
CREATE TABLE IF NOT EXISTS enrollments (
    aid TEXT PRIMARY KEY,
    controller_aid TEXT NOT NULL,
    enrolled_at TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    observed_since TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS kel_events (
    aid TEXT NOT NULL,
    sequence_num INTEGER NOT NULL,
    event_json TEXT NOT NULL,
    event_digest TEXT NOT NULL,
    received_at TEXT NOT NULL,
    PRIMARY KEY (aid, sequence_num)
);
CREATE TABLE IF NOT EXISTS observations (
    aid TEXT NOT NULL,
    sequence_num INTEGER NOT NULL,
    kel_digest TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    PRIMARY KEY (aid, sequence_num)
);
CREATE TABLE IF NOT EXISTS digest_conflicts (
    id BIGSERIAL PRIMARY KEY,
    aid TEXT NOT NULL,
    sequence_num INTEGER NOT NULL,
    digest_a TEXT NOT NULL,
    digest_b TEXT NOT NULL,
    detected_at TEXT NOT NULL
);
`);
  }

  async close(): Promise<void> {
    await this.pool.end();
  }

  async enroll(aid: string, controllerAid: string): Promise<void> {
    const now = new Date().toISOString();
    await this.pool.query(
      `INSERT INTO enrollments (aid, controller_aid, enrolled_at, status, observed_since)
       VALUES ($1, $2, $3, 'active', $4)
       ON CONFLICT (aid) DO UPDATE SET status='active', observed_since=EXCLUDED.observed_since`,
      [aid, controllerAid, now, now],
    );
  }

  async isEnrolled(aid: string): Promise<boolean> {
    const res = await this.pool.query(
      `SELECT COUNT(1)::int AS n FROM enrollments WHERE aid=$1 AND status='active'`,
      [aid],
    );
    return (res.rows[0]?.n ?? 0) > 0;
  }

  async observedSince(aid: string): Promise<string> {
    const res = await this.pool.query(`SELECT observed_since FROM enrollments WHERE aid=$1`, [aid]);
    return res.rows[0]?.observed_since ?? '';
  }

  async storeEvent(
    aid: string,
    seq: number,
    event: Record<string, unknown>,
    digest: string,
  ): Promise<void> {
    const existing = await this.pool.query(
      `SELECT event_digest FROM kel_events WHERE aid=$1 AND sequence_num=$2`,
      [aid, seq],
    );
    if (existing.rows.length > 0) {
      const existingDigest = existing.rows[0].event_digest as string;
      if (existingDigest !== digest) {
        await this.pool.query(
          `INSERT INTO digest_conflicts (aid, sequence_num, digest_a, digest_b, detected_at)
           VALUES ($1,$2,$3,$4,$5)`,
          [aid, seq, existingDigest, digest, new Date().toISOString()],
        );
        throw new ConflictError(`conflicting event at seq ${seq}`);
      }
      return;
    }
    const now = new Date().toISOString();
    const eventJson = JSON.stringify(event);
    await this.pool.query(
      `INSERT INTO kel_events (aid, sequence_num, event_json, event_digest, received_at)
       VALUES ($1,$2,$3,$4,$5)`,
      [aid, seq, eventJson, digest, now],
    );
    await this.pool.query(
      `INSERT INTO observations (aid, sequence_num, kel_digest, observed_at) VALUES ($1,$2,$3,$4)
       ON CONFLICT (aid, sequence_num) DO UPDATE
       SET kel_digest=EXCLUDED.kel_digest, observed_at=EXCLUDED.observed_at`,
      [aid, seq, digest, now],
    );
  }

  async getKelEvents(aid: string): Promise<Record<string, unknown>[]> {
    const res = await this.pool.query(
      `SELECT event_json FROM kel_events WHERE aid=$1 ORDER BY sequence_num`,
      [aid],
    );
    return res.rows.map((row) => JSON.parse(row.event_json as string) as Record<string, unknown>);
  }

  async getObservationDigest(aid: string, seq: number): Promise<{ digest: string; ok: boolean }> {
    const res = await this.pool.query(
      `SELECT kel_digest FROM observations WHERE aid=$1 AND sequence_num=$2`,
      [aid, seq],
    );
    if (res.rows.length === 0) return { digest: '', ok: false };
    return { digest: res.rows[0].kel_digest as string, ok: true };
  }
}

export class ConflictError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ConflictError';
  }
}