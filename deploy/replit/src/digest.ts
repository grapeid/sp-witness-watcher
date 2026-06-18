import { blake3 } from '@noble/hashes/blake3';
import { marshalSorted } from './json-canonical.js';

/** Blake3-256 Matter qb64 (code E) over canonical KEL bytes through seq. */
export function kelDigestAtSeq(events: Record<string, unknown>[], seq: number): string {
  const filtered = eventsUpToSeq(events, seq);
  const raw = canonicalKelBytes(filtered);
  const sum = blake3(raw);
  return matterFixedQB64('E', sum);
}

export function currentSeq(events: Record<string, unknown>[]): number {
  let max = -1;
  for (const ev of events) {
    const s = eventSeq(ev);
    if (s > max) max = s;
  }
  return max;
}

function eventsUpToSeq(events: Record<string, unknown>[], seq: number): Record<string, unknown>[] {
  const out = events.filter((ev) => eventSeq(ev) <= seq);
  if (out.length === 0) {
    throw new Error(`no events at or before seq ${seq}`);
  }
  out.sort((a, b) => eventSeq(a) - eventSeq(b));
  return out;
}

function eventSeq(ev: Record<string, unknown>): number {
  const v = ev['s'];
  if (typeof v === 'string') return parseInt(v, 10) || 0;
  if (typeof v === 'number') return Math.trunc(v);
  return -1;
}

/** Matches Go encoding/json.Marshal per-event (sorted map keys). */
function canonicalKelBytes(events: Record<string, unknown>[]): Uint8Array {
  const parts = events.map((ev) => marshalSorted(ev));
  const body = `[${parts.join(',')}]`;
  return new TextEncoder().encode(body);
}

/** Port of Go matterFixedQB64 + custom base64url (no padding). */
function matterFixedQB64(code: string, raw: Uint8Array): string {
  const ps = (3 - (raw.length % 3)) % 3;
  const padded = new Uint8Array(ps + raw.length);
  padded.set(raw, ps);
  const b64 = base64UrlEncode(padded);
  return code + b64.slice(code.length % 4);
}

function base64UrlEncode(data: Uint8Array): string {
  const table = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  const out: string[] = [];
  for (let i = 0; i < data.length; i += 3) {
    const remain = data.length - i;
    let n: number;
    if (remain >= 3) {
      n = (data[i] << 16) | (data[i + 1] << 8) | data[i + 2];
      out.push(
        table[(n >> 18) & 63],
        table[(n >> 12) & 63],
        table[(n >> 6) & 63],
        table[n & 63],
      );
    } else if (remain === 2) {
      n = (data[i] << 16) | (data[i + 1] << 8);
      out.push(table[(n >> 18) & 63], table[(n >> 12) & 63], table[(n >> 6) & 63]);
    } else {
      n = data[i] << 16;
      out.push(table[(n >> 18) & 63], table[(n >> 12) & 63]);
    }
  }
  return out.join('');
}