/** Simple in-memory per-IP rate limiter (matches Go ipLimiter). */
export class IpLimiter {
  private readonly hits = new Map<string, number[]>();

  constructor(
    private readonly limit: number,
    private readonly windowMs: number,
  ) {}

  allow(ip: string): boolean {
    const now = Date.now();
    const cutoff = now - this.windowMs;
    const prev = this.hits.get(ip) ?? [];
    const filt = prev.filter((t) => t > cutoff);
    if (filt.length >= this.limit) {
      this.hits.set(ip, filt);
      return false;
    }
    filt.push(now);
    this.hits.set(ip, filt);
    return true;
  }
}