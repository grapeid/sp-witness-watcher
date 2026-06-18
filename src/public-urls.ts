/** Public witness/watcher base URLs for enroll hints (one numbered pool instance). */

function instanceSuffix(): string {
  const n = process.env.WW_INSTANCE?.trim();
  return n && n !== '0' ? n : '1';
}

export function witnessEventUrl(): string {
  const base = process.env.WW_WITNESS_PUBLIC_URL?.replace(/\/$/, '');
  if (base) return `${base}/witness/event`;
  return `https://witness${instanceSuffix()}.grapeid.org/witness/event`;
}

export function watcherKelDigestUrl(): string {
  const base = process.env.WW_WATCHER_PUBLIC_URL?.replace(/\/$/, '');
  if (base) return `${base}/public/kel-digest`;
  return `https://watcher${instanceSuffix()}.grapeid.org/public/kel-digest`;
}