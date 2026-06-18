import { ed25519 } from '@noble/curves/ed25519';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

export interface ServiceIdentity {
  aid: string;
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

interface IdentityFile {
  aid: string;
  public_key_b64: string;
  private_seed_b64: string;
}

/** Load from WW_SERVICE_IDENTITY_JSON, file, or generate (dev only). */
export async function loadOrCreateIdentity(dataDir: string): Promise<ServiceIdentity> {
  const envJson = process.env.WW_SERVICE_IDENTITY_JSON;
  if (envJson) {
    return parseIdentityFile(JSON.parse(envJson) as IdentityFile);
  }

  await mkdir(dataDir, { recursive: true, mode: 0o755 });
  const path = join(dataDir, 'service_identity.json');
  try {
    const raw = await readFile(path, 'utf8');
    return parseIdentityFile(JSON.parse(raw) as IdentityFile);
  } catch {
    // generate below
  }

  const priv = ed25519.utils.randomPrivateKey();
  const pub = ed25519.getPublicKey(priv);
  const aid = 'E' + base64Url(pub).slice(0, 43);
  const out: IdentityFile = {
    aid,
    public_key_b64: Buffer.from(pub).toString('base64'),
    private_seed_b64: Buffer.from(priv).toString('base64'),
  };
  await writeFile(path, JSON.stringify(out, null, 2), { mode: 0o600 });
  return { aid, publicKey: pub, privateKey: priv };
}

function parseIdentityFile(raw: IdentityFile): ServiceIdentity {
  const pub = Buffer.from(raw.public_key_b64, 'base64');
  const seed = Buffer.from(raw.private_seed_b64, 'base64');
  if (pub.length !== 32 || seed.length !== 32) {
    throw new Error('invalid service identity key material');
  }
  const priv = new Uint8Array(seed);
  const derivedPub = ed25519.getPublicKey(priv);
  if (Buffer.compare(Buffer.from(derivedPub), pub) !== 0) {
    throw new Error('service identity public key does not match seed');
  }
  return { aid: raw.aid, publicKey: derivedPub, privateKey: priv };
}

/** Base64url signature (no padding), matching Go signer.Sign. */
export function sign(identity: ServiceIdentity, payload: Uint8Array): string {
  const sig = ed25519.sign(payload, identity.privateKey);
  return base64Url(sig);
}

function base64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}
