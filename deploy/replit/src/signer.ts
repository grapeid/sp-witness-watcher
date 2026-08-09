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
  const aid = nonTransferableAid(pub);
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
  // The identifier is DERIVED, never read from the file.
  //
  // A witness is named by a non-transferable identifier, which is its verifying
  // key carrying a prefix — that is what lets anyone check a receipt holding
  // nothing but the identifier written in the key event. Taking the stored
  // value on trust would let the file name a key it does not hold, which is the
  // one thing this kind of identifier is supposed to make impossible.
  //
  // Deriving it also means an instance created before this keeps its keys and
  // simply starts reporting the correct identifier, with no migration and no
  // regenerated identity.
  return { aid: nonTransferableAid(derivedPub), publicKey: derivedPub, privateKey: priv };
}

/**
 * CESR non-transferable identifier (code "B") for an Ed25519 public key.
 *
 * What stood here was `"E" + base64url(key)`, which is not a CESR identifier at
 * all: "E" denotes a Blake3 digest, and this is not a digest of anything. It was
 * the right length by coincidence and unparseable by every KERI implementation,
 * including the one that has to verify our receipts.
 *
 * The encoding is not a plain concatenation. A 1-character code needs the raw
 * bytes padded by one leading zero so the result aligns to base64, and the
 * leading character of that encoding is then replaced by the code.
 */
export function nonTransferableAid(publicKey: Uint8Array): string {
  const padded = new Uint8Array(1 + publicKey.length);
  padded.set(publicKey, 1);
  return 'B' + base64Url(padded).slice(1);
}

/**
 * CESR indexed-less signature (code "0B") over the given bytes.
 *
 * A 2-character code needs two leading pad bytes, and the two leading
 * characters of the encoding are replaced by the code.
 */
export function cesrSignature(identity: ServiceIdentity, payload: Uint8Array): string {
  const sig = ed25519.sign(payload, identity.privateKey);
  const padded = new Uint8Array(2 + sig.length);
  padded.set(sig, 2);
  return '0B' + base64Url(padded).slice(2);
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
