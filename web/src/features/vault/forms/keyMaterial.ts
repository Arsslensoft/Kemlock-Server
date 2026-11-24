// Key material for the ssh-key, pgp-key, certificate and contact items. The shapes are the
// Kemlock app's `VaultKey` and `Contact` JSON (kemlock-core models): halves are standard base64,
// an SSH key's private half is PKCS#8 DER and its public half SPKI DER, a PGP key's halves are the
// binary transferable keys. No function here logs or keeps what it is given.

export function toB64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(binary);
}

export function fromB64(text: string): Uint8Array {
  const binary = atob(text.replace(/-/g, '+').replace(/_/g, '/'));
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
  return out;
}

const B64_BODY = /^[A-Za-z0-9+/]+={0,2}$/;

export interface PemBlock {
  label: string;
  /** The body, base64 with no whitespace, and no armor headers or checksum line. */
  body: string;
}

/** Every `-----BEGIN X-----` block of a text, with armor headers and the `=CRC` line dropped. */
export function pemBlocks(text: string): PemBlock[] {
  const blocks: PemBlock[] = [];
  const re = /-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----/g;
  for (const match of text.matchAll(re)) {
    const lines = (match[2] ?? '').split(/\r?\n/).map((line) => line.trim());
    // Armor headers (`Version: ...`) run up to the first blank line.
    const blank = lines.findIndex((line, index) => index > 0 && line === '');
    const first = lines.findIndex((line) => line !== '');
    const start = first !== -1 && blank > first && /^[A-Za-z-]+: /.test(lines[first] ?? '') ? blank : 0;
    const body = lines
      .slice(start)
      .filter((line) => line !== '' && !line.startsWith('='))
      .join('');
    blocks.push({ label: match[1] ?? '', body });
  }
  return blocks;
}

function validBody(body: string): boolean {
  if (body === '' || body.length % 4 !== 0 || !B64_BODY.test(body)) return false;
  try {
    atob(body);
    return true;
  } catch {
    return false;
  }
}

export interface PgpHalves {
  private?: string;
  public?: string;
}

/** The private and public halves of pasted armor; undefined when a block is not OpenPGP. */
export function pgpHalves(text: string): PgpHalves | undefined {
  const out: PgpHalves = {};
  for (const block of pemBlocks(text)) {
    if (!validBody(block.body)) return undefined;
    // An OpenPGP packet starts with a byte whose top bit is set.
    if ((fromB64(block.body)[0] ?? 0) < 0x80) return undefined;
    if (block.label === 'PGP PRIVATE KEY BLOCK' && out.private === undefined) out.private = block.body;
    else if (block.label === 'PGP PUBLIC KEY BLOCK' && out.public === undefined) out.public = block.body;
    else return undefined;
  }
  return out.private === undefined && out.public === undefined ? undefined : out;
}

export type SshAlgorithm = 'ed25519' | 'ecdsa-p256';

export interface SshMaterial {
  algorithm: SshAlgorithm;
  /** PKCS#8 DER, base64. */
  private: string;
  /** SPKI DER, base64. */
  public: string;
}

const ED25519_OID = [0x06, 0x03, 0x2b, 0x65, 0x70];
const P256_OID = [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const SPKI_ED25519 = Uint8Array.from([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]);
const SPKI_P256 = Uint8Array.from([
  0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48,
  0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
]);

function contains(bytes: Uint8Array, needle: number[]): boolean {
  outer: for (let i = 0; i + needle.length <= Math.min(bytes.length, 64); i += 1) {
    for (let j = 0; j < needle.length; j += 1) if (bytes[i + j] !== needle[j]) continue outer;
    return true;
  }
  return false;
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, part) => n + part.length, 0));
  let at = 0;
  for (const part of parts) {
    out.set(part, at);
    at += part.length;
  }
  return out;
}

/** The algorithm a PKCS#8 DER names, for the two the web vault writes; undefined for any other. */
export function sshAlgorithmOf(der: Uint8Array): SshAlgorithm | undefined {
  if (contains(der, ED25519_OID)) return 'ed25519';
  if (contains(der, P256_OID)) return 'ecdsa-p256';
  return undefined;
}

/** A new Ed25519 key pair made by the browser (WebCrypto); rejects where it is not supported. */
export async function generateEd25519(): Promise<SshMaterial> {
  const pair = (await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])) as CryptoKeyPair;
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', pair.privateKey));
  const spki = new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey));
  return { algorithm: 'ed25519', private: toB64(pkcs8), public: toB64(spki) };
}

/** Reads a pasted PKCS#8 private key (PEM, or bare base64); undefined when it is not one this reads. */
export async function readPastedSshKey(text: string): Promise<SshMaterial | undefined> {
  const blocks = pemBlocks(text);
  const only = blocks.length === 1 ? blocks[0] : undefined;
  const body = blocks.length === 0 ? text.replace(/\s+/g, '') : only?.label === 'PRIVATE KEY' ? only.body : '';
  if (!validBody(body)) return undefined;
  const der = fromB64(body);
  const algorithm = sshAlgorithmOf(der);
  if (!algorithm) return undefined;
  try {
    const params = algorithm === 'ed25519' ? { name: 'Ed25519' } : { name: 'ECDSA', namedCurve: 'P-256' };
    const key = await crypto.subtle.importKey('pkcs8', der, params, true, ['sign']);
    const jwk = await crypto.subtle.exportKey('jwk', key);
    if (!jwk.x) return undefined;
    const x = fromB64(jwk.x);
    let spki: Uint8Array;
    if (algorithm === 'ed25519') spki = concat(SPKI_ED25519, x);
    else {
      if (!jwk.y) return undefined;
      spki = concat(SPKI_P256, x, fromB64(jwk.y));
    }
    return { algorithm, private: toB64(der), public: toB64(spki) };
  } catch {
    return undefined;
  }
}

/** Bytes of the public key material of a v4 key of this algorithm, from `at`; undefined if unknown. */
function publicLength(algo: number, b: Uint8Array, at: number): number | undefined {
  const mpi = (p: number) => 2 + Math.ceil((((b[p] ?? 0) << 8) | (b[p + 1] ?? 0)) / 8);
  switch (algo) {
    case 1:
    case 2:
    case 3:
      return mpi(at) + mpi(at + mpi(at));
    case 16:
      return mpi(at) + mpi(at + mpi(at)) + mpi(at + mpi(at) + mpi(at + mpi(at)));
    case 17: {
      let n = 0;
      for (let i = 0; i < 4; i += 1) n += mpi(at + n);
      return n;
    }
    case 18: {
      const oid = 1 + (b[at] ?? 0);
      const m = mpi(at + oid);
      return oid + m + 1 + (b[at + oid + m] ?? 0);
    }
    case 19:
    case 22: {
      const oid = 1 + (b[at] ?? 0);
      return oid + mpi(at + oid);
    }
    case 25:
    case 27:
      return 32;
    case 26:
      return 56;
    case 28:
      return 57;
    default:
      return undefined;
  }
}

/**
 * Whether the secret key packet that opens a binary transferable secret key (base64) is locked by
 * a passphrase: its S2K usage octet is not zero. undefined when the packet cannot be read.
 */
export function pgpSecretProtected(base64: string): boolean | undefined {
  try {
    const b = fromB64(base64);
    const head = b[0] ?? 0;
    let tag: number;
    let at: number;
    if ((head & 0x40) !== 0) {
      tag = head & 0x3f;
      const l = b[1] ?? 0;
      at = l < 192 ? 2 : l < 224 ? 3 : l === 255 ? 6 : 2;
    } else {
      tag = (head >> 2) & 0xf;
      at = 1 + [1, 2, 4][head & 3]!;
    }
    if (tag !== 5) return undefined;
    const version = b[at];
    if (version === 4) {
      const algo = b[at + 5] ?? 0;
      const n = publicLength(algo, b, at + 6);
      const usage = n === undefined ? undefined : b[at + 6 + n];
      return usage === undefined ? undefined : usage !== 0;
    }
    if (version === 6) {
      const n = ((b[at + 6] ?? 0) * 2 ** 24) + ((b[at + 7] ?? 0) << 16) + ((b[at + 8] ?? 0) << 8) + (b[at + 9] ?? 0);
      const usage = b[at + 10 + n];
      return usage === undefined ? undefined : usage !== 0;
    }
    return undefined;
  } catch {
    return undefined;
  }
}
