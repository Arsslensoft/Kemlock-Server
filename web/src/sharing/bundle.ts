// A public-key bundle and its fingerprint, read here so the browser checks what it is told
// (docs/crypto.md, "Public-key bundle and fingerprint"):
//
//   bundle      = "kemlock/v1/bundle" ‖ account id (16) ‖ u32be(key version)
//                 ‖ kx1 public key (1600) ‖ sig1 public key (1984)
//   fingerprint = SHA-512("kemlock/v1/fingerprint" ‖ bundle)
//
// People compare the fingerprint as 12 groups of 5 digits: group i is
// u40be(fingerprint[5i .. 5i+5]) mod 100000. The worker computes the same text; this module
// also gives the raw 64 bytes a confirmation carries, which the worker's text API doesn't.
const BUNDLE_LABEL = new TextEncoder().encode('kemlock/v1/bundle');
const FINGERPRINT_LABEL = new TextEncoder().encode('kemlock/v1/fingerprint');
const KX1_LEN = 1600;
const SIG1_LEN = 1984;

export interface ParsedBundle {
  /** The account's id as 16 bytes. */
  accountId: Uint8Array;
  keyVersion: number;
  /** The kx1 exchange public key: what a key is sealed to. */
  kx1: Uint8Array;
  sig1: Uint8Array;
}

/** Splits a bundle into its parts; null when it isn't one. */
export function parseBundle(bundle: Uint8Array): ParsedBundle | null {
  const head = BUNDLE_LABEL.length;
  if (bundle.length !== head + 16 + 4 + KX1_LEN + SIG1_LEN) return null;
  for (let i = 0; i < head; i += 1) if (bundle[i] !== BUNDLE_LABEL[i]) return null;
  const view = new DataView(bundle.buffer, bundle.byteOffset, bundle.byteLength);
  const kxStart = head + 20;
  return {
    accountId: bundle.slice(head, head + 16),
    keyVersion: view.getUint32(head + 16),
    kx1: bundle.slice(kxStart, kxStart + KX1_LEN),
    sig1: bundle.slice(kxStart + KX1_LEN),
  };
}

/** The 64 fingerprint bytes of a bundle. */
export async function fingerprintBytes(bundle: Uint8Array): Promise<Uint8Array> {
  const input = new Uint8Array(FINGERPRINT_LABEL.length + bundle.length);
  input.set(FINGERPRINT_LABEL, 0);
  input.set(bundle, FINGERPRINT_LABEL.length);
  const digest = await globalThis.crypto.subtle.digest('SHA-512', input as BufferSource);
  return new Uint8Array(digest);
}

/** 12 groups of 5 digits from the 64 bytes, joined by spaces. */
export function fingerprintText(bytes: Uint8Array): string {
  const groups: string[] = [];
  for (let i = 0; i < 12; i += 1) {
    let value = 0;
    for (let j = 0; j < 5; j += 1) value = value * 256 + (bytes[i * 5 + j] ?? 0);
    groups.push(String(value % 100000).padStart(5, '0'));
  }
  return groups.join(' ');
}

/** A UUID's 16 bytes. */
export function uuidBytes(uuid: string): Uint8Array {
  const hex = uuid.replace(/-/g, '');
  if (!/^[0-9a-fA-F]{32}$/.test(hex)) throw new Error('not a UUID');
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i += 1) out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export interface Fingerprint {
  /** For the person to compare. */
  text: string;
  /** What a confirmation sends back. */
  bytes: Uint8Array;
  /** Whether the worker's own text agrees with the one worked out here. */
  consistent: boolean;
}

/**
 * The fingerprint of a bundle, from the worker (`workerText`) and from the bytes. A bundle the
 * worker or this module can't read gives null, and a text that differs between them is flagged,
 * so a confirmation is never built on a fingerprint nobody checked.
 */
export async function checkedFingerprint(
  bundle: Uint8Array,
  workerText: (bundle: Uint8Array) => Promise<string>,
): Promise<Fingerprint | null> {
  if (parseBundle(bundle) === null) return null;
  const bytes = await fingerprintBytes(bundle);
  const text = await workerText(bundle);
  return { text, bytes, consistent: text === fingerprintText(bytes) };
}
