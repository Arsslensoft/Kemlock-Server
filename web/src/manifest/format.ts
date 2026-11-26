// The signed manifest's bytes (docs/crypto.md, "Signed manifest"):
//
//   manifest = "kemlock/v1/manifest" ‖ owner (17) ‖ u64be(counter) ‖ u32be(n)
//              ‖ n × (item id (16) ‖ u64be(revision) ‖ SHA-256(ciphertext) (32) ‖ u8(deleted))
//
// Entries are sorted by item id bytes; a tombstone's hash is 32 zero bytes. The worker signs and
// checks the bytes (it parses them too, and refuses anything not canonical); the page reads them
// to compare what the server serves, and writes them to sign. Counters and revisions are JS
// numbers: a manifest with one past 2^53 - 1 is refused rather than read wrongly.
import { sha256Hex } from '@/lib/hash';

const LABEL = new TextEncoder().encode('kemlock/v1/manifest');
const OWNER_LEN = 17;
const HEADER_LEN = LABEL.length + OWNER_LEN + 8 + 4;
const ENTRY_LEN = 16 + 8 + 32 + 1;

/** SHA-256 of a tombstone: 32 zero bytes, as hex. */
export const TOMBSTONE_HASH = '0'.repeat(64);

/** One item the manifest vouches for. `hash` is lower-case hex of SHA-256(ciphertext). */
export interface ManifestEntry {
  /** hyphenated lower-case UUID */
  id: string;
  revision: number;
  hash: string;
  deleted: boolean;
}

export interface Manifest {
  /** `user:<uuid>` or `space:<uuid>` */
  owner: string;
  counter: number;
  entries: ManifestEntry[];
}

const HEX = /^[0-9a-f]*$/;

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0 || !HEX.test(hex)) throw new Error('not hex');
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

/** A hyphenated lower-case UUID's 16 bytes. */
function uuidToBytes(uuid: string): Uint8Array {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(uuid)) {
    throw new Error('not a UUID');
  }
  return hexToBytes(uuid.replace(/-/g, ''));
}

function bytesToUuid(bytes: Uint8Array): string {
  const hex = bytesToHex(bytes);
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function ownerToBytes(owner: string): Uint8Array {
  const [kind, id, ...rest] = owner.split(':');
  if (rest.length > 0 || id === undefined) throw new Error('not an owner');
  const out = new Uint8Array(OWNER_LEN);
  if (kind === 'user') out[0] = 1;
  else if (kind === 'space') out[0] = 2;
  else throw new Error('not an owner');
  out.set(uuidToBytes(id), 1);
  return out;
}

function bytesToOwner(bytes: Uint8Array): string | null {
  const id = bytesToUuid(bytes.subarray(1));
  if (bytes[0] === 1) return `user:${id}`;
  if (bytes[0] === 2) return `space:${id}`;
  return null;
}

/** The SHA-256 of a ciphertext as lower-case hex: what an entry holds for a live item. */
export function ciphertextHash(ciphertext: Uint8Array): Promise<string> {
  return sha256Hex(ciphertext);
}

/**
 * The manifest's bytes, entries sorted by item id. Throws on a repeated item id, a tombstone whose
 * hash is not all zero, a hash that is not 64 hex digits, or a number that does not fit.
 */
export function encodeManifest(manifest: Manifest): Uint8Array {
  if (!Number.isSafeInteger(manifest.counter) || manifest.counter < 0) throw new Error('counter');
  const entries = manifest.entries
    .map((entry) => ({ ...entry, idBytes: uuidToBytes(entry.id) }))
    .sort((a, b) => compareBytes(a.idBytes, b.idBytes));
  for (let i = 1; i < entries.length; i += 1) {
    const [before, entry] = [entries[i - 1], entries[i]];
    if (before && entry && compareBytes(before.idBytes, entry.idBytes) === 0) {
      throw new Error('an item twice');
    }
  }
  const out = new Uint8Array(HEADER_LEN + entries.length * ENTRY_LEN);
  const view = new DataView(out.buffer);
  out.set(LABEL, 0);
  out.set(ownerToBytes(manifest.owner), LABEL.length);
  view.setBigUint64(LABEL.length + OWNER_LEN, BigInt(manifest.counter));
  view.setUint32(LABEL.length + OWNER_LEN + 8, entries.length);
  let at = HEADER_LEN;
  for (const entry of entries) {
    if (!Number.isSafeInteger(entry.revision) || entry.revision < 0) throw new Error('revision');
    if (entry.hash.length !== 64) throw new Error('hash');
    if (entry.deleted && entry.hash !== TOMBSTONE_HASH) throw new Error('tombstone hash');
    out.set(entry.idBytes, at);
    view.setBigUint64(at + 16, BigInt(entry.revision));
    out.set(hexToBytes(entry.hash), at + 24);
    out[at + 56] = entry.deleted ? 1 : 0;
    at += ENTRY_LEN;
  }
  return out;
}

function compareBytes(a: Uint8Array, b: Uint8Array): number {
  for (let i = 0; i < Math.min(a.length, b.length); i += 1) {
    const difference = (a[i] ?? 0) - (b[i] ?? 0);
    if (difference !== 0) return difference;
  }
  return a.length - b.length;
}

/**
 * Reads a manifest's bytes; null for anything that is not a canonical one (another label, a count
 * that does not match the length, entries out of order or repeated, a flag other than 0 or 1, a
 * tombstone with a hash, trailing bytes, or a number past 2^53 - 1). It does not check a
 * signature: the worker does that, over these same bytes.
 */
export function decodeManifest(bytes: Uint8Array): Manifest | null {
  if (bytes.length < HEADER_LEN) return null;
  for (let i = 0; i < LABEL.length; i += 1) if (bytes[i] !== LABEL[i]) return null;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const owner = bytesToOwner(bytes.subarray(LABEL.length, LABEL.length + OWNER_LEN));
  const counter = view.getBigUint64(LABEL.length + OWNER_LEN);
  const count = view.getUint32(LABEL.length + OWNER_LEN + 8);
  if (owner === null || counter > BigInt(Number.MAX_SAFE_INTEGER)) return null;
  // The length is checked before anything is allocated for the entries.
  if (bytes.length !== HEADER_LEN + count * ENTRY_LEN) return null;
  const entries: ManifestEntry[] = [];
  let previous: Uint8Array | undefined;
  for (let i = 0; i < count; i += 1) {
    const at = HEADER_LEN + i * ENTRY_LEN;
    const idBytes = bytes.subarray(at, at + 16);
    const revision = view.getBigUint64(at + 16);
    const hash = bytesToHex(bytes.subarray(at + 24, at + 56));
    const flag = bytes[at + 56];
    if (flag !== 0 && flag !== 1) return null;
    if (revision > BigInt(Number.MAX_SAFE_INTEGER)) return null;
    if (flag === 1 && hash !== TOMBSTONE_HASH) return null;
    if (previous && compareBytes(previous, idBytes) >= 0) return null;
    previous = idBytes;
    entries.push({ id: bytesToUuid(idBytes), revision: Number(revision), hash, deleted: flag === 1 });
  }
  return { owner, counter: Number(counter), entries };
}
