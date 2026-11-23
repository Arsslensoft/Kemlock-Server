// The words and short forms two admins read to each other to check a server's identity key.
// The pairwise words are the ones docs/federation.md defines ("The fingerprint"); the console
// computes them itself from the keys it was given, so a server can't show matching words for the
// wrong key. `keyWords` and `shortFingerprint` are display-only forms of one key, which the
// document doesn't define: they are this console's own, labelled as such where shown.
import { decodeB64, utf8 } from '@/lib/b64url';

const CONSONANTS = 'bdfghjklmnprstvz';
const VOWELS = 'aiou';

/** One proquint: `consonant vowel consonant vowel consonant` for 16 bits (4, 2, 4, 2, 4). */
export function proquint(n: number): string {
  const v = n & 0xffff;
  return [
    CONSONANTS[(v >> 12) & 0xf],
    VOWELS[(v >> 10) & 0x3],
    CONSONANTS[(v >> 6) & 0xf],
    VOWELS[(v >> 4) & 0x3],
    CONSONANTS[v & 0xf],
  ].join('');
}

/** `u32be(len) ‖ bytes`, the length prefix of docs/crypto.md. */
function lp(bytes: Uint8Array): Uint8Array {
  const out = new Uint8Array(4 + bytes.length);
  new DataView(out.buffer).setUint32(0, bytes.length);
  out.set(bytes, 4);
  return out;
}

function concat(...parts: Uint8Array[]): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let at = 0;
  for (const part of parts) {
    out.set(part, at);
    at += part.length;
  }
  return out;
}

async function digest(
  name: 'SHA-256' | 'SHA-512',
  bytes: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array> {
  return new Uint8Array(await globalThis.crypto.subtle.digest(name, bytes));
}

function wordsOf(hash: Uint8Array): string {
  const words: string[] = [];
  for (let i = 0; i < 6; i += 1) {
    words.push(proquint(((hash[2 * i] ?? 0) << 8) | (hash[2 * i + 1] ?? 0)));
  }
  return words.join('-');
}

export interface ServerKey {
  /** The server id, 16 bytes as a UUID or 32 hex characters, or base64url. */
  serverId: string;
  /** The `sig1` identity public key, base64url. */
  identityKey: string;
}

export function idBytes(id: string): Uint8Array {
  // A UUID is 32 hex characters, written with dashes by the server; anything else is base64url.
  const hex = id.replace(/-/g, '');
  return /^[0-9a-fA-F]{32}$/.test(hex)
    ? Uint8Array.from(hex.match(/../g) ?? [], (pair) => Number.parseInt(pair, 16))
    : decodeB64(id);
}

function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const length = Math.min(a.length, b.length);
  for (let i = 0; i < length; i += 1) {
    const diff = (a[i] ?? 0) - (b[i] ?? 0);
    if (diff !== 0) return diff;
  }
  return a.length - b.length;
}

/**
 * The six words both admins compare: SHA-512 over the label and both servers' ids and keys, the
 * lower server id first, so both consoles get the same words (docs/federation.md).
 */
export async function pairFingerprint(a: ServerKey, b: ServerKey): Promise<string> {
  const left = { id: idBytes(a.serverId), key: decodeB64(a.identityKey) };
  const right = { id: idBytes(b.serverId), key: decodeB64(b.identityKey) };
  const aFirst = compareBytes(left.id, right.id) <= 0;
  const [first, second] = aFirst ? [left, right] : [right, left];
  const hash = await digest(
    'SHA-512',
    concat(
      utf8('kemlock/v1/fed/fingerprint'),
      lp(first.id),
      lp(first.key),
      lp(second.id),
      lp(second.key),
    ),
  );
  return wordsOf(hash);
}

/** Six words for one identity key, for tables and the mismatch page. Console-only. */
export async function keyWords(identityKey: string): Promise<string> {
  const hash = await digest(
    'SHA-512',
    concat(utf8('kemlock/v1/fed/key-words'), lp(decodeB64(identityKey))),
  );
  return wordsOf(hash);
}

/** `9F14 D6A2 3C78 E05B`: the first 8 bytes of SHA-256 of the key. Console-only. */
export async function shortFingerprint(identityKey: string): Promise<string> {
  const hash = await digest('SHA-256', concat(decodeB64(identityKey)));
  const hex = [...hash.subarray(0, 8)]
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('')
    .toUpperCase();
  return hex.match(/.{4}/g)?.join(' ') ?? hex;
}

export interface KeyLabels {
  words: string;
  short: string;
}

export async function keyLabels(identityKey: string): Promise<KeyLabels> {
  const [words, short] = await Promise.all([keyWords(identityKey), shortFingerprint(identityKey)]);
  return { words, short };
}
