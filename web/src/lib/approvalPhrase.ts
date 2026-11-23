// The device-approval phrase (docs/crypto.md, "Device-approval phrase"): five words both devices
// show for one request, worked out here from the request's one-time kx1 public key. The server's
// own `phrase` field is a cross-check at most and is never shown, or a server could substitute a
// key and send matching words to both screens.
import wordlist from './eff_large_wordlist.txt?raw';

export const PHRASE_LABEL = 'kemlock approval v1';
export const PHRASE_WORDS = 5;
export const WORD_COUNT = 7776;
const BITS_PER_WORD = 13;

let cached: string[] | undefined;

/** EFF's large list, one word per line, `abacus` first. */
export function words(): string[] {
  cached ??= wordlist
    .split('\n')
    .map((word) => word.trim())
    .filter((word) => word !== '');
  return cached;
}

/** The bytes to hash for a request's key: the label, then the key. */
export function phraseInput(publicKey: Uint8Array): Uint8Array {
  const label = new TextEncoder().encode(PHRASE_LABEL);
  const input = new Uint8Array(label.length + publicKey.length);
  input.set(label, 0);
  input.set(publicKey, label.length);
  return input;
}

/** The phrase for a SHA-256 digest: the first 65 bits as five 13-bit groups, each mod 7776. */
export function phraseFromDigest(digest: Uint8Array): string {
  if (digest.length < 9) throw new Error('a digest is 32 bytes');
  // The first 72 bits; the top 65 of them are the phrase's.
  let head = 0n;
  for (let i = 0; i < 9; i += 1) head = (head << 8n) | BigInt(digest[i] ?? 0);
  const bits = head >> BigInt(72 - PHRASE_WORDS * BITS_PER_WORD);
  const list = words();
  const out: string[] = [];
  for (let i = 0; i < PHRASE_WORDS; i += 1) {
    const shift = BigInt(BITS_PER_WORD * (PHRASE_WORDS - 1 - i));
    const group = Number((bits >> shift) & ((1n << BigInt(BITS_PER_WORD)) - 1n));
    out.push(list[group % WORD_COUNT] ?? 'abacus');
  }
  return out.join(' ');
}

/** The phrase for a request's one-time public key (1,600 bytes of kx1). */
export async function approvalPhrase(publicKey: Uint8Array): Promise<string> {
  const input = phraseInput(publicKey);
  const digest = await globalThis.crypto.subtle.digest('SHA-256', input as BufferSource);
  return phraseFromDigest(new Uint8Array(digest));
}
