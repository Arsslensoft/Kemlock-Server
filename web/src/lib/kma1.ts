// Seals a file as `KMA1`, the format the Kemlock app writes an attachment in and the server stores
// (docs/crypto.md, "Files"):
//
//   "KMA1" | nonce prefix (8 random bytes) | chunk 0 | chunk 1 | ... | last chunk
//   chunk = AES-256-GCM(key, nonce = prefix | u32be(counter), aad = 0x00, or 0x01 for the last
//           chunk, up to 65536 bytes of plaintext) | tag (16)
//
// Each file has its own random 256-bit key. The key is never stored with the file: it goes in the
// item's body, which is itself sealed, so the server holds only ciphertext. WebCrypto's AES-GCM
// returns the ciphertext with its tag at the end, which is the chunk layout as it is.
import { decodeB64, encodeB64 } from '@/lib/b64url';

const HEADER = 12;
const PREFIX = 8;
const CHUNK = 65536;
const TAG = 16;
const MAGIC = [0x4b, 0x4d, 0x41, 0x31];

/** The length of the `KMA1` file a `plain`-byte file becomes. */
export function kma1Length(plain: number): number {
  return HEADER + plain + TAG * Math.max(1, Math.ceil(plain / CHUNK));
}

function random(length: number): Uint8Array<ArrayBuffer> {
  const bytes = new Uint8Array(length);
  globalThis.crypto.getRandomValues(bytes);
  return bytes;
}

/** A new file key: 32 random bytes. */
export function newFileKey(): Uint8Array {
  return random(32);
}

/** The key as the body keeps it: standard base64, as the Kemlock app reads it. */
export function fileKeyText(key: Uint8Array): string {
  let binary = '';
  for (const byte of key) binary += String.fromCharCode(byte);
  return btoa(binary);
}

/** A new attachment id: 16 random bytes in base64url, as the app names its files. */
export function newAttachmentId(): string {
  return encodeB64(random(16));
}

/** The bytes of a key as the body keeps it (base64 or base64url). */
export function fileKeyBytes(text: string): Uint8Array {
  return decodeB64(text.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''));
}

/**
 * `plain` as a `KMA1` file under `key`. `prefix` is the 8-byte nonce prefix; it is random unless a
 * test pins it.
 */
export async function sealKma1(
  key: Uint8Array,
  plain: Uint8Array,
  prefix: Uint8Array = random(PREFIX),
): Promise<Uint8Array> {
  if (key.length !== 32) throw new Error('a KMA1 key is 32 bytes');
  if (prefix.length !== PREFIX) throw new Error('a KMA1 nonce prefix is 8 bytes');
  const aes = await globalThis.crypto.subtle.importKey('raw', key as Uint8Array<ArrayBuffer>, 'AES-GCM', false, [
    'encrypt',
  ]);
  const chunks = Math.max(1, Math.ceil(plain.length / CHUNK));
  const out = new Uint8Array(kma1Length(plain.length));
  out.set(MAGIC, 0);
  out.set(prefix, MAGIC.length);
  let at = HEADER;
  for (let counter = 0; counter < chunks; counter += 1) {
    const last = counter === chunks - 1;
    const nonce = new Uint8Array(12);
    nonce.set(prefix);
    new DataView(nonce.buffer).setUint32(PREFIX, counter);
    const slice = plain.subarray(counter * CHUNK, last ? plain.length : (counter + 1) * CHUNK);
    const sealed = new Uint8Array(
      await globalThis.crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: nonce, additionalData: Uint8Array.of(last ? 1 : 0), tagLength: TAG * 8 },
        aes,
        slice as Uint8Array<ArrayBuffer>,
      ),
    );
    out.set(sealed, at);
    at += sealed.length;
  }
  return out;
}
