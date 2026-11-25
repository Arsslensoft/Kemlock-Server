// Opens a `KMA1` file, the format an attachment is stored in (docs/crypto.md, "Files"):
//
//   "KMA1" | nonce prefix (8 bytes) | chunk 0 | chunk 1 | ... | last chunk
//   chunk = AES-256-GCM(key, nonce = prefix | u32be(counter), aad = 0x00, or 0x01 for the last
//           chunk, up to 65536 bytes of plaintext) | tag (16)
//
// Each file has its own 256-bit key, kept in the item's body. A file that was changed, cut short,
// reordered or opened with another key fails, and no plaintext is returned.
import { fromB64 } from '../forms/keyMaterial';

const HEADER = 12;
const PREFIX = 8;
const CHUNK = 65536;
const TAG = 16;
const SEALED_CHUNK = CHUNK + TAG;
const MAGIC = [0x4b, 0x4d, 0x41, 0x31];

export class Kma1Error extends Error {
  constructor(readonly reason: 'key' | 'shape' | 'damaged') {
    super(
      reason === 'key'
        ? 'the file key is not 32 bytes'
        : reason === 'shape'
          ? 'not a KMA1 file'
          : 'the file is damaged, or the key is not its own',
    );
    this.name = 'Kma1Error';
  }
}

/** The length of the `KMA1` file a `plain`-byte file becomes. */
export function kma1Length(plain: number): number {
  return HEADER + plain + TAG * Math.max(1, Math.ceil(plain / CHUNK));
}

/** The plaintext of `file`, opened with `keyBase64` (the file's own key, base64 or base64url). */
export async function openKma1(keyBase64: string, file: Uint8Array): Promise<Uint8Array> {
  let raw: Uint8Array;
  try {
    raw = fromB64(keyBase64);
  } catch {
    throw new Kma1Error('key');
  }
  if (raw.length !== 32) throw new Kma1Error('key');
  if (file.length < HEADER + TAG || MAGIC.some((byte, i) => file[i] !== byte)) throw new Kma1Error('shape');
  const key = await crypto.subtle.importKey('raw', raw as Uint8Array<ArrayBuffer>, 'AES-GCM', false, ['decrypt']);
  const body = file.subarray(HEADER);
  const count = Math.ceil(body.length / SEALED_CHUNK);
  const parts: Uint8Array[] = [];
  let total = 0;
  try {
    for (let i = 0; i < count; i += 1) {
      const last = i === count - 1;
      const sealed = body.subarray(i * SEALED_CHUNK, last ? body.length : (i + 1) * SEALED_CHUNK);
      const nonce = new Uint8Array(12);
      nonce.set(file.subarray(4, 4 + PREFIX));
      new DataView(nonce.buffer).setUint32(PREFIX, i);
      const plain = new Uint8Array(
        await crypto.subtle.decrypt(
          { name: 'AES-GCM', iv: nonce, additionalData: Uint8Array.of(last ? 1 : 0), tagLength: TAG * 8 },
          key,
          sealed as Uint8Array<ArrayBuffer>,
        ),
      );
      parts.push(plain);
      total += plain.length;
    }
  } catch {
    throw new Kma1Error('damaged');
  }
  const out = new Uint8Array(total);
  let at = 0;
  for (const part of parts) {
    out.set(part, at);
    at += part.length;
  }
  return out;
}
