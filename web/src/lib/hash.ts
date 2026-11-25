// The SHA-256 of a file's bytes, as lower-case hex. A file item and a note's attachment keep it
// beside their name and size, inside the sealed body, so the duplicate finder can tell two copies
// of one file apart from two files of one size without opening either.

/** The SHA-256 of `bytes` as 64 lower-case hex digits. */
export async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', bytes as Uint8Array<ArrayBuffer>));
  return [...digest].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}
