// base64url without padding (RFC 4648 section 5), the one binary encoding of /kem/v1
// (docs/crypto.md, "Conventions"). A decoder refuses padding.

const ALPHABET = /^[A-Za-z0-9_-]*$/;

export function encodeB64(bytes: Uint8Array): string {
  let binary = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function decodeB64(text: string): Uint8Array {
  if (!ALPHABET.test(text) || text.length % 4 === 1) {
    throw new Error('not unpadded base64url');
  }
  const padded = text.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((text.length + 3) % 4);
  const binary = atob(padded);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
  return out;
}

export function utf8(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

export function fromUtf8(bytes: Uint8Array): string {
  return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
}

/** Overwrites key material once it is no longer needed. */
export function wipe(...buffers: Array<Uint8Array | undefined>): void {
  for (const buffer of buffers) buffer?.fill(0);
}
