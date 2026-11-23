// A well-formed public-key bundle for tests (docs/crypto.md): the label, an account id, a key
// version, then a kx1 and a sig1 public key of the right lengths. Nothing here is a real key.
import { encodeB64 } from '@/lib/b64url';

export function makeBundle(accountId: Uint8Array, keyVersion = 1, fill = 0x11): Uint8Array {
  const label = new TextEncoder().encode('kemlock/v1/bundle');
  const out = new Uint8Array(label.length + 16 + 4 + 1600 + 1984);
  out.set(label, 0);
  out.set(accountId.slice(0, 16), label.length);
  new DataView(out.buffer).setUint32(label.length + 16, keyVersion);
  out.fill(fill, label.length + 20, label.length + 20 + 1600);
  out.fill(0x22, label.length + 20 + 1600);
  return out;
}

export function makeBundleB64(uuid: string, keyVersion = 1, fill = 0x11): string {
  const hex = uuid.replace(/-/g, '');
  const id = new Uint8Array(16);
  for (let i = 0; i < 16; i += 1) id[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return encodeB64(makeBundle(id, keyVersion, fill));
}
