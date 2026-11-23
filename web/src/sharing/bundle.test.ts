// @vitest-environment node
import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  checkedFingerprint,
  fingerprintBytes,
  fingerprintText,
  parseBundle,
  uuidBytes,
} from './bundle';

function makeBundle(version = 1): Uint8Array {
  const label = new TextEncoder().encode('kemlock/v1/bundle');
  const out = new Uint8Array(label.length + 16 + 4 + 1600 + 1984);
  out.set(label, 0);
  out.fill(0xa1, label.length, label.length + 16);
  new DataView(out.buffer).setUint32(label.length + 16, version);
  out.fill(0x11, label.length + 20, label.length + 20 + 1600);
  out.fill(0x22, label.length + 20 + 1600);
  return out;
}

describe('bundles', () => {
  it('are split into account id, version and the two public keys', () => {
    const parsed = parseBundle(makeBundle(3));
    expect(parsed?.keyVersion).toBe(3);
    expect(parsed?.accountId).toHaveLength(16);
    expect(parsed?.kx1).toHaveLength(1600);
    expect(parsed?.kx1[0]).toBe(0x11);
    expect(parsed?.sig1).toHaveLength(1984);
    expect(parsed?.sig1[0]).toBe(0x22);
  });

  it('are refused when the label or the length is wrong', () => {
    expect(parseBundle(new Uint8Array(10))).toBeNull();
    const bad = makeBundle();
    bad[0] = 0;
    expect(parseBundle(bad)).toBeNull();
  });

  it('have the SHA-512 fingerprint docs/crypto.md defines', async () => {
    const bundle = makeBundle();
    const expected = createHash('sha512')
      .update(Buffer.concat([Buffer.from('kemlock/v1/fingerprint'), Buffer.from(bundle)]))
      .digest();
    expect(Buffer.from(await fingerprintBytes(bundle)).equals(expected)).toBe(true);
  });

  it('show 12 groups of 5 digits, u40be mod 100000 each', () => {
    const bytes = new Uint8Array(64);
    bytes.set([0, 0, 0, 0, 1], 0);
    bytes.set([0xff, 0xff, 0xff, 0xff, 0xff], 5);
    const text = fingerprintText(bytes);
    const groups = text.split(' ');
    expect(groups).toHaveLength(12);
    expect(groups[0]).toBe('00001');
    expect(groups[1]).toBe(String(1099511627775 % 100000).padStart(5, '0'));
    for (const group of groups) expect(group).toMatch(/^\d{5}$/);
  });

  it('turn a UUID into its 16 bytes', () => {
    expect(Array.from(uuidBytes('00112233-4455-6677-8899-aabbccddeeff'))).toEqual([
      0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    ]);
    expect(() => uuidBytes('nope')).toThrow();
  });

  it('are fingerprinted from the worker and the bytes, and a disagreement is flagged', async () => {
    const bundle = makeBundle();
    const own = fingerprintText(await fingerprintBytes(bundle));
    const agree = await checkedFingerprint(bundle, async () => own);
    expect(agree?.consistent).toBe(true);
    expect(agree?.bytes).toHaveLength(64);
    const differ = await checkedFingerprint(bundle, async () => '00000 '.repeat(12).trim());
    expect(differ?.consistent).toBe(false);
    expect(await checkedFingerprint(new Uint8Array(3), async () => '')).toBeNull();
  });
});
