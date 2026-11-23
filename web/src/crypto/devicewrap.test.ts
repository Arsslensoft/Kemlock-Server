// @vitest-environment node
import { describe, expect, it } from 'vitest';
import { createDeviceWrap, deviceWrapAad } from './devicewrap';
import type { DeviceKeyStore } from './keystore';

const ACCOUNT = '11111111-1111-4111-8111-111111111111';
const DEVICE = '22222222-2222-4222-8222-222222222222';

/** A UUID's 16 bytes, in the order docs/crypto.md writes them. */
function hexBytes(uuid: string): number[] {
  return (uuid.replace(/-/g, '').match(/../g) ?? []).map((h) => parseInt(h, 16));
}

function memory(): { store: DeviceKeyStore; held: () => CryptoKey | undefined } {
  let key: CryptoKey | undefined;
  return {
    store: {
      load: async () => key,
      save: async (k) => {
        key = k;
      },
      clear: async () => {
        key = undefined;
      },
    },
    held: () => key,
  };
}

const root = () => new Uint8Array(64).fill(7);

describe('the trusted-device copy of the root key', () => {
  it('is 0x01 0x03, a nonce, and the root key sealed under a key nobody can read', async () => {
    const { store, held } = memory();
    const wrap = createDeviceWrap({ store });
    const sealed = await wrap.seal(root(), ACCOUNT, DEVICE, 1);
    expect(sealed.length).toBe(2 + 12 + 64 + 16);
    expect([sealed[0], sealed[1]]).toEqual([1, 3]);
    expect(held()?.extractable).toBe(false);
    await expect(crypto.subtle.exportKey('raw', held() as CryptoKey)).rejects.toThrow();
    expect([...(await wrap.open(sealed, ACCOUNT, DEVICE, 1))]).toEqual([...root()]);
  });

  it('opens only for its own account, device and key version', async () => {
    const { store } = memory();
    const wrap = createDeviceWrap({ store });
    const sealed = await wrap.seal(root(), ACCOUNT, DEVICE, 1);
    await expect(wrap.open(sealed, DEVICE, DEVICE, 1)).rejects.toMatchObject({ code: 'invalid' });
    await expect(wrap.open(sealed, ACCOUNT, ACCOUNT, 1)).rejects.toMatchObject({ code: 'invalid' });
    await expect(wrap.open(sealed, ACCOUNT, DEVICE, 2)).rejects.toMatchObject({ code: 'invalid' });
    const altered = sealed.slice();
    altered[20] = (altered[20] ?? 0) ^ 1;
    await expect(wrap.open(altered, ACCOUNT, DEVICE, 1)).rejects.toMatchObject({ code: 'invalid' });
  });

  it('is not ours when it is another platform, or when the key is gone', async () => {
    const { store } = memory();
    const wrap = createDeviceWrap({ store });
    const sealed = await wrap.seal(root(), ACCOUNT, DEVICE, 1);
    const android = sealed.slice();
    android[1] = 2;
    await expect(wrap.open(android, ACCOUNT, DEVICE, 1)).rejects.toMatchObject({ code: 'invalid' });
    await wrap.reset();
    await expect(wrap.open(sealed, ACCOUNT, DEVICE, 1)).rejects.toMatchObject({ code: 'invalid' });
  });

  it('binds the label, the two ids and the key version, as docs/crypto.md says', () => {
    const aad = deviceWrapAad(ACCOUNT, DEVICE, 258);
    const label = new TextEncoder().encode('kemlock/v1/root-wrap/device');
    expect(new TextDecoder().decode(aad.slice(0, label.length))).toBe('kemlock/v1/root-wrap/device');
    expect([...aad.slice(label.length, label.length + 16)]).toEqual(hexBytes(ACCOUNT));
    expect([...aad.slice(label.length + 16, label.length + 32)]).toEqual(hexBytes(DEVICE));
    expect([...aad.slice(label.length + 32)]).toEqual([0, 0, 1, 2]);
  });
});
