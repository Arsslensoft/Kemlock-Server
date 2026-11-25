// This browser's copy of the root key (docs/crypto.md, "The trusted-device copy of the root key",
// platform byte 0x03, WebCrypto):
//
//   u8(1), u8(3), nonce(12), AES-256-GCM(non-extractable key, nonce, root key, aad), tag(16)
//   aad = "kemlock/v1/root-wrap/device", account id (16), device id (16), u32be(key version)
//
// The AES key is made here, non-extractable, and kept in IndexedDB as a key object: nothing, this
// script included, can read its bytes, so the copy the server keeps (PUT /kem/v1/devices/key-copy)
// opens only in this browser. The root key passes through this module inside the worker and is
// wiped after use; the page receives only the sealed copy.
import type { DeviceKeyStore } from './keystore';
import { CryptoError } from './types';

const AAD_LABEL = 'kemlock/v1/root-wrap/device';
const VERSION = 1;
const PLATFORM_WEBCRYPTO = 3;
const NONCE_LEN = 12;
const TAG_LEN = 16;

export interface DeviceWrap {
  seal(root: Uint8Array, accountId: string, deviceId: string, keyVersion: number): Promise<Uint8Array>;
  open(sealed: Uint8Array, accountId: string, deviceId: string, keyVersion: number): Promise<Uint8Array>;
  /** Forgets the key: every copy made with it stops opening (this browser is no longer trusted). */
  reset(): Promise<void>;
}

export interface DeviceWrapDeps {
  store: DeviceKeyStore;
  subtle?: SubtleCrypto;
  random?: (bytes: Uint8Array<ArrayBuffer>) => Uint8Array<ArrayBuffer>;
}

function uuidBytes(text: string): Uint8Array {
  const hex = text.replace(/-/g, '');
  if (!/^[0-9a-fA-F]{32}$/.test(hex)) throw new CryptoError('invalid');
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i += 1) out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** The additional data a copy binds: the account, the device and the key version. */
export function deviceWrapAad(
  accountId: string,
  deviceId: string,
  keyVersion: number,
): Uint8Array<ArrayBuffer> {
  const label = new TextEncoder().encode(AAD_LABEL);
  const out = new Uint8Array(label.length + 36);
  out.set(label, 0);
  out.set(uuidBytes(accountId), label.length);
  out.set(uuidBytes(deviceId), label.length + 16);
  new DataView(out.buffer).setUint32(label.length + 32, keyVersion);
  return out;
}

export function createDeviceWrap(deps: DeviceWrapDeps): DeviceWrap {
  const subtle = deps.subtle ?? crypto.subtle;
  const random = deps.random ?? ((bytes) => crypto.getRandomValues(bytes));

  async function key(make: boolean): Promise<CryptoKey | undefined> {
    const held = await deps.store.load();
    if (held || !make) return held;
    const fresh = await subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    // Another tab may have made its key since the load: its key stays, and ours is thrown away,
    // or whichever put came last would win and the other tab's copies would stop opening.
    if (await deps.store.add(fresh)) return fresh;
    const winner = await deps.store.load();
    if (!winner) throw new CryptoError('unavailable');
    return winner;
  }

  return {
    async seal(root, accountId, deviceId, keyVersion) {
      const aes = await key(true);
      if (!aes) throw new CryptoError('unavailable');
      const nonce = random(new Uint8Array(NONCE_LEN));
      const sealed = new Uint8Array(
        await subtle.encrypt(
          { name: 'AES-GCM', iv: nonce, additionalData: deviceWrapAad(accountId, deviceId, keyVersion) },
          aes,
          root as Uint8Array<ArrayBuffer>,
        ),
      );
      const out = new Uint8Array(2 + NONCE_LEN + sealed.length);
      out[0] = VERSION;
      out[1] = PLATFORM_WEBCRYPTO;
      out.set(nonce, 2);
      out.set(sealed, 2 + NONCE_LEN);
      return out;
    },
    async open(sealed, accountId, deviceId, keyVersion) {
      // Another version or another platform's copy is not ours to open.
      if (
        sealed.length < 2 + NONCE_LEN + TAG_LEN ||
        sealed[0] !== VERSION ||
        sealed[1] !== PLATFORM_WEBCRYPTO
      ) {
        throw new CryptoError('invalid');
      }
      const aes = await key(false);
      if (!aes) throw new CryptoError('invalid');
      try {
        return new Uint8Array(
          await subtle.decrypt(
            {
              name: 'AES-GCM',
              iv: sealed.slice(2, 2 + NONCE_LEN),
              additionalData: deviceWrapAad(accountId, deviceId, keyVersion),
            },
            aes,
            sealed.slice(2 + NONCE_LEN),
          ),
        );
      } catch {
        throw new CryptoError('invalid');
      }
    },
    reset: () => deps.store.clear(),
  };
}
