// This browser's trusted-device copy of the root key (docs/crypto.md, "The trusted-device copy of
// the root key"). No React in here, so it is tested with fakes.
//
//   trust:  the worker seals the open account's root key under a non-extractable key of this browser,
//           and the server keeps the blob (PUT /kem/v1/devices/key-copy);
//   unlock: after a sign-in with no password, the blob comes back (GET) and the worker opens it, which
//           it can only do in this browser, for this account, device and key version.
//
// A sign-in on a browser with no copy, or one the server no longer holds, or one that does not open
// (another browser's, a replaced key), just returns false: the caller asks another device.
import type { DevicesApi } from '@/api/devices';
import type { Api } from '@/api/client';
import type { Session } from '@/app/session';
import type { CryptoPort } from '@/crypto-port';
import { decodeB64, encodeB64 } from '@/lib/b64url';

export interface TrustedDeviceDeps {
  devices: Pick<DevicesApi, 'keyCopy' | 'putKeyCopy'>;
  api: Pick<Api, 'accountKeys'>;
  crypto: Pick<CryptoPort, 'deviceCopyOpen' | 'deviceCopySeal' | 'unlockWithRoot' | 'release'>;
  session: Session;
}

/** Keeps this browser's copy of the open account's root key on the server. */
export async function trustThisBrowser(deps: TrustedDeviceDeps, keyVersion: number): Promise<void> {
  const { userId, deviceId } = deps.session.getState();
  if (!userId || !deviceId) throw new Error('nobody is signed in');
  const copy = await deps.crypto.deviceCopySeal(userId, deviceId, keyVersion);
  await deps.devices.putKeyCopy({ wrappedKey: encodeB64(copy), protection: 'web-crypto', keyVersion });
}

/** Opens the vault with this browser's copy; false when it has none that opens. */
export async function unlockWithTrustedDevice(deps: TrustedDeviceDeps): Promise<boolean> {
  const { userId, deviceId } = deps.session.getState();
  if (!userId || !deviceId) return false;
  let root: Uint8Array | undefined;
  try {
    const copy = await deps.devices.keyCopy();
    if (!copy) return false;
    const keys = await deps.api.accountKeys();
    root = await deps.crypto.deviceCopyOpen(userId, deviceId, keys.keyVersion, decodeB64(copy.wrappedKey));
    await deps.crypto.unlockWithRoot(userId, root, {
      keyVersion: keys.keyVersion,
      ...(keys.sealedPrivateKeys ? { sealedPrivateKeys: decodeB64(keys.sealedPrivateKeys) } : {}),
    });
    root = undefined;
  } catch {
    if (root) await deps.crypto.release(root).catch(() => undefined);
    return false;
  }
  deps.session.unlocked();
  return true;
}
