// The first sign-in of an account single sign-on made: it has no keys, so this device makes them.
// No React in here, so it is tested with fakes.
//
//   1. the worker makes the root key, the key pairs, the signed bundle and the sealed private keys
//      (no password, so no password wrap) and holds the vault open;
//   2. it seals this browser's copy of the root key under the key only this browser holds;
//   3. the server stores the lot (POST /kem/v1/account/keys/enrol) and refuses once keys exist.
//
// Nothing but the sealed copy leaves the worker. If the server refuses or fails, the vault is shut
// and the session ended: an account with keys the server does not have must not look signed in.
import type { KeysApi } from '@/api/keys';
import type { Session } from '@/app/session';
import type { CryptoPort } from '@/crypto-port';
import { encodeB64 } from '@/lib/b64url';

export interface EnrolKeysDeps {
  keys: KeysApi;
  crypto: Pick<CryptoPort, 'newSsoAccount' | 'deviceCopySeal' | 'lock'>;
  session: Session;
}

/** The first key version of an account. */
const FIRST_KEY_VERSION = 1;

/** Makes and stores the signed-in account's keys, and opens the vault with them. */
export async function enrolNewAccountKeys(deps: EnrolKeysDeps): Promise<void> {
  const { userId, deviceId } = deps.session.getState();
  if (!userId || !deviceId) throw new Error('nobody is signed in');
  try {
    const made = await deps.crypto.newSsoAccount(userId);
    const copy = await deps.crypto.deviceCopySeal(userId, deviceId, FIRST_KEY_VERSION);
    await deps.keys.enrol({
      publicBundle: encodeB64(made.publicBundle),
      bundleSignature: encodeB64(made.bundleSignature),
      sealedPrivateKeys: encodeB64(made.sealedPrivateKeys),
      deviceCopy: { wrappedKey: encodeB64(copy), protection: 'web-crypto' },
    });
  } catch (error) {
    await deps.crypto.lock().catch(() => undefined);
    deps.session.end();
    throw error;
  }
  deps.session.unlocked();
}
