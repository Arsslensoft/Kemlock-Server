import { createDevicesApi } from '@/api/devices';
import { clearCopiedSecret } from '@/lib/clipboard';
import { clearVault } from '@/features/vault/hooks';
import { vaultCrypto } from '@/crypto-port';
import { forgetGrant } from '@/features/admin/reauth';
import { api, queryClient, session } from './services';

const devicesApi = createDevicesApi(api);

/** How long signing out waits for the server before it ends the session here regardless. */
export const SERVER_SIGN_OUT_MS = 3000;

/** Cached answers that hold no secret and that routing needs before anyone is signed in. */
const KEPT_QUERIES = new Set(['config', 'placement']);

/** Drops every cached answer that may hold decrypted data (items, spaces, Sends, settings). */
function forgetCachedData(): void {
  queryClient.removeQueries({
    predicate: (query) => !KEPT_QUERIES.has(String(query.queryKey[0])),
  });
}

/** Forgets the keys but keeps the tokens: the master password opens the vault again. */
export async function lockVault(): Promise<void> {
  // First, so that nothing syncs the vault while the keys go.
  session.locked();
  // A password or code copied from the vault does not stay on the clipboard of a locked one.
  void clearCopiedSecret();
  await vaultCrypto.lock();
  clearVault();
  forgetCachedData();
  // An admin step-up stays with the keys: locking drops it too.
  forgetGrant();
}

/**
 * The server ended the session (the refresh token was refused): the page still holds the last
 * user's decrypted items, and the next sign-in in this tab must not see them.
 */
export function forgetEndedSession(): void {
  void clearCopiedSecret();
  clearVault();
  forgetCachedData();
  forgetGrant();
}

/**
 * Ends this device's session on the server, so its refresh token stops working, not just here.
 * Best effort: a server that is out of reach, slow, or has ended the session already does not hold
 * the sign-out up.
 */
async function endOnServer(deviceId: string): Promise<void> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    await Promise.race([
      devicesApi.signOut(deviceId),
      new Promise<void>((resolve) => {
        timer = setTimeout(resolve, SERVER_SIGN_OUT_MS);
      }),
    ]);
  } catch {
    // The tokens are forgotten here either way.
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Ends the session on the server, then forgets the keys and the tokens, and this browser's own keys
 * with them: the DPoP key the tokens were bound to, and the trusted-device key (the server drops
 * this device's copy of the root key when it signs the device out, so that key only opens what is
 * already dead). The next sign-in makes new ones. With `server: false` the server is not asked, for
 * callers that have just had the server end this session (leaving a browser from Devices, an
 * account erased).
 */
export async function signOut(options: { server?: boolean } = {}): Promise<void> {
  void clearCopiedSecret();
  const { deviceId, status } = session.getState();
  // First, while the tokens and the DPoP key still work. Not when the server has just ended it
  // (this device signed itself out, or the account was erased).
  if (options.server !== false && deviceId && status !== 'signed-out') await endOnServer(deviceId);
  await vaultCrypto.lock();
  clearVault();
  session.end();
  await Promise.all([vaultCrypto.dpopReset(), vaultCrypto.deviceCopyReset()]).catch(() => undefined);
  forgetGrant();
  queryClient.clear();
}
