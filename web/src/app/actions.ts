import { createDevicesApi } from '@/api/devices';
import { clearCopiedSecret } from '@/lib/clipboard';
import { forgetLoaded } from './forget';
import { vaultCrypto } from '@/crypto-port';
import { forgetGrant } from '@/features/admin/reauth';
import { api, queryClient, session } from './services';

const devicesApi = createDevicesApi(api);

/** How long signing out waits for the server before it ends the session here regardless. */
export const SERVER_SIGN_OUT_MS = 3000;

/** How many times the sign-out request is sent when it fails, and the pause between them. */
const SIGN_OUT_ATTEMPTS = 3;
const SIGN_OUT_RETRY_MS = 800;

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
  forgetLoaded();
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
  forgetLoaded();
  forgetCachedData();
  forgetGrant();
}

/**
 * Ends this device's session on the server, so its refresh token stops working, not just here. The
 * device and its trusted-device key copy stay on the server: for an account with no password that
 * copy is the only way back into the vault. Best effort: a server that is out of reach, slow, or
 * has ended the session already does not hold the sign-out up.
 */
async function endOnServer(): Promise<void> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  // A request that fails early (a dropped connection) is sent again while the wait lasts, and one
  // that is only slow is left running when the wait ends, so it still reaches the server after
  // the tokens are gone here. The refresh token is revoked by whichever gets there.
  const attempts = (async () => {
    for (let attempt = 0; attempt < SIGN_OUT_ATTEMPTS; attempt += 1) {
      try {
        await devicesApi.endSession();
        return;
      } catch {
        if (attempt + 1 < SIGN_OUT_ATTEMPTS) {
          await new Promise<void>((resolve) => setTimeout(resolve, SIGN_OUT_RETRY_MS));
        }
      }
    }
  })();
  try {
    await Promise.race([
      attempts,
      new Promise<void>((resolve) => {
        timer = setTimeout(resolve, SERVER_SIGN_OUT_MS);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Ends the session on the server, then forgets the keys and the tokens. The browser's DPoP key and
 * trusted-device key are left alone: they are shared by every account and every tab of this
 * browser, so resetting them would sign other tabs out and break other accounts' trusted copies
 * (the server unbinds this device's DPoP key when it ends the session). The tab's own reload key
 * goes with the session. With `server: false` the server is not asked, for callers that have just
 * had the server end this session (a device removed from Devices, an account erased).
 */
export async function signOut(options: { server?: boolean } = {}): Promise<void> {
  void clearCopiedSecret();
  // First, while the tokens and the DPoP key still work. Not when the server has just ended it
  // (this device was removed from Devices, or the account was erased).
  if (options.server !== false && session.getState().status !== 'signed-out') await endOnServer();
  await vaultCrypto.lock();
  forgetLoaded();
  session.end();
  forgetGrant();
  queryClient.clear();
}
