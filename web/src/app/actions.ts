import { type Tokens, createApi } from '@/api/client';
import { createDevicesApi } from '@/api/devices';
import { ApiError } from '@/api/errors';
import { clearCopiedSecret } from '@/lib/clipboard';
import { forgetLoaded } from './forget';
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

/** How long, after each failure, signing out waits before it asks the server to end the session again. */
export const REVOKE_RETRY_MS: readonly number[] = [5_000, 20_000, 60_000, 300_000, 900_000];

/** Whether a failed sign-out call may work later: the network or the server, not an answer. */
function worthRetrying(error: unknown): boolean {
  if (error instanceof ApiError) return error.status >= 500 || error.status === 408 || error.status === 429;
  return true;
}

/**
 * Keeps asking the server to end a session after the person was signed out here without it
 * answering: until one try works, the server refuses (the session is gone or never was), or the
 * delays run out. Only a page that stays open can do this; the tokens it holds are in this closure
 * and nowhere else.
 */
export function keepRevoking(attempt: () => Promise<unknown>, delays: readonly number[] = REVOKE_RETRY_MS): void {
  const [next, ...rest] = delays;
  if (next === undefined) return;
  setTimeout(() => {
    attempt().catch((error: unknown) => {
      if (worthRetrying(error)) keepRevoking(attempt, rest);
    });
  }, next);
}

/**
 * Retries the sign-out call over a client of its own, which holds the session's tokens as they were
 * when the person signed out: the page's client forgets them in the same moment.
 */
function revokeInBackground(held: Tokens | undefined): void {
  if (!held) return;
  let tokens: Tokens | undefined = held;
  const detached = createApi({
    origin: window.location.origin,
    tokens: {
      get: () => tokens,
      set: (next) => {
        tokens = next;
      },
      clear: () => {
        tokens = undefined;
      },
    },
    dpop: (htm, htu, nonce, accessToken) => vaultCrypto.dpopProof(htm, htu, nonce, accessToken),
    onSessionEnded: () => {
      tokens = undefined;
    },
  });
  const devices = createDevicesApi(detached);
  // The server refused the refresh token, or the tokens were dropped: nothing is left to end.
  keepRevoking(() => (tokens ? devices.endSession() : Promise.resolve()));
}

/**
 * Ends this device's session on the server, so its refresh token stops working, not just here. The
 * device and its trusted-device key copy stay on the server: for an account with no password that
 * copy is the only way back into the vault. A server that is out of reach, slow, or has ended the
 * session already does not hold the sign-out up; when it was out of reach or too slow, the call is
 * tried again in the background, so the refresh token does not stay valid on the server.
 */
async function endOnServer(): Promise<void> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const held = session.tokenStore.get();
  const first = devicesApi.endSession();
  try {
    const timedOut = await Promise.race([
      first.then(() => false),
      new Promise<boolean>((resolve) => {
        timer = setTimeout(() => resolve(true), SERVER_SIGN_OUT_MS);
      }),
    ]);
    // Too slow: it may still arrive, or hang for good, so it is also tried again in the background.
    // A try that finds the session already ended is answered with a refusal, and that stops it.
    if (timedOut) revokeInBackground(held);
  } catch (error) {
    // The tokens are forgotten here either way.
    if (worthRetrying(error)) revokeInBackground(held);
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
