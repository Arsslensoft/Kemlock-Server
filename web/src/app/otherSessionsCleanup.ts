// A one-time clean-up for browsers that used an earlier version of the web vault.
//
// That version kept the session tokens in the clear in `sessionStorage`, and a root key sealed under
// the browser's shared trusted-device key. The browser keeps a closed tab's `sessionStorage` for
// session restore, so such a tab may still hold a refresh token that works. This revokes it: the
// first time this version has a session (a sign-in, or a restore of a reloaded tab), it asks the
// server to end this device's other sessions and keep the one it is in (`POST /kem/v1/auth/sign-out`
// with `{"others": true}`), once per browser. The tokens an old closed tab holds then stop working,
// and what is left of such a tab (a root sealed under the shared key) opens, but with no live token
// it can fetch nothing: the web vault keeps no vault data in the browser (no service worker, Cache
// API or stored query cache; IndexedDB holds only keys), so there is no ciphertext on this side to
// decrypt either.
//
// The device, its key copy and its DPoP key stay, and so do the trusted-device key and the other
// accounts that sign in here. Another tab of the same browser that is signed in on its own session
// is ended too, once. A browser that nobody had signed in on has nothing old to revoke and is left
// alone.
import type { DevicesApi } from '@/api/devices';
import type { Session } from './session';

const DONE_KEY = 'kemlock.otherSessions.ended';

/** The part of `Storage` this module uses, so tests can pass a fake. */
export type CleanupStorage = Pick<Storage, 'getItem' | 'setItem'>;

function browserStorage(): CleanupStorage | undefined {
  try {
    return window.localStorage;
  } catch {
    return undefined;
  }
}

/**
 * Starts the clean-up if this browser has not had it. Returns the function that stops it.
 * `usedBefore` says whether this browser has been signed in to before (it remembers a device id).
 */
export function startOtherSessionsCleanup(deps: {
  session: Pick<Session, 'getState' | 'subscribe'>;
  devices: Pick<DevicesApi, 'endOtherSessions'>;
  usedBefore: boolean;
  storage?: CleanupStorage | undefined;
}): () => void {
  const storage = 'storage' in deps ? deps.storage : browserStorage();
  const done = () => {
    try {
      storage?.setItem(DONE_KEY, '1');
    } catch {
      // Asked again next time.
    }
  };
  try {
    if (storage?.getItem(DONE_KEY) === '1') return () => undefined;
  } catch {
    // Unreadable: carry on, and ask again.
  }
  if (!deps.usedBefore) {
    done();
    return () => undefined;
  }

  let running = false;
  let finished = false;
  async function check(): Promise<void> {
    if (running || finished || deps.session.getState().status === 'signed-out') return;
    running = true;
    try {
      await deps.devices.endOtherSessions();
      finished = true;
      done();
    } catch {
      // The server did not answer: the next sign-in or restore asks again.
    } finally {
      running = false;
    }
  }
  const stop = deps.session.subscribe(() => void check());
  void check();
  return () => {
    stop();
    finished = true;
  };
}
