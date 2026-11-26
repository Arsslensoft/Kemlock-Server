// A one-time clean-up for browsers that used an earlier version of the web vault.
//
// That version sealed the reload copy of the open vault under the trusted-device key, a long-lived
// non-extractable key in IndexedDB that every user got, whether or not they ever chose to trust the
// browser. Tabs closed under it may still hold a root key sealed with it in their `sessionStorage`
// (the browser keeps that for session restore), and it would still open. The reload copy now has a
// key of its own (tabKey.ts), and this resets the old one, once per browser, for a person who has no
// trusted-device copy on the server: nothing legitimate needs the key then. The first time there is a
// session to ask the server with, it asks `GET /kem/v1/devices/key-copy`; a 404 (no copy) resets the
// key, an answer with a copy keeps it, and an error tries again at the next sign-in.
//
// The key is the browser's, shared by every account that signs in here, so this resets it on the word
// of the account that happens to be signed in first. Another account's trusted copy on this browser
// would then ask another device to approve once. That is the price of closing the old copies, and
// only a browser that was already in use before this version is asked (a fresh one never had them).
import type { Session } from './session';
import type { DevicesApi } from '@/api/devices';
import type { CryptoPort } from '@/crypto-port';

const DONE_KEY = 'kemlock.deviceKey.checked';

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
export function startDeviceKeyCleanup(deps: {
  session: Pick<Session, 'getState' | 'subscribe'>;
  devices: Pick<DevicesApi, 'keyCopy'>;
  crypto: Pick<CryptoPort, 'deviceCopyReset'>;
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
    // A browser nobody has signed in on has no old copies to close.
    done();
    return () => undefined;
  }

  let running = false;
  let finished = false;
  async function check(): Promise<void> {
    if (running || finished || deps.session.getState().status === 'signed-out') return;
    running = true;
    try {
      const copy = await deps.devices.keyCopy();
      if (copy === null) await deps.crypto.deviceCopyReset();
      finished = true;
      done();
    } catch {
      // The server or the key store did not answer: the next sign-in asks again.
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
