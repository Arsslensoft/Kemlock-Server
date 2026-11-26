// Keeping a closed tab's reload copy from outliving the tab (see session.ts, the header).
//
// Each tab seals its session under a key of its own, in IndexedDB. A page that is open says so every
// few seconds (`touchTabKey`) and holds a Web Lock named for its tab, so another tab's cleanup can
// tell a tab that is open but throttled from one that is gone. The first thing every page load does
// is delete the keys whose page has been silent for longer than a reload takes and whose lock is
// not held: the blobs they sealed, still in a closed tab's `sessionStorage`, stop opening.
import { purgeTabKeys, touchTabKey } from '@/crypto/keystore';
import { RELOAD_WINDOW_MS, type Session } from './session';

/** How often an open page stamps its tab key. */
export const TAB_HEARTBEAT_MS = 4_000;

/** A tab key whose page has been silent this long, and holds no lock, is a closed tab's. */
export const TAB_KEY_MAX_AGE_MS = RELOAD_WINDOW_MS + TAB_HEARTBEAT_MS;

const LOCK_PREFIX = 'kemlock-tab:';

/** The part of `LockManager` this module uses, so tests can pass a fake. */
export interface TabLocks {
  request(name: string, callback: () => Promise<unknown>): Promise<unknown>;
  query(): Promise<{ held?: ReadonlyArray<{ name?: string | undefined }> | undefined }>;
}

function browserLocks(): TabLocks | undefined {
  try {
    return typeof navigator !== 'undefined' && navigator.locks ? navigator.locks : undefined;
  } catch {
    return undefined;
  }
}

/** Whether some page holds the tab's lock, that is, the tab is open. */
export async function tabIsOpen(tabId: string, locks: TabLocks | undefined = browserLocks()): Promise<boolean> {
  if (!locks) return false;
  try {
    const { held } = await locks.query();
    return (held ?? []).some((lock) => lock.name === `${LOCK_PREFIX}${tabId}`);
  } catch {
    return false;
  }
}

/** Deletes the reload keys of closed tabs. Run before anything else on every page load; never throws. */
export async function purgeClosedTabKeys(now: number = Date.now()): Promise<void> {
  try {
    await purgeTabKeys({ now, maxAgeMs: TAB_KEY_MAX_AGE_MS, isOpen: (tabId) => tabIsOpen(tabId) });
  } catch {
    // IndexedDB is blocked or broken: nothing to purge, and nothing the keys could have sealed either.
  }
}

const held = new Set<string>();

/** Holds the lock for the tab until this page goes away. */
function holdTabLock(tabId: string, locks: TabLocks | undefined): void {
  if (!locks || held.has(tabId)) return;
  held.add(tabId);
  // The callback's promise never settles: the lock lasts as long as the page does.
  void locks.request(`${LOCK_PREFIX}${tabId}`, () => new Promise<never>(() => undefined)).catch(() => undefined);
}

/**
 * While this page is open, keeps its tab's key marked as in use. Returns the function that stops it.
 * Starts only once, at start-up; it follows the session's tab id as that changes at sign-in.
 */
export function keepTabKeyAlive(
  session: Pick<Session, 'currentTab'>,
  options: {
    locks?: TabLocks | undefined;
    now?: () => number;
    every?: number;
    touch?: (tabId: string, now: number) => Promise<void>;
  } = {},
): () => void {
  const locks = 'locks' in options ? options.locks : browserLocks();
  const now = options.now ?? (() => Date.now());
  const touch = options.touch ?? ((tabId: string, at: number) => touchTabKey(tabId, at));
  const beat = () => {
    const tabId = session.currentTab();
    if (!tabId) return;
    holdTabLock(tabId, locks);
    void touch(tabId, now()).catch(() => undefined);
  };
  const timer = setInterval(beat, options.every ?? TAB_HEARTBEAT_MS);
  beat();
  return () => clearInterval(timer);
}
