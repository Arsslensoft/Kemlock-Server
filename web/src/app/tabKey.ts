// Keeping a closed tab's reload copy from outliving the tab (see session.ts, the header).
//
// Each tab seals its session under a key of its own, in IndexedDB. A page that is open says so every
// few seconds (`touchTabKey`) and holds a Web Lock named for its tab, so another tab's cleanup can
// tell a tab that is open but throttled from one that is gone. The first thing every page load does
// is delete the keys whose page has been silent for longer than a reload takes and whose lock is
// not held: the blobs they sealed, still in a closed tab's `sessionStorage`, stop opening. Every
// open vault page does the same on each heartbeat, so a closed tab's key also dies while another
// tab is open.
//
// What this does not stop: someone with the browser's developer tools on this origin. They can keep
// stamping a closed tab's key from any page of the origin (the stamp is not a secret), then open the
// tab's storage with the app script blocked and use the key. The tab key is a defence against a
// later user of the profile who only has the files or the browser's session restore, not against a
// script running on the origin. A closed tab leaves that window open for as long as the attacker
// keeps stamping, and no longer than a reload takes (plus one heartbeat) if they do not.
import { purgeTabKeys, touchTabKey } from '@/crypto/keystore';
import { RELOAD_WINDOW_MS, type Session } from './session';

/** How often an open page stamps its tab key. */
export const TAB_HEARTBEAT_MS = 4_000;

/** A tab key whose page has been silent this long, and holds no lock, is a closed tab's. */
export const TAB_KEY_MAX_AGE_MS = RELOAD_WINDOW_MS + TAB_HEARTBEAT_MS;

/** How long a page load waits for the purge before it gives up on restoring a session. */
export const PURGE_TIMEOUT_MS = 3_000;

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
    const { held: locked } = await locks.query();
    return (locked ?? []).some((lock) => lock.name === `${LOCK_PREFIX}${tabId}`);
  } catch {
    return false;
  }
}

/**
 * Deletes the reload keys of closed tabs. Run before anything else on every page load. True when it
 * finished (an IndexedDB that fails outright counts: nothing could open a key there either), false
 * when it did not finish in `timeoutMs`: a hung IndexedDB, and then the caller must not restore a
 * session whose key might be a closed tab's.
 */
export async function purgeClosedTabKeys(
  options: { now?: number; timeoutMs?: number; run?: (now: number) => Promise<void> } = {},
): Promise<boolean> {
  const now = options.now ?? Date.now();
  const run =
    options.run ??
    ((at: number) => purgeTabKeys({ now: at, maxAgeMs: TAB_KEY_MAX_AGE_MS, isOpen: (tabId) => tabIsOpen(tabId) }));
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<'timeout'>((resolve) => {
    timer = setTimeout(() => resolve('timeout'), options.timeoutMs ?? PURGE_TIMEOUT_MS);
  });
  try {
    const outcome = await Promise.race([
      run(now).then(
        () => 'done' as const,
        () => 'done' as const,
      ),
      timeout,
    ]);
    return outcome === 'done';
  } finally {
    clearTimeout(timer);
  }
}

/** The tabs this page holds a lock for, each with what lets the lock go. */
const held = new Map<string, () => void>();

/** Holds the lock for the tab until `releaseTabLocks` or until this page goes away. */
export function holdTabLock(tabId: string, locks: TabLocks | undefined = browserLocks()): void {
  if (!locks || held.has(tabId)) return;
  let release: () => void = () => undefined;
  const hold = new Promise<void>((resolve) => {
    release = resolve;
  });
  held.set(tabId, release);
  void locks.request(`${LOCK_PREFIX}${tabId}`, () => hold).catch(() => held.delete(tabId));
}

/**
 * Lets this page's locks go. A page that holds a Web Lock may be kept out of the back/forward
 * cache, so they go when the page is hidden for good (`pagehide`) and come back with it
 * (`pageshow`). A tab whose page is gone is purged like a closed one, which is what it is.
 */
export function releaseTabLocks(): void {
  for (const release of held.values()) release();
  held.clear();
}

/**
 * Says this tab is open and its key in use, from the moment a restore has opened it: before the
 * restore's network call, so a slow server does not leave a key another page's cleanup may take.
 */
export async function claimTabKey(
  tabId: string,
  options: {
    locks?: TabLocks | undefined;
    now?: () => number;
    touch?: (tabId: string, now: number) => Promise<void>;
  } = {},
): Promise<void> {
  const locks = 'locks' in options ? options.locks : browserLocks();
  holdTabLock(tabId, locks);
  const touch = options.touch ?? ((id: string, at: number) => touchTabKey(id, at));
  await touch(tabId, (options.now ?? (() => Date.now()))());
}

/**
 * While this page is open, keeps its tab's key marked as in use, and deletes the keys of closed
 * tabs each time (so a closed tab's key dies while any vault page is open, not only at the next
 * load). Returns the function that stops it. Starts only once, at start-up; it follows the session's
 * tab id as that changes at sign-in. The locks go on `pagehide` and come back on `pageshow` from the
 * back/forward cache, so holding them does not keep the page out of it.
 */
export function keepTabKeyAlive(
  session: Pick<Session, 'currentTab'>,
  options: {
    locks?: TabLocks | undefined;
    now?: () => number;
    every?: number;
    touch?: (tabId: string, now: number) => Promise<void>;
    purge?: () => Promise<unknown>;
  } = {},
): () => void {
  const locks = 'locks' in options ? options.locks : browserLocks();
  const now = options.now ?? (() => Date.now());
  const touch = options.touch ?? ((tabId: string, at: number) => touchTabKey(tabId, at));
  const purge = options.purge ?? (() => purgeClosedTabKeys());
  const beat = () => {
    const tabId = session.currentTab();
    if (!tabId) return;
    holdTabLock(tabId, locks);
    void (async () => {
      // Stamped first, so the cleanup never sees this page's own key as quiet.
      await touch(tabId, now()).catch(() => undefined);
      await purge().catch(() => undefined);
    })();
  };
  const timer = setInterval(beat, options.every ?? TAB_HEARTBEAT_MS);
  const onHide = () => releaseTabLocks();
  const onShow = (event: Event) => {
    if ((event as PageTransitionEvent).persisted) beat();
  };
  window.addEventListener('pagehide', onHide);
  window.addEventListener('pageshow', onShow);
  beat();
  return () => {
    clearInterval(timer);
    window.removeEventListener('pagehide', onHide);
    window.removeEventListener('pageshow', onShow);
  };
}
