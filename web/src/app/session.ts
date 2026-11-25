// Who is signed in and whether the vault is open, kept for the life of one browser tab.
//
// A reload of the tab must not sign the person out or shut the vault, so this module writes to
// `sessionStorage`, which is private to the tab and gone when the tab closes (never `localStorage`,
// which outlives the tab and is shared by every tab of the origin):
//
//   - the signed-in details (email, name, account, device, admin): nothing secret;
//   - the tokens. They are DPoP-bound to a non-extractable key pair the crypto worker keeps in
//     IndexedDB (src/crypto/dpop.ts), and every call needs a proof signed with that key. A script
//     that reads the tokens out of storage, or a person who copies them, cannot use them anywhere
//     but this browser profile. The key pair outlives a reload, so the same tokens stay valid;
//   - this browser's sealed copy of the root key, kept while the vault is open (src/app/persistence.ts
//     makes it). It is sealed under an AES key that is non-extractable and lives in IndexedDB, so
//     the blob opens only in this browser, for this account and device; only the worker ever holds
//     the opened key.
//
// Locking the vault deletes the sealed copy at once, so a locked vault stays locked after a reload:
// the master password is needed again. Signing out, or the server ending the session, deletes all
// of it. Storage that is missing, blocked or corrupt is treated as empty, so the worst case is the
// old behaviour: a reload signs you out. The keys themselves stay in the crypto worker only.
//
// Only a reload of this very tab may take any of it back. `sessionStorage` is also copied into a
// restored closed tab (Ctrl+Shift+T, "continue where you left off"), a duplicated tab and a window
// opened by this one, and none of those may come back signed in: a closed tab must not reopen with
// the vault open, and two tabs holding one rotating refresh token would have the server's reuse
// detection sign both out. So a page leaving writes `leftAt` (`leaving`), and at start everything
// kept is honoured only when the browser says this load is a reload AND the page left a moment ago
// (RELOAD_WINDOW_MS). Otherwise it is all dropped and signing in is needed. A reload that races a
// token refresh still in flight can lose the new refresh token and end the session; that is the
// price of the single-use refresh token, and the person signs in again.
import { useSyncExternalStore } from 'react';
import type { TokenStore, Tokens } from '@/api/client';

export type SessionStatus = 'signed-out' | 'locked' | 'unlocked';

export interface SessionState {
  status: SessionStatus;
  email: string | null;
  name: string | null;
  userId: string | null;
  deviceId: string | null;
  admin: boolean;
}

export interface SignedInInfo {
  email: string;
  userId: string;
  deviceId: string;
  admin: boolean;
  name?: string | null;
}

/** The part of `Storage` this module uses, so tests can pass a fake. */
export type TabStorage = Pick<Storage, 'getItem' | 'setItem' | 'removeItem'>;

/** This browser's copy of the root key, sealed by the crypto worker, and the key version it binds. */
export interface SealedRoot {
  /** base64url of the sealed blob. */
  sealed: string;
  keyVersion: number;
}

export interface SessionOptions {
  /** Where the session survives a reload; none means it does not. */
  storage?: TabStorage | undefined;
  /** Milliseconds since the epoch. */
  now?: () => number;
  /** How this page was reached: the browser's navigation type ('reload', 'navigate', ...). */
  navigationType?: () => string | undefined;
}

/** How long a page may have been gone and still count as a reload of the same tab. */
export const RELOAD_WINDOW_MS = 10_000;

/** The type of the navigation that loaded this page, when the browser says. */
export function browserNavigationType(): string | undefined {
  try {
    const [entry] = performance.getEntriesByType('navigation') as PerformanceNavigationTiming[];
    return entry?.type;
  } catch {
    return undefined;
  }
}

const INFO_KEY = 'kemlock.session.info';
const TOKENS_KEY = 'kemlock.session.tokens';
const ROOT_KEY = 'kemlock.session.root';
const LEFT_KEY = 'kemlock.session.leftAt';

const SIGNED_OUT: SessionState = {
  status: 'signed-out',
  email: null,
  name: null,
  userId: null,
  deviceId: null,
  admin: false,
};

/** The tab's own storage, or nothing when the browser blocks it. */
export function tabStorage(): TabStorage | undefined {
  try {
    return window.sessionStorage;
  } catch {
    return undefined;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function readTokens(value: unknown): Tokens | undefined {
  if (!isRecord(value)) return undefined;
  const { access, refresh, accessExpiresAt, refreshExpiresAt } = value;
  if (
    typeof access !== 'string' ||
    typeof refresh !== 'string' ||
    typeof accessExpiresAt !== 'number' ||
    typeof refreshExpiresAt !== 'number'
  ) {
    return undefined;
  }
  return { access, refresh, accessExpiresAt, refreshExpiresAt };
}

function readInfo(value: unknown): SignedInInfo | undefined {
  if (!isRecord(value)) return undefined;
  const { email, name, userId, deviceId, admin } = value;
  if (
    typeof email !== 'string' ||
    typeof userId !== 'string' ||
    typeof deviceId !== 'string' ||
    typeof admin !== 'boolean'
  ) {
    return undefined;
  }
  return { email, userId, deviceId, admin, name: typeof name === 'string' ? name : null };
}

function readRoot(value: unknown): SealedRoot | undefined {
  if (!isRecord(value)) return undefined;
  const { sealed, keyVersion } = value;
  if (typeof sealed !== 'string' || sealed === '' || typeof keyVersion !== 'number') return undefined;
  return { sealed, keyVersion };
}

export function createSession(options: SessionOptions = {}) {
  const storage = options.storage;
  const now = options.now ?? (() => Date.now());
  const navigationType = options.navigationType ?? browserNavigationType;
  let state: SessionState = SIGNED_OUT;
  let tokens: Tokens | undefined;
  const listeners = new Set<() => void>();

  function set(next: SessionState): void {
    state = next;
    for (const listener of listeners) listener();
  }

  function write(key: string, value: unknown): void {
    try {
      storage?.setItem(key, JSON.stringify(value));
    } catch {
      // Full or blocked: the session just does not survive a reload.
    }
  }

  function read(key: string): unknown {
    try {
      const text = storage?.getItem(key);
      return text ? (JSON.parse(text) as unknown) : undefined;
    } catch {
      return undefined;
    }
  }

  function remove(...keys: string[]): void {
    for (const key of keys) {
      try {
        storage?.removeItem(key);
      } catch {
        // Nothing to do: the entry stays, and the next restore finds it unusable or ends it.
      }
    }
  }

  const tokenStore: TokenStore = {
    get: () => tokens,
    set: (next) => {
      tokens = next;
      if (state.status === 'signed-out') {
        // A sign-in sets the tokens and calls `signedIn` straight after, which stores them. A
        // refresh that settles after sign-out sets them with nothing following: they must not
        // reach the storage, and are dropped once this turn is over.
        queueMicrotask(() => {
          if (state.status === 'signed-out' && tokens === next) tokens = undefined;
        });
        return;
      }
      write(TOKENS_KEY, next);
    },
    clear: () => {
      tokens = undefined;
      remove(TOKENS_KEY);
    },
  };

  /** The sealed copy of the root key: present only while the vault is open. */
  const sealedRoot = {
    get: (): SealedRoot | undefined => readRoot(read(ROOT_KEY)),
    set: (root: SealedRoot): void => write(ROOT_KEY, root),
    clear: (): void => remove(ROOT_KEY),
  };

  return {
    getState: (): SessionState => state,
    subscribe(listener: () => void): () => void {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    tokenStore,
    sealedRoot,
    /** Tokens are in, the vault is still shut. */
    signedIn(info: SignedInInfo): void {
      // A new sign-in has no open keys yet; whatever copy an earlier one left is not trusted.
      remove(ROOT_KEY);
      if (tokens) write(TOKENS_KEY, tokens);
      const next: SessionState = {
        status: 'locked',
        email: info.email,
        name: info.name ?? state.name,
        userId: info.userId,
        deviceId: info.deviceId,
        admin: info.admin,
      };
      write(INFO_KEY, {
        email: next.email,
        name: next.name,
        userId: next.userId,
        deviceId: next.deviceId,
        admin: next.admin,
      });
      set(next);
    },
    /**
     * The account became an admin in fact: the first admin signs in during setup before any second
     * step is on, so the server's `admin` was false then (an admin without one is not an admin).
     * The server checks again on every request; this only lets the console's routes open.
     */
    adminConfirmed(): void {
      if (state.status === 'signed-out' || state.admin) return;
      const next: SessionState = { ...state, admin: true };
      write(INFO_KEY, {
        email: next.email,
        name: next.name,
        userId: next.userId,
        deviceId: next.deviceId,
        admin: true,
      });
      set(next);
    },
    /** The person changed their name on Profile: the avatar and its menu show the new one. */
    renamed(name: string | null): void {
      if (state.status === 'signed-out') return;
      const next: SessionState = { ...state, name };
      write(INFO_KEY, {
        email: next.email,
        name: next.name,
        userId: next.userId,
        deviceId: next.deviceId,
        admin: next.admin,
      });
      set(next);
    },
    unlocked(): void {
      if (state.status !== 'signed-out') set({ ...state, status: 'unlocked' });
    },
    /**
     * Keys forgotten, tokens kept: the master password opens the vault again. The sealed copy goes
     * too, or a reload would open the vault again without it.
     */
    locked(): void {
      remove(ROOT_KEY);
      if (state.status !== 'signed-out') set({ ...state, status: 'locked' });
    },
    /** Forgets everything, in memory and in the tab's storage. */
    end(): void {
      tokens = undefined;
      remove(INFO_KEY, TOKENS_KEY, ROOT_KEY, LEFT_KEY);
      set(SIGNED_OUT);
    },
    /** The page is going away (`pagehide`): a reload within a few seconds may take the session back. */
    leaving(): void {
      if (state.status !== 'signed-out') write(LEFT_KEY, now());
    },
    /** The page came back from the back/forward cache with its memory intact: no reload follows. */
    returned(): void {
      remove(LEFT_KEY);
    },
    /**
     * Takes back what an earlier page of this tab kept: the tokens and who they belong to, with the
     * vault shut. True when there was a session to take back. Anything missing, corrupt or past
     * its refresh token's life is cleared and counts as signed out, and so is everything when this
     * load is not a reload of this tab that left a moment ago (see the header). Call it once, at start.
     */
    restore(): boolean {
      if (state.status !== 'signed-out') return false;
      const leftAt = read(LEFT_KEY);
      remove(LEFT_KEY);
      const away = typeof leftAt === 'number' ? now() - leftAt : Number.POSITIVE_INFINITY;
      if (navigationType() !== 'reload' || away < 0 || away >= RELOAD_WINDOW_MS) {
        remove(INFO_KEY, TOKENS_KEY, ROOT_KEY);
        return false;
      }
      const info = readInfo(read(INFO_KEY));
      const kept = readTokens(read(TOKENS_KEY));
      if (!info || !kept || kept.refreshExpiresAt <= now()) {
        remove(INFO_KEY, TOKENS_KEY, ROOT_KEY);
        return false;
      }
      tokens = kept;
      set({
        status: 'locked',
        email: info.email,
        name: info.name ?? null,
        userId: info.userId,
        deviceId: info.deviceId,
        admin: info.admin,
      });
      return true;
    },
  };
}

export type Session = ReturnType<typeof createSession>;

export function useSessionState(session: Session): SessionState {
  return useSyncExternalStore(session.subscribe, session.getState, session.getState);
}
