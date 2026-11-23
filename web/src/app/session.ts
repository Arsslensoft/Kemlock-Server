// Who is signed in and whether the vault is open. Tokens live in memory only, and the keys live in
// the crypto worker, so a reload signs you out: there is nothing in storage to steal.
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

const SIGNED_OUT: SessionState = {
  status: 'signed-out',
  email: null,
  name: null,
  userId: null,
  deviceId: null,
  admin: false,
};

export function createSession() {
  let state: SessionState = SIGNED_OUT;
  let tokens: Tokens | undefined;
  const listeners = new Set<() => void>();

  function set(next: SessionState): void {
    state = next;
    for (const listener of listeners) listener();
  }

  const tokenStore: TokenStore = {
    get: () => tokens,
    set: (next) => {
      tokens = next;
    },
    clear: () => {
      tokens = undefined;
    },
  };

  return {
    getState: (): SessionState => state,
    subscribe(listener: () => void): () => void {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    tokenStore,
    /** Tokens are in, the vault is still shut. */
    signedIn(info: SignedInInfo): void {
      set({
        status: 'locked',
        email: info.email,
        name: info.name ?? state.name,
        userId: info.userId,
        deviceId: info.deviceId,
        admin: info.admin,
      });
    },
    unlocked(): void {
      if (state.status !== 'signed-out') set({ ...state, status: 'unlocked' });
    },
    /** Keys forgotten, tokens kept: the master password opens the vault again. */
    locked(): void {
      if (state.status !== 'signed-out') set({ ...state, status: 'locked' });
    },
    /** Forgets everything. */
    end(): void {
      tokens = undefined;
      set(SIGNED_OUT);
    },
  };
}

export type Session = ReturnType<typeof createSession>;

export function useSessionState(session: Session): SessionState {
  return useSyncExternalStore(session.subscribe, session.getState, session.getState);
}
