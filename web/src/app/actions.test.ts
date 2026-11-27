import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fakeCalls } from '@/test/fake-crypto';
import { ApiError } from '@/api/errors';
import { REVOKE_RETRY_MS, SERVER_SIGN_OUT_MS, forgetEndedSession, keepRevoking, lockVault, signOut } from './actions';
import { api, queryClient, session } from './services';

beforeEach(() => queryClient.clear());

describe('locking the vault', () => {
  it('drops the decrypted spaces and Sends too, and keeps the config and placement', async () => {
    session.signedIn({ email: 'sam@example.co', userId: 'u', deviceId: 'd', admin: false });
    session.unlocked();
    queryClient.setQueryData(['vault'], []);
    queryClient.setQueryData(['writable-collections'], []);
    queryClient.setQueryData(['spaces'], [{ name: 'decrypted' }]);
    queryClient.setQueryData(['spaces', 'one'], { name: 'decrypted' });
    queryClient.setQueryData(['sends'], [{ linkKey: 'secret' }]);
    queryClient.setQueryData(['config'], { setup: 'complete' });
    queryClient.setQueryData(['placement'], { ready: true });
    await lockVault();
    for (const key of [['vault'], ['writable-collections'], ['spaces'], ['spaces', 'one'], ['sends']]) {
      expect(queryClient.getQueryData(key), key.join('/')).toBeUndefined();
    }
    expect(queryClient.getQueryData(['config'])).toEqual({ setup: 'complete' });
    expect(queryClient.getQueryData(['placement'])).toEqual({ ready: true });
    session.end();
  });
});

describe('forgetting what a session decrypted', () => {
  it('drops the cached data and keeps the config routing needs', () => {
    queryClient.setQueryData(['vault'], [{ id: 'previous user item' }]);
    queryClient.setQueryData(['devices', 'list'], []);
    queryClient.setQueryData(['config'], { setup: 'complete' });
    forgetEndedSession();
    expect(queryClient.getQueryData(['vault'])).toBeUndefined();
    expect(queryClient.getQueryData(['devices', 'list'])).toBeUndefined();
    expect(queryClient.getQueryData(['config'])).toEqual({ setup: 'complete' });
  });
});

describe('signing out', () => {
  it('forgets the keys and the session but not the browser keys other accounts and tabs share', async () => {
    session.signedIn({ email: 'sam@example.co', userId: 'u', deviceId: 'd', admin: false });
    fakeCalls.length = 0;
    await signOut();
    expect(session.getState().status).toBe('signed-out');
    expect(fakeCalls).toContain('lock');
    // The DPoP key signs other tabs' requests and the trusted-device key opens other accounts' copies.
    expect(fakeCalls).not.toContain('dpopReset');
    expect(fakeCalls).not.toContain('deviceCopyReset');
  });

  describe('on the server', () => {
    it("ends this device's session first, while the tokens and the DPoP key still work", async () => {
      session.signedIn({ email: 'sam@example.co', userId: 'u', deviceId: 'device-1', admin: false });
      fakeCalls.length = 0;
      const seen: Array<{ status: string; calls: string[] }> = [];
      const send = vi.spyOn(api, 'send').mockImplementation(async () => {
        seen.push({ status: session.getState().status, calls: [...fakeCalls] });
      });
      await signOut();
      // This session only: the device row and its trusted-device key copy stay on the server, which
      // an account with no password needs to open its vault again.
      expect(send).toHaveBeenCalledTimes(1);
      expect(send).toHaveBeenCalledWith({ method: 'POST', path: '/kem/v1/auth/sign-out' });
      expect(seen).toEqual([{ status: 'locked', calls: [] }]);
      expect(session.getState().status).toBe('signed-out');
      send.mockRestore();
    });

    it('signs out here even when the server cannot be reached', async () => {
      session.signedIn({ email: 'sam@example.co', userId: 'u', deviceId: 'device-1', admin: false });
      const send = vi.spyOn(api, 'send').mockRejectedValue(new Error('offline'));
      await expect(signOut()).resolves.toBeUndefined();
      expect(session.getState().status).toBe('signed-out');
      send.mockRestore();
    });

    it('does not wait on a server that does not answer', async () => {
      vi.useFakeTimers();
      try {
        session.signedIn({ email: 'sam@example.co', userId: 'u', deviceId: 'device-1', admin: false });
        const send = vi.spyOn(api, 'send').mockImplementation(() => new Promise<void>(() => undefined));
        const done = signOut();
        await vi.advanceTimersByTimeAsync(SERVER_SIGN_OUT_MS);
        await done;
        expect(session.getState().status).toBe('signed-out');
        send.mockRestore();
      } finally {
        vi.useRealTimers();
      }
    });

    it('does not ask when the server has just ended the session, or nobody is signed in', async () => {
      const send = vi.spyOn(api, 'send').mockResolvedValue(undefined as never);
      session.signedIn({ email: 'sam@example.co', userId: 'u', deviceId: 'device-1', admin: false });
      await signOut({ server: false });
      await signOut();
      expect(send).not.toHaveBeenCalled();
      send.mockRestore();
    });
  });
});

describe('a sign-out the server did not answer', () => {
  const held = () => ({
    access: 'at-1',
    refresh: 'rt-1',
    accessExpiresAt: Date.now() + 3_600_000,
    refreshExpiresAt: Date.now() + 7_200_000,
  });

  it('asks the server again in the background, with the tokens the session had', async () => {
    vi.useFakeTimers();
    const fetched = vi.fn(async (_url: string, _init?: RequestInit) => new Response(null, { status: 204 }));
    vi.stubGlobal('fetch', fetched);
    const send = vi.spyOn(api, 'send').mockImplementation(() => new Promise<void>(() => undefined));
    try {
      session.signedIn({ email: 'sam@example.co', userId: 'u', deviceId: 'device-1', admin: false });
      session.tokenStore.set(held());
      const done = signOut();
      await vi.advanceTimersByTimeAsync(SERVER_SIGN_OUT_MS);
      await done;
      // Signed out here at once, with the tokens gone from the page's own client.
      expect(session.getState().status).toBe('signed-out');
      expect(session.tokenStore.get()).toBeUndefined();
      expect(fetched).not.toHaveBeenCalled();
      await vi.advanceTimersByTimeAsync(REVOKE_RETRY_MS[0] ?? 0);
      expect(fetched).toHaveBeenCalledOnce();
      const [url, init] = fetched.mock.calls[0] ?? [];
      expect(url).toBe('/kem/v1/auth/sign-out');
      expect((init?.headers as Record<string, string>)['Authorization']).toBe('DPoP at-1');
      // It worked: nothing more is asked.
      await vi.advanceTimersByTimeAsync(REVOKE_RETRY_MS.reduce((a, b) => a + b, 0));
      expect(fetched).toHaveBeenCalledOnce();
    } finally {
      send.mockRestore();
      vi.unstubAllGlobals();
      vi.useRealTimers();
    }
  });

  it('keeps trying after a failure, and stops at the server’s answer', async () => {
    vi.useFakeTimers();
    try {
      const attempt = vi
        .fn<() => Promise<unknown>>()
        .mockRejectedValueOnce(new Error('offline'))
        .mockRejectedValueOnce(new ApiError(503, undefined))
        .mockRejectedValueOnce(new ApiError(401, undefined));
      keepRevoking(attempt, [10, 20, 30, 40]);
      await vi.advanceTimersByTimeAsync(10);
      expect(attempt).toHaveBeenCalledTimes(1);
      await vi.advanceTimersByTimeAsync(20);
      expect(attempt).toHaveBeenCalledTimes(2);
      await vi.advanceTimersByTimeAsync(30);
      expect(attempt).toHaveBeenCalledTimes(3);
      // A 401 says the session is gone: that is the end.
      await vi.advanceTimersByTimeAsync(1000);
      expect(attempt).toHaveBeenCalledTimes(3);
    } finally {
      vi.useRealTimers();
    }
  });

  it('makes no more tries once a new session began', async () => {
    vi.useFakeTimers();
    try {
      const attempt = vi.fn<() => Promise<unknown>>().mockRejectedValue(new Error('offline'));
      let cancelled = false;
      const finished = vi.fn();
      keepRevoking(attempt, [10, 10, 10], () => cancelled, finished);
      await vi.advanceTimersByTimeAsync(10);
      expect(attempt).toHaveBeenCalledTimes(1);
      cancelled = true;
      await vi.advanceTimersByTimeAsync(1000);
      expect(attempt).toHaveBeenCalledTimes(1);
      expect(finished).toHaveBeenCalledOnce();
    } finally {
      vi.useRealTimers();
    }
  });

  it('gives up when the delays run out', async () => {
    vi.useFakeTimers();
    try {
      const attempt = vi.fn<() => Promise<unknown>>().mockRejectedValue(new Error('offline'));
      keepRevoking(attempt, [10, 10]);
      await vi.advanceTimersByTimeAsync(1000);
      expect(attempt).toHaveBeenCalledTimes(2);
    } finally {
      vi.useRealTimers();
    }
  });
});
