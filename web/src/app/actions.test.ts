import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fakeCalls } from '@/test/fake-crypto';
import { SERVER_SIGN_OUT_MS, forgetEndedSession, lockVault, signOut } from './actions';
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

    it('sends the sign-out again when it fails early, and leaves a slow one running', async () => {
      vi.useFakeTimers();
      try {
        session.signedIn({ email: 'sam@example.co', userId: 'u', deviceId: 'device-1', admin: false });
        const send = vi
          .spyOn(api, 'send')
          .mockRejectedValueOnce(new Error('dropped'))
          .mockResolvedValue(undefined as never);
        const done = signOut();
        await vi.advanceTimersByTimeAsync(2000);
        await done;
        expect(send).toHaveBeenCalledTimes(2);
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
