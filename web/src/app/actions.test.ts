import { beforeEach, describe, expect, it, vi } from 'vitest';
import { crypto as fakeCrypto, fakeCalls } from '@/test/fake-crypto';
import { forgetEndedSession, lockVault, signOut } from './actions';
import { queryClient, session } from './services';

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
  it("forgets this browser's DPoP key and trusted-device key with the session", async () => {
    session.signedIn({ email: 'sam@example.co', userId: 'u', deviceId: 'd', admin: false });
    fakeCalls.length = 0;
    await signOut();
    expect(session.getState().status).toBe('signed-out');
    expect(fakeCalls).toEqual(expect.arrayContaining(['lock', 'dpopReset', 'deviceCopyReset']));
  });

  it('still signs out when a key cannot be forgotten', async () => {
    session.signedIn({ email: 'sam@example.co', userId: 'u', deviceId: 'd', admin: false });
    const spy = vi.spyOn(fakeCrypto, 'dpopReset').mockRejectedValueOnce(new Error('blocked'));
    await expect(signOut()).resolves.toBeUndefined();
    expect(session.getState().status).toBe('signed-out');
    spy.mockRestore();
  });
});
