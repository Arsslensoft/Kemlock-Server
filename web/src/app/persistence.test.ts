import { beforeEach, describe, expect, it, vi } from 'vitest';
import { crypto as fake, fakeCalls } from '@/test/fake-crypto';
import { keepRootSealed, restoreSession } from './persistence';
import { type TabStorage, createSession } from './session';

const USER = '11111111-1111-4111-8111-111111111111';
const DEVICE = '22222222-2222-4222-8222-222222222222';
const NOW = 1_700_000_000_000;

const tokens = {
  access: 'access-1',
  refresh: 'refresh-1',
  accessExpiresAt: NOW + 600_000,
  refreshExpiresAt: NOW + 86_400_000,
};

/** One tab's storage: it outlives the session objects, as it outlives a reload. */
function tabStore(): TabStorage & { keys: () => string[] } {
  const items = new Map<string, string>();
  return {
    getItem: (key) => items.get(key) ?? null,
    setItem: (key, value) => void items.set(key, value),
    removeItem: (key) => void items.delete(key),
    keys: () => [...items.keys()].sort(),
  };
}

function setup(storage: TabStorage) {
  const session = createSession({ storage, now: () => NOW });
  const api = { accountKeys: vi.fn(async () => ({ keyVersion: 1, sealedPrivateKeys: 'c2s' }) as never) };
  const deps = { session, api, crypto: fake };
  return { session, api, deps };
}

/** A person signs in and the vault opens: what every unlock path ends with. */
async function signInAndUnlock(storage: TabStorage) {
  const first = setup(storage);
  keepRootSealed(first.deps);
  first.session.tokenStore.set(tokens);
  first.session.signedIn({ email: 'sam@example.co', name: 'Sam', userId: USER, deviceId: DEVICE, admin: true });
  await fake.newSsoAccount(USER); // the worker holds the root key
  first.session.unlocked();
  await vi.waitFor(() => expect(first.session.sealedRoot.get()).toBeDefined());
  return first;
}

/** The tab is reloaded: the page's memory and the worker's keys are gone, the tab's storage stays. */
async function reload(storage: TabStorage) {
  await fake.lock();
  fakeCalls.length = 0;
  const next = setup(storage);
  await restoreSession(next.deps);
  return next;
}

beforeEach(async () => {
  await fake.lock();
  fakeCalls.length = 0;
});

describe('keeping the vault open across a reload', () => {
  it('seals the root key when the vault opens, and a reload opens it again', async () => {
    const storage = tabStore();
    await signInAndUnlock(storage);
    expect(storage.keys()).toEqual(['kemlock.session.info', 'kemlock.session.root', 'kemlock.session.tokens']);

    const back = await reload(storage);
    expect(back.session.getState()).toEqual({
      status: 'unlocked',
      email: 'sam@example.co',
      name: 'Sam',
      userId: USER,
      deviceId: DEVICE,
      admin: true,
    });
    expect(back.session.tokenStore.get()).toEqual(tokens);
    expect(fakeCalls).toEqual(['deviceCopyOpen', 'unlockWithRoot']);
  });

  it('takes the key version and the sealed private keys from the server on a restore', async () => {
    const storage = tabStore();
    await signInAndUnlock(storage);
    const spy = vi.spyOn(fake, 'unlockWithRoot');
    await reload(storage);
    expect(spy).toHaveBeenCalledWith(USER, expect.anything(), {
      keyVersion: 1,
      sealedPrivateKeys: expect.any(Uint8Array),
    });
    spy.mockRestore();
  });

  it('does not seal again after a restore', async () => {
    const storage = tabStore();
    await signInAndUnlock(storage);
    await fake.lock();
    fakeCalls.length = 0;
    const next = setup(storage);
    keepRootSealed(next.deps);
    await restoreSession(next.deps);
    await Promise.resolve();
    expect(next.session.getState().status).toBe('unlocked');
    expect(fakeCalls).not.toContain('deviceCopySeal');
    expect(next.api.accountKeys).toHaveBeenCalledTimes(1);
  });

  it('keeps a locked vault locked after a reload, and does not even try the sealed copy', async () => {
    const storage = tabStore();
    const first = await signInAndUnlock(storage);
    first.session.locked();
    expect(storage.keys()).toEqual(['kemlock.session.info', 'kemlock.session.tokens']);

    const back = await reload(storage);
    expect(back.session.getState().status).toBe('locked');
    expect(back.session.getState().email).toBe('sam@example.co');
    expect(back.session.tokenStore.get()).toEqual(tokens);
    expect(fakeCalls).toEqual([]);
  });

  it('seals again when the vault is opened after a lock', async () => {
    const storage = tabStore();
    const first = await signInAndUnlock(storage);
    first.session.locked();
    await fake.newSsoAccount(USER);
    first.session.unlocked();
    await vi.waitFor(() => expect(first.session.sealedRoot.get()).toBeDefined());
    expect((await reload(storage)).session.getState().status).toBe('unlocked');
  });

  it('forgets everything on sign-out', async () => {
    const storage = tabStore();
    const first = await signInAndUnlock(storage);
    first.session.end();
    expect(storage.keys()).toEqual([]);
    const back = await reload(storage);
    expect(back.session.getState().status).toBe('signed-out');
    expect(back.session.tokenStore.get()).toBeUndefined();
  });

  it('stores a refreshed token, so a reload after a refresh still has the live one', async () => {
    const storage = tabStore();
    const first = await signInAndUnlock(storage);
    const refreshed = { ...tokens, access: 'access-2', refresh: 'refresh-2' };
    first.session.tokenStore.set(refreshed);
    expect((await reload(storage)).session.tokenStore.get()).toEqual(refreshed);
    first.session.tokenStore.clear();
    expect(storage.getItem('kemlock.session.tokens')).toBeNull();
  });

  it('does not seal a vault that was shut while the keys were being fetched', async () => {
    const storage = tabStore();
    const first = setup(storage);
    keepRootSealed(first.deps);
    first.session.tokenStore.set(tokens);
    first.session.signedIn({ email: 'sam@example.co', userId: USER, deviceId: DEVICE, admin: false });
    await fake.newSsoAccount(USER);
    first.api.accountKeys.mockImplementation(async () => {
      first.session.locked();
      return { keyVersion: 1 } as never;
    });
    first.session.unlocked();
    await vi.waitFor(() => expect(first.api.accountKeys).toHaveBeenCalled());
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(first.session.sealedRoot.get()).toBeUndefined();
  });

  it('stays locked, and drops the sealed copy, when the browser key was reset', async () => {
    const storage = tabStore();
    await signInAndUnlock(storage);
    // Another browser's copy, or one made under a key that was reset: the worker will not open it.
    storage.setItem(
      'kemlock.session.root',
      JSON.stringify({ sealed: 'AAAA', keyVersion: 1 }),
    );
    const back = await reload(storage);
    expect(back.session.getState().status).toBe('locked');
    expect(back.session.tokenStore.get()).toEqual(tokens);
    expect(storage.keys()).toEqual(['kemlock.session.info', 'kemlock.session.tokens']);
  });

  it('stays locked when the key version moved on', async () => {
    const storage = tabStore();
    await signInAndUnlock(storage);
    const next = setup(storage);
    next.api.accountKeys.mockResolvedValue({ keyVersion: 2 } as never);
    await fake.lock();
    await restoreSession(next.deps);
    expect(next.session.getState().status).toBe('locked');
    expect(next.session.sealedRoot.get()).toBeUndefined();
  });

  it('stays locked when the vault will not open with the root key', async () => {
    const storage = tabStore();
    await signInAndUnlock(storage);
    await fake.lock();
    const spy = vi.spyOn(fake, 'unlockWithRoot').mockRejectedValueOnce(new Error('no'));
    const release = vi.spyOn(fake, 'release');
    const next = setup(storage);
    await restoreSession(next.deps);
    expect(next.session.getState().status).toBe('locked');
    expect(next.session.sealedRoot.get()).toBeUndefined();
    expect(release).toHaveBeenCalled();
    spy.mockRestore();
    release.mockRestore();
  });

  it('is signed out when the server ends the session while the keys are fetched', async () => {
    const storage = tabStore();
    await signInAndUnlock(storage);
    await fake.lock();
    const next = setup(storage);
    next.api.accountKeys.mockImplementation(async () => {
      // What the API client does when the refresh token is refused.
      next.session.tokenStore.clear();
      next.session.end();
      throw new Error('401');
    });
    await restoreSession(next.deps);
    expect(next.session.getState().status).toBe('signed-out');
    expect(storage.keys()).toEqual([]);
  });

  it('is signed out when the refresh token has run out', async () => {
    const storage = tabStore();
    await signInAndUnlock(storage);
    storage.setItem('kemlock.session.tokens', JSON.stringify({ ...tokens, refreshExpiresAt: NOW }));
    const back = await reload(storage);
    expect(back.session.getState().status).toBe('signed-out');
    expect(storage.keys()).toEqual([]);
    expect(fakeCalls).toEqual([]);
  });

  it('ignores storage it cannot read', async () => {
    for (const bad of ['not json', '{}', '[]', 'null', '{"email":1}']) {
      const storage = tabStore();
      storage.setItem('kemlock.session.info', bad);
      storage.setItem('kemlock.session.tokens', bad);
      storage.setItem('kemlock.session.root', bad);
      const back = await reload(storage);
      expect(back.session.getState().status).toBe('signed-out');
      expect(storage.keys()).toEqual([]);
    }
  });

  it('treats a damaged sealed copy as none: signed in, vault shut', async () => {
    const storage = tabStore();
    await signInAndUnlock(storage);
    storage.setItem('kemlock.session.root', '{"sealed":42}');
    const back = await reload(storage);
    expect(back.session.getState().status).toBe('locked');
    expect(fakeCalls).toEqual([]);
  });

  it('works with storage that throws, and with none', async () => {
    const blocked: TabStorage = {
      getItem: () => {
        throw new Error('blocked');
      },
      setItem: () => {
        throw new Error('blocked');
      },
      removeItem: () => {
        throw new Error('blocked');
      },
    };
    for (const storage of [blocked, undefined]) {
      const session = createSession({ storage, now: () => NOW });
      session.tokenStore.set(tokens);
      session.signedIn({ email: 'sam@example.co', userId: USER, deviceId: DEVICE, admin: false });
      session.unlocked();
      session.locked();
      session.end();
      const api = { accountKeys: vi.fn() };
      await restoreSession({ session, api, crypto: fake });
      expect(session.getState().status).toBe('signed-out');
      expect(api.accountKeys).not.toHaveBeenCalled();
    }
  });

  it('starts nothing when no tab storage has a session', async () => {
    const storage = tabStore();
    const next = setup(storage);
    await restoreSession(next.deps);
    expect(next.session.getState().status).toBe('signed-out');
    expect(next.api.accountKeys).not.toHaveBeenCalled();
  });
});
