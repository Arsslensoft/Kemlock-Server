import { describe, expect, it, vi } from 'vitest';
import { type CleanupStorage, startDeviceKeyCleanup } from './deviceKeyCleanup';
import { createSession } from './session';

const info = { email: 'sam@example.co', userId: 'u', deviceId: 'd', admin: false };

function memory(): CleanupStorage & { items: Map<string, string> } {
  const items = new Map<string, string>();
  return {
    items,
    getItem: (key) => items.get(key) ?? null,
    setItem: (key, value) => void items.set(key, value),
  };
}

function setup(copy: unknown, options: { usedBefore?: boolean; storage?: CleanupStorage } = {}) {
  const session = createSession();
  const storage = options.storage ?? memory();
  const keyCopy = vi.fn(async () => copy as never);
  const deviceCopyReset = vi.fn(async () => undefined);
  const stop = startDeviceKeyCleanup({
    session,
    devices: { keyCopy },
    crypto: { deviceCopyReset },
    usedBefore: options.usedBefore ?? true,
    storage,
  });
  return { session, storage, keyCopy, deviceCopyReset, stop };
}

const settle = () => new Promise((resolve) => setTimeout(resolve, 0));

describe('the old trusted-device key', () => {
  it('is reset, once, for an account with no copy on the server', async () => {
    const { session, storage, keyCopy, deviceCopyReset } = setup(null);
    expect(keyCopy).not.toHaveBeenCalled();
    session.signedIn(info);
    await settle();
    expect(keyCopy).toHaveBeenCalledTimes(1);
    expect(deviceCopyReset).toHaveBeenCalledTimes(1);
    expect(storage.items.get('kemlock.deviceKey.checked')).toBe('1');
    // Not again, however the session moves.
    session.unlocked();
    session.locked();
    await settle();
    expect(keyCopy).toHaveBeenCalledTimes(1);
    expect(deviceCopyReset).toHaveBeenCalledTimes(1);
  });

  it('is kept for an account that trusts this browser', async () => {
    const { session, storage, deviceCopyReset } = setup({ wrappedKey: 'x' });
    session.signedIn(info);
    await settle();
    expect(deviceCopyReset).not.toHaveBeenCalled();
    expect(storage.items.get('kemlock.deviceKey.checked')).toBe('1');
  });

  it('asks again at the next sign-in when the server did not answer', async () => {
    const session = createSession();
    const storage = memory();
    const keyCopy = vi
      .fn<() => Promise<never>>()
      .mockRejectedValueOnce(new Error('offline'))
      .mockResolvedValue(null as never);
    const deviceCopyReset = vi.fn(async () => undefined);
    startDeviceKeyCleanup({ session, devices: { keyCopy }, crypto: { deviceCopyReset }, usedBefore: true, storage });
    session.signedIn(info);
    await settle();
    expect(deviceCopyReset).not.toHaveBeenCalled();
    expect(storage.items.has('kemlock.deviceKey.checked')).toBe(false);
    session.unlocked();
    await settle();
    expect(deviceCopyReset).toHaveBeenCalledTimes(1);
  });

  it('is not touched on a browser nobody had signed in on, and that is the end of it', async () => {
    const { session, storage, keyCopy, deviceCopyReset } = setup(null, { usedBefore: false });
    expect(storage.items.get('kemlock.deviceKey.checked')).toBe('1');
    session.signedIn(info);
    await settle();
    expect(keyCopy).not.toHaveBeenCalled();
    expect(deviceCopyReset).not.toHaveBeenCalled();
  });

  it('is left alone once it has been dealt with', async () => {
    const storage = memory();
    storage.setItem('kemlock.deviceKey.checked', '1');
    const { session, keyCopy } = setup(null, { storage });
    session.signedIn(info);
    await settle();
    expect(keyCopy).not.toHaveBeenCalled();
  });

  it('asks when the session was already there at start, as after a reload', async () => {
    const session = createSession();
    session.signedIn(info);
    const keyCopy = vi.fn(async () => null as never);
    const deviceCopyReset = vi.fn(async () => undefined);
    startDeviceKeyCleanup({
      session,
      devices: { keyCopy },
      crypto: { deviceCopyReset },
      usedBefore: true,
      storage: memory(),
    });
    await settle();
    expect(deviceCopyReset).toHaveBeenCalledTimes(1);
  });
});
