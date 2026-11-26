import { describe, expect, it, vi } from 'vitest';
import { type CleanupStorage, startOtherSessionsCleanup } from './otherSessionsCleanup';
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

function setup(options: { usedBefore?: boolean; storage?: ReturnType<typeof memory>; fails?: number } = {}) {
  const session = createSession();
  const storage = options.storage ?? memory();
  const endOtherSessions = vi.fn(async () => undefined);
  for (let i = 0; i < (options.fails ?? 0); i += 1) endOtherSessions.mockRejectedValueOnce(new Error('offline'));
  const stop = startOtherSessionsCleanup({
    session,
    devices: { endOtherSessions },
    usedBefore: options.usedBefore ?? true,
    storage,
  });
  return { session, storage, endOtherSessions, stop };
}

const settle = () => new Promise((resolve) => setTimeout(resolve, 0));

describe("ending an earlier version's other sessions", () => {
  it('asks the server once, at the first sign-in of a browser used before, and not before', async () => {
    const { session, storage, endOtherSessions } = setup();
    await settle();
    expect(endOtherSessions).not.toHaveBeenCalled();
    session.signedIn(info);
    await settle();
    expect(endOtherSessions).toHaveBeenCalledTimes(1);
    expect(storage.items.get('kemlock.otherSessions.ended')).toBe('1');
    // Not again, however the session moves.
    session.unlocked();
    session.locked();
    await settle();
    expect(endOtherSessions).toHaveBeenCalledTimes(1);
  });

  it('asks when the session was already there at start, as after a reload', async () => {
    const session = createSession();
    session.signedIn(info);
    const endOtherSessions = vi.fn(async () => undefined);
    startOtherSessionsCleanup({ session, devices: { endOtherSessions }, usedBefore: true, storage: memory() });
    await settle();
    expect(endOtherSessions).toHaveBeenCalledTimes(1);
  });

  it('asks again at the next sign-in when the server did not answer', async () => {
    const { session, storage, endOtherSessions } = setup({ fails: 1 });
    session.signedIn(info);
    await settle();
    expect(storage.items.has('kemlock.otherSessions.ended')).toBe(false);
    session.unlocked();
    await settle();
    expect(endOtherSessions).toHaveBeenCalledTimes(2);
    expect(storage.items.get('kemlock.otherSessions.ended')).toBe('1');
  });

  it('leaves a browser nobody had signed in on alone, and that is the end of it', async () => {
    const { session, storage, endOtherSessions } = setup({ usedBefore: false });
    expect(storage.items.get('kemlock.otherSessions.ended')).toBe('1');
    session.signedIn(info);
    await settle();
    expect(endOtherSessions).not.toHaveBeenCalled();
  });

  it('is left alone once it has been done', async () => {
    const storage = memory();
    storage.setItem('kemlock.otherSessions.ended', '1');
    const { session, endOtherSessions } = setup({ storage });
    session.signedIn(info);
    await settle();
    expect(endOtherSessions).not.toHaveBeenCalled();
  });
});
