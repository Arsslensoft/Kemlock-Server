import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { PoliciesDto } from '@/api/policies';
import { NO_POLICIES } from '@/api/policies';
import {
  DEFAULT_HIDDEN_MINUTES,
  DEFAULT_IDLE_MINUTES,
  createAutoLock,
  limitsFor,
  startAutoLock,
} from './autoLock';
import { createSession } from './session';

const MIN = 60_000;

beforeEach(() => vi.useFakeTimers());
afterEach(() => vi.useRealTimers());

describe('what the policy allows', () => {
  it('is 15 minutes idle and 5 hidden, and locks, when no space says otherwise', () => {
    expect(limitsFor()).toEqual({ idleMs: 15 * MIN, hiddenMs: 5 * MIN, action: 'lock' });
    expect(limitsFor(NO_POLICIES)).toEqual({ idleMs: 15 * MIN, hiddenMs: 5 * MIN, action: 'lock' });
    expect(DEFAULT_IDLE_MINUTES).toBe(15);
    expect(DEFAULT_HIDDEN_MINUTES).toBe(5);
  });

  it('is cut down to the strictest session timeout, and never stretched by a longer one', () => {
    expect(limitsFor({ sessionTimeoutMinutes: 2, sessionTimeoutAction: 'logOut' })).toEqual({
      idleMs: 2 * MIN,
      hiddenMs: 2 * MIN,
      action: 'logOut',
    });
    expect(limitsFor({ sessionTimeoutMinutes: 10 })).toMatchObject({ idleMs: 10 * MIN, hiddenMs: 5 * MIN });
    expect(limitsFor({ sessionTimeoutMinutes: 480 })).toMatchObject({ idleMs: 15 * MIN, hiddenMs: 5 * MIN });
  });

  it('ignores a timeout that is not a number of minutes above zero', () => {
    for (const minutes of [0, -5, Number.NaN, null, undefined]) {
      expect(limitsFor({ sessionTimeoutMinutes: minutes })).toMatchObject({ idleMs: 15 * MIN });
    }
  });
});

describe('the clock', () => {
  function make() {
    const expire = vi.fn();
    const clock = createAutoLock({ expire });
    return { expire, clock };
  }

  it('expires after the idle time with nothing done, and not before', () => {
    const { expire, clock } = make();
    clock.start(limitsFor(), false);
    vi.advanceTimersByTime(15 * MIN - 1);
    expect(expire).not.toHaveBeenCalled();
    vi.advanceTimersByTime(1);
    expect(expire).toHaveBeenCalledTimes(1);
    expect(expire).toHaveBeenCalledWith('lock');
  });

  it('starts the idle time again whenever the person does something', () => {
    const { expire, clock } = make();
    clock.start(limitsFor(), false);
    vi.advanceTimersByTime(14 * MIN);
    clock.activity();
    vi.advanceTimersByTime(14 * MIN);
    expect(expire).not.toHaveBeenCalled();
    vi.advanceTimersByTime(1 * MIN);
    expect(expire).toHaveBeenCalledTimes(1);
  });

  it('expires a tab that stays out of sight, sooner than an idle one, and not one that comes back', () => {
    const { expire, clock } = make();
    clock.start(limitsFor(), false);
    clock.hidden(true);
    vi.advanceTimersByTime(4 * MIN);
    clock.hidden(false);
    // Back after four minutes hidden: the idle time, not the hidden time, counts again.
    clock.activity();
    vi.advanceTimersByTime(10 * MIN);
    expect(expire).not.toHaveBeenCalled();
    clock.hidden(true);
    vi.advanceTimersByTime(5 * MIN);
    expect(expire).toHaveBeenCalledTimes(1);
  });

  it('expires a tab that comes back from the background after the hidden limit ran out unseen', () => {
    const { expire, clock } = make();
    clock.start(limitsFor(), false);
    clock.hidden(true);
    // The page was frozen: the clock moved on and no timer fired.
    vi.setSystemTime(Date.now() + 6 * MIN);
    clock.hidden(false);
    expect(expire).toHaveBeenCalledTimes(1);
    expect(expire).toHaveBeenCalledWith('lock');
  });

  it('does not expire a tab that comes back inside the hidden limit', () => {
    const { expire, clock } = make();
    clock.start(limitsFor(), false);
    clock.hidden(true);
    vi.setSystemTime(Date.now() + 4 * MIN);
    clock.hidden(false);
    expect(expire).not.toHaveBeenCalled();
  });

  it('expires at once when the time ran out unseen, as on a computer that slept', () => {
    const { expire, clock } = make();
    clock.start(limitsFor(), false);
    // A sleeping computer runs no timers: the clock jumps and nothing fires.
    vi.setSystemTime(Date.now() + 20 * MIN);
    clock.check();
    expect(expire).toHaveBeenCalledTimes(1);
  });

  it('takes the policy when it arrives, which may already have run out', () => {
    const { expire, clock } = make();
    clock.start(limitsFor(), false);
    vi.advanceTimersByTime(3 * MIN);
    clock.setLimits(limitsFor({ sessionTimeoutMinutes: 2, sessionTimeoutAction: 'logOut' }));
    expect(expire).toHaveBeenCalledTimes(1);
    expect(expire).toHaveBeenCalledWith('logOut');
  });

  it('holds the hidden limit while something is unsaved, but not the idle limit', () => {
    const expire = vi.fn();
    let unsaved = true;
    const clock = createAutoLock({ expire, holdHidden: () => unsaved });
    clock.start(limitsFor(), false);
    clock.hidden(true);
    vi.advanceTimersByTime(10 * MIN);
    expect(expire).not.toHaveBeenCalled();
    // The form is saved: the time already spent hidden counts at the next check.
    unsaved = false;
    clock.check();
    expect(expire).toHaveBeenCalledTimes(1);
  });

  it('still expires on the idle limit with something unsaved', () => {
    const expire = vi.fn();
    const clock = createAutoLock({ expire, holdHidden: () => true });
    clock.start(limitsFor(), false);
    clock.hidden(true);
    vi.advanceTimersByTime(15 * MIN);
    expect(expire).toHaveBeenCalledTimes(1);
  });

  it('stops, and does nothing once stopped', () => {
    const { expire, clock } = make();
    clock.start(limitsFor(), false);
    clock.stop();
    clock.activity();
    clock.hidden(true);
    vi.advanceTimersByTime(60 * MIN);
    expect(expire).not.toHaveBeenCalled();
  });
});

describe('in the page', () => {
  const info = { email: 'sam@example.co', userId: 'u', deviceId: 'd', admin: false };
  let visibility = 'visible';

  beforeEach(() => {
    visibility = 'visible';
    vi.spyOn(document, 'visibilityState', 'get').mockImplementation(() => visibility as DocumentVisibilityState);
  });
  afterEach(() => vi.restoreAllMocks());

  function setup(policy: Partial<PoliciesDto> | Error = {}) {
    const session = createSession();
    const expire = vi.fn();
    const mine = vi.fn(async (): Promise<PoliciesDto> => {
      if (policy instanceof Error) throw policy;
      return { ...NO_POLICIES, ...policy };
    });
    const stop = startAutoLock({ session, policies: { mine }, expire });
    return { session, expire, mine, stop };
  }

  function open(session: ReturnType<typeof createSession>) {
    session.signedIn(info);
    session.unlocked();
  }

  it('does nothing while the vault is shut, and starts when it opens', async () => {
    const { session, expire, mine, stop } = setup();
    session.signedIn(info);
    await vi.advanceTimersByTimeAsync(60 * MIN);
    expect(mine).not.toHaveBeenCalled();
    session.unlocked();
    expect(mine).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(15 * MIN);
    expect(expire).toHaveBeenCalledTimes(1);
    expect(expire).toHaveBeenCalledWith('lock');
    stop();
  });

  it('counts keys, clicks and scrolls as the person being there', async () => {
    const { session, expire, stop } = setup();
    open(session);
    for (const type of ['keydown', 'pointerdown', 'wheel']) {
      await vi.advanceTimersByTimeAsync(10 * MIN);
      window.dispatchEvent(new Event(type));
    }
    expect(expire).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(15 * MIN);
    expect(expire).toHaveBeenCalledTimes(1);
    stop();
  });

  it('locks a tab that was hidden for the hidden time, and not one that came back in time', async () => {
    const { session, expire, stop } = setup();
    open(session);
    visibility = 'hidden';
    document.dispatchEvent(new Event('visibilitychange'));
    await vi.advanceTimersByTimeAsync(4 * MIN);
    visibility = 'visible';
    document.dispatchEvent(new Event('visibilitychange'));
    window.dispatchEvent(new Event('keydown'));
    await vi.advanceTimersByTimeAsync(5 * MIN);
    expect(expire).not.toHaveBeenCalled();
    visibility = 'hidden';
    document.dispatchEvent(new Event('visibilitychange'));
    await vi.advanceTimersByTimeAsync(5 * MIN);
    expect(expire).toHaveBeenCalledTimes(1);
    stop();
  });

  it('obeys the strictest session timeout and its action', async () => {
    const { session, expire, stop } = setup({ sessionTimeoutMinutes: 3, sessionTimeoutAction: 'logOut' });
    open(session);
    await vi.advanceTimersByTimeAsync(3 * MIN);
    expect(expire).toHaveBeenCalledTimes(1);
    expect(expire).toHaveBeenCalledWith('logOut');
    stop();
  });

  it('keeps the defaults when the policy cannot be fetched', async () => {
    const { session, expire, stop } = setup(new Error('offline'));
    open(session);
    await vi.advanceTimersByTimeAsync(14 * MIN);
    expect(expire).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(1 * MIN);
    expect(expire).toHaveBeenCalledTimes(1);
    expect(expire).toHaveBeenCalledWith('lock');
    stop();
  });

  it('stops with the vault: a lock by hand leaves nothing to fire, and the next unlock starts afresh', async () => {
    const { session, expire, mine, stop } = setup();
    open(session);
    await vi.advanceTimersByTimeAsync(10 * MIN);
    session.locked();
    await vi.advanceTimersByTimeAsync(60 * MIN);
    expect(expire).not.toHaveBeenCalled();
    session.unlocked();
    expect(mine).toHaveBeenCalledTimes(2);
    await vi.advanceTimersByTimeAsync(14 * MIN);
    expect(expire).not.toHaveBeenCalled();
    stop();
  });

  it('starts when the page was reloaded with the vault already open', async () => {
    const session = createSession();
    open(session);
    const expire = vi.fn();
    const stop = startAutoLock({ session, policies: { mine: async () => NO_POLICIES }, expire });
    await vi.advanceTimersByTimeAsync(15 * MIN);
    expect(expire).toHaveBeenCalledTimes(1);
    stop();
  });
});
