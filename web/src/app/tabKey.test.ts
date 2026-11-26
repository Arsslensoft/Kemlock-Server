import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  PURGE_TIMEOUT_MS,
  TAB_HEARTBEAT_MS,
  TAB_KEY_MAX_AGE_MS,
  claimTabKey,
  keepTabKeyAlive,
  purgeClosedTabKeys,
  releaseTabLocks,
  tabIsOpen,
  type TabLocks,
} from './tabKey';
import { RELOAD_WINDOW_MS } from './session';

function locks(held: string[]): TabLocks & { requested: string[]; released: string[] } {
  const requested: string[] = [];
  const released: string[] = [];
  return {
    requested,
    released,
    // Like the browser's: the lock lasts until the callback's promise settles.
    request: async (name, callback) => {
      requested.push(name);
      await callback();
      released.push(name);
    },
    query: async () => ({ held: held.map((name) => ({ name })) }),
  };
}

afterEach(() => vi.useRealTimers());

describe('which tabs are open', () => {
  it('knows a tab by the lock its page holds', async () => {
    const held = locks(['kemlock-tab:abc12345']);
    expect(await tabIsOpen('abc12345', held)).toBe(true);
    expect(await tabIsOpen('other-tab', held)).toBe(false);
  });

  it('takes a browser with no locks, or a query that fails, for closed', async () => {
    expect(await tabIsOpen('abc12345', undefined)).toBe(false);
    const broken: TabLocks = { request: async () => undefined, query: () => Promise.reject(new Error('no')) };
    expect(await tabIsOpen('abc12345', broken)).toBe(false);
  });

  it('lets a key live a little longer than a reload takes, and no longer', () => {
    expect(TAB_KEY_MAX_AGE_MS).toBe(RELOAD_WINDOW_MS + TAB_HEARTBEAT_MS);
  });
});

describe('an open page says its tab is open', () => {
  it('stamps the key and holds the tab lock now and every few seconds, and stops when told', () => {
    vi.useFakeTimers();
    const held = locks([]);
    const touch = vi.fn(async () => undefined);
    let id: string | undefined = 'tab-aaaa-0001';
    const stop = keepTabKeyAlive({ currentTab: () => id }, { locks: held, now: () => 5, every: 1000, touch });
    expect(touch).toHaveBeenCalledWith('tab-aaaa-0001', 5);
    expect(held.requested).toEqual(['kemlock-tab:tab-aaaa-0001']);
    vi.advanceTimersByTime(3000);
    expect(touch).toHaveBeenCalledTimes(4);
    // The lock is asked for once per tab, however often the page stamps.
    expect(held.requested).toHaveLength(1);
    // A new sign-in has a new tab; no tab, nothing to stamp.
    id = 'tab-aaaa-0002';
    vi.advanceTimersByTime(1000);
    expect(held.requested).toEqual(['kemlock-tab:tab-aaaa-0001', 'kemlock-tab:tab-aaaa-0002']);
    id = undefined;
    vi.advanceTimersByTime(1000);
    expect(touch).toHaveBeenCalledTimes(5);
    stop();
    id = 'tab-aaaa-0003';
    vi.advanceTimersByTime(5000);
    expect(touch).toHaveBeenCalledTimes(5);
  });
});

describe('the purge on a page load', () => {
  it('says it finished when it did', async () => {
    const run = vi.fn(async () => undefined);
    expect(await purgeClosedTabKeys({ now: 7, run })).toBe(true);
    expect(run).toHaveBeenCalledWith(7);
  });

  it('counts an IndexedDB that fails outright as finished: nothing could open a key there either', async () => {
    expect(await purgeClosedTabKeys({ run: () => Promise.reject(new Error('blocked')) })).toBe(true);
  });

  it('gives up on an IndexedDB that hangs, so the page is not left on the spinner', async () => {
    vi.useFakeTimers();
    const outcome = purgeClosedTabKeys({ run: () => new Promise(() => undefined) });
    await vi.advanceTimersByTimeAsync(PURGE_TIMEOUT_MS);
    expect(await outcome).toBe(false);
  });
});

describe('claiming a restored tab', () => {
  it('holds the lock and stamps the key at once', async () => {
    const held = locks([]);
    const touch = vi.fn(async () => undefined);
    await claimTabKey('tab-claim-0001', { locks: held, now: () => 9, touch });
    expect(held.requested).toEqual(['kemlock-tab:tab-claim-0001']);
    expect(touch).toHaveBeenCalledWith('tab-claim-0001', 9);
    releaseTabLocks();
  });
});

describe('the locks and the page going away', () => {
  it('lets the lock go on pagehide and takes it again when the page returns from the cache', async () => {
    vi.useFakeTimers();
    const held = locks([]);
    const stop = keepTabKeyAlive(
      { currentTab: () => 'tab-cache-0001' },
      { locks: held, every: 1000, touch: async () => undefined, purge: async () => undefined },
    );
    expect(held.requested).toEqual(['kemlock-tab:tab-cache-0001']);
    window.dispatchEvent(new Event('pagehide'));
    await vi.advanceTimersByTimeAsync(0);
    expect(held.released).toEqual(['kemlock-tab:tab-cache-0001']);
    // Not a page from the cache: nothing is taken again.
    window.dispatchEvent(new Event('pageshow'));
    expect(held.requested).toHaveLength(1);
    const back = new Event('pageshow');
    Object.defineProperty(back, 'persisted', { value: true });
    window.dispatchEvent(back);
    expect(held.requested).toEqual(['kemlock-tab:tab-cache-0001', 'kemlock-tab:tab-cache-0001']);
    stop();
    releaseTabLocks();
  });
});

describe('the cleanup on each heartbeat', () => {
  it("stamps its own key first and then deletes the keys of closed tabs", async () => {
    vi.useFakeTimers();
    const order: string[] = [];
    const stop = keepTabKeyAlive(
      { currentTab: () => 'tab-beat-0001' },
      {
        locks: locks([]),
        every: 1000,
        touch: async () => void order.push('touch'),
        purge: async () => void order.push('purge'),
      },
    );
    await vi.advanceTimersByTimeAsync(0);
    expect(order).toEqual(['touch', 'purge']);
    await vi.advanceTimersByTimeAsync(1000);
    expect(order).toEqual(['touch', 'purge', 'touch', 'purge']);
    stop();
    releaseTabLocks();
  });
});
