import { afterEach, describe, expect, it, vi } from 'vitest';
import { keepTabKeyAlive, tabIsOpen, TAB_HEARTBEAT_MS, TAB_KEY_MAX_AGE_MS, type TabLocks } from './tabKey';
import { RELOAD_WINDOW_MS } from './session';

function locks(held: string[]): TabLocks & { requested: string[] } {
  const requested: string[] = [];
  return {
    requested,
    request: async (name) => {
      requested.push(name);
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
