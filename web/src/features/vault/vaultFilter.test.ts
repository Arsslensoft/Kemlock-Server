import { describe, expect, it, vi } from 'vitest';
import { createVaultFilterStore } from './vaultFilter';

function memory(initial?: string) {
  const data = new Map<string, string>();
  if (initial !== undefined) data.set('kemlock.vault.filter', initial);
  return {
    data,
    getItem: (key: string) => data.get(key) ?? null,
    setItem: (key: string, value: string) => void data.set(key, value),
  };
}

describe('the Vault filter of each page', () => {
  it('starts at all vaults on every page', () => {
    const store = createVaultFilterStore(memory());
    expect(store.get('items')).toBe('all');
    expect(store.get('trash')).toBe('all');
    expect(store.get('duplicates')).toBe('all');
  });

  it('is kept per page, so Trash can show Family while All items shows everything', () => {
    const store = createVaultFilterStore(memory());
    store.set('trash', 'family-id');
    expect(store.get('trash')).toBe('family-id');
    expect(store.get('items')).toBe('all');
  });

  it('is remembered for the tab', () => {
    const storage = memory();
    createVaultFilterStore(storage).set('items', 'personal');
    expect(createVaultFilterStore(storage).get('items')).toBe('personal');
  });

  it('forgets a page set back to all vaults', () => {
    const storage = memory();
    const store = createVaultFilterStore(storage);
    store.set('items', 'personal');
    store.set('items', 'all');
    expect(JSON.parse(storage.data.get('kemlock.vault.filter') ?? '{}')).toEqual({});
  });

  it('tells a listener on a change, and not on a choice that is already made', () => {
    const store = createVaultFilterStore(memory());
    const listener = vi.fn();
    const stop = store.subscribe(listener);
    store.set('items', 'personal');
    store.set('items', 'personal');
    expect(listener).toHaveBeenCalledTimes(1);
    stop();
    store.set('items', 'all');
    expect(listener).toHaveBeenCalledTimes(1);
  });

  it('forgets every page on reset, and tells the listeners', () => {
    const storage = memory();
    const store = createVaultFilterStore(storage);
    store.set('items', 'personal');
    store.set('trash', 'family-id');
    const listener = vi.fn();
    store.subscribe(listener);
    store.reset();
    expect(store.get('items')).toBe('all');
    expect(store.get('trash')).toBe('all');
    expect(listener).toHaveBeenCalledTimes(1);
    // Nor does a fresh store of the same tab find them again.
    expect(createVaultFilterStore(storage).get('items')).toBe('all');
  });

  it('ignores damaged text and values it does not know', () => {
    expect(createVaultFilterStore(memory('{not json')).get('items')).toBe('all');
    expect(createVaultFilterStore(memory('{"items":3,"nowhere":"x"}')).get('items')).toBe('all');
    expect(createVaultFilterStore(memory('[1]')).get('items')).toBe('all');
  });

  it('works without storage, or with storage that throws', () => {
    expect(createVaultFilterStore(undefined).get('items')).toBe('all');
    const blocked = {
      getItem: () => {
        throw new Error('blocked');
      },
      setItem: () => {
        throw new Error('blocked');
      },
    };
    const store = createVaultFilterStore(blocked);
    expect(() => store.set('items', 'personal')).not.toThrow();
    expect(store.get('items')).toBe('personal');
  });
});
