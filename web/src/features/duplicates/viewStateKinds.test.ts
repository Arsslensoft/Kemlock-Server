import { describe, expect, it } from 'vitest';
import { KIND_ORDER } from '@/features/vault/kinds';
import { DUPLICATE_FILTERS, createViewStore } from './viewState';

function memory(initial?: string) {
  const data = new Map<string, string>();
  if (initial !== undefined) data.set('kemlock.duplicates.view', initial);
  return {
    getItem: (key: string) => data.get(key) ?? null,
    setItem: (key: string, value: string) => void data.set(key, value),
  };
}

describe('the duplicates filters', () => {
  it('are All, every item type in the design\'s order, then "In two places"', () => {
    expect([...DUPLICATE_FILTERS]).toEqual(['all', ...KIND_ORDER, 'places']);
  });

  it('remember a type that had no chip before, such as files or SSH keys', () => {
    for (const filter of ['file', 'backup-codes', 'passkey', 'card', 'identity', 'contact', 'certificate', 'ssh-key', 'pgp-key']) {
      const storage = memory();
      createViewStore(storage).save({ filter: filter as (typeof DUPLICATE_FILTERS)[number], selectedId: 'g1' });
      expect(createViewStore(storage).load()).toEqual({ filter, selectedId: 'g1' });
    }
  });
});
