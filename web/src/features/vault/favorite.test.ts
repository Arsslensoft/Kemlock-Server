import { describe, expect, it } from 'vitest';
import { isFavorite } from './favorite';
import type { VaultItem } from './vault';

const item = (data: Record<string, unknown>): VaultItem => ({
  id: 'i',
  owner: 'user:u',
  kind: 'card',
  revision: 1,
  keyVersion: 1,
  data,
  sizes: { ciphertext: 0, itemKey: 0 },
});

describe('isFavorite', () => {
  it('counts favorite and pinned', () => {
    expect(isFavorite(item({ favorite: true }))).toBe(true);
    expect(isFavorite(item({ pinned: true }))).toBe(true);
    expect(isFavorite(item({}))).toBe(false);
  });
});
