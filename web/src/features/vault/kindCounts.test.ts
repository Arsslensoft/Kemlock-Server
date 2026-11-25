import { describe, expect, it } from 'vitest';
import { countKinds } from './kindCounts';

describe('countKinds', () => {
  it('counts every item once, in the total and under its kind', () => {
    const counts = countKinds([{ kind: 'login' }, { kind: 'note' }, { kind: 'login' }, { kind: 'otp' }]);
    expect(counts).toEqual({ total: 4, byKind: { login: 2, note: 1, otp: 1 } });
  });

  it('leaves a kind with no items out, so a reader falls back to zero', () => {
    const { byKind } = countKinds([{ kind: 'login' }]);
    expect(byKind['card']).toBeUndefined();
    expect(byKind['card'] ?? 0).toBe(0);
  });

  it('counts a kind from a newer app in the total', () => {
    expect(countKinds([{ kind: 'hologram' }, { kind: 'login' }])).toEqual({
      total: 2,
      byKind: { hologram: 1, login: 1 },
    });
  });

  it('is empty for no items', () => {
    expect(countKinds([])).toEqual({ total: 0, byKind: {} });
  });
});
