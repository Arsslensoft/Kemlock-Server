import { describe, expect, it } from 'vitest';
import { isKindActive, withQuery } from './shellNav';

describe('the header search', () => {
  it('keeps the kind and favourites filters and starts the pages over', () => {
    expect(withQuery({ kind: 'login', fav: true, page: 3, q: 'old' }, 'bank')).toEqual({
      kind: 'login',
      fav: true,
      q: 'bank',
    });
  });

  it('removes q for an empty box, and keeps the rest', () => {
    expect(withQuery({ kind: 'note', q: 'old', page: 2 }, '')).toEqual({ kind: 'note' });
    expect(withQuery({}, '')).toEqual({});
  });
});

describe('the sidebar kind links', () => {
  it('are on the list with their kind, whatever q, page or favourites say', () => {
    expect(isKindActive('/vault', undefined, undefined)).toBe(true);
    expect(isKindActive('/vault', 'login', 'login')).toBe(true);
    expect(isKindActive('/vault', 'note', 'note')).toBe(true);
  });

  it('are off for another kind, and for any other page', () => {
    expect(isKindActive('/vault', 'login', undefined)).toBe(false);
    expect(isKindActive('/vault', undefined, 'login')).toBe(false);
    expect(isKindActive('/vault', 'note', 'login')).toBe(false);
    expect(isKindActive('/vault/new', undefined, undefined)).toBe(false);
    expect(isKindActive('/trash', 'login', 'login')).toBe(false);
  });
});
