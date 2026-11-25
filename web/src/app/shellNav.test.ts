import { describe, expect, it } from 'vitest';
import { initials, isKindActive, withQuery } from './shellNav';

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

describe('the avatar letters', () => {
  it('are the first letters of the first two words of the name', () => {
    expect(initials('Sam Rivera', 'sam@example.org')).toBe('SR');
    expect(initials('  ada  king lovelace ', null)).toBe('AK');
  });

  it('are the first two letters of a one-word name', () => {
    expect(initials('Sam', 'sam@example.org')).toBe('SA');
  });

  it('come from the address when there is no name, or a blank one', () => {
    expect(initials(null, 'sam.rivera@example.org')).toBe('SR');
    expect(initials('   ', 'sam.rivera@example.org')).toBe('SR');
  });

  it('are a question mark for nobody', () => {
    expect(initials(null, null)).toBe('?');
  });
});
