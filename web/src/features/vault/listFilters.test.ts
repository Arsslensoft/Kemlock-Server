import { describe, expect, it } from 'vitest';
import { SPACE, login, vaultItem } from '@/test/tools-fixtures';
import { FAMILY_ID } from '@/test/vault-fixtures';
import {
  ALL_VAULTS,
  PERSONAL,
  countByKind,
  filterItems,
  inVault,
  knownVault,
  matches,
  vaultIdOf,
} from './listFilters';

const mineLogin = login('GitHub', 'sam@example.org', 'pw', ['https://github.com']);
const familyLogin = login('Netflix', 'family', 'pw', ['netflix.com'], {}, { owner: SPACE });
const mineNote = vaultItem('note', { name: 'Wi-Fi at home', text: 'secret words' });
const familyNote = vaultItem('note', { name: 'Lease', text: 'x' }, { owner: SPACE });
const mineOtp = vaultItem('otp', { name: 'GitHub code', secret: 'JBSWY3DP', issuer: 'GitHub' });
const mineCard = vaultItem('card', { name: 'Travel card', cardholder: 'Sam Rivera', number: '4111111111111111' });
const all = [mineLogin, familyLogin, mineNote, familyNote, mineOtp, mineCard];

describe('the vault an item is in', () => {
  it('is personal for the account\'s own vault and the space\'s id for a space', () => {
    expect(vaultIdOf(mineLogin.owner)).toBe(PERSONAL);
    expect(vaultIdOf(SPACE)).toBe(FAMILY_ID);
  });

  it('is matched by the filter, and "all" matches every one', () => {
    expect(inVault(mineLogin, ALL_VAULTS)).toBe(true);
    expect(inVault(mineLogin, PERSONAL)).toBe(true);
    expect(inVault(mineLogin, FAMILY_ID)).toBe(false);
    expect(inVault(familyLogin, FAMILY_ID)).toBe(true);
    expect(inVault(familyLogin, PERSONAL)).toBe(false);
  });

  it('keeps a choice that still exists and falls back to all vaults for one that doesn\'t', () => {
    const options = [{ id: PERSONAL }, { id: FAMILY_ID }];
    expect(knownVault(FAMILY_ID, options)).toBe(FAMILY_ID);
    expect(knownVault(ALL_VAULTS, options)).toBe(ALL_VAULTS);
    expect(knownVault('a-space-left-long-ago', options)).toBe(ALL_VAULTS);
  });
});

describe('filterItems', () => {
  const names = (items: Array<{ data: { name?: string } | null }>) => items.map((item) => item.data?.name);

  it('lists everything by name when nothing filters', () => {
    expect(names(filterItems(all, {}))).toEqual([
      'GitHub',
      'GitHub code',
      'Lease',
      'Netflix',
      'Travel card',
      'Wi-Fi at home',
    ]);
  });

  it('narrows to a type', () => {
    expect(names(filterItems(all, { kind: 'note' }))).toEqual(['Lease', 'Wi-Fi at home']);
    expect(names(filterItems(all, { kind: 'otp' }))).toEqual(['GitHub code']);
    expect(filterItems(all, { kind: 'file' })).toEqual([]);
  });

  it('narrows to a vault', () => {
    expect(names(filterItems(all, { vault: FAMILY_ID }))).toEqual(['Lease', 'Netflix']);
    expect(names(filterItems(all, { vault: PERSONAL }))).toHaveLength(4);
  });

  it('combines the type and the vault', () => {
    expect(names(filterItems(all, { kind: 'login', vault: FAMILY_ID }))).toEqual(['Netflix']);
    expect(names(filterItems(all, { kind: 'note', vault: PERSONAL }))).toEqual(['Wi-Fi at home']);
    expect(filterItems(all, { kind: 'otp', vault: FAMILY_ID })).toEqual([]);
  });

  it('combines both with the search and with favourites', () => {
    expect(names(filterItems(all, { vault: PERSONAL, q: 'github' }))).toEqual(['GitHub', 'GitHub code']);
    expect(names(filterItems(all, { kind: 'login', vault: PERSONAL, q: 'github' }))).toEqual(['GitHub']);
    const starred = login('Starred', 'u', 'p', ['x.example'], { favorite: true });
    expect(names(filterItems([...all, starred], { fav: true }))).toEqual(['Starred']);
    expect(names(filterItems([...all, starred], { fav: true, kind: 'note' }))).toEqual([]);
  });

  it('does not change the list it is given', () => {
    const before = [...all];
    filterItems(all, { kind: 'login' });
    expect(all).toEqual(before);
  });
});

describe('the search', () => {
  it('finds an item by its name, username, website, issuer, email, cardholder or its type', () => {
    expect(matches(mineLogin, 'git')).toBe(true);
    expect(matches(mineLogin, 'sam@')).toBe(true);
    expect(matches(mineLogin, 'github.com')).toBe(true);
    expect(matches(mineOtp, 'github')).toBe(true);
    expect(matches(mineNote, 'NOTE')).toBe(true);
    expect(matches(mineCard, 'Rivera')).toBe(true);
    expect(matches(vaultItem('contact', { name: 'Alex', email: 'alex@example.org', company: 'Example Co' }), 'example co')).toBe(true);
  });

  it('never reads a secret: not a password, a note\'s text, a card number or a code\'s secret', () => {
    expect(matches(mineLogin, 'pw')).toBe(false);
    expect(matches(mineNote, 'secret words')).toBe(false);
    expect(matches(mineCard, '4111')).toBe(false);
    expect(matches(mineOtp, 'JBSWY3DP')).toBe(false);
  });

  it('matches everything for an empty search', () => {
    expect(matches(mineLogin, '')).toBe(true);
    expect(matches(mineLogin, '   ')).toBe(true);
  });
});

describe('countByKind', () => {
  it('counts every item and each kind, for the sidebar', () => {
    const counts = countByKind(all);
    expect(counts.total).toBe(6);
    expect(counts.byKind).toEqual({ login: 2, note: 2, otp: 1, card: 1 });
    expect(counts.byKind['file'] ?? 0).toBe(0);
  });

  it('is empty for an empty vault', () => {
    expect(countByKind([])).toEqual({ total: 0, byKind: {} });
  });
});
