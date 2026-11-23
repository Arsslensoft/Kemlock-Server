import { describe, expect, it } from 'vitest';
import { SPACE, login, vaultItem } from '@/test/tools-fixtures';
import { findDuplicates, groupId, tagsOf } from './detect';

describe('tagsOf', () => {
  it('makes a cred and an account tag per website, once per registrable domain', () => {
    const item = login('GitHub', 'Sam@Example.org', 'pw', ['https://github.com', 'https://gist.github.com']);
    const tags = tagsOf(item);
    expect(tags.map((t) => t.input)).toEqual([
      '["account","github.com","sam@example.org"]',
      '["cred","github.com","sam@example.org","pw"]',
    ]);
  });

  it('skips a website whose rule is never or a regular expression, and an empty password', () => {
    const item = vaultItem('login', {
      name: 'x',
      username: 'u',
      password: '',
      uris: [{ uri: 'a.example', match: 5 }, { uri: '^b', match: 4 }, { uri: 'c.example' }],
    });
    expect(tagsOf(item).map((t) => t.name)).toEqual(['account']);
  });

  it('tags the other kinds by their value', () => {
    expect(tagsOf(vaultItem('otp', { secret: 'jbsw y3dp' }))[0]?.input).toBe('["secret","JBSWY3DP"]');
    expect(tagsOf(vaultItem('note', { text: 'hi  \r\n' }))[0]?.input).toBe('["note","hi"]');
    expect(
      tagsOf(vaultItem('card', { number: '4111 1111', expMonth: 5, expYear: 2029 }))[0]?.input,
    ).toBe('["card","41111111","2029-05"]');
    expect(tagsOf(vaultItem('backup-codes', { codes: ['b', 'a', 'b'] }))[0]?.input).toBe(
      '["codes","a","b"]',
    );
    expect(tagsOf(vaultItem('login', null))).toEqual([]);
  });
});

describe('findDuplicates', () => {
  it('groups logins with the same site, username and password', () => {
    const a = login('GitHub', 'sam', 'pw', ['https://github.com'], { updatedAt: '2026-11-20T10:00:00Z' });
    const b = login('github.com', 'SAM', 'pw', ['gist.github.com'], { updatedAt: '2026-10-03T10:00:00Z' });
    const other = login('Other', 'sam', 'pw', ['https://example.org']);
    const groups = findDuplicates([b, other, a]);
    expect(groups).toHaveLength(1);
    expect(groups[0]?.why).toBe('cred');
    // The most recently changed item comes first.
    expect(groups[0]?.items.map((i) => i.id)).toEqual([a.id, b.id]);
    expect(groups[0]?.id).toBe(groupId([a, b]));
  });

  it('says so when only the password differs', () => {
    const a = login('Proton Mail', 'sam', 'new', ['proton.me']);
    const b = login('proton.me', 'sam', 'old', ['account.proton.me']);
    expect(findDuplicates([a, b])[0]?.why).toBe('account');
  });

  it('finds codes by their secret however it is spelled', () => {
    const a = vaultItem('otp', { name: 'AWS root', secret: 'JBSWY3DPEHPK3PXP' });
    const b = vaultItem('otp', { name: 'Amazon Web Services', secret: 'jbsw y3dp ehpk 3pxp===' });
    const groups = findDuplicates([a, b]);
    expect(groups).toHaveLength(1);
    expect(groups[0]?.why).toBe('secret');
  });

  it('matches across vaults and marks the group as in two places', () => {
    const mine = login('Netflix', 'sam', 'pw', ['netflix.com']);
    const family = login('Netflix', 'sam', 'pw', ['netflix.com'], {}, { owner: SPACE });
    const groups = findDuplicates([mine, family]);
    expect(groups).toHaveLength(1);
    expect(groups[0]?.crossOwner).toBe(true);
  });

  it('ignores trashed items, unreadable items and items with nothing to compare', () => {
    const a = login('A', 'sam', 'pw', ['a.example']);
    const trashed = login('A', 'sam', 'pw', ['a.example'], { trashedAt: '2026-11-01T00:00:00Z' });
    const unreadable = vaultItem('login', null);
    const empty = vaultItem('note', { text: '' });
    const empty2 = vaultItem('note', { text: '' });
    expect(findDuplicates([a, trashed, unreadable, empty, empty2])).toEqual([]);
  });

  it('joins three items through shared values into one group', () => {
    const a = login('A', 'sam', 'pw', ['a.example', 'b.example']);
    const b = login('B', 'sam', 'pw', ['b.example']);
    const c = login('C', 'sam', 'x', ['a.example']);
    const groups = findDuplicates([a, b, c]);
    expect(groups).toHaveLength(1);
    expect(groups[0]?.items).toHaveLength(3);
  });
});
