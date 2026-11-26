import { describe, expect, it } from 'vitest';
import { renamedLinkFields, siteInfoOf } from './itemLinks';
import type { VaultItem } from './vault';

const LOGIN = '00000000-0000-4000-8000-0000000000a1';
const CODE = '00000000-0000-4000-8000-0000000000a2';
const BACKUP = '00000000-0000-4000-8000-0000000000a3';
const OTHER = '00000000-0000-4000-8000-0000000000a4';
const NEW_ID = '00000000-0000-4000-8000-0000000000ee';
const OWNER = 'user:00000000-0000-4000-8000-0000000000aa';

function make(id: string, kind: string, data: Record<string, unknown> | null): VaultItem {
  return { id, owner: OWNER, kind, revision: 1, keyVersion: 1, data, sizes: { ciphertext: 1, itemKey: 1 } };
}

// A code the importer made from a login's TOTP: it names the login one way.
const login = () => make(LOGIN, 'login', { name: 'GitHub', urls: ['https://github.com'] });
const code = () => make(CODE, 'otp', { name: 'GitHub code', linkedLoginId: LOGIN });

describe('a move', () => {
  it('makes an item that named the old id name the new one, by `links` and by the old reference', () => {
    const both = make(CODE, 'otp', { links: [{ id: LOGIN }, { id: OTHER }], linkedLoginId: LOGIN });
    expect(renamedLinkFields(both, LOGIN, NEW_ID)).toEqual({
      links: [{ id: OTHER }, { id: NEW_ID }],
      linkedLoginId: NEW_ID,
    });
    expect(renamedLinkFields(code(), LOGIN, NEW_ID)).toEqual({ linkedLoginId: NEW_ID });
  });

  it('has nothing to say for an item that did not name it', () => {
    expect(renamedLinkFields(make(OTHER, 'note', { links: [{ id: CODE }] }), LOGIN, NEW_ID)).toBeUndefined();
  });
});

describe('the websites of an MFA code or backup codes', () => {
  it('shows their own first', () => {
    const own = make(CODE, 'otp', { urls: ['https://own.example'], linkedLoginId: LOGIN });
    expect(siteInfoOf(own, [login(), own])).toEqual({ urls: ['https://own.example'] });
  });

  it('shows the linked login\'s, read-only, when they have none, through either kind of link', () => {
    const viaLinks = make(BACKUP, 'backup-codes', { name: 'Recovery', links: [{ id: LOGIN }] });
    expect(siteInfoOf(code(), [login(), code()])).toEqual({ urls: ['https://github.com'], fromLogin: 'GitHub' });
    expect(siteInfoOf(viaLinks, [login(), viaLinks])).toEqual({ urls: ['https://github.com'], fromLogin: 'GitHub' });
  });

  it('reads the websites a login keeps as match rules', () => {
    const ruled = make(LOGIN, 'login', { name: 'Work', uris: [{ uri: 'https://work.example', match: 1 }] });
    expect(siteInfoOf(code(), [ruled, code()])?.urls).toEqual(['https://work.example']);
  });

  it('is undefined with no websites of their own and no linked login that has some', () => {
    const bare = make(LOGIN, 'login', { name: 'Bare' });
    expect(siteInfoOf(code(), [bare, code()])).toBeUndefined();
    expect(siteInfoOf(make(CODE, 'otp', {}), [])).toBeUndefined();
  });
});
