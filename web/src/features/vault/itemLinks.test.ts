import { beforeEach, describe, expect, it } from 'vitest';
import type { PutResult } from '@/api/client';
import { crypto, resetFakeCrypto } from '@/test/fake-crypto';
import { saveBatch } from './batch';
import {
  connectedItems,
  legacyLink,
  namedIds,
  namesItem,
  pickableItems,
  renamedLinkFields,
  siteInfoOf,
  unlinkPair,
} from './itemLinks';
import { LinkError, readLinks } from './links';
import { type VaultDeps, type VaultItem, VaultStore } from './vault';

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

beforeEach(async () => {
  resetFakeCrypto();
  await crypto.unlock('u', new TextEncoder().encode('wrapped:u'), new Uint8Array(), new Uint8Array());
});

describe('the link the importer makes', () => {
  it('reads the login a code names, as a lower-case id, and ignores what is not an id', () => {
    expect(legacyLink({ linkedLoginId: LOGIN.toUpperCase() })).toBe(LOGIN);
    expect(legacyLink({ linkedLoginId: 'nope' })).toBeUndefined();
    expect(legacyLink({})).toBeUndefined();
    expect(legacyLink(null)).toBeUndefined();
  });

  it('counts it with `links` among the ids a body names', () => {
    expect(namedIds({ links: [{ id: OTHER }], linkedLoginId: LOGIN })).toEqual([LOGIN, OTHER]);
    expect(namesItem(code(), LOGIN)).toBe(true);
    expect(namesItem(login(), CODE)).toBe(false);
  });

  it('lists the login on the code and, the reverse side, the code on the login', () => {
    const all = [login(), code()];
    expect(connectedItems(code(), all).map((i) => i.id)).toEqual([LOGIN]);
    expect(connectedItems(login(), all).map((i) => i.id)).toEqual([CODE]);
  });

  it('lists an item linked both ways once, and one linked only through `links` too', () => {
    const both = make(CODE, 'otp', { name: 'GitHub code', linkedLoginId: LOGIN, links: [{ id: LOGIN }] });
    const backup = make(BACKUP, 'backup-codes', { name: 'Recovery', links: [{ id: LOGIN }] });
    expect(connectedItems(both, [login(), both, backup]).map((i) => i.id)).toEqual([LOGIN]);
    expect(connectedItems(login(), [login(), both, backup]).map((i) => i.id)).toEqual([CODE, BACKUP]);
  });

  it('does not offer an item that is already connected that way', () => {
    const all = [login(), code(), make(OTHER, 'note', { name: 'Notes' })];
    expect(pickableItems(login(), all, '', () => true).map((i) => i.id)).toEqual([OTHER]);
  });
});

describe('unlinking', () => {
  function setup() {
    const store = new VaultStore();
    const deps: VaultDeps = {
      api: {
        putItem: async (dto): Promise<PutResult> => ({ item: dto, etag: null }),
        putBatch: async (request) => request.writes.map((w) => w.item),
        sync: async () => ({ notModified: true }) as never,
      },
      crypto,
      now: () => new Date('2026-11-25T12:00:00Z'),
    };
    return { store, deps };
  }

  it('clears the reference on the code and writes nothing on the login that never named it', async () => {
    const { store, deps } = setup();
    const inputs = unlinkPair(code(), login());
    expect(inputs.map((input) => input.existing?.id)).toEqual([CODE]);
    const [saved] = await saveBatch(deps, store, inputs);
    expect(saved?.data).not.toHaveProperty('linkedLoginId');
    expect(saved?.data).toMatchObject({ name: 'GitHub code' });
  });

  it('does the same from the login\'s side', () => {
    expect(unlinkPair(login(), code()).map((input) => input.existing?.id)).toEqual([CODE]);
  });

  it('removes both ends of a two-way link, and the old reference with them', async () => {
    const { store, deps } = setup();
    const a = make(CODE, 'otp', { name: 'GitHub code', linkedLoginId: LOGIN, links: [{ id: LOGIN }, { id: OTHER }] });
    const b = make(LOGIN, 'login', { name: 'GitHub', links: [{ id: CODE }] });
    const saved = await saveBatch(deps, store, unlinkPair(a, b));
    const byId = new Map(saved.map((item) => [item.id, item]));
    expect(byId.get(CODE)?.data).not.toHaveProperty('linkedLoginId');
    expect(readLinks(byId.get(CODE)?.data)).toEqual([OTHER]);
    expect(byId.get(LOGIN)?.data).not.toHaveProperty('links');
  });

  it('refuses an item with itself and one that could not be read', () => {
    expect(() => unlinkPair(login(), login())).toThrow(LinkError);
    expect(() => unlinkPair(login(), make(CODE, 'otp', null))).toThrow(LinkError);
  });
});

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
