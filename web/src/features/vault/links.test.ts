import { beforeEach, describe, expect, it } from 'vitest';
import type { PutResult } from '@/api/client';
import type { ItemDto } from '@/api/types';
import { crypto, resetFakeCrypto } from '@/test/fake-crypto';
import { saveBatch } from './batch';
import {
  LinkError,
  isLinked,
  linkCandidates,
  linkInputs,
  linkedItems,
  readLinks,
  unlinkInputs,
  writeLinks,
} from './links';
import { type VaultDeps, VaultStore, type VaultItem, saveItem } from './vault';

const A = '00000000-0000-4000-8000-00000000000a';
const B = '00000000-0000-4000-8000-00000000000b';
const C = '00000000-0000-4000-8000-00000000000c';
const OWNER = 'user:00000000-0000-4000-8000-0000000000aa';
const NOW = new Date('2026-11-25T12:00:00Z');

function setup() {
  const batches: ItemDto[][] = [];
  const api: VaultDeps['api'] = {
    async putItem(dto): Promise<PutResult> {
      return { item: dto, etag: null };
    },
    async putBatch(request) {
      batches.push(request.writes.map((w) => w.item));
      return request.writes.map((w) => w.item);
    },
    async sync() {
      return { notModified: true } as never;
    },
  };
  const store = new VaultStore();
  let n = 0;
  const deps: VaultDeps = { api, crypto, now: () => NOW, newId: () => `00000000-0000-4000-8000-${String(++n).padStart(12, '0')}` };
  return { batches, store, deps };
}

async function make(
  deps: VaultDeps,
  store: VaultStore,
  id: string,
  name: string,
  data: Record<string, unknown> = {},
  kind = 'login',
): Promise<VaultItem> {
  return saveItem({ ...deps, newId: () => id }, store, { kind, owner: OWNER, fields: { name, ...data } });
}

beforeEach(async () => {
  resetFakeCrypto();
  await crypto.unlock('u', new TextEncoder().encode('wrapped:u'), new Uint8Array(), new Uint8Array());
});

describe('links in an item body', () => {
  it('reads the ids sorted, lower-cased and without repeats, and ignores entries it cannot read', () => {
    const data = {
      links: [
        { id: C.toUpperCase() },
        { id: B },
        { id: B },
        { id: 'not-a-uuid' },
        { name: 'no id' },
        'a string',
        null,
      ],
    };
    expect(readLinks(data)).toEqual([B, C]);
    expect(readLinks({ links: 'nope' })).toEqual([]);
    expect(readLinks({})).toEqual([]);
    expect(readLinks(null)).toEqual([]);
  });

  it('writes { id } entries sorted by id, and no member at all when there are none', () => {
    expect(writeLinks({}, [C, A, B])).toEqual([{ id: A }, { id: B }, { id: C }]);
    expect(writeLinks({ links: [{ id: A }] }, [])).toBeUndefined();
  });

  it('keeps what an existing entry carried besides its id', () => {
    const held = { links: [{ id: B, note: 'kept' }] };
    expect(writeLinks(held, [C, B])).toEqual([{ id: B, note: 'kept' }, { id: C }]);
  });
});

describe('linking two items', () => {
  it('writes the link on both items in one batch', async () => {
    const { batches, store, deps } = setup();
    const a = await make(deps, store, A, 'GitHub');
    const b = await make(deps, store, B, 'GitHub code', {}, 'otp');
    await saveBatch(deps, store, linkInputs(a, b));

    expect(batches).toHaveLength(1);
    expect(batches[0]?.map((dto) => [dto.id, dto.revision])).toEqual([
      [A, 2],
      [B, 2],
    ]);
    expect(readLinks(store.items.get(A)?.data)).toEqual([B]);
    expect(readLinks(store.items.get(B)?.data)).toEqual([A]);
    // The rest of each body is as it was.
    expect(store.items.get(A)?.data).toMatchObject({ name: 'GitHub' });
  });

  it('keeps the links of an item sorted by id as more are added', async () => {
    const { store, deps } = setup();
    const a = await make(deps, store, A, 'Hub');
    const c = await make(deps, store, C, 'C');
    const b = await make(deps, store, B, 'B');
    await saveBatch(deps, store, linkInputs(a, c));
    await saveBatch(deps, store, linkInputs(store.items.get(A) as VaultItem, b));
    expect(store.items.get(A)?.data?.['links']).toEqual([{ id: B }, { id: C }]);
  });

  it('writes only the end that is missing, and nothing when both are there', async () => {
    const { store, deps } = setup();
    const a = await make(deps, store, A, 'A', { links: [{ id: B }] });
    const b = await make(deps, store, B, 'B');
    expect(linkInputs(a, b).map((input) => input.existing?.id)).toEqual([B]);

    await saveBatch(deps, store, linkInputs(a, b));
    const again = linkInputs(store.items.get(A) as VaultItem, store.items.get(B) as VaultItem);
    expect(again).toEqual([]);
  });

  it('refuses an item linked to itself and an item that could not be read', async () => {
    const { store, deps } = setup();
    const a = await make(deps, store, A, 'A');
    const unreadable: VaultItem = { ...a, id: B, data: null };
    expect(() => linkInputs(a, a)).toThrow(LinkError);
    expect(() => linkInputs(a, unreadable)).toThrow(LinkError);
    expect(() => unlinkInputs(unreadable, a)).toThrow(LinkError);
  });
});

describe('unlinking', () => {
  it('removes both ends, from either side', async () => {
    const { store, deps } = setup();
    const a = await make(deps, store, A, 'A');
    const b = await make(deps, store, B, 'B');
    await saveBatch(deps, store, linkInputs(a, b));

    // Unlinked from B, the other item's end goes too.
    await saveBatch(deps, store, unlinkInputs(store.items.get(B) as VaultItem, store.items.get(A) as VaultItem));
    expect(store.items.get(A)?.data).not.toHaveProperty('links');
    expect(store.items.get(B)?.data).not.toHaveProperty('links');
  });

  it('removes only that link and leaves the others', async () => {
    const { store, deps } = setup();
    const a = await make(deps, store, A, 'A');
    const b = await make(deps, store, B, 'B');
    const c = await make(deps, store, C, 'C');
    await saveBatch(deps, store, linkInputs(a, b));
    await saveBatch(deps, store, linkInputs(store.items.get(A) as VaultItem, c));
    await saveBatch(deps, store, unlinkInputs(store.items.get(A) as VaultItem, store.items.get(B) as VaultItem));

    expect(readLinks(store.items.get(A)?.data)).toEqual([C]);
    expect(readLinks(store.items.get(C)?.data)).toEqual([A]);
    expect(readLinks(store.items.get(B)?.data)).toEqual([]);
  });

  it('clears a half-made link: one end named, the other not', async () => {
    const { store, deps } = setup();
    const a = await make(deps, store, A, 'A', { links: [{ id: B }] });
    const b = await make(deps, store, B, 'B');
    expect(isLinked(a, b)).toBe(true);
    expect(isLinked(b, a)).toBe(false);
    const inputs = unlinkInputs(a, b);
    expect(inputs.map((input) => input.existing?.id)).toEqual([A]);
  });
});

describe('finding linked items and candidates', () => {
  async function vault() {
    const { store, deps } = setup();
    const a = await make(deps, store, A, 'GitHub', { username: 'sam', urls: ['https://github.com'] });
    const b = await make(deps, store, B, 'GitHub code', { issuer: 'GitHub' }, 'otp');
    const c = await make(deps, store, C, 'Bank', { username: 'sam@bank.example' });
    return { store, deps, a, b, c };
  }

  it('lists the items a link names, by name, whichever end names it', async () => {
    const { store, deps, a, b, c } = await vault();
    await saveBatch(deps, store, linkInputs(a, b));
    const all = [...store.items.values()];
    expect(linkedItems(store.items.get(A) as VaultItem, all).map((i) => i.id)).toEqual([B]);
    expect(linkedItems(store.items.get(B) as VaultItem, all).map((i) => i.id)).toEqual([A]);
    expect(linkedItems(c, all)).toEqual([]);
  });

  it('leaves out a link whose item is gone', async () => {
    const { store, deps } = await vault();
    const orphan = await make(deps, store, '00000000-0000-4000-8000-0000000000d1', 'Orphan', { links: [{ id: B }, { id: '00000000-0000-4000-8000-0000000000ff' }] });
    expect(linkedItems(orphan, [...store.items.values()]).map((i) => i.id)).toEqual([B]);
  });

  it('offers what can be linked: not itself, not already linked, not trashed, not unreadable, not read-only', async () => {
    const { store, deps, a, b, c } = await vault();
    const trashed = await make(deps, store, '00000000-0000-4000-8000-0000000000d2', 'Old', { trashedAt: NOW.toISOString() });
    const unreadable: VaultItem = { ...c, id: '00000000-0000-4000-8000-0000000000d3', data: null };
    const readOnly = await make(deps, store, '00000000-0000-4000-8000-0000000000d4', 'Shared');
    await saveBatch(deps, store, linkInputs(a, b));
    const all = [...store.items.values(), unreadable];
    const current = store.items.get(A) as VaultItem;

    const offered = linkCandidates(current, all, '', (candidate) => candidate.id !== readOnly.id).map((i) => i.id);
    expect(offered).toEqual([C]);
    expect(offered).not.toContain(trashed.id);
  });

  it('narrows by name, username, issuer and website', async () => {
    const { store, a, c } = await vault();
    const all = [...store.items.values()];
    expect(linkCandidates(c, all, 'github').map((i) => i.id)).toEqual([A, B]);
    expect(linkCandidates(c, all, 'GITHUB.COM').map((i) => i.id)).toEqual([A]);
    expect(linkCandidates(a, all, 'bank.example').map((i) => i.id)).toEqual([C]);
    expect(linkCandidates(a, all, 'zzz')).toEqual([]);
  });
});
