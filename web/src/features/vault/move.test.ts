import { beforeEach, describe, expect, it } from 'vitest';
import type { ItemDto } from '@/api/types';
import { crypto, resetFakeCrypto } from '@/test/fake-crypto';
import { linkInputs, readLinks } from './links';
import { MoveError, holdsFiles, isHere, moveItem, moveRefusal } from './move';
import { saveBatch } from './batch';
import { type VaultDeps, VaultStore, type VaultItem, saveItem } from './vault';

const SPACE = '00000000-0000-4000-8000-0000000000bb';
const COLLECTION = '00000000-0000-4000-8000-0000000000cc';
const OTHER_COLLECTION = '00000000-0000-4000-8000-0000000000dd';
const USER_OWNER = 'user:00000000-0000-4000-8000-0000000000aa';
const SPACE_OWNER = `space:${SPACE}`;
const NOW = new Date('2026-11-25T12:00:00Z');
const NEW_ID = '00000000-0000-4000-8000-0000000000ee';

function setup() {
  const batches: Array<Array<{ expectedRevision: number | null; item: ItemDto }>> = [];
  const store = new VaultStore();
  let n = 0;
  const deps: VaultDeps = {
    api: {
      async putItem(dto) {
        return { item: dto, etag: null };
      },
      async putBatch(request) {
        batches.push(request.writes as never);
        return request.writes.map((w) => w.item);
      },
      async sync() {
        return { notModified: true } as never;
      },
    },
    crypto,
    now: () => NOW,
    newId: () => `00000000-0000-4000-8000-${String(++n).padStart(12, '0')}`,
  };
  return { batches, store, deps };
}

function made(deps: VaultDeps, store: VaultStore, id: string, fields: Record<string, unknown>, extra: Partial<{ kind: string; owner: string; collectionId: string }> = {}) {
  return saveItem({ ...deps, newId: () => id }, store, {
    kind: extra.kind ?? 'login',
    owner: extra.owner ?? USER_OWNER,
    collectionId: extra.collectionId,
    fields,
  });
}

beforeEach(async () => {
  resetFakeCrypto();
  await crypto.unlock('u', new TextEncoder().encode('wrapped:u'), new Uint8Array(), new Uint8Array());
});

describe('moving an item to a space', () => {
  it('makes it again in the collection under a new id and deletes the old one, in one batch', async () => {
    const { batches, store, deps } = setup();
    const original = await made(deps, store, '00000000-0000-4000-8000-0000000000a1', {
      name: 'VPN',
      username: 'ops',
      password: 'pw',
      favorite: true,
    });
    const moved = await moveItem({ ...deps, newId: () => NEW_ID }, store, original, { owner: SPACE_OWNER, collectionId: COLLECTION });

    expect(batches).toHaveLength(1);
    const [created, removed] = batches[0] ?? [];
    expect(created).toMatchObject({
      expectedRevision: null,
      item: { id: NEW_ID, owner: SPACE_OWNER, collectionId: COLLECTION, revision: 1, deleted: false },
    });
    expect(removed).toMatchObject({
      expectedRevision: 1,
      item: { id: original.id, owner: USER_OWNER, revision: 2, deleted: true },
    });
    expect(moved).toMatchObject({ id: NEW_ID, owner: SPACE_OWNER, collectionId: COLLECTION });
    expect(moved.data).toMatchObject({ id: NEW_ID, name: 'VPN', username: 'ops', password: 'pw', favorite: true });
    expect(store.items.has(original.id)).toBe(false);
    expect(store.items.get(NEW_ID)).toBe(moved);
  });

  it('moves it back to the account\'s own vault, leaving the collection behind', async () => {
    const { batches, store, deps } = setup();
    const inSpace = await made(deps, store, '00000000-0000-4000-8000-0000000000a2', { name: 'Wiki' }, { owner: SPACE_OWNER, collectionId: COLLECTION });
    const moved = await moveItem({ ...deps, newId: () => NEW_ID }, store, inSpace, { owner: USER_OWNER });
    expect(moved.owner).toBe(USER_OWNER);
    expect(moved).not.toHaveProperty('collectionId');
    expect(batches[0]?.[0]?.item).not.toHaveProperty('collectionId');
    // The old one is deleted where it was: in its own collection.
    expect(batches[0]?.[1]?.item).toMatchObject({ id: inSpace.id, owner: SPACE_OWNER, collectionId: COLLECTION, deleted: true });
  });

  it('moves it between two collections of a space', async () => {
    const { store, deps } = setup();
    const item = await made(deps, store, '00000000-0000-4000-8000-0000000000a3', { name: 'Wiki' }, { owner: SPACE_OWNER, collectionId: COLLECTION });
    const moved = await moveItem({ ...deps, newId: () => NEW_ID }, store, item, { owner: SPACE_OWNER, collectionId: OTHER_COLLECTION });
    expect(moved.collectionId).toBe(OTHER_COLLECTION);
  });

  it('makes the items that link to it name the new id, in the same batch', async () => {
    const { batches, store, deps } = setup();
    const login = await made(deps, store, '00000000-0000-4000-8000-0000000000a4', { name: 'GitHub' });
    const code = await made(deps, store, '00000000-0000-4000-8000-0000000000a5', { name: 'GitHub code' }, { kind: 'otp' });
    const other = await made(deps, store, '00000000-0000-4000-8000-0000000000a6', { name: 'Unrelated' });
    await saveBatch(deps, store, linkInputs(login, code));
    batches.length = 0;

    const current = store.items.get(login.id) as VaultItem;
    const linked = [store.items.get(code.id) as VaultItem, other];
    const moved = await moveItem({ ...deps, newId: () => NEW_ID }, store, current, { owner: SPACE_OWNER, collectionId: COLLECTION }, linked);

    expect(batches).toHaveLength(1);
    expect(batches[0]?.map((w) => w.item.id)).toEqual([NEW_ID, code.id, login.id]);
    // The code names the moved login now; the unrelated item was not touched.
    expect(readLinks(store.items.get(code.id)?.data)).toEqual([NEW_ID]);
    expect(readLinks(moved.data)).toEqual([code.id]);
    expect(store.items.get(other.id)?.revision).toBe(1);
  });

  it('leaves an item it was not told about as it is: its link then names an id that is gone', async () => {
    const { store, deps } = setup();
    const login = await made(deps, store, '00000000-0000-4000-8000-0000000000a7', { name: 'GitHub' });
    const code = await made(deps, store, '00000000-0000-4000-8000-0000000000a8', { name: 'Code' }, { kind: 'otp' });
    await saveBatch(deps, store, linkInputs(login, code));
    await moveItem({ ...deps, newId: () => NEW_ID }, store, store.items.get(login.id) as VaultItem, { owner: SPACE_OWNER, collectionId: COLLECTION });
    expect(readLinks(store.items.get(code.id)?.data)).toEqual([login.id]);
  });
});

describe('what cannot move', () => {
  it('refuses an item that holds a file, which stays under its own id', async () => {
    const { store, deps } = setup();
    const file = await made(deps, store, '00000000-0000-4000-8000-0000000000b1', { name: 'Lease', file: { name: 'lease.pdf', size: 1, key: 'k', kemlockFile: 'f' } }, { kind: 'file' });
    const note = await made(deps, store, '00000000-0000-4000-8000-0000000000b2', { name: 'Note', text: 't', attachments: [{ name: 'a.txt', size: 1, key: 'k', kemlockFile: 'g' }] }, { kind: 'note' });
    expect(holdsFiles(file)).toBe(true);
    expect(holdsFiles(note)).toBe(true);
    for (const item of [file, note]) {
      expect(moveRefusal(item)).toBe('files');
      await expect(moveItem(deps, store, item, { owner: SPACE_OWNER, collectionId: COLLECTION })).rejects.toMatchObject({ reason: 'files' });
    }
    expect(store.items.has(file.id)).toBe(true);
  });

  it('moves a note whose attachments list is empty', async () => {
    const { store, deps } = setup();
    const note = await made(deps, store, '00000000-0000-4000-8000-0000000000b3', { name: 'Note', text: 't', attachments: [] }, { kind: 'note' });
    expect(moveRefusal(note)).toBeUndefined();
  });

  it('refuses an item in the Trash and one that could not be read', async () => {
    const { store, deps } = setup();
    const trashed = await made(deps, store, '00000000-0000-4000-8000-0000000000b4', { name: 'Old', trashedAt: NOW.toISOString() });
    const unreadable: VaultItem = { ...trashed, id: '00000000-0000-4000-8000-0000000000b5', data: null };
    expect(moveRefusal(trashed)).toBe('trashed');
    expect(moveRefusal(unreadable)).toBe('unreadable');
  });

  it('refuses to move an item to where it is, and a space without a collection', async () => {
    const { store, deps } = setup();
    const item = await made(deps, store, '00000000-0000-4000-8000-0000000000b6', { name: 'A' }, { owner: SPACE_OWNER, collectionId: COLLECTION });
    expect(isHere(item, { owner: SPACE_OWNER, collectionId: COLLECTION })).toBe(true);
    expect(isHere(item, { owner: SPACE_OWNER, collectionId: OTHER_COLLECTION })).toBe(false);
    expect(isHere(item, { owner: USER_OWNER })).toBe(false);
    await expect(moveItem(deps, store, item, { owner: SPACE_OWNER, collectionId: COLLECTION })).rejects.toMatchObject({ reason: 'same-place' });
    const plain = await made(deps, store, '00000000-0000-4000-8000-0000000000b7', { name: 'B' });
    await expect(moveItem(deps, store, plain, { owner: SPACE_OWNER })).rejects.toBeInstanceOf(MoveError);
    await expect(moveItem(deps, store, plain, { owner: SPACE_OWNER })).rejects.toMatchObject({ reason: 'collection' });
  });
});
