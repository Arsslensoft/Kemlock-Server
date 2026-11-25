import { beforeEach, describe, expect, it } from 'vitest';
import type { ItemDto } from '@/api/types';
import { decodeB64, fromUtf8 } from '@/lib/b64url';
import { crypto, resetFakeCrypto } from '@/test/fake-crypto';
import { type FakeFiles, fakeFiles } from '@/test/fake-files';
import { saveBatch } from './batch';
import { linkInputs, readLinks } from './links';
import {
  MAX_RELINKS,
  MoveError,
  holdsFiles,
  isHere,
  moveItem,
  moveRefusal,
  targetRefusal,
} from './move';
import { type VaultDeps, type VaultItem, VaultStore, saveItem } from './vault';

const SPACE = '00000000-0000-4000-8000-0000000000bb';
const OTHER_SPACE = '00000000-0000-4000-8000-0000000000bc';
const COLLECTION = '00000000-0000-4000-8000-0000000000cc';
const OTHER_COLLECTION = '00000000-0000-4000-8000-0000000000dd';
const USER_OWNER = 'user:00000000-0000-4000-8000-0000000000aa';
const SPACE_OWNER = `space:${SPACE}`;
const NOW = new Date('2026-11-25T12:00:00Z');
const NEW_ID = '00000000-0000-4000-8000-0000000000ee';

type Write = { expectedRevision: number | null; item: ItemDto };

function setup() {
  /** What the server holds, by item id. */
  const rows = new Map<string, ItemDto>();
  const puts: Array<{ dto: ItemDto; precondition: unknown }> = [];
  const batches: Write[][] = [];
  const store = new VaultStore();
  let n = 0;
  const deps: VaultDeps = {
    api: {
      async putItem(dto, precondition) {
        puts.push({ dto, precondition });
        rows.set(dto.id, dto);
        return { item: dto, etag: null };
      },
      async putBatch(request) {
        batches.push(request.writes as Write[]);
        for (const write of request.writes) rows.set(write.item.id, write.item);
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
  // The server takes a file only for an item it holds.
  const files = fakeFiles({ knowsItem: (id) => rows.has(id) && rows.get(id)?.deleted !== true });
  return { rows, puts, batches, store, deps, files };
}

/** The body inside a sealed item: the fake crypto keeps it as the last member of the ciphertext. */
function bodyOf(dto: ItemDto | undefined): Record<string, unknown> {
  const sealed = JSON.parse(fromUtf8(decodeB64(dto?.ciphertext ?? ''))) as unknown[];
  return JSON.parse(String(sealed[sealed.length - 1])) as Record<string, unknown>;
}

function made(
  deps: VaultDeps,
  store: VaultStore,
  id: string,
  fields: Record<string, unknown>,
  extra: Partial<{ kind: string; owner: string; collectionId: string }> = {},
) {
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

describe('moving an item to another owner', () => {
  it('makes it again in the collection under a new id and deletes the old one, in one batch', async () => {
    const { batches, store, deps } = setup();
    const original = await made(deps, store, '00000000-0000-4000-8000-0000000000a1', {
      name: 'VPN',
      username: 'ops',
      password: 'pw',
      favorite: true,
    });
    const moved = await moveItem({ ...deps, newId: () => NEW_ID }, store, original, {
      owner: SPACE_OWNER,
      collectionId: COLLECTION,
    });

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

  it("moves it back to the account's own vault, leaving the collection behind", async () => {
    const { batches, store, deps } = setup();
    const inSpace = await made(deps, store, '00000000-0000-4000-8000-0000000000a2', { name: 'Wiki' }, { owner: SPACE_OWNER, collectionId: COLLECTION });
    const moved = await moveItem({ ...deps, newId: () => NEW_ID }, store, inSpace, { owner: USER_OWNER });
    expect(moved.owner).toBe(USER_OWNER);
    expect(moved).not.toHaveProperty('collectionId');
    expect(batches[0]?.[0]?.item).not.toHaveProperty('collectionId');
    // The old one is deleted where it was: in its own collection.
    expect(batches[0]?.[1]?.item).toMatchObject({ id: inSpace.id, owner: SPACE_OWNER, collectionId: COLLECTION, deleted: true });
  });

  it('moves it from one space to another with a new id', async () => {
    const { batches, store, deps } = setup();
    const item = await made(deps, store, '00000000-0000-4000-8000-0000000000a3', { name: 'Wiki' }, { owner: SPACE_OWNER, collectionId: COLLECTION });
    const moved = await moveItem({ ...deps, newId: () => NEW_ID }, store, item, { owner: `space:${OTHER_SPACE}`, collectionId: OTHER_COLLECTION });
    expect(moved).toMatchObject({ id: NEW_ID, owner: `space:${OTHER_SPACE}`, collectionId: OTHER_COLLECTION });
    expect(batches[0]?.[1]?.item).toMatchObject({ id: item.id, deleted: true });
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
    const moved = await moveItem({ ...deps, newId: () => NEW_ID }, store, current, { owner: SPACE_OWNER, collectionId: COLLECTION }, { linked });

    expect(batches).toHaveLength(1);
    expect(batches[0]?.map((w) => w.item.id)).toEqual([NEW_ID, code.id, login.id]);
    // The code names the moved login now; the unrelated item was not touched.
    expect(readLinks(store.items.get(code.id)?.data)).toEqual([NEW_ID]);
    expect(readLinks(moved.data)).toEqual([code.id]);
    expect(store.items.get(other.id)?.revision).toBe(1);
  });

  it('moves the link the importer made from a TOTP too: the code names the new id in `linkedLoginId`', async () => {
    const { store, deps } = setup();
    const login = await made(deps, store, '00000000-0000-4000-8000-0000000000a7', { name: 'GitHub' });
    const code = await made(deps, store, '00000000-0000-4000-8000-0000000000a8', { name: 'Code', linkedLoginId: login.id }, { kind: 'otp' });
    await moveItem({ ...deps, newId: () => NEW_ID }, store, login, { owner: SPACE_OWNER, collectionId: COLLECTION }, { linked: [code] });
    expect(store.items.get(code.id)?.data?.['linkedLoginId']).toBe(NEW_ID);
  });

  it("leaves an item it was not told about as it is: its link then names an id that is gone", async () => {
    const { store, deps } = setup();
    const login = await made(deps, store, '00000000-0000-4000-8000-0000000000a9', { name: 'GitHub' });
    const code = await made(deps, store, '00000000-0000-4000-8000-0000000000b0', { name: 'Code' }, { kind: 'otp' });
    await saveBatch(deps, store, linkInputs(login, code));
    await moveItem({ ...deps, newId: () => NEW_ID }, store, store.items.get(login.id) as VaultItem, { owner: SPACE_OWNER, collectionId: COLLECTION });
    expect(readLinks(store.items.get(code.id)?.data)).toEqual([login.id]);
  });

  it('refuses a move that would rewrite more links than one batch holds, and writes nothing', async () => {
    const { rows, batches, store, deps } = setup();
    const login = await made(deps, store, '00000000-0000-4000-8000-0000000000b1', { name: 'Hub' });
    rows.clear();
    const crowd = Array.from({ length: MAX_RELINKS + 1 }, (_, i): VaultItem => ({
      id: `00000000-0000-4000-8000-${String(1000 + i).padStart(12, '0')}`,
      owner: USER_OWNER,
      kind: 'note',
      revision: 1,
      keyVersion: 1,
      data: { name: `n${i}`, links: [{ id: login.id }] },
      sizes: { ciphertext: 1, itemKey: 1 },
    }));
    await expect(
      moveItem(deps, store, login, { owner: SPACE_OWNER, collectionId: COLLECTION }, { linked: crowd }),
    ).rejects.toMatchObject({ reason: 'too-many-links' });
    expect(batches).toEqual([]);
    expect(rows.size).toBe(0);
    expect(store.items.has(login.id)).toBe(true);
  });

  it('moves it with exactly as many links as one batch holds', async () => {
    const { batches, store, deps } = setup();
    const login = await made(deps, store, '00000000-0000-4000-8000-0000000000b2', { name: 'Hub' });
    const crowd = Array.from({ length: MAX_RELINKS }, (_, i): VaultItem => ({
      id: `00000000-0000-4000-8000-${String(2000 + i).padStart(12, '0')}`,
      owner: USER_OWNER,
      kind: 'note',
      revision: 1,
      keyVersion: 1,
      data: { name: `n${i}`, links: [{ id: login.id }] },
      sizes: { ciphertext: 1, itemKey: 1 },
    }));
    await moveItem({ ...deps, newId: () => NEW_ID }, store, login, { owner: SPACE_OWNER, collectionId: COLLECTION }, { linked: crowd });
    expect(batches[0]).toHaveLength(500);
  });
});

describe('moving between two collections of one space', () => {
  it('keeps the id, as the next revision, resealed under the new collection', async () => {
    const { puts, batches, store, deps } = setup();
    const item = await made(deps, store, '00000000-0000-4000-8000-0000000000c1', { name: 'Wiki', links: [{ id: NEW_ID }] }, { owner: SPACE_OWNER, collectionId: COLLECTION });
    puts.length = 0;
    const moved = await moveItem(deps, store, item, { owner: SPACE_OWNER, collectionId: OTHER_COLLECTION });
    expect(moved).toMatchObject({ id: item.id, revision: 2, owner: SPACE_OWNER, collectionId: OTHER_COLLECTION });
    expect(puts).toHaveLength(1);
    expect(puts[0]?.dto).toMatchObject({ id: item.id, revision: 2, collectionId: OTHER_COLLECTION, deleted: false });
    expect(puts[0]?.precondition).toEqual({ ifMatch: 1 });
    // No tombstone and no relinks: the id is the same.
    expect(batches).toEqual([]);
    expect(moved.data).toMatchObject({ name: 'Wiki', links: [{ id: NEW_ID }] });
    expect(store.items.get(item.id)).toBe(moved);
  });

  it('keeps its files where they are, without sending them again', async () => {
    const { store, deps, files } = setup();
    const item = await made(
      deps,
      store,
      '00000000-0000-4000-8000-0000000000c2',
      { name: 'Lease', file: { name: 'lease.pdf', size: 3, key: 'k', kemlockFile: 'f-1' } },
      { kind: 'file', owner: SPACE_OWNER, collectionId: COLLECTION },
    );
    const moved = await moveItem(deps, store, item, { owner: SPACE_OWNER, collectionId: OTHER_COLLECTION }, { files });
    expect(moved.data?.['file']).toMatchObject({ kemlockFile: 'f-1' });
    expect(files.calls).toEqual([]);
  });
});

describe('moving an item that holds files', () => {
  async function withFiles(files: FakeFiles, id: string, fields: Record<string, unknown>, kind: string, store: VaultStore, deps: VaultDeps) {
    files.held.set(id, new Map([['old-1', new Uint8Array([1, 2, 3, 4])], ['old-2', new Uint8Array([5, 6])]]));
    return made(deps, store, id, fields, { kind });
  }

  it('moves a File item to a space: the stub first, the file sent again, one batch for the rest', async () => {
    const { rows, puts, batches, store, deps, files } = setup();
    const lease = await withFiles(
      files,
      '00000000-0000-4000-8000-0000000000d1',
      { name: 'Lease', file: { id: 'a1', name: 'lease.pdf', size: 4, type: 'application/pdf', key: 'k', addedAt: 1, kemlockFile: 'old-1' } },
      'file',
      store,
      deps,
    );
    puts.length = 0;
    const moved = await moveItem({ ...deps, newId: () => NEW_ID }, store, lease, { owner: SPACE_OWNER, collectionId: COLLECTION }, { files });

    // The stub: the new item, naming no file, written before any file could start.
    expect(puts).toHaveLength(1);
    expect(puts[0]?.dto).toMatchObject({ id: NEW_ID, owner: SPACE_OWNER, collectionId: COLLECTION, revision: 1 });
    expect(puts[0]?.precondition).toEqual({ ifNoneMatch: true });
    expect(bodyOf(puts[0]?.dto)['file']).not.toHaveProperty('kemlockFile');
    expect(bodyOf(puts[0]?.dto)['file']).toMatchObject({ name: 'lease.pdf', key: 'k' });

    // The file, sealed as it was, under the new item.
    expect(files.calls.slice(0, 2)).toEqual([`start:${NEW_ID}`, `upload:${NEW_ID}/new-file-1`]);
    expect(files.held.get(NEW_ID)?.get('new-file-1')).toEqual(new Uint8Array([1, 2, 3, 4]));

    // One batch: the stub as revision 2 naming the new file, and the old item deleted.
    expect(batches).toHaveLength(1);
    expect(batches[0]?.map((w) => [w.item.id, w.item.revision, w.item.deleted])).toEqual([
      [NEW_ID, 2, false],
      [lease.id, 2, true],
    ]);
    expect(batches[0]?.[0]?.expectedRevision).toBe(1);
    expect(bodyOf(batches[0]?.[0]?.item)['file']).toMatchObject({ kemlockFile: 'new-file-1', name: 'lease.pdf' });
    expect(moved).toMatchObject({ id: NEW_ID, owner: SPACE_OWNER, revision: 2 });
    expect(moved.data?.['id']).toBe(NEW_ID);
    expect(store.items.has(lease.id)).toBe(false);
    expect(rows.get(lease.id)?.deleted).toBe(true);
    // The old files go once the old item has gone.
    expect(files.held.get(lease.id)?.has('old-1')).toBe(false);
    expect(files.calls).toContain(`remove:${lease.id}/old-1`);
  });

  it('moves a note with two attachments, one never uploaded, which keeps its entry and gains no file', async () => {
    const { batches, store, deps, files } = setup();
    const note = await withFiles(
      files,
      '00000000-0000-4000-8000-0000000000d2',
      {
        name: 'Wi-Fi',
        text: 'hunter2',
        attachments: [
          { id: 'a1', name: 'map.png', size: 4, key: 'k1', addedAt: 1, kemlockFile: 'old-1' },
          { id: 'a2', name: 'pending.txt', size: 9, key: 'k2', addedAt: 2 },
        ],
      },
      'note',
      store,
      deps,
    );
    const moved = await moveItem({ ...deps, newId: () => NEW_ID }, store, note, { owner: SPACE_OWNER, collectionId: COLLECTION }, { files });

    expect(files.calls.filter((call) => call.startsWith('start:'))).toEqual([`start:${NEW_ID}`]);
    const entries = moved.data?.['attachments'] as Array<Record<string, unknown>>;
    expect(entries).toHaveLength(2);
    expect(entries[0]).toMatchObject({ name: 'map.png', key: 'k1', kemlockFile: 'new-file-1' });
    expect(entries[1]).toMatchObject({ name: 'pending.txt', key: 'k2' });
    expect(entries[1]).not.toHaveProperty('kemlockFile');
    expect(bodyOf(batches[0]?.[0]?.item)['text']).toBe('hunter2');
  });

  it('moves the files of an item with links, which are rewritten in the same batch', async () => {
    const { batches, store, deps, files } = setup();
    const note = await withFiles(files, '00000000-0000-4000-8000-0000000000d3', { name: 'Doc', file: { name: 'a', size: 4, key: 'k', kemlockFile: 'old-1' } }, 'file', store, deps);
    const login = await made(deps, store, '00000000-0000-4000-8000-0000000000d4', { name: 'Site', links: [{ id: note.id }] });
    await moveItem({ ...deps, newId: () => NEW_ID }, store, note, { owner: SPACE_OWNER, collectionId: COLLECTION }, { files, linked: [login] });
    expect(batches[0]?.map((w) => w.item.id)).toEqual([NEW_ID, login.id, note.id]);
    expect(readLinks(store.items.get(login.id)?.data)).toEqual([NEW_ID]);
  });

  it('cleans up when the quota refuses a file: the files sent are removed, the stub deleted, the old item untouched', async () => {
    const { rows, puts, batches, store, deps } = setup();
    const files = fakeFiles({ knowsItem: (id) => rows.has(id) && rows.get(id)?.deleted !== true, refuseStart: 2 });
    const note = await withFiles(
      files,
      '00000000-0000-4000-8000-0000000000d5',
      {
        name: 'Two files',
        text: 't',
        attachments: [
          { id: 'a1', name: 'one.txt', size: 4, key: 'k1', addedAt: 1, kemlockFile: 'old-1' },
          { id: 'a2', name: 'two.txt', size: 2, key: 'k2', addedAt: 2, kemlockFile: 'old-2' },
        ],
      },
      'note',
      store,
      deps,
    );
    puts.length = 0;

    await expect(
      moveItem({ ...deps, newId: () => NEW_ID }, store, note, { owner: SPACE_OWNER, collectionId: COLLECTION }, { files }),
    ).rejects.toMatchObject({ status: 413, slug: 'storage-limit-exceeded' });

    // The first file went up and came down again; none is left under the new item.
    expect(files.calls).toContain(`remove:${NEW_ID}/new-file-1`);
    expect(files.held.get(NEW_ID)?.size ?? 0).toBe(0);
    // The stub was written, and then deleted for good.
    expect(puts.map((p) => [p.dto.id, p.dto.revision, p.dto.deleted])).toEqual([
      [NEW_ID, 1, false],
      [NEW_ID, 2, true],
    ]);
    expect(store.items.has(NEW_ID)).toBe(false);
    // No batch was sent: the old item and its files are as they were.
    expect(batches).toEqual([]);
    expect(rows.get(note.id)?.deleted).toBe(false);
    expect(store.items.get(note.id)).toBe(note);
    expect(files.held.get(note.id)?.size).toBe(2);
  });

  it('cleans up when the batch itself fails', async () => {
    const { rows, puts, store, deps, files } = setup();
    const lease = await withFiles(files, '00000000-0000-4000-8000-0000000000d6', { name: 'Lease', file: { name: 'a', size: 4, key: 'k', kemlockFile: 'old-1' } }, 'file', store, deps);
    puts.length = 0;
    const failing: VaultDeps = {
      ...deps,
      newId: () => NEW_ID,
      api: {
        ...deps.api,
        putBatch: async () => {
          throw new Error('the server went away');
        },
      },
    };
    await expect(moveItem(failing, store, lease, { owner: SPACE_OWNER, collectionId: COLLECTION }, { files })).rejects.toThrow('went away');
    expect(files.held.get(NEW_ID)?.size ?? 0).toBe(0);
    expect(rows.get(NEW_ID)?.deleted).toBe(true);
    expect(store.items.has(NEW_ID)).toBe(false);
    expect(store.items.get(lease.id)).toBe(lease);
  });

  it('needs the files client to move files', async () => {
    const { store, deps, files } = setup();
    const lease = await withFiles(files, '00000000-0000-4000-8000-0000000000d7', { name: 'Lease', file: { name: 'a', size: 4, key: 'k', kemlockFile: 'old-1' } }, 'file', store, deps);
    await expect(moveItem(deps, store, lease, { owner: SPACE_OWNER, collectionId: COLLECTION })).rejects.toThrow('files client');
  });

  it('tells a note with files from one without', async () => {
    const { store, deps } = setup();
    const file = await made(deps, store, '00000000-0000-4000-8000-0000000000d8', { name: 'Lease', file: { name: 'a.pdf', size: 1, key: 'k', kemlockFile: 'f' } }, { kind: 'file' });
    const note = await made(deps, store, '00000000-0000-4000-8000-0000000000d9', { name: 'N', attachments: [{ name: 'a.txt', size: 1, key: 'k' }] }, { kind: 'note' });
    const empty = await made(deps, store, '00000000-0000-4000-8000-0000000000da', { name: 'E', attachments: [] }, { kind: 'note' });
    expect(holdsFiles(file)).toBe(true);
    expect(holdsFiles(note)).toBe(true);
    expect(holdsFiles(empty)).toBe(false);
  });
});

describe('what cannot move', () => {
  it('refuses an item in the Trash and one that could not be read', async () => {
    const { store, deps } = setup();
    const trashed = await made(deps, store, '00000000-0000-4000-8000-0000000000e1', { name: 'Old', trashedAt: NOW.toISOString() });
    const unreadable: VaultItem = { ...trashed, id: '00000000-0000-4000-8000-0000000000e2', data: null };
    expect(moveRefusal(trashed)).toBe('trashed');
    expect(moveRefusal(unreadable)).toBe('unreadable');
  });

  it('refuses an item the person may only read', async () => {
    const { batches, store, deps } = setup();
    const viewed = await made(deps, store, '00000000-0000-4000-8000-0000000000e3', { name: 'Shared' }, { owner: SPACE_OWNER, collectionId: COLLECTION });
    expect(moveRefusal(viewed, false)).toBe('read-only');
    expect(moveRefusal(viewed, true)).toBeUndefined();
    await expect(moveItem(deps, store, viewed, { owner: USER_OWNER }, { writable: false })).rejects.toMatchObject({ reason: 'read-only' });
    expect(batches).toEqual([]);
  });

  it('refuses to move an item to where it is, and a space without a collection', async () => {
    const { store, deps } = setup();
    const item = await made(deps, store, '00000000-0000-4000-8000-0000000000e4', { name: 'A' }, { owner: SPACE_OWNER, collectionId: COLLECTION });
    expect(isHere(item, { owner: SPACE_OWNER, collectionId: COLLECTION })).toBe(true);
    expect(isHere(item, { owner: SPACE_OWNER, collectionId: OTHER_COLLECTION })).toBe(false);
    expect(isHere(item, { owner: USER_OWNER })).toBe(false);
    await expect(moveItem(deps, store, item, { owner: SPACE_OWNER, collectionId: COLLECTION })).rejects.toMatchObject({ reason: 'same-place' });
    const plain = await made(deps, store, '00000000-0000-4000-8000-0000000000e5', { name: 'B' });
    await expect(moveItem(deps, store, plain, { owner: SPACE_OWNER })).rejects.toBeInstanceOf(MoveError);
    await expect(moveItem(deps, store, plain, { owner: SPACE_OWNER })).rejects.toMatchObject({ reason: 'collection' });
  });

  it('keeps a contact in the account\'s own vault: it can leave a space but not enter one', async () => {
    const { batches, store, deps } = setup();
    const contact = await made(deps, store, '00000000-0000-4000-8000-0000000000e6', { name: 'Ada', email: 'ada@example.org' }, { kind: 'contact' });
    expect(targetRefusal(contact, { owner: SPACE_OWNER, collectionId: COLLECTION })).toBe('contact');
    await expect(moveItem(deps, store, contact, { owner: SPACE_OWNER, collectionId: COLLECTION })).rejects.toMatchObject({ reason: 'contact' });
    expect(batches).toEqual([]);
    // One that is in a space already (from an older app) can come home.
    const inSpace = await made(deps, store, '00000000-0000-4000-8000-0000000000e7', { name: 'Grace' }, { kind: 'contact', owner: SPACE_OWNER, collectionId: COLLECTION });
    expect(targetRefusal(inSpace, { owner: USER_OWNER })).toBeUndefined();
    const home = await moveItem({ ...deps, newId: () => NEW_ID }, store, inSpace, { owner: USER_OWNER });
    expect(home.owner).toBe(USER_OWNER);
  });
});
