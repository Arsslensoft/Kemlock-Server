import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { PutResult, SyncResult } from '@/api/client';
import { ApiError } from '@/api/errors';
import type { ItemDto } from '@/api/types';
import { crypto, resetFakeCrypto } from '@/test/fake-crypto';
import {
  type VaultDeps,
  VaultStore,
  deleteForGood,
  emptyTrash,
  goneOn,
  isTrashed,
  loginOf,
  restoreItem,
  saveItem,
  syncVault,
  trashItem,
} from './vault';

const OWNER = 'user:00000000-0000-4000-8000-0000000000aa';
const NOW = new Date('2026-11-21T12:00:00Z');

/** An in-memory server: what the real one stores, so a round trip really goes through seal and open. */
function fakeServer() {
  const rows = new Map<string, ItemDto>();
  const log: Array<{ method: string; dto?: ItemDto; precondition?: unknown }> = [];
  let pages: SyncResult[] | undefined;
  const api: VaultDeps['api'] = {
    async putItem(dto, precondition): Promise<PutResult> {
      log.push({ method: 'put', dto, precondition });
      rows.set(dto.id, dto);
      return { item: dto, etag: null };
    },
    async putBatch(request) {
      log.push({ method: 'batch' });
      for (const write of request.writes) rows.set(write.item.id, write.item);
      return request.writes.map((w) => w.item);
    },
    async sync(since) {
      log.push({ method: 'sync', precondition: since });
      if (pages) {
        const next = pages.shift();
        if (!next) throw new Error('no page queued');
        return next;
      }
      return {
        notModified: false,
        page: { items: [...rows.values()], cursor: `c${rows.size}`, more: false },
      };
    },
  };
  return {
    api,
    rows,
    log,
    queue(...next: SyncResult[]) {
      pages = next;
    },
  };
}

function setup() {
  const server = fakeServer();
  const store = new VaultStore();
  const deps: VaultDeps = {
    api: server.api,
    crypto,
    now: () => NOW,
    newId: (() => {
      let n = 0;
      return () => `00000000-0000-4000-8000-${String(++n).padStart(12, '0')}`;
    })(),
  };
  return { server, store, deps };
}

beforeEach(async () => {
  resetFakeCrypto();
  await crypto.unlock('u', new TextEncoder().encode('wrapped:u'), new Uint8Array(), new Uint8Array());
});

describe('saving', () => {
  it('seals a new item as revision 1 with If-None-Match', async () => {
    const { server, store, deps } = setup();
    const saved = await saveItem(deps, store, {
      kind: 'login',
      owner: OWNER,
      fields: { name: 'GitHub', username: 'sam', password: 'pw', urls: ['https://github.com'] },
    });
    expect(saved.revision).toBe(1);
    expect(server.log[0]?.precondition).toEqual({ ifNoneMatch: true });
    const sent = server.rows.get(saved.id);
    expect(sent).toMatchObject({ format: 'kem1', kind: 'login', owner: OWNER, revision: 1, deleted: false });
    // What goes to the server is ciphertext: the name and password are not in it as JSON fields.
    expect(sent?.ciphertext).toBeTruthy();
    expect(store.items.get(saved.id)?.data?.updatedAt).toBe(NOW.toISOString());
  });

  it('edits as the next revision with If-Match, keeping fields it does not own', async () => {
    const { server, store, deps } = setup();
    const first = await saveItem(deps, store, {
      kind: 'login',
      owner: OWNER,
      fields: { name: 'GitHub', otherAppField: { keep: 'me' } },
    });
    const second = await saveItem(deps, store, {
      existing: first,
      kind: 'login',
      owner: OWNER,
      fields: { name: 'GitHub (work)' },
    });
    expect(second.revision).toBe(2);
    expect(server.log[1]?.precondition).toEqual({ ifMatch: 1 });
    expect(second.data).toMatchObject({ name: 'GitHub (work)', otherAppField: { keep: 'me' } });
  });

  it('removes a field the form cleared', async () => {
    const { store, deps } = setup();
    const first = await saveItem(deps, store, {
      kind: 'login',
      owner: OWNER,
      fields: { name: 'A', notes: 'n' },
    });
    const second = await saveItem(deps, store, {
      existing: first,
      kind: 'login',
      owner: OWNER,
      fields: { notes: undefined },
    });
    expect(second.data).not.toHaveProperty('notes');
  });
});

describe('sync', () => {
  it('opens what the server holds', async () => {
    const { store, deps } = setup();
    await saveItem(deps, store, { kind: 'login', owner: OWNER, fields: { name: 'A', username: 'u', password: 'p', urls: ['https://a.example'] } });
    await saveItem(deps, store, { kind: 'note', owner: OWNER, fields: { name: 'B', text: 'hi' } });
    store.reset();
    const items = await syncVault(deps, store);
    expect(items).toHaveLength(2);
    const login = items.find((i) => i.kind === 'login');
    expect(login && loginOf(login)).toEqual({ username: 'u', password: 'p', urls: ['https://a.example'] });
    expect(store.cursor).toBe('c2');
  });

  it('follows pages until there are no more', async () => {
    const { server, store, deps } = setup();
    const seed = setup();
    const a = await saveItem(seed.deps, seed.store, { kind: 'note', owner: OWNER, fields: { name: 'A' } });
    const b = await saveItem(seed.deps, seed.store, { kind: 'note', owner: OWNER, fields: { name: 'B' } });
    const dto = (id: string) => seed.server.rows.get(id) as ItemDto;
    server.queue(
      { notModified: false, page: { items: [dto(a.id)], cursor: 'p1', more: true } },
      { notModified: false, page: { items: [dto(b.id)], cursor: 'p2', more: false } },
    );
    const items = await syncVault(deps, store);
    expect(items.map((i) => i.data?.name).sort()).toEqual(['A', 'B']);
    expect(server.log.filter((l) => l.method === 'sync').map((l) => l.precondition)).toEqual([
      undefined,
      'p1',
    ]);
  });

  it('keeps the list when nothing changed', async () => {
    const { server, store, deps } = setup();
    await saveItem(deps, store, { kind: 'note', owner: OWNER, fields: { name: 'A' } });
    store.cursor = 'c1';
    server.queue({ notModified: true, cursor: 'c1' });
    expect(await syncVault(deps, store)).toHaveLength(1);
  });

  it('starts over when the cursor is too old', async () => {
    const { server, store, deps } = setup();
    await saveItem(deps, store, { kind: 'note', owner: OWNER, fields: { name: 'A' } });
    store.cursor = 'stale';
    const original = server.api.sync;
    let first = true;
    server.api.sync = async (since, limit) => {
      if (first) {
        first = false;
        throw new ApiError(410, {
          type: 'urn:kemlock:problem:full-sync-required',
          title: 'x',
          status: 410,
        });
      }
      return original(since, limit);
    };
    const items = await syncVault(deps, store);
    expect(items).toHaveLength(1);
    expect(store.cursor).toBe('c1');
  });

  it('drops a tombstone and ignores an older revision', async () => {
    const { server, store, deps } = setup();
    const saved = await saveItem(deps, store, { kind: 'note', owner: OWNER, fields: { name: 'A' } });
    const old = server.rows.get(saved.id) as ItemDto;
    server.queue({ notModified: false, page: { items: [{ ...old, revision: 0 }], cursor: 'x', more: false } });
    expect(await syncVault(deps, store)).toHaveLength(1);
    server.queue({
      notModified: false,
      page: { items: [{ id: saved.id, owner: OWNER, kind: 'note', format: 'kem1', revision: 2, keyVersion: 1, deleted: true }], cursor: 'y', more: false },
    });
    expect(await syncVault(deps, store)).toHaveLength(0);
  });

  it('keeps an item it cannot open, without data', async () => {
    const { server, store, deps } = setup();
    const saved = await saveItem(deps, store, { kind: 'note', owner: OWNER, fields: { name: 'A' } });
    const dto = server.rows.get(saved.id) as ItemDto;
    store.reset();
    // Same ciphertext under a different revision: the fake's AAD check fails, like the real one.
    server.queue({ notModified: false, page: { items: [{ ...dto, revision: 5 }], cursor: 'z', more: false } });
    const [item] = await syncVault(deps, store);
    expect(item?.data).toBeNull();
    expect(item?.revision).toBe(5);
  });
});

describe('the Trash', () => {
  it('moves an item to the Trash and back', async () => {
    const { store, deps } = setup();
    const saved = await saveItem(deps, store, { kind: 'login', owner: OWNER, fields: { name: 'Old forum' } });
    const trashed = await trashItem(deps, store, saved);
    expect(isTrashed(trashed)).toBe(true);
    expect(trashed.revision).toBe(2);
    expect(goneOn(trashed)?.toISOString()).toBe('2026-12-21T12:00:00.000Z');
    const restored = await restoreItem(deps, store, trashed);
    expect(isTrashed(restored)).toBe(false);
    expect(restored.revision).toBe(3);
    expect(restored.data?.name).toBe('Old forum');
  });

  it('deletes for good with a tombstone one revision on', async () => {
    const { server, store, deps } = setup();
    const saved = await saveItem(deps, store, { kind: 'login', owner: OWNER, fields: { name: 'A' } });
    await deleteForGood(deps, store, saved);
    const sent = server.rows.get(saved.id);
    expect(sent).toMatchObject({ deleted: true, revision: 2 });
    expect(sent?.ciphertext).toBeUndefined();
    expect(server.log.at(-1)?.precondition).toEqual({ ifMatch: 1 });
    expect(store.items.has(saved.id)).toBe(false);
  });

  it('empties the Trash in one batch', async () => {
    const { server, store, deps } = setup();
    const a = await saveItem(deps, store, { kind: 'note', owner: OWNER, fields: { name: 'A' } });
    const b = await saveItem(deps, store, { kind: 'note', owner: OWNER, fields: { name: 'B' } });
    const batch = vi.spyOn(server.api, 'putBatch');
    await emptyTrash(deps, store, [a, b]);
    expect(batch).toHaveBeenCalledOnce();
    const writes = batch.mock.calls[0]?.[0].writes ?? [];
    expect(writes.map((w) => w.expectedRevision)).toEqual([1, 1]);
    expect(writes.every((w) => w.item.deleted === true && w.item.revision === 2)).toBe(true);
    expect(store.items.size).toBe(0);
  });
});
