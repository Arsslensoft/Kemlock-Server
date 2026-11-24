import { beforeEach, describe, expect, it } from 'vitest';
import type { BatchRequest, ItemDto } from '@/api/types';
import { importItems } from '@/import/importItems';
import { crypto, resetFakeCrypto } from '@/test/fake-crypto';
import { saveBatch } from './batch';
import { type VaultDeps, VaultStore, openDto, saveItem } from './vault';

const OWNER = 'user:00000000-0000-4000-8000-0000000000aa';
const NOW = new Date('2026-11-22T09:00:00Z');

function setup() {
  const batches: BatchRequest[] = [];
  const puts: ItemDto[] = [];
  const rows = new Map<string, ItemDto>();
  let n = 0;
  const deps: VaultDeps = {
    api: {
      async putItem(dto) {
        puts.push(dto);
        rows.set(dto.id, dto);
        return { item: dto, etag: null };
      },
      async putBatch(request) {
        batches.push(request);
        for (const w of request.writes) rows.set(w.item.id, w.item);
        return request.writes.map((w) => w.item);
      },
      async sync() {
        return { notModified: true, cursor: null };
      },
    },
    crypto,
    now: () => NOW,
    newId: () => `00000000-0000-4000-8000-${String(++n).padStart(12, '0')}`,
  };
  return { deps, batches, puts, rows, store: new VaultStore() };
}

beforeEach(async () => {
  resetFakeCrypto();
  await crypto.unlock('u', new TextEncoder().encode('wrapped:u'), new Uint8Array(), new Uint8Array());
});

describe('saveBatch', () => {
  it('writes every item in one batch call with the revisions it read', async () => {
    const { deps, batches, puts, store } = setup();
    const a = await saveItem(deps, store, { kind: 'login', owner: OWNER, fields: { name: 'A' } });
    const b = await saveItem(deps, store, { kind: 'login', owner: OWNER, fields: { name: 'B' } });
    puts.length = 0;

    const saved = await saveBatch(deps, store, [
      { existing: a, kind: 'login', owner: OWNER, fields: { name: 'A2' } },
      { existing: b, kind: 'login', owner: OWNER, fields: { trashedAt: NOW.toISOString() } },
      { kind: 'note', owner: OWNER, fields: { name: 'New', text: 'hi' } },
    ]);

    expect(puts).toEqual([]);
    expect(batches).toHaveLength(1);
    expect(batches[0]?.writes.map((w) => w.expectedRevision)).toEqual([1, 1, null]);
    expect(saved.map((s) => s.revision)).toEqual([2, 2, 1]);
    expect(store.items.get(a.id)?.data?.name).toBe('A2');
    expect(store.items.get(b.id)?.data?.trashedAt).toBe(NOW.toISOString());
  });

  it('seals under the new revision, so each item opens as it was saved', async () => {
    const { deps, store, rows } = setup();
    const [saved] = await saveBatch(deps, store, [
      { kind: 'login', owner: OWNER, fields: { name: 'A', password: 'pw' } },
    ]);
    const dto = rows.get(saved?.id ?? '');
    expect(dto).toBeDefined();
    const opened = await openDto(crypto, dto as ItemDto);
    expect(opened?.data?.password).toBe('pw');
  });

  it('removes a field set to undefined, which is how Undo clears what a merge added', async () => {
    const { deps, store } = setup();
    const [first] = await saveBatch(deps, store, [
      { kind: 'login', owner: OWNER, fields: { name: 'A', folder: 'Work' } },
    ]);
    const [second] = await saveBatch(deps, store, [
      { existing: first, kind: 'login', owner: OWNER, fields: { folder: undefined } },
    ]);
    expect(second?.data).not.toHaveProperty('folder');
  });
});

describe('importItems', () => {
  it('writes in batches of 500 and reports progress after each', async () => {
    const { deps, batches, store } = setup();
    const items = Array.from({ length: 1203 }, (_, i) => ({
      id: `10000000-0000-4000-8000-${String(i).padStart(12, '0')}`,
      kind: 'note',
      data: { name: `n${i}`, text: 'x' },
    }));
    const progress: Array<[number, number]> = [];
    const outcome = await importItems(deps, store, items, OWNER, (d, t) => progress.push([d, t]));
    expect(outcome.imported).toBe(1203);
    expect(batches.map((b) => b.writes.length)).toEqual([500, 500, 203]);
    expect(progress).toEqual([
      [500, 1203],
      [1000, 1203],
      [1203, 1203],
    ]);
    // The ids the conversion chose are the ids written, so links between items hold.
    expect(batches[0]?.writes[0]?.item.id).toBe(items[0]?.id);
    expect(store.items.get(items[1202]?.id ?? '')?.data?.name).toBe('n1202');
  });

  it('stops at a failed batch and says nothing was imported after it', async () => {
    const { deps, store } = setup();
    let calls = 0;
    const failing: VaultDeps = {
      ...deps,
      api: {
        ...deps.api,
        async putBatch(request) {
          calls += 1;
          if (calls === 2) throw new Error('down');
          return request.writes.map((w) => w.item);
        },
      },
    };
    const items = Array.from({ length: 600 }, (_, i) => ({
      id: `20000000-0000-4000-8000-${String(i).padStart(12, '0')}`,
      kind: 'note',
      data: { name: `n${i}` },
    }));
    await expect(importItems(failing, store, items, OWNER)).rejects.toThrow('down');
    expect(store.items.size).toBe(500);
  });
});

describe('saveBatch ids', () => {
  it('writes the entry id as the item id', async () => {
    const { deps, store } = setup();
    const [saved] = await saveBatch(deps, store, [{ kind: 'note', owner: OWNER, fields: { name: 'N' } }]);
    expect(saved?.data?.id).toBe(saved?.id);
  });
});
