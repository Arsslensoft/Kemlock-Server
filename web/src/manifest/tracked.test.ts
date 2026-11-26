import { describe, expect, it, vi } from 'vitest';
import { ApiError } from '@/api/errors';
import type { ItemDto } from '@/api/types';
import { type VaultApi, trackedApi } from './tracked';

const ITEM: ItemDto = {
  id: '11111111-1111-4111-8111-111111111111',
  owner: 'user:99999999-9999-4999-8999-999999999999',
  kind: 'login',
  format: 'kem1',
  revision: 2,
  keyVersion: 1,
  ciphertext: 'Y2lwaGVy',
  itemKey: 'a2V5',
  deleted: false,
};

function setup() {
  const page = { items: [ITEM], cursor: 'c1', more: false };
  const api = {
    sync: vi.fn(async () => ({ notModified: false as const, page })),
    putItem: vi.fn(async (item: ItemDto) => ({ item, etag: '"2"' })),
    putBatch: vi.fn(async (request: { writes: Array<{ item: ItemDto }> }) => request.writes.map((w) => w.item)),
  };
  const keeper = {
    reset: vi.fn(),
    wrote: vi.fn(async () => undefined),
  };
  return { api, keeper, tracked: trackedApi(api as unknown as VaultApi, keeper) };
}

describe('trackedApi', () => {
  it('starts the keeper over with a sync from scratch, and hands the page back as it is', async () => {
    const run = setup();
    const result = await run.tracked.sync(undefined, 500);
    expect(result).toEqual({ notModified: false, page: { items: [ITEM], cursor: 'c1', more: false } });
    expect(run.keeper.reset).toHaveBeenCalledOnce();
    expect(run.api.sync).toHaveBeenCalledWith(undefined, 500);
  });

  it('keeps what the keeper holds for a sync from a cursor', async () => {
    const run = setup();
    await run.tracked.sync('c1', 500);
    expect(run.keeper.reset).not.toHaveBeenCalled();
    run.api.sync.mockResolvedValueOnce({ notModified: true as never, cursor: 'c1' } as never);
    expect(await run.tracked.sync('c1', 500)).toEqual({ notModified: true, cursor: 'c1' });
    expect(run.keeper.reset).not.toHaveBeenCalled();
  });

  it('starts over when the server says the cursor is no longer good, and passes the error on', async () => {
    const run = setup();
    const gone = new ApiError(410, { type: 'urn:kemlock:problem:full-sync-required', title: 'gone', status: 410 });
    run.api.sync.mockRejectedValueOnce(gone);
    await expect(run.tracked.sync('old', 500)).rejects.toBe(gone);
    expect(run.keeper.reset).toHaveBeenCalledOnce();
    const other = new Error('offline');
    run.api.sync.mockRejectedValueOnce(other);
    await expect(run.tracked.sync('c1', 500)).rejects.toBe(other);
    expect(run.keeper.reset).toHaveBeenCalledOnce();
  });

  it('tells the keeper of a write after it went through, and of nothing that failed', async () => {
    const run = setup();
    const result = await run.tracked.putItem(ITEM, { ifMatch: 1 });
    expect(result).toEqual({ item: ITEM, etag: '"2"' });
    expect(run.keeper.wrote).toHaveBeenCalledWith([ITEM]);

    run.keeper.wrote.mockClear();
    run.api.putItem.mockRejectedValueOnce(new Error('stale'));
    await expect(run.tracked.putItem(ITEM, { ifMatch: 1 })).rejects.toThrow('stale');
    expect(run.keeper.wrote).not.toHaveBeenCalled();
  });

  it('lets a batch through and lists every item written', async () => {
    const run = setup();
    const other = { ...ITEM, id: '22222222-2222-4222-8222-222222222222' };
    const items = await run.tracked.putBatch({ writes: [{ item: ITEM }, { expectedRevision: 1, item: other }] });
    expect(items).toEqual([ITEM, other]);
    expect(run.keeper.wrote).toHaveBeenCalledWith([ITEM, other]);
  });

  it('never lets the keeper fail a write', async () => {
    const run = setup();
    run.keeper.wrote.mockRejectedValue(new Error('keeper broke'));
    await expect(run.tracked.putItem(ITEM, { ifNoneMatch: true })).resolves.toEqual({ item: ITEM, etag: '"2"' });
    await expect(run.tracked.putBatch({ writes: [{ item: ITEM }] })).resolves.toEqual([ITEM]);
  });
});
