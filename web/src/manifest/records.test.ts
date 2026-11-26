import { describe, expect, it, vi } from 'vitest';
import { browserRecordStore, memoryRecordStore } from './records';

const record = (counter: number) => ({ manifest: `m${counter}`, counter, deleted: {} });

describe('the record stores', () => {
  it('keep what was put, per key', async () => {
    const store = memoryRecordStore();
    expect(await store.get('a')).toBeUndefined();
    await store.put('a', record(1));
    await store.put('b', record(2));
    expect(await store.get('a')).toEqual(record(1));
    expect(await store.get('b')).toEqual(record(2));
  });

  it('keep to the page’s own memory in a browser with no IndexedDB', async () => {
    const store = browserRecordStore(undefined);
    await store.put('a', record(3));
    expect(await store.get('a')).toEqual(record(3));
  });

  it('keep to the page’s own memory when IndexedDB will not open, and never throw for it', async () => {
    const factory = {
      open: vi.fn(() => {
        throw new Error('blocked');
      }),
    } as unknown as IDBFactory;
    const store = browserRecordStore(factory);
    await expect(store.put('a', record(4))).resolves.toBeUndefined();
    expect(await store.get('a')).toEqual(record(4));
  });
});
