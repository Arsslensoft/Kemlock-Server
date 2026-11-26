import { describe, expect, it, vi } from 'vitest';
import { type ManifestRecord, browserRecordStore, indexedDbRecordStore, memoryRecordStore } from './records';

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

/** Just enough of IndexedDB for the store: one object store, requests that answer a tick later. */
function fakeIndexedDb(data = new Map<string, ManifestRecord>()): IDBFactory {
  type Callback = { onsuccess?: () => void; result?: unknown };
  const later = (run: () => void) => queueMicrotask(run);
  const db = {
    close: () => undefined,
    transaction: () => {
      const tx: { oncomplete?: () => void; objectStore?: () => unknown } = {};
      const objectStore = {
        get: (key: string) => {
          const request: Callback = { result: data.get(key) };
          later(() => request.onsuccess?.());
          return request;
        },
        put: (value: ManifestRecord, key: string) => {
          data.set(key, value);
          const request: Callback = {};
          later(() => request.onsuccess?.());
          return request;
        },
      };
      tx.objectStore = () => objectStore;
      // The transaction completes after the requests inside it have answered.
      later(() => later(() => later(() => tx.oncomplete?.())));
      return tx;
    },
  };
  return {
    open: () => {
      const request: Callback & { onupgradeneeded?: () => void } = {};
      later(() => {
        request.result = { ...db, createObjectStore: () => undefined };
        request.onupgradeneeded?.();
        request.onsuccess?.();
      });
      return request;
    },
  } as unknown as IDBFactory;
}

describe('a record is never lowered', () => {
  it('by the page memory', async () => {
    const store = memoryRecordStore();
    await store.put('a', record(5));
    await store.put('a', record(4));
    expect(await store.get('a')).toEqual(record(5));
    await store.put('a', { ...record(5), deleted: { x: { revision: 1, seenAt: 1 } } });
    expect((await store.get('a'))?.deleted).toEqual({ x: { revision: 1, seenAt: 1 } });
  });

  it('by IndexedDB, in the one transaction that reads the held record and writes', async () => {
    const data = new Map<string, ManifestRecord>();
    const store = indexedDbRecordStore(fakeIndexedDb(data));
    await store.put('a', record(5));
    // Another tab, behind, writes what it has.
    await store.put('a', record(4));
    expect(data.get('a')).toEqual(record(5));
    expect(await store.get('a')).toEqual(record(5));
    await store.put('a', record(6));
    expect(data.get('a')).toEqual(record(6));
  });

  it('by the browser store, whichever of memory and IndexedDB is behind', async () => {
    const data = new Map<string, ManifestRecord>([['a', record(7)]]);
    const store = browserRecordStore(fakeIndexedDb(data));
    expect(await store.get('a')).toEqual(record(7));
    await store.put('a', record(3));
    expect(await store.get('a')).toEqual(record(7));
    expect(data.get('a')).toEqual(record(7));
  });
});
