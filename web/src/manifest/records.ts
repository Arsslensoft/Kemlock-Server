// What this browser remembers of each owner's manifest: the last one it accepted, so a server that
// later serves a lower counter (or none) is caught, and the ids it saw deleted. It lives in
// IndexedDB, beside the DPoP key's database but not in it (that one is the worker's), and outlives
// the session on purpose: a rollback is a comparison with what was seen before. A browser that has
// no IndexedDB keeps it for the life of the page only.
import type { DeletedRecord } from './compare';

export interface ManifestRecord {
  /** base64url of the exact bytes of the last accepted manifest. */
  manifest: string;
  counter: number;
  deleted: DeletedRecord;
}

export interface RecordStore {
  get(key: string): Promise<ManifestRecord | undefined>;
  /**
   * Keeps `record` unless the one held has a higher counter: the highest counter seen is what a
   * server is held to, so a stale tab or a slow write can never lower it. The comparison and the
   * write are one step.
   */
  put(key: string, record: ManifestRecord): Promise<void>;
}

export function memoryRecordStore(): RecordStore {
  const records = new Map<string, ManifestRecord>();
  return {
    get: async (key) => records.get(key),
    put: async (key, record) => {
      const held = records.get(key);
      if (!held || held.counter <= record.counter) records.set(key, record);
    },
  };
}

const DATABASE = 'kemlock-manifests';
const STORE = 'records';

function request<T>(req: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error ?? new Error('indexeddb'));
  });
}

function open(factory: IDBFactory): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = factory.open(DATABASE, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error ?? new Error('indexeddb'));
    req.onblocked = () => reject(new Error('indexeddb'));
  });
}

async function withStore<T>(
  factory: IDBFactory,
  mode: IDBTransactionMode,
  run: (store: IDBObjectStore) => IDBRequest<T>,
): Promise<T> {
  const db = await open(factory);
  try {
    return await request(run(db.transaction(STORE, mode).objectStore(STORE)));
  } finally {
    db.close();
  }
}

/** The records in IndexedDB. A read or write that fails is an error for the caller to weigh. */
export function indexedDbRecordStore(factory: IDBFactory): RecordStore {
  return {
    async get(key) {
      return (await withStore(factory, 'readonly', (s) => s.get(key))) as ManifestRecord | undefined;
    },
    async put(key, record) {
      const db = await open(factory);
      try {
        // One transaction reads the held record and writes the new one, so two tabs that both
        // read before either wrote cannot leave the lower counter standing.
        await new Promise<void>((resolve, reject) => {
          const tx = db.transaction(STORE, 'readwrite');
          const store = tx.objectStore(STORE);
          const read = store.get(key);
          read.onsuccess = () => {
            const held = read.result as ManifestRecord | undefined;
            if (!held || held.counter <= record.counter) store.put(record, key);
          };
          tx.oncomplete = () => resolve();
          tx.onerror = () => reject(tx.error ?? new Error('indexeddb'));
          tx.onabort = () => reject(tx.error ?? new Error('indexeddb'));
        });
      } finally {
        db.close();
      }
    },
  };
}

/**
 * The store the app uses: IndexedDB when the browser has it, with the page's own memory behind it,
 * so a browser that blocks storage still checks a manifest against the one it saw a moment ago.
 */
export function browserRecordStore(factory: IDBFactory | undefined): RecordStore {
  const memory = memoryRecordStore();
  if (!factory) return memory;
  const persistent = indexedDbRecordStore(factory);
  return {
    async get(key) {
      const local = await memory.get(key);
      let stored: ManifestRecord | undefined;
      try {
        stored = await persistent.get(key);
      } catch {
        return local;
      }
      // Whichever saw the higher counter is the one to hold the server to.
      return local && (!stored || local.counter > stored.counter) ? local : stored;
    },
    async put(key, record) {
      await memory.put(key, record);
      try {
        await persistent.put(key, record);
      } catch {
        // Storage that is blocked or full leaves only this page's memory.
      }
    },
  };
}
