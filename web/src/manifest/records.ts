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
  put(key: string, record: ManifestRecord): Promise<void>;
}

export function memoryRecordStore(): RecordStore {
  const records = new Map<string, ManifestRecord>();
  return {
    get: async (key) => records.get(key),
    put: async (key, record) => {
      records.set(key, record);
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
      await withStore(factory, 'readwrite', (s) => s.put(record, key));
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
