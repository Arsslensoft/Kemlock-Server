// Where the DPoP key pair lives: IndexedDB, as a structured-cloned CryptoKeyPair whose private key
// is non-extractable. The browser stores the key object, never its bytes, so a script that can
// read the database still cannot read the key.

import { CryptoError } from './types';

export interface KeyStore {
  load(): Promise<CryptoKeyPair | undefined>;
  save(pair: CryptoKeyPair): Promise<void>;
  clear(): Promise<void>;
}

const DATABASE = 'kemlock-crypto';
const STORE = 'keys';
const RECORD = 'dpop';

function request<T>(req: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error ?? new CryptoError('unavailable'));
  });
}

function open(factory: IDBFactory): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = factory.open(DATABASE, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error ?? new CryptoError('unavailable'));
    req.onblocked = () => reject(new CryptoError('unavailable'));
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

/** The key store the worker uses. `factory` is injectable for tests. */
export function indexedDbKeyStore(factory: IDBFactory = indexedDB): KeyStore {
  return {
    async load() {
      const value = await withStore(factory, 'readonly', (s) => s.get(RECORD));
      return value as CryptoKeyPair | undefined;
    },
    async save(pair) {
      await withStore(factory, 'readwrite', (s) => s.put(pair, RECORD));
    },
    async clear() {
      await withStore(factory, 'readwrite', (s) => s.delete(RECORD));
    },
  };
}

/** Where this browser's trusted-device key lives: the same database, another record. */
export interface DeviceKeyStore {
  load(): Promise<CryptoKey | undefined>;
  /**
   * Stores the key unless one is there already, and says whether it did. Two tabs that both find
   * the store empty must not overwrite each other: the loser reloads and uses the winner's key.
   */
  add(key: CryptoKey): Promise<boolean>;
  clear(): Promise<void>;
}

const DEVICE_RECORD = 'device-wrap';

/** The AES-GCM key that seals this browser's copy of the root key, as a non-extractable key object. */
export function indexedDbDeviceKeyStore(factory: IDBFactory = indexedDB): DeviceKeyStore {
  return {
    async load() {
      const value = await withStore(factory, 'readonly', (s) => s.get(DEVICE_RECORD));
      return value as CryptoKey | undefined;
    },
    async add(key) {
      try {
        await withStore(factory, 'readwrite', (s) => s.add(key, DEVICE_RECORD));
        return true;
      } catch (error) {
        if ((error as { name?: unknown } | null)?.name === 'ConstraintError') return false;
        throw error;
      }
    },
    async clear() {
      await withStore(factory, 'readwrite', (s) => s.delete(DEVICE_RECORD));
    },
  };
}

// One tab's reload key (src/app/tabKey.ts). A reload of the tab keeps the session and the open
// vault in `sessionStorage`, sealed under an AES key of its own, never the trusted-device key: this
// one belongs to one tab, is non-extractable, and is stamped with the time its page was last heard
// from. A closed tab's `sessionStorage` can outlive the tab (session restore), so a key whose page
// has been silent for longer than a reload takes is deleted when the origin next loads, and what it
// sealed stops opening.
const TAB_PREFIX = 'tab-wrap:';

interface TabKeyRecord {
  key: CryptoKey;
  /** Milliseconds since the epoch, when the page last said it was there. */
  aliveAt: number;
}

function tabRecordName(tabId: string): string {
  return `${TAB_PREFIX}${tabId}`;
}

function isTabRecord(value: unknown): value is TabKeyRecord {
  return (
    typeof value === 'object' &&
    value !== null &&
    'key' in value &&
    'aliveAt' in value &&
    typeof (value as { aliveAt: unknown }).aliveAt === 'number'
  );
}

/** Whether a page heard from at `aliveAt` still counts as there, at `now`, after `maxAgeMs`. */
export function tabKeyFresh(aliveAt: number, now: number, maxAgeMs: number): boolean {
  const age = now - aliveAt;
  return age >= 0 && age < maxAgeMs;
}

/** The AES-GCM key one tab seals its reload copy under, in its own record. */
export function indexedDbTabKeyStore(
  tabId: string,
  factory: IDBFactory = indexedDB,
  now: () => number = () => Date.now(),
): DeviceKeyStore {
  const name = tabRecordName(tabId);
  return {
    async load() {
      const value: unknown = await withStore(factory, 'readonly', (s) => s.get(name));
      return isTabRecord(value) ? value.key : undefined;
    },
    async add(key) {
      try {
        const record: TabKeyRecord = { key, aliveAt: now() };
        await withStore(factory, 'readwrite', (s) => s.add(record, name));
        return true;
      } catch (error) {
        if ((error as { name?: unknown } | null)?.name === 'ConstraintError') return false;
        throw error;
      }
    },
    async clear() {
      await withStore(factory, 'readwrite', (s) => s.delete(name));
    },
  };
}

/** Runs `step` on the record `name` inside one read-write transaction, so nothing slips in between. */
async function inRecordTransaction(
  factory: IDBFactory,
  name: string,
  step: (store: IDBObjectStore, value: unknown) => void,
): Promise<void> {
  const db = await open(factory);
  try {
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(STORE, 'readwrite');
      const store = tx.objectStore(STORE);
      const read = store.get(name);
      read.onsuccess = () => step(store, read.result as unknown);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error ?? new CryptoError('unavailable'));
      tx.onabort = () => reject(tx.error ?? new CryptoError('unavailable'));
    });
  } finally {
    db.close();
  }
}

/** Says this tab's page is still there, so its key is not taken for a closed tab's. */
export async function touchTabKey(
  tabId: string,
  now: number,
  factory: IDBFactory = indexedDB,
): Promise<void> {
  const name = tabRecordName(tabId);
  await inRecordTransaction(factory, name, (store, value) => {
    if (isTabRecord(value)) store.put({ ...value, aliveAt: now }, name);
  });
}

/**
 * Deletes every tab key whose page has been silent for `maxAgeMs` or more and is not known to be
 * open (`isOpen`, the Web Locks the pages hold). Run first thing on every page load.
 */
export async function purgeTabKeys(options: {
  now: number;
  maxAgeMs: number;
  isOpen?: (tabId: string) => Promise<boolean>;
  factory?: IDBFactory;
}): Promise<void> {
  const factory = options.factory ?? indexedDB;
  const names = (await withStore(factory, 'readonly', (s) => s.getAllKeys())).filter(
    (name): name is string => typeof name === 'string' && name.startsWith(TAB_PREFIX),
  );
  for (const name of names) {
    const value: unknown = await withStore(factory, 'readonly', (s) => s.get(name));
    if (isTabRecord(value) && tabKeyFresh(value.aliveAt, options.now, options.maxAgeMs)) continue;
    if (options.isOpen && (await options.isOpen(name.slice(TAB_PREFIX.length)))) continue;
    // Checked again inside the transaction: the page may have said it is there in the meantime.
    await inRecordTransaction(factory, name, (store, current) => {
      if (isTabRecord(current) && tabKeyFresh(current.aliveAt, options.now, options.maxAgeMs)) return;
      store.delete(name);
    });
  }
}
