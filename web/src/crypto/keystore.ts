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
  save(key: CryptoKey): Promise<void>;
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
    async save(key) {
      await withStore(factory, 'readwrite', (s) => s.put(key, DEVICE_RECORD));
    },
    async clear() {
      await withStore(factory, 'readwrite', (s) => s.delete(DEVICE_RECORD));
    },
  };
}
