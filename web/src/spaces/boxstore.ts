// The key boxes this browser accepted (docs/crypto.md, "Signed key boxes"), kept for the account and
// sealed by its worker the way the chain anchors are (src/spaces/anchors.ts):
//
//  - for each (space, key, version) the SHA-256 of the box it opened, and whether it was signed.
//    A box with that hash is accepted again without asking who sealed it, so a sealer who has since
//    left, or whose account moved to another key version, doesn't lock a member out of a key they
//    already hold; a box that differs is checked afresh, and an unsigned one that differs is refused;
//  - for each (space, key) the newest version of which it accepted a **signed** box, so a server
//    can't take the signature away again by serving an unsigned box of that key.
//
// It lives in IndexedDB in a database of its own, each value sealed by the worker under the
// account's user key (`sealLocal`) and bound to its key, so the server can't reach it and a script
// that can write to IndexedDB can't make a value the worker opens. A value that doesn't open is an
// error, never "none". Where IndexedDB isn't available the memory is the page's, and an unsigned box
// is accepted once more next time: safe, only more asking.
import type { LocalSeal } from './anchors';

/** What was accepted for one (space, key, version). */
export interface BoxRecord {
  /** Base64url of the SHA-256 of the box. */
  hash: string;
  /** Whether the box carried a valid signature of a member this browser could trace. */
  signed: boolean;
}

/** A key of a space: its own key `space`, or a collection's `collection:<uuid>`. */
export type KeyRef = string;

export interface BoxStore {
  load(account: string, space: string, key: KeyRef, version: number): Promise<BoxRecord | undefined>;
  save(account: string, space: string, key: KeyRef, version: number, record: BoxRecord): Promise<void>;
  /** The newest version of this key of which a signed box was accepted. */
  newestSigned(account: string, space: string, key: KeyRef): Promise<number | undefined>;
}

const DATABASE = 'kemlock-space-boxes';
const BOXES = 'boxes';

const boxKey = (account: string, space: string, key: KeyRef, version: number) =>
  `box/${account}/${space}/${key}/${version}`;
const signedKey = (account: string, space: string, key: KeyRef) =>
  `signed/${account}/${space}/${key}`;

function isRecord(value: unknown): value is BoxRecord {
  if (typeof value !== 'object' || value === null) return false;
  const v = value as Record<string, unknown>;
  return typeof v.hash === 'string' && typeof v.signed === 'boolean';
}

/** Reads a kept record from its text; anything that isn't one is an error. */
export function parseBoxRecord(text: string): BoxRecord {
  const value: unknown = JSON.parse(text);
  if (!isRecord(value)) throw new Error('the kept key box is damaged');
  return { hash: value.hash, signed: value.signed };
}

function parseVersion(text: string): number {
  const version = Number(text);
  if (!Number.isSafeInteger(version) || version < 0) throw new Error('the kept key version is damaged');
  return version;
}

/** The accepted boxes in memory: for tests, and the fallback when IndexedDB can't be used. */
export function memoryBoxStore(): BoxStore {
  const records = new Map<string, BoxRecord>();
  const newest = new Map<string, number>();
  return {
    async load(account, space, key, version) {
      return records.get(boxKey(account, space, key, version));
    },
    async save(account, space, key, version, record) {
      records.set(boxKey(account, space, key, version), record);
      if (record.signed) {
        const kept = newest.get(signedKey(account, space, key));
        if (kept === undefined || kept < version) newest.set(signedKey(account, space, key), version);
      }
    },
    async newestSigned(account, space, key) {
      return newest.get(signedKey(account, space, key));
    },
  };
}

function request<T>(req: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error ?? new Error('indexeddb'));
  });
}

function open(factory: IDBFactory): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = factory.open(DATABASE, 1);
    req.onupgradeneeded = () => {
      req.result.createObjectStore(BOXES);
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error ?? new Error('indexeddb'));
    req.onblocked = () => reject(new Error('indexeddb'));
  });
}

/**
 * The accepted boxes in IndexedDB, sealed by `seal`. `factory` is injectable for tests. A read or
 * write that fails, and a value that doesn't open or isn't what it should be, is thrown.
 */
export function indexedDbBoxStore(seal: LocalSeal, factory: IDBFactory = indexedDB): BoxStore {
  async function withStore<T>(
    mode: IDBTransactionMode,
    run: (store: IDBObjectStore) => IDBRequest<T>,
  ): Promise<T> {
    const db = await open(factory);
    try {
      return await request(run(db.transaction(BOXES, mode).objectStore(BOXES)));
    } finally {
      db.close();
    }
  }
  async function read(key: string): Promise<string | undefined> {
    const value: unknown = await withStore('readonly', (s) => s.get(key));
    if (value === undefined) return undefined;
    if (typeof value !== 'string') throw new Error('a kept value is damaged');
    return seal.openLocal(key, value);
  }
  async function write(key: string, text: string): Promise<void> {
    const sealed = await seal.sealLocal(key, text);
    await withStore('readwrite', (s) => s.put(sealed, key));
  }
  const store: BoxStore = {
    async load(account, space, key, version) {
      const text = await read(boxKey(account, space, key, version));
      return text === undefined ? undefined : parseBoxRecord(text);
    },
    async save(account, space, key, version, record) {
      await write(boxKey(account, space, key, version), JSON.stringify(record));
      if (record.signed) {
        const kept = await store.newestSigned(account, space, key);
        if (kept === undefined || kept < version) {
          await write(signedKey(account, space, key), String(version));
        }
      }
    },
    async newestSigned(account, space, key) {
      const text = await read(signedKey(account, space, key));
      return text === undefined ? undefined : parseVersion(text);
    },
  };
  return store;
}

/** The store the app uses: IndexedDB where there is one, memory otherwise. */
export function defaultBoxStore(seal: LocalSeal): BoxStore {
  try {
    if (typeof indexedDB !== 'undefined') return indexedDbBoxStore(seal);
  } catch {
    // Falls through to memory.
  }
  return memoryBoxStore();
}
