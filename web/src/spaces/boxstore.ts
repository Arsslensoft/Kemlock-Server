// The key boxes this browser accepted (docs/crypto.md, "Signed key boxes"), kept for the account and
// sealed by its worker the way the chain anchors are (src/spaces/anchors.ts):
//
//  - for each (space, key, version) the SHA-256 of the box it opened, and whether it was signed.
//    A box with that hash is accepted again without asking who sealed it, so a sealer who has since
//    left, or whose account moved to another key version, doesn't lock a member out of a key they
//    already hold; a box that differs is checked afresh, and an unsigned one that differs is refused;
//  - for each space, whether it ever accepted a **signed** box of it: from then on an unsigned box
//    of any key it hadn't already accepted is refused, so a server can't take the signatures away
//    again, or serve an unsigned box of a key it made itself, once any key of the space is signed.
//
// It lives in IndexedDB in a database of its own, each value sealed by the worker under the
// account's user key (`sealLocal`) and bound to its key, so the server can't reach it and a script
// that can write to IndexedDB can't make a value the worker opens. A value that doesn't open is an
// error, never "none". Where IndexedDB isn't available the memory is the page's, and an unsigned box
// is accepted once more next time: safe, only more asking.
import { type Reseal, registerLocalStore } from '@/local/registry';
import type { LocalSeal } from './anchors';

/** What was accepted for one (space, key, version). */
export interface BoxRecord {
  /** Base64url of the SHA-256 of the box. */
  hash: string;
  /** Whether the box carried a valid signature of a member this browser could trace. */
  signed: boolean;
  /**
   * For an unsigned box: a person compared the key's fingerprint with a member who holds it and
   * typed its last group. Until then the key is read but never sealed under or written to.
   */
  compared?: boolean;
}

/** A key of a space: its own key `space`, or a collection's `collection:<uuid>`. */
export type KeyRef = string;

export interface BoxStore {
  load(account: string, space: string, key: KeyRef, version: number): Promise<BoxRecord | undefined>;
  save(account: string, space: string, key: KeyRef, version: number, record: BoxRecord): Promise<void>;
  /** Whether a signed box of any key of this space was ever accepted. */
  hasSigned(account: string, space: string): Promise<boolean>;
}

const DATABASE = 'kemlock-space-boxes';
const BOXES = 'boxes';

const boxKey = (account: string, space: string, key: KeyRef, version: number) =>
  `box/${account}/${space}/${key}/${version}`;
const signedKey = (account: string, space: string) => `signed/${account}/${space}`;

function isRecord(value: unknown): value is BoxRecord {
  if (typeof value !== 'object' || value === null) return false;
  const v = value as Record<string, unknown>;
  return (
    typeof v.hash === 'string' &&
    typeof v.signed === 'boolean' &&
    (v.compared === undefined || typeof v.compared === 'boolean')
  );
}

/** Reads a kept record from its text; anything that isn't one is an error. */
export function parseBoxRecord(text: string): BoxRecord {
  const value: unknown = JSON.parse(text);
  if (!isRecord(value)) throw new Error('the kept key box is damaged');
  return { hash: value.hash, signed: value.signed, ...(value.compared === undefined ? {} : { compared: value.compared }) };
}

/** The accepted boxes in memory: for tests, and the fallback when IndexedDB can't be used. */
export function memoryBoxStore(): BoxStore {
  const records = new Map<string, BoxRecord>();
  const signed = new Set<string>();
  return {
    async load(account, space, key, version) {
      return records.get(boxKey(account, space, key, version));
    },
    async save(account, space, key, version, record) {
      records.set(boxKey(account, space, key, version), record);
      if (record.signed) signed.add(signedKey(account, space));
    },
    async hasSigned(account, space) {
      return signed.has(signedKey(account, space));
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
      if (record.signed) await write(signedKey(account, space), '1');
    },
    async hasSigned(account, space) {
      return (await read(signedKey(account, space))) === '1';
    },
  };
  return store;
}

/** The account a kept key belongs to: its second segment (`box/<account>/…`, `signed/<account>/…`). */
const accountOf = (key: string) => key.split('/')[1];

/**
 * Seals again, through `reseal`, every value kept for `account` in the database of accepted boxes.
 * A value that doesn't open is left as it is. Used by a rotation, while the worker holds both the
 * old and the new keys.
 */
export async function resealBoxStore(factory: IDBFactory, account: string, reseal: Reseal): Promise<void> {
  const db = await open(factory);
  try {
    const keys = await request<IDBValidKey[]>(db.transaction(BOXES, 'readonly').objectStore(BOXES).getAllKeys());
    const values = await request<unknown[]>(db.transaction(BOXES, 'readonly').objectStore(BOXES).getAll());
    const moved: Array<[string, string]> = [];
    for (const [i, key] of keys.entries()) {
      const value = values[i];
      if (typeof key !== 'string' || accountOf(key) !== account || typeof value !== 'string') continue;
      try {
        moved.push([key, await reseal(key, value)]);
      } catch {
        // Doesn't open now: not this account's, or damaged. Left as it is.
      }
    }
    if (moved.length === 0) return;
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(BOXES, 'readwrite');
      const objects = tx.objectStore(BOXES);
      for (const [key, value] of moved) objects.put(value, key);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error ?? new Error('indexeddb'));
      tx.onabort = () => reject(tx.error ?? new Error('indexeddb'));
    });
  } finally {
    db.close();
  }
}

registerLocalStore({
  name: 'space-key-boxes',
  async resealAll(account, reseal) {
    if (typeof indexedDB === 'undefined') return;
    await resealBoxStore(indexedDB, account, reseal);
  },
});

/** The store the app uses: IndexedDB where there is one, memory otherwise. */
export function defaultBoxStore(seal: LocalSeal): BoxStore {
  try {
    if (typeof indexedDB !== 'undefined') return indexedDbBoxStore(seal);
  } catch {
    // Falls through to memory.
  }
  return memoryBoxStore();
}
