// What this browser remembers of each space's chain: the anchor (docs/crypto.md, "Hash link":
// the `seq` and `epoch` of the last record it accepted, and the link of every record up to it).
// The anchor is why a server can't roll a chain back, fork it, or serve another one, unnoticed,
// and its presence says first contact was done for that space, so it is only ever stored after the
// person compared the fingerprint (or the chain is the account's own).
//
// It lives in IndexedDB, in a database of its own, keyed by account and space: the server can't
// reach it, and a different account on the same browser has its own. Where IndexedDB isn't
// available (private windows in some browsers) the anchor lasts until the page closes, and first
// contact is asked again next time: safe, only more asking.
import type { ChainAnchor } from '@/crypto/types';

export interface AnchorStore {
  load(account: string, space: string): Promise<ChainAnchor | undefined>;
  /**
   * Replaces the anchor of a space, unless the one kept is further along: an anchor never goes
   * back, except by a fence ("Epochs"), which `afterFence` says this is.
   */
  save(account: string, space: string, anchor: ChainAnchor, afterFence?: boolean): Promise<void>;
}

const DATABASE = 'kemlock-space-anchors';
const STORE = 'anchors';

function keyOf(account: string, space: string): string {
  return `${account}/${space}`;
}

/** Whether `kept` is at least as far along as `next`, so `next` must not replace it. */
function further(kept: ChainAnchor | undefined, next: ChainAnchor): boolean {
  return kept !== undefined && kept.seq > next.seq;
}

/** An anchor store in memory: for tests, and the fallback when IndexedDB can't be used. */
export function memoryAnchorStore(): AnchorStore {
  const kept = new Map<string, ChainAnchor>();
  return {
    async load(account, space) {
      return kept.get(keyOf(account, space));
    },
    async save(account, space, anchor, afterFence = false) {
      const key = keyOf(account, space);
      if (afterFence || !further(kept.get(key), anchor)) kept.set(key, anchor);
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
    req.onupgradeneeded = () => req.result.createObjectStore(STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error ?? new Error('indexeddb'));
    req.onblocked = () => reject(new Error('indexeddb'));
  });
}

function isAnchor(value: unknown): value is ChainAnchor {
  if (typeof value !== 'object' || value === null) return false;
  const v = value as Record<string, unknown>;
  return (
    typeof v.seq === 'number' &&
    typeof v.epoch === 'number' &&
    Array.isArray(v.links) &&
    v.links.every((link) => typeof link === 'string')
  );
}

/**
 * The anchors in IndexedDB. `factory` is injectable for tests. A read or write that fails is not
 * hidden: a space whose anchor can't be read is "can't be checked", and one that can't be stored
 * asks for first contact again.
 */
export function indexedDbAnchorStore(factory: IDBFactory = indexedDB): AnchorStore {
  async function withStore<T>(
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
  return {
    async load(account, space) {
      const value: unknown = await withStore('readonly', (s) => s.get(keyOf(account, space)));
      return isAnchor(value) ? value : undefined;
    },
    async save(account, space, anchor, afterFence = false) {
      const kept = await this.load(account, space);
      if (!afterFence && further(kept, anchor)) return;
      await withStore('readwrite', (s) => s.put(anchor, keyOf(account, space)));
    },
  };
}

/** The store the app uses: IndexedDB where there is one, memory otherwise. */
export function defaultAnchorStore(): AnchorStore {
  try {
    if (typeof indexedDB !== 'undefined') return indexedDbAnchorStore();
  } catch {
    // Falls through to memory.
  }
  return memoryAnchorStore();
}
