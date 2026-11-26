// What this browser remembers about spaces, kept for the account and sealed by its worker:
//
//  - the **anchor** of each space's chain (docs/crypto.md, "Hash link": the `seq` and `epoch` of the
//    last record it accepted, and the link of every record up to it). It is why a server can't roll
//    a chain back, fork it, or serve another one, unnoticed, and its presence says first contact was
//    done for that space, so it is only ever stored after the person compared the fingerprint (or
//    the chain is the account's own);
//  - the **pins**: members whose fingerprint a person compared in this browser. A member's
//    confirmation vouches for another member's keys only when the confirmer is me or a pinned one.
//
// Both live in IndexedDB, in a database of their own, keyed by account and space or member, and
// each value is sealed by the worker under the account's user key (`sealLocal`), bound to its key:
// the server can't reach them, and a script that can write to IndexedDB can't make a value the
// worker opens. A value that doesn't open, or isn't what it should be, is an error, never "none":
// a space whose anchor was damaged is "can't be checked", not a space met for the first time.
//
// Where IndexedDB isn't available (private windows in some browsers) they last until the page
// closes, and first contact and comparisons are asked again next time: safe, only more asking.
import type { ChainAnchor } from '@/crypto/types';

/** What seals and opens a value for the unlocked account: the crypto worker. */
export interface LocalSeal {
  sealLocal(label: string, text: string): Promise<string>;
  openLocal(label: string, sealed: string): Promise<string>;
}

export interface AnchorStore {
  load(account: string, space: string): Promise<ChainAnchor | undefined>;
  /**
   * Replaces the anchor of a space, unless the one kept is further along: an anchor never goes
   * back, except by a fence ("Epochs"), which `afterFence` says this is.
   */
  save(account: string, space: string, anchor: ChainAnchor, afterFence?: boolean): Promise<void>;
  /**
   * Whether this account has ever been served a chain for the space, whether or not first contact
   * was done: a space served with none after that is a chain taken back, not a space with none.
   */
  seen(account: string, space: string): Promise<boolean>;
  markSeen(account: string, space: string): Promise<void>;
}

/** The members a person compared the fingerprint of, here. A pin is a fingerprint, 12 groups of 5 digits. */
export interface PinStore {
  /** The fingerprint pinned for a member, if any. */
  load(account: string, member: string): Promise<string | undefined>;
  /** Pins a member's fingerprint, replacing the one before. */
  save(account: string, member: string, fingerprint: string): Promise<void>;
}

/**
 * The highest revision of each item of an owner that this browser has seen with a valid write
 * signature (docs/crypto.md, "Signed item writes"): an item id to a revision. A newer revision of
 * such an item that comes without a signature is not taken in, after a reload or on a fresh full
 * sync as in the session that saw the signature. It lives beside the anchors, sealed the same way.
 */
export type SignedFloor = Record<string, number>;

export interface FloorStore {
  /** The floor kept for an owner; empty when none is. */
  load(account: string, owner: string): Promise<SignedFloor>;
  save(account: string, owner: string, floor: SignedFloor): Promise<void>;
}

const DATABASE = 'kemlock-space-anchors';
const ANCHORS = 'anchors';
const PINS = 'pins';

const anchorKey = (account: string, space: string) => `anchor/${account}/${space}`;
const seenKey = (account: string, space: string) => `seen/${account}/${space}`;
const pinKey = (account: string, member: string) => `pin/${account}/${member}`;
const floorKey = (account: string, owner: string) => `floor/${account}/${owner}`;

/** Reads a kept floor from its text; anything that isn't one is an error. */
export function parseFloor(text: string): SignedFloor {
  const value: unknown = JSON.parse(text);
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new Error('the kept floor is damaged');
  const floor: SignedFloor = {};
  for (const [id, revision] of Object.entries(value)) {
    if (!Number.isSafeInteger(revision) || (revision as number) < 1) throw new Error('the kept floor is damaged');
    floor[id] = revision as number;
  }
  return floor;
}

/** Whether `kept` is at least as far along as `next`, so `next` must not replace it. */
function further(kept: ChainAnchor | undefined, next: ChainAnchor): boolean {
  return kept !== undefined && kept.seq > next.seq;
}

function isAnchor(value: unknown): value is ChainAnchor {
  if (typeof value !== 'object' || value === null) return false;
  const v = value as Record<string, unknown>;
  return (
    Number.isSafeInteger(v.seq) &&
    Number.isSafeInteger(v.epoch) &&
    Array.isArray(v.links) &&
    v.links.every((link) => typeof link === 'string')
  );
}

/** Reads a kept anchor from its text; anything that isn't one is an error. */
export function parseAnchor(text: string): ChainAnchor {
  const value: unknown = JSON.parse(text);
  if (!isAnchor(value)) throw new Error('the kept anchor is damaged');
  return value;
}

/** The anchors and pins in memory: for tests, and the fallback when IndexedDB can't be used. */
export function memoryStores(): { anchors: AnchorStore; pins: PinStore; floors: FloorStore } {
  const floors = new Map<string, SignedFloor>();
  const anchors = new Map<string, ChainAnchor>();
  const pins = new Map<string, string>();
  const seen = new Set<string>();
  return {
    anchors: {
      async load(account, space) {
        return anchors.get(anchorKey(account, space));
      },
      async save(account, space, anchor, afterFence = false) {
        const key = anchorKey(account, space);
        if (afterFence || !further(anchors.get(key), anchor)) anchors.set(key, anchor);
      },
      async seen(account, space) {
        return seen.has(seenKey(account, space));
      },
      async markSeen(account, space) {
        seen.add(seenKey(account, space));
      },
    },
    pins: {
      async load(account, member) {
        return pins.get(pinKey(account, member));
      },
      async save(account, member, fingerprint) {
        pins.set(pinKey(account, member), fingerprint);
      },
    },
    floors: {
      async load(account, owner) {
        return { ...floors.get(floorKey(account, owner)) };
      },
      async save(account, owner, floor) {
        floors.set(floorKey(account, owner), { ...floor });
      },
    },
  };
}

export function memoryAnchorStore(): AnchorStore {
  return memoryStores().anchors;
}

export function memoryPinStore(): PinStore {
  return memoryStores().pins;
}

export function memoryFloorStore(): FloorStore {
  return memoryStores().floors;
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
      req.result.createObjectStore(ANCHORS);
      req.result.createObjectStore(PINS);
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error ?? new Error('indexeddb'));
    req.onblocked = () => reject(new Error('indexeddb'));
  });
}

/**
 * The anchors and pins in IndexedDB, sealed by `seal`. `factory` is injectable for tests. A read
 * or write that fails, and a value that doesn't open or isn't what it should be, is thrown.
 */
export function indexedDbStores(
  seal: LocalSeal,
  factory: IDBFactory = indexedDB,
): { anchors: AnchorStore; pins: PinStore; floors: FloorStore } {
  async function withStore<T>(
    name: string,
    mode: IDBTransactionMode,
    run: (store: IDBObjectStore) => IDBRequest<T>,
  ): Promise<T> {
    const db = await open(factory);
    try {
      return await request(run(db.transaction(name, mode).objectStore(name)));
    } finally {
      db.close();
    }
  }
  /** The text kept under a key, opened; undefined only when nothing is kept. */
  async function read(store: string, key: string): Promise<string | undefined> {
    const value: unknown = await withStore(store, 'readonly', (s) => s.get(key));
    if (value === undefined) return undefined;
    if (typeof value !== 'string') throw new Error('a kept value is damaged');
    return seal.openLocal(key, value);
  }
  async function write(store: string, key: string, text: string): Promise<void> {
    const sealed = await seal.sealLocal(key, text);
    await withStore(store, 'readwrite', (s) => s.put(sealed, key));
  }
  const anchors: AnchorStore = {
    async load(account, space) {
      const text = await read(ANCHORS, anchorKey(account, space));
      return text === undefined ? undefined : parseAnchor(text);
    },
    async save(account, space, anchor, afterFence = false) {
      if (!afterFence && further(await this.load(account, space), anchor)) return;
      await write(ANCHORS, anchorKey(account, space), JSON.stringify(anchor));
    },
    async seen(account, space) {
      return (await read(ANCHORS, seenKey(account, space))) === '1';
    },
    async markSeen(account, space) {
      await write(ANCHORS, seenKey(account, space), '1');
    },
  };
  const pins: PinStore = {
    load: (account, member) => read(PINS, pinKey(account, member)),
    save: (account, member, fingerprint) => write(PINS, pinKey(account, member), fingerprint),
  };
  const floors: FloorStore = {
    async load(account, owner) {
      const text = await read(ANCHORS, floorKey(account, owner));
      return text === undefined ? {} : parseFloor(text);
    },
    save: (account, owner, floor) => write(ANCHORS, floorKey(account, owner), JSON.stringify(floor)),
  };
  return { anchors, pins, floors };
}

/** The stores the app uses: IndexedDB where there is one, memory otherwise. */
export function defaultStores(seal: LocalSeal): { anchors: AnchorStore; pins: PinStore; floors: FloorStore } {
  try {
    if (typeof indexedDB !== 'undefined') return indexedDbStores(seal);
  } catch {
    // Falls through to memory.
  }
  return memoryStores();
}
