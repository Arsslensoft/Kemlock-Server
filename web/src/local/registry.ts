// The places this browser keeps values sealed by the worker (`sealLocal`), listed in one place so a
// rotation of the account's root key can move them all to the new keys.
//
// They are sealed under a child of the user key, so after a rotation none of them opens. While the
// worker holds both the old and the new keys, the rotation asks each registered store to open every
// value of the account and seal it again (`resealAll`). A store registers itself when its module
// loads (`registerLocalStore`), and `local/stores.ts` imports the modules that do, so the list the
// app has is that one file's imports. A store that keeps sealed values and is not registered here
// loses them at a rotation, and must read that as "ask again", not as damage.

/** Opens a sealed value under the keys in use now and seals it again under the new keys. */
export type Reseal = (label: string, sealed: string) => Promise<string>;

export interface LocalStore {
  /** A name for the store, unique among them. */
  readonly name: string;
  /**
   * Seals again every value this store keeps for `account` that opens now, through `reseal`. A
   * value that does not open is left as it is (it belongs to another account, or it is damaged).
   */
  resealAll(account: string, reseal: Reseal): Promise<void>;
}

const stores = new Map<string, LocalStore>();

/** Registers a store, replacing one of the same name. Returns what takes it out again. */
export function registerLocalStore(store: LocalStore): () => void {
  stores.set(store.name, store);
  return () => {
    if (stores.get(store.name) === store) stores.delete(store.name);
  };
}

/** The names of the stores registered now. */
export function registeredLocalStores(): string[] {
  return [...stores.keys()];
}

/**
 * Seals again everything every registered store keeps for `account`. A store that fails does not
 * stop the others: its values stay sealed under the old keys, which the store reads as "ask again".
 * Returns the names of the stores that failed.
 */
export async function resealLocalStores(account: string, reseal: Reseal): Promise<string[]> {
  const failed: string[] = [];
  for (const store of [...stores.values()]) {
    try {
      await store.resealAll(account, reseal);
    } catch {
      failed.push(store.name);
    }
  }
  return failed;
}
