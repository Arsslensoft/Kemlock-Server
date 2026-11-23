// "Not duplicates": the groups a person said are not duplicates, remembered in this browser only.
//
// Decision: not in the vault. A vault item of a made-up kind would show up as an "other" row in
// every Kemlock, Bitwarden and Amethystora app, and no other app would read it as a dismissal. So
// the dismissed groups are a set of item ids (never a value) in localStorage. Another browser asks
// again. The canvas's "on every app" is a later step that needs a kind every app agrees on.

const KEY = 'kemlock.duplicates.dismissed';

export interface DismissedStore {
  has(groupId: string): boolean;
  add(groupId: string): void;
  remove(groupId: string): void;
  all(): string[];
}

/** A store over any `Storage`-like object; every access is guarded, since storage may be blocked. */
export function createDismissedStore(
  storage: Pick<Storage, 'getItem' | 'setItem'> | undefined,
  key: string = KEY,
): DismissedStore {
  let memory = new Set<string>();
  let loaded = false;

  function load(): Set<string> {
    if (loaded) return memory;
    loaded = true;
    try {
      const raw = storage?.getItem(key);
      const parsed: unknown = raw ? JSON.parse(raw) : [];
      if (Array.isArray(parsed)) {
        memory = new Set(parsed.filter((id): id is string => typeof id === 'string'));
      }
    } catch {
      // Blocked or damaged storage: the set lives in memory for this page.
    }
    return memory;
  }

  function save(): void {
    try {
      storage?.setItem(key, JSON.stringify([...memory]));
    } catch {
      // Keep the in-memory set.
    }
  }

  return {
    has: (id) => load().has(id),
    add(id) {
      load().add(id);
      save();
    },
    remove(id) {
      load().delete(id);
      save();
    },
    all: () => [...load()],
  };
}

export function browserStorage(): Storage | undefined {
  try {
    return window.localStorage;
  } catch {
    return undefined;
  }
}

export const dismissedGroups = createDismissedStore(browserStorage());
