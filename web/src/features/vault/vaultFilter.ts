// The Vault filter of each list page ("All vaults", "Personal" or a space), kept for this tab so it
// survives a click on a sidebar link: those lead to the same page with another type, and the filter
// is the person's, not the address's.
//
// sessionStorage, as the Duplicates view is: nothing here is a secret (a vault id), and a blocked
// or damaged store just means starting at "All vaults".
import { useCallback, useSyncExternalStore } from 'react';
import { ALL_VAULTS } from './listFilters';

export type FilterPage = 'items' | 'trash' | 'duplicates';

const KEY = 'kemlock.vault.filter';

export interface VaultFilterStore {
  get(page: FilterPage): string;
  set(page: FilterPage, vault: string): void;
  subscribe(listener: () => void): () => void;
}

/** A store over any `Storage`-like object; every access is guarded, since storage may be blocked. */
export function createVaultFilterStore(
  storage: Pick<Storage, 'getItem' | 'setItem'> | undefined,
): VaultFilterStore {
  let chosen: Partial<Record<FilterPage, string>> | undefined;
  const listeners = new Set<() => void>();

  function load(): Partial<Record<FilterPage, string>> {
    if (chosen) return chosen;
    chosen = {};
    try {
      const raw = storage?.getItem(KEY);
      const parsed: unknown = raw ? JSON.parse(raw) : null;
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        for (const page of ['items', 'trash', 'duplicates'] as const) {
          const value = (parsed as Record<string, unknown>)[page];
          if (typeof value === 'string' && value !== '') chosen[page] = value;
        }
      }
    } catch {
      // Blocked or damaged storage: start at "All vaults".
    }
    return chosen;
  }

  return {
    get: (page) => load()[page] ?? ALL_VAULTS,
    set(page, vault) {
      const current = load();
      if ((current[page] ?? ALL_VAULTS) === vault) return;
      if (vault === ALL_VAULTS) delete current[page];
      else current[page] = vault;
      try {
        storage?.setItem(KEY, JSON.stringify(current));
      } catch {
        // Not remembered across a reload; this page keeps it.
      }
      for (const listener of listeners) listener();
    },
    subscribe(listener) {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
  };
}

function tabStorage(): Storage | undefined {
  try {
    return window.sessionStorage;
  } catch {
    return undefined;
  }
}

export const vaultFilterStore = createVaultFilterStore(tabStorage());

/** The page's Vault filter and how to change it. */
export function useVaultFilter(
  page: FilterPage,
  store: VaultFilterStore = vaultFilterStore,
): [string, (vault: string) => void] {
  const vault = useSyncExternalStore(
    store.subscribe,
    () => store.get(page),
    () => ALL_VAULTS,
  );
  const set = useCallback((next: string) => store.set(page, next), [store, page]);
  return [vault, set];
}
