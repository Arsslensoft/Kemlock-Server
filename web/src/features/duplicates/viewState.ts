// What the Duplicates list was showing (the filter and the selected group), kept for this tab so
// that opening a group to merge it and coming back lands on the same list, not a fresh one.
//
// sessionStorage, not the router: the merge screen is reached and left by plain links, and its
// way back can't know where the person came from. Nothing here is a secret (a filter name and a
// group id), and a damaged or blocked store just means starting from the defaults.

import { KIND_ORDER } from '@/features/vault/kindList';

/** Every item type has its chip, in the order the design fixes; `places` is the groups in two vaults. */
export const DUPLICATE_FILTERS = ['all', ...KIND_ORDER, 'places'] as const;
export type DuplicateFilter = (typeof DUPLICATE_FILTERS)[number];

export interface DuplicatesView {
  filter: DuplicateFilter;
  selectedId: string | undefined;
}

const KEY = 'kemlock.duplicates.view';

export interface ViewStore {
  load(): DuplicatesView;
  save(view: DuplicatesView): void;
}

/** A store over any `Storage`-like object; every access is guarded, since storage may be blocked. */
export function createViewStore(storage: Pick<Storage, 'getItem' | 'setItem'> | undefined): ViewStore {
  return {
    load() {
      const view: DuplicatesView = { filter: 'all', selectedId: undefined };
      try {
        const raw = storage?.getItem(KEY);
        const parsed: unknown = raw ? JSON.parse(raw) : null;
        if (parsed && typeof parsed === 'object') {
          const { filter, selectedId } = parsed as Record<string, unknown>;
          if (DUPLICATE_FILTERS.some((id) => id === filter)) view.filter = filter as DuplicateFilter;
          if (typeof selectedId === 'string') view.selectedId = selectedId;
        }
      } catch {
        // Blocked or damaged storage: start from the defaults.
      }
      return view;
    },
    save(view) {
      try {
        storage?.setItem(KEY, JSON.stringify(view));
      } catch {
        // Not remembered; the list still works.
      }
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

export const duplicatesViewStore = createViewStore(tabStorage());
