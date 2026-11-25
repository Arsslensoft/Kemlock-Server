// What the list pages (All items, a type, Trash, Duplicates) filter by, kept apart from React so it
// is tested with plain items. A vault is the person's own (`personal`) or one space, by its id.
import { isFavorite } from './favorite';
import { readWebsites } from './websites';
import { type VaultItem, itemName, spaceOf } from './vault';

/** The filter value for "All vaults". */
export const ALL_VAULTS = 'all';
/** The filter value for the person's own vault. */
export const PERSONAL = 'personal';

/** The vault an item lives in, as the filter names it: `personal`, or the space's id. */
export function vaultIdOf(owner: string): string {
  return spaceOf(owner) ?? PERSONAL;
}

/** Whether `item` is in the vault the filter picks (`all` picks every one). */
export function inVault(item: Pick<VaultItem, 'owner'>, vault: string): boolean {
  return vault === ALL_VAULTS || vaultIdOf(item.owner) === vault;
}

const SEARCHED_TEXT = ['username', 'email', 'issuer', 'label', 'serviceName', 'company', 'phone'] as const;

/** Whether the search words are in the item's name, username, websites or the like. Never a secret. */
export function matches(item: VaultItem, query: string): boolean {
  const needle = query.trim().toLowerCase();
  if (needle === '') return true;
  const data = item.data;
  const fields: string[] = [itemName(item), item.kind];
  for (const key of SEARCHED_TEXT) {
    const value = data?.[key];
    if (typeof value === 'string') fields.push(value);
  }
  for (const site of readWebsites(data)) fields.push(site.uri);
  return fields.some((field) => field.toLowerCase().includes(needle));
}

export interface ListQuery {
  /** A stored kind id; undefined is every kind. */
  kind?: string | undefined;
  /** `all`, `personal` or a space's id. */
  vault?: string | undefined;
  fav?: boolean | undefined;
  q?: string | undefined;
}

/** The items a list shows for `query`, by name. The type and the vault combine. */
export function filterItems(items: readonly VaultItem[], query: ListQuery): VaultItem[] {
  const { kind, vault = ALL_VAULTS, fav, q = '' } = query;
  return items
    .filter((item) => (kind ? item.kind === kind : true))
    .filter((item) => inVault(item, vault))
    .filter((item) => (fav ? isFavorite(item) : true))
    .filter((item) => matches(item, q))
    .sort((a, b) => itemName(a).localeCompare(itemName(b)));
}

export interface KindCounts {
  /** Every item, of any kind. */
  total: number;
  /** How many of each stored kind id. A kind with none is absent. */
  byKind: Record<string, number>;
}

/** How many items there are in all, and of each kind: what the sidebar shows. */
export function countByKind(items: readonly Pick<VaultItem, 'kind'>[]): KindCounts {
  const byKind: Record<string, number> = {};
  for (const item of items) byKind[item.kind] = (byKind[item.kind] ?? 0) + 1;
  return { total: items.length, byKind };
}

/** The chosen vault if it still exists, else all vaults (a space left, or a stale choice). */
export function knownVault(chosen: string, options: readonly { id: string }[]): string {
  return chosen === ALL_VAULTS || options.some((option) => option.id === chosen) ? chosen : ALL_VAULTS;
}
