// Links between items. An item body may hold `links`, a list of `{ "id": "<item uuid>" }` sorted
// by id, naming the items it is linked to. A link is two-way: A links B when both bodies name each
// other, so linking writes both items in one batch and unlinking removes both ends. An item
// without links has no `links` member at all, so existing items stay byte for byte, and an app
// that doesn't know the member keeps it as it keeps every key it doesn't read.
//
// No React in here: the pure steps are tested with plain items, the write is `saveBatch`.
import type { ItemData, SaveInput, VaultItem } from './vault';
import { isTrashed, itemName } from './vault';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function entryId(entry: unknown): string | undefined {
  if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) return undefined;
  const id = (entry as { id?: unknown }).id;
  return typeof id === 'string' && UUID.test(id) ? id.toLowerCase() : undefined;
}

/** The ids an item links to, sorted. Entries it can't read (no id, not a UUID) are ignored. */
export function readLinks(data: ItemData | null | undefined): string[] {
  const raw = data?.['links'];
  if (!Array.isArray(raw)) return [];
  const ids = new Set<string>();
  for (const entry of raw) {
    const id = entryId(entry);
    if (id) ids.add(id);
  }
  return [...ids].sort();
}

/**
 * The `links` member for `ids`: `{ id }` entries sorted by id, or undefined when there are none
 * (the member is then left out). An entry the body already held keeps whatever else it carried.
 */
export function writeLinks(
  data: ItemData | null | undefined,
  ids: Iterable<string>,
): Array<Record<string, unknown>> | undefined {
  const held = new Map<string, Record<string, unknown>>();
  const raw = data?.['links'];
  if (Array.isArray(raw)) {
    for (const entry of raw) {
      const id = entryId(entry);
      if (id) held.set(id, entry as Record<string, unknown>);
    }
  }
  const sorted = [...new Set([...ids].map((id) => id.toLowerCase()))].sort();
  if (sorted.length === 0) return undefined;
  return sorted.map((id) => held.get(id) ?? { id });
}

/** Whether `item` names `other` in its links. */
export function isLinked(item: VaultItem, other: VaultItem): boolean {
  return readLinks(item.data).includes(other.id.toLowerCase());
}

/** Why two items can't be linked or unlinked, when they can't. */
export class LinkError extends Error {
  constructor(readonly reason: 'same-item' | 'unreadable') {
    super(reason === 'same-item' ? 'an item cannot be linked to itself' : 'an item that cannot be read cannot be changed');
    this.name = 'LinkError';
  }
}

function withLinks(item: VaultItem, ids: string[]): SaveInput {
  return {
    existing: item,
    kind: item.kind,
    owner: item.owner,
    fields: { links: writeLinks(item.data, ids) },
  };
}

function check(a: VaultItem, b: VaultItem): void {
  if (a.id === b.id) throw new LinkError('same-item');
  // Saving an item that couldn't be opened would replace its body with the links alone.
  if (a.data === null || b.data === null) throw new LinkError('unreadable');
}

/**
 * The saves that link `a` and `b`: each item names the other. An end that already does so is left
 * out, so linking twice writes nothing. Write them with `saveBatch`, all or none.
 */
export function linkInputs(a: VaultItem, b: VaultItem): SaveInput[] {
  check(a, b);
  const inputs: SaveInput[] = [];
  if (!isLinked(a, b)) inputs.push(withLinks(a, [...readLinks(a.data), b.id]));
  if (!isLinked(b, a)) inputs.push(withLinks(b, [...readLinks(b.data), a.id]));
  return inputs;
}

/** The saves that unlink `a` and `b`: both ends drop the other, whichever still names it. */
export function unlinkInputs(a: VaultItem, b: VaultItem): SaveInput[] {
  check(a, b);
  const inputs: SaveInput[] = [];
  if (isLinked(a, b)) inputs.push(withLinks(a, readLinks(a.data).filter((id) => id !== b.id.toLowerCase())));
  if (isLinked(b, a)) inputs.push(withLinks(b, readLinks(b.data).filter((id) => id !== a.id.toLowerCase())));
  return inputs;
}

/**
 * The items `item` links to, by name. A link counts when `item` names the other item or the other
 * names `item`, so a half-made link (one end written, the other refused) still shows and can be
 * unlinked. An id with no item behind it (deleted, or in a space this person can't open) is left out.
 */
export function linkedItems(item: VaultItem, all: readonly VaultItem[]): VaultItem[] {
  const own = new Set(readLinks(item.data));
  const found = all.filter(
    (other) => other.id !== item.id && (own.has(other.id.toLowerCase()) || isLinked(other, item)),
  );
  return found.sort((x, y) => itemName(x).localeCompare(itemName(y)) || x.id.localeCompare(y.id));
}

const PICKER_LIMIT = 50;

function haystack(item: VaultItem): string {
  const data = item.data ?? {};
  const parts = [itemName(item)];
  for (const key of ['username', 'issuer', 'label', 'serviceName', 'email', 'company', 'cardholder']) {
    const value = data[key];
    if (typeof value === 'string') parts.push(value);
  }
  for (const key of ['urls', 'websites']) {
    const value = data[key];
    if (Array.isArray(value)) for (const entry of value) if (typeof entry === 'string') parts.push(entry);
  }
  return parts.join('\n').toLowerCase();
}

/**
 * What the picker offers for `item`: items that are not trashed, can be read, aren't `item`, aren't
 * linked to it already and that `canWrite` says this person may change (a link writes both ends).
 * `query` narrows by name, username, website and the like.
 */
export function linkCandidates(
  item: VaultItem,
  all: readonly VaultItem[],
  query: string,
  canWrite: (candidate: VaultItem) => boolean = () => true,
): VaultItem[] {
  const needle = query.trim().toLowerCase();
  const linked = new Set(linkedItems(item, all).map((other) => other.id));
  return all
    .filter(
      (other) =>
        other.id !== item.id &&
        other.data !== null &&
        !isTrashed(other) &&
        !linked.has(other.id) &&
        canWrite(other) &&
        (needle === '' || haystack(other).includes(needle)),
    )
    .sort((x, y) => itemName(x).localeCompare(itemName(y)) || x.id.localeCompare(y.id))
    .slice(0, PICKER_LIMIT);
}
