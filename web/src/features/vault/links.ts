// Links between items. An item body may hold `links`, a list of `{ "id": "<item uuid>" }` sorted
// by id, naming the items it is linked to. A link is two-way: A links B when both bodies name each
// other, so linking writes both items and unlinking removes both ends. An item without links has
// no `links` member at all, so existing items stay byte for byte, and an app that doesn't know the
// member keeps it as it keeps every key it doesn't read (docs/crypto.md, "Item bodies").
//
// One older link is read too: a code the importer made from a login's TOTP names that login in
// `linkedLoginId`. It counts as a link on both sides (the login shows the code), unlinking clears
// it, and it is never copied into `links`.
//
// This is the one place the member is read and written: the item forms, the item page and the
// batch writes all use it. No React in here: the pure steps are tested with plain items.
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

/** The login a code names in `linkedLoginId` (the importer wrote it), when it is an item id. */
export function legacyLink(data: ItemData | null | undefined): string | undefined {
  const id = data?.['linkedLoginId'];
  return typeof id === 'string' && UUID.test(id) ? id.toLowerCase() : undefined;
}

/** Every id the body links to: its `links`, and the login in `linkedLoginId`. Sorted, each once. */
export function linksOf(data: ItemData | null | undefined): string[] {
  const ids = new Set(readLinks(data));
  const legacy = legacyLink(data);
  if (legacy !== undefined) ids.add(legacy);
  return [...ids].sort();
}

/**
 * The `links` member for `ids`: `{ id }` entries sorted by id, or undefined when there are none
 * (the member is then left out). An entry the body already held keeps whatever else it carried,
 * and an entry this code can't read (another shape, no id) stays, after the others.
 */
export function writeLinks(
  data: ItemData | null | undefined,
  ids: Iterable<string>,
): Array<Record<string, unknown>> | undefined {
  const held = new Map<string, Record<string, unknown>>();
  const unread: unknown[] = [];
  const raw = data?.['links'];
  if (Array.isArray(raw)) {
    for (const entry of raw) {
      const id = entryId(entry);
      if (id) held.set(id, entry as Record<string, unknown>);
      else unread.push(entry);
    }
  }
  const sorted = [...new Set([...ids].map((id) => id.toLowerCase()))].sort();
  const out = [...sorted.map((id) => held.get(id) ?? { id }), ...unread] as Array<Record<string, unknown>>;
  return out.length > 0 ? out : undefined;
}

/** Whether `item` names `other`, in its links or as the login of a code. */
export function isLinked(item: VaultItem, other: VaultItem): boolean {
  return linksOf(item.data).includes(other.id.toLowerCase());
}

/** Why two items can't be linked or unlinked, when they can't. */
export class LinkError extends Error {
  constructor(readonly reason: 'same-item' | 'unreadable') {
    super(reason === 'same-item' ? 'an item cannot be linked to itself' : 'an item that cannot be read cannot be changed');
    this.name = 'LinkError';
  }
}

/** The save that makes `item` name `other`. */
function naming(item: VaultItem, other: VaultItem): SaveInput {
  return {
    existing: item,
    kind: item.kind,
    owner: item.owner,
    fields: { links: writeLinks(item.data, [...readLinks(item.data), other.id]) },
  };
}

/** The save that makes `item` stop naming `other`: out of its links, and out of `linkedLoginId` too. */
function dropping(item: VaultItem, other: VaultItem): SaveInput {
  const self = other.id.toLowerCase();
  const fields: ItemData = { links: writeLinks(item.data, readLinks(item.data).filter((id) => id !== self)) };
  if (legacyLink(item.data) === self) fields['linkedLoginId'] = undefined;
  return { existing: item, kind: item.kind, owner: item.owner, fields };
}

function check(a: VaultItem, b: VaultItem): void {
  if (a.id === b.id) throw new LinkError('same-item');
  // Saving an item that couldn't be opened would replace its body with the links alone.
  if (a.data === null || b.data === null) throw new LinkError('unreadable');
}

/**
 * The saves that link `a` and `b`: each item names the other. An end that already does so is left
 * out, so linking twice writes nothing. Write them together, all or none.
 */
export function linkInputs(a: VaultItem, b: VaultItem): SaveInput[] {
  check(a, b);
  const inputs: SaveInput[] = [];
  if (!isLinked(a, b)) inputs.push(naming(a, b));
  if (!isLinked(b, a)) inputs.push(naming(b, a));
  return inputs;
}

/** The saves that unlink `a` and `b`: both ends drop the other, whichever still names it. */
export function unlinkInputs(a: VaultItem, b: VaultItem): SaveInput[] {
  check(a, b);
  const inputs: SaveInput[] = [];
  if (isLinked(a, b)) inputs.push(dropping(a, b));
  if (isLinked(b, a)) inputs.push(dropping(b, a));
  return inputs;
}

/**
 * The items `item` links to, by name. A link counts when `item` names the other item or the other
 * names `item`, so a half-made link (one end written, the other refused) still shows and can be
 * unlinked. An id with no item behind it (deleted, or in a space this person can't open) is left out.
 */
export function linkedItems(item: VaultItem, all: readonly VaultItem[]): VaultItem[] {
  const own = new Set(linksOf(item.data));
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
  const linked = new Set(linkedItems(item, all).map((other) => other.id.toLowerCase()));
  return pick(all, { selfId: item.id, taken: linked, query, canWrite });
}

interface PickOptions {
  selfId: string | undefined;
  taken: ReadonlySet<string>;
  query: string;
  canWrite: (candidate: VaultItem) => boolean;
}

function pick(all: readonly VaultItem[], { selfId, taken, query, canWrite }: PickOptions): VaultItem[] {
  const needle = query.trim().toLowerCase();
  return all
    .filter(
      (other) =>
        other.id !== selfId &&
        other.data !== null &&
        !isTrashed(other) &&
        !taken.has(other.id.toLowerCase()) &&
        canWrite(other) &&
        (needle === '' || haystack(other).includes(needle)),
    )
    .sort((x, y) => itemName(x).localeCompare(itemName(y)) || x.id.localeCompare(y.id))
    .slice(0, PICKER_LIMIT);
}

/**
 * What the form's picker offers: the same as `linkCandidates`, for an item that may not exist yet
 * (`selfId` is undefined while it is new) and with the ids the form has chosen so far.
 */
export function formLinkCandidates(
  all: readonly VaultItem[],
  options: {
    selfId?: string | undefined;
    chosen: readonly string[];
    query: string;
    canWrite?: (candidate: VaultItem) => boolean;
  },
): VaultItem[] {
  return pick(all, {
    selfId: options.selfId,
    taken: new Set(options.chosen.map((id) => id.toLowerCase())),
    query: options.query,
    canWrite: options.canWrite ?? (() => true),
  });
}

/**
 * The ids an item links to as a form shows them: its `links` and the login of a code the importer
 * made (`linkedLoginId`), so that link can be seen and removed too.
 */
export function formLinks(data: ItemData | null | undefined): string[] {
  return linksOf(data);
}

/**
 * The ids of the items that name `selfId` as the login of a code (`linkedLoginId`). The login's
 * own body doesn't say so, so its form is given these to show the codes linked to it.
 */
export function incomingLinks(selfId: string, all: readonly VaultItem[]): string[] {
  const self = selfId.toLowerCase();
  return all
    .filter((other) => other.id.toLowerCase() !== self && legacyLink(other.data) === self)
    .map((other) => other.id.toLowerCase())
    .sort();
}

/**
 * The fields a form writes for the links it holds: `links` (left out when none, and any entry it
 * can't read kept), and `linkedLoginId` dropped when the person unlinked that login. The login of
 * a code stays in `linkedLoginId` and is not copied into `links`, unless `links` held it already.
 */
export function linksFields(existing: ItemData | null | undefined, ids: readonly string[]): ItemData {
  const kept = new Set(ids.map((id) => id.toLowerCase()));
  const legacy = legacyLink(existing);
  const own = new Set(readLinks(existing));
  const written = [...kept].filter((id) => id !== legacy || own.has(id));
  const fields: ItemData = { links: writeLinks(existing, written) };
  if (legacy !== undefined && !kept.has(legacy)) fields['linkedLoginId'] = undefined;
  return fields;
}

export interface LinkWrite {
  /** The other end, as it is now. */
  item: VaultItem;
  /** The `links` it must hold. */
  links: string[];
  /** It names this item in `linkedLoginId`, which goes too. */
  clearLegacy: boolean;
}

/** The fields to save for a planned write: its `links`, and `linkedLoginId` cleared when it must be. */
export function linkWriteFields(write: LinkWrite): ItemData {
  const fields: ItemData = { links: writeLinks(write.item.data, write.links) };
  if (write.clearLegacy) fields['linkedLoginId'] = undefined;
  return fields;
}

/**
 * The writes that make the links of `selfId` two-way: each id it now links to must name it, and each
 * id it linked to when the form opened and no longer does must not (its `linkedLoginId` included).
 * An end that is right already is left out, so a retry only does what is left. An item that isn't
 * in the vault (it was deleted) or can't be read is skipped.
 */
export function planLinkWrites(
  selfId: string,
  before: readonly string[],
  after: readonly string[],
  lookup: (id: string) => VaultItem | undefined,
): LinkWrite[] {
  const self = selfId.toLowerCase();
  const now = new Set(after.map((id) => id.toLowerCase()));
  const was = new Set(before.map((id) => id.toLowerCase()));
  const writes: LinkWrite[] = [];
  const consider = (id: string, wanted: boolean) => {
    if (id === self) return;
    const item = lookup(id);
    if (!item || item.data === null) return;
    if (linksOf(item.data).includes(self) === wanted) return;
    const held = readLinks(item.data);
    writes.push(
      wanted
        ? { item, links: [...held, self], clearLegacy: false }
        : { item, links: held.filter((other) => other !== self), clearLegacy: legacyLink(item.data) === self },
    );
  };
  for (const id of now) consider(id, true);
  for (const id of was) if (!now.has(id)) consider(id, false);
  return writes;
}
