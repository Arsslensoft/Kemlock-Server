// What a merge does to the items that point at the items it removes. A link between items is
// two-way (each names the other), so when the items that go to the Trash are folded into the kept one,
// every item that named one of them must name the kept one instead, and every item the kept one now
// links to must link back; an MFA code's `linkedLoginId` and a login's `accountId` follow the item
// that stayed. The Kemlock app does the same for a login's `accountId` (kemlock-core
// duplicate_merge.dart) and puts it back on Undo only while it still holds what the merge wrote.
// Pure, like merge.ts: the writes go in the merge's own batch.
import type { ItemData, VaultItem } from '@/features/vault/vault';
import { stable } from './mergeFill';

/** The vault the merge reads, and whether the person may change an item of it. */
export interface MergeContext {
  /** Every item the vault holds, the trashed ones too: any of them may point at a merged item. */
  all: readonly VaultItem[];
  /** Whether the person may write the item (an item of a space they can only read, they may not). */
  canWrite?: ((item: VaultItem) => boolean) | undefined;
}

/** One item the merge rewrites besides the merged ones, with what it held and what it holds after. */
export interface Relink {
  item: VaultItem;
  /** The members the merge changed, as the item held them (`undefined` for one it didn't hold). */
  before: ItemData;
  /** The same members as the merge writes them. */
  after: ItemData;
}

/** The ids an item links to, lower case. Entries it can't read are ignored. */
export function linkIds(data: ItemData | null | undefined): string[] {
  const list = data?.['links'];
  if (!Array.isArray(list)) return [];
  const ids: string[] = [];
  for (const entry of list) {
    const id = entry && typeof entry === 'object' ? (entry as { id?: unknown }).id : undefined;
    if (typeof id === 'string' && id !== '') ids.push(id.toLowerCase());
  }
  return ids;
}

const idOf = (entry: unknown): string =>
  entry && typeof entry === 'object' && typeof (entry as { id?: unknown }).id === 'string'
    ? (entry as { id: string }).id.toLowerCase()
    : '';

/**
 * An item's `links` with the ids in `drop` taken out and `add` put in: each id once (an entry that
 * carried more than its id keeps it), sorted by id, never the item's own, and `undefined` when none
 * is left, so the member goes.
 */
export function rewriteLinks(item: VaultItem, drop: ReadonlySet<string>, add: string | undefined): unknown[] | undefined {
  const own = item.id.toLowerCase();
  const seen = new Set<string>();
  const out: unknown[] = [];
  const list = Array.isArray(item.data?.['links']) ? (item.data?.['links'] as unknown[]) : [];
  for (const entry of list) {
    const id = idOf(entry);
    if (id === '' || id === own || drop.has(id) || seen.has(id)) continue;
    seen.add(id);
    out.push(entry);
  }
  if (add !== undefined && add.toLowerCase() !== own && !seen.has(add.toLowerCase())) out.push({ id: add });
  out.sort((a, b) => (idOf(a) < idOf(b) ? -1 : idOf(a) > idOf(b) ? 1 : 0));
  return out.length > 0 ? out : undefined;
}

/** The items outside the merge that name one of its items in their links. */
export function itemsNaming(members: ReadonlySet<string>, ctx: MergeContext | undefined): VaultItem[] {
  if (!ctx) return [];
  return ctx.all.filter(
    (item) => !members.has(item.id.toLowerCase()) && item.data !== null && linkIds(item.data).some((id) => members.has(id)),
  );
}

/**
 * The items to rewrite for a merge into `kept`, the others in `trashedIds`. `listed` are the ids the
 * kept item's final links hold. Items the person may not write are left as they are: the kept item
 * still links to them, and the item page reads a link from either end.
 */
export function planRelinks(
  kept: VaultItem,
  trashedIds: ReadonlySet<string>,
  listed: ReadonlySet<string>,
  ctx: MergeContext | undefined,
): Relink[] {
  if (!ctx) return [];
  const members = new Set([...trashedIds, kept.id.toLowerCase()]);
  const relinks: Relink[] = [];
  for (const item of ctx.all) {
    const data = item.data;
    if (data === null || members.has(item.id.toLowerCase())) continue;
    if (ctx.canWrite && !ctx.canWrite(item)) continue;
    const before: ItemData = {};
    const after: ItemData = {};

    const ids = linkIds(data);
    const namesTrashed = ids.some((id) => trashedIds.has(id));
    const namesKept = ids.includes(kept.id.toLowerCase());
    // It named an item that goes, or the kept item now links to it and it doesn't link back.
    if (namesTrashed || (listed.has(item.id.toLowerCase()) && !namesKept)) {
      before['links'] = data['links'];
      after['links'] = rewriteLinks(item, trashedIds, kept.id);
    }

    const login = data['linkedLoginId'];
    if (item.kind === 'otp' && typeof login === 'string' && trashedIds.has(login.toLowerCase())) {
      before['linkedLoginId'] = login;
      after['linkedLoginId'] = kept.id;
    }
    const account = data['accountId'];
    if (item.kind === 'login' && typeof account === 'string' && trashedIds.has(account.toLowerCase())) {
      before['accountId'] = account;
      after['accountId'] = kept.id;
    }
    if (Object.keys(after).length > 0) relinks.push({ item, before, after });
  }
  return relinks;
}

/**
 * What Undo puts back on an item the merge rewrote: each member, but only while it still holds what
 * the merge wrote. An item edited or linked elsewhere since keeps what it holds. `undefined` when
 * nothing is left to put back.
 */
export function undoFields(relink: Relink, held: VaultItem | undefined): ItemData | undefined {
  if (!held || held.data === null) return undefined;
  const fields: ItemData = {};
  for (const key of Object.keys(relink.after)) {
    if (stable(held.data[key]) === stable(relink.after[key])) fields[key] = relink.before[key];
  }
  return Object.keys(fields).length > 0 ? fields : undefined;
}
