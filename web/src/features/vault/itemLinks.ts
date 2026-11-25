// What the item page adds to the links of links.ts: the older link the importer makes. A code made
// from a login's TOTP names that login in `linkedLoginId`, one way. The page shows it as a link,
// on the code and (the reverse side) on the login, unlinking clears it, and a move rewrites it.
//
// Built on `readLinks` and `writeLinks` only, so it works with whichever links.ts is in the build.
// No React in here.
import { LinkError, linkCandidates, readLinks, writeLinks } from './links';
import { type ItemData, type SaveInput, type VaultItem, itemName } from './vault';
import { readWebsites } from './websites';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** The login `linkedLoginId` names, as a lower-case id. */
export function legacyLink(data: ItemData | null | undefined): string | undefined {
  const id = data?.['linkedLoginId'];
  return typeof id === 'string' && UUID.test(id) ? id.toLowerCase() : undefined;
}

/** Every id a body names, by `links` and by `linkedLoginId`. */
export function namedIds(data: ItemData | null | undefined): string[] {
  const ids = new Set(readLinks(data));
  const legacy = legacyLink(data);
  if (legacy) ids.add(legacy);
  return [...ids].sort();
}

/** Whether `item` names the item with id `otherId`. */
export function namesItem(item: VaultItem, otherId: string): boolean {
  return namedIds(item.data).includes(otherId.toLowerCase());
}

/**
 * The items connected to `item`, by name: the ones it names and the ones that name it, by `links` or
 * by `linkedLoginId`. A half-made link still shows, so it can be unlinked. An id with no item behind
 * it (deleted, or in a space this person can't open) is left out.
 */
export function connectedItems(item: VaultItem, all: readonly VaultItem[]): VaultItem[] {
  const mine = new Set(namedIds(item.data));
  return all
    .filter((other) => other.id !== item.id && (mine.has(other.id.toLowerCase()) || namesItem(other, item.id)))
    .sort((x, y) => itemName(x).localeCompare(itemName(y)) || x.id.localeCompare(y.id));
}

/** The websites an item shows, and the login they come from when they are not its own. */
export interface SiteInfo {
  urls: string[];
  /** The name of the linked login the websites belong to; absent for the item's own. */
  fromLogin?: string | undefined;
}

/**
 * The websites of an MFA code or backup codes: their own (`uris`, `websites` or `urls`), else the
 * websites of a login they are linked to, which only that login changes. Undefined when there are none.
 */
export function siteInfoOf(item: VaultItem, all: readonly VaultItem[]): SiteInfo | undefined {
  const own = readWebsites(item.data).map((rule) => rule.uri).filter((uri) => uri !== '');
  if (own.length > 0) return { urls: own };
  for (const other of connectedItems(item, all)) {
    if (other.kind !== 'login') continue;
    const urls = readWebsites(other.data).map((rule) => rule.uri).filter((uri) => uri !== '');
    if (urls.length > 0) return { urls, fromLogin: itemName(other) };
  }
  return undefined;
}

/** What the picker offers: `linkCandidates`, without the items already connected the older way. */
export function pickableItems(
  item: VaultItem,
  all: readonly VaultItem[],
  query: string,
  canWrite: (candidate: VaultItem) => boolean,
): VaultItem[] {
  const connected = new Set(connectedItems(item, all).map((other) => other.id));
  return linkCandidates(item, all, query, canWrite).filter((candidate) => !connected.has(candidate.id));
}

function without(item: VaultItem, otherId: string): SaveInput {
  const id = otherId.toLowerCase();
  const fields: ItemData = { links: writeLinks(item.data, readLinks(item.data).filter((held) => held !== id)) };
  if (legacyLink(item.data) === id) fields['linkedLoginId'] = undefined;
  return { existing: item, kind: item.kind, owner: item.owner, fields };
}

/**
 * The saves that unlink `a` and `b`: each end that names the other drops it, whether by `links` or
 * by `linkedLoginId`. Write them together, all or none.
 */
export function unlinkPair(a: VaultItem, b: VaultItem): SaveInput[] {
  if (a.id === b.id) throw new LinkError('same-item');
  // Saving an item that couldn't be opened would replace its body with the links alone.
  if (a.data === null || b.data === null) throw new LinkError('unreadable');
  const inputs: SaveInput[] = [];
  if (namesItem(a, b.id)) inputs.push(without(a, b.id));
  if (namesItem(b, a.id)) inputs.push(without(b, a.id));
  return inputs;
}

/**
 * The fields that make `other` name `newId` where it named `oldId`, or undefined when it names
 * `oldId` neither way. A move gives an item a new id; this keeps the links to it.
 */
export function renamedLinkFields(other: VaultItem, oldId: string, newId: string): ItemData | undefined {
  const old = oldId.toLowerCase();
  const fields: ItemData = {};
  const ids = readLinks(other.data);
  if (ids.includes(old)) fields['links'] = writeLinks(other.data, [...ids.filter((held) => held !== old), newId]);
  if (legacyLink(other.data) === old) fields['linkedLoginId'] = newId;
  return Object.keys(fields).length > 0 ? fields : undefined;
}
