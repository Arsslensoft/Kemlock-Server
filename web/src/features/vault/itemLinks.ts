// What the item page adds to the links of links.ts: the websites a code borrows from the login it
// is linked to, and what a move does to the links that name the item it moves. The links
// themselves, the older `linkedLoginId` one included, are read and written by links.ts alone.
//
// No React in here.
import { linkedItems, legacyLink, readLinks, writeLinks } from './links';
import { type ItemData, type VaultItem, itemName } from './vault';
import { readWebsites } from './websites';

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
  for (const other of linkedItems(item, all)) {
    if (other.kind !== 'login') continue;
    const urls = readWebsites(other.data).map((rule) => rule.uri).filter((uri) => uri !== '');
    if (urls.length > 0) return { urls, fromLogin: itemName(other) };
  }
  return undefined;
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
