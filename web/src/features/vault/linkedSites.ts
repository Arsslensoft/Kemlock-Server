// The websites of an MFA code or a set of backup codes. A code lives beside a login, and the login
// already says where it is used, so a code linked to an item that has websites shows those
// read-only ("Change it there"); only the original item edits them. Unlinked, the code has a
// website field of its own, stored as `websites`, the list of hosts the Kemlock app writes on a
// code (kemlock-core `OtpAccount.websites`).
import { hostOfWebsite } from '@/lib/psl';
import type { ItemData, VaultItem } from './vault';
import { type WebsiteRule, readWebsites, writeWebsites } from './websites';

function fillsOnHost(rule: WebsiteRule): boolean {
  return rule.match !== 'regex' && rule.match !== 'never' && hostOfWebsite(rule.uri) !== '';
}

/** The hosts an item's websites fill on, each once, in order. */
export function hostsOfItem(data: ItemData | null | undefined): string[] {
  const hosts = new Set<string>();
  for (const rule of readWebsites(data)) if (fillsOnHost(rule)) hosts.add(hostOfWebsite(rule.uri));
  return [...hosts];
}

export interface LinkedWebsites {
  /** The hosts of the linked items that have websites. */
  hosts: string[];
  /** Those items, in the order they are linked. */
  sources: VaultItem[];
}

/** What the linked items lend: nothing (undefined) when none of them has a website. */
export function linkedWebsites(links: readonly string[], items: readonly VaultItem[]): LinkedWebsites | undefined {
  const byId = new Map(items.map((item) => [item.id.toLowerCase(), item]));
  const sources: VaultItem[] = [];
  const hosts = new Set<string>();
  for (const id of links) {
    const item = byId.get(id.toLowerCase());
    if (!item) continue;
    const own = hostsOfItem(item.data);
    if (own.length === 0) continue;
    sources.push(item);
    for (const host of own) hosts.add(host);
  }
  return sources.length > 0 ? { hosts: [...hosts], sources } : undefined;
}

/** The hosts typed in the field, split at commas, semicolons, spaces and lines; each once. */
export function parseHosts(text: string): string[] {
  const hosts = new Set<string>();
  for (const part of text.split(/[\s,;]+/)) {
    const host = hostOfWebsite(part);
    if (host !== '') hosts.add(host);
  }
  return [...hosts];
}

/** The field's text for an item: its hosts, comma separated. */
export function hostsText(data: ItemData | null | undefined): string {
  return hostsOfItem(data).join(', ');
}

/**
 * The `websites` member (and `uris`, when the item has rules) for the hosts typed. A rule the item
 * had for a host that is still listed keeps its match; a rule that fills on no host (a regular
 * expression, Never) stays.
 */
export function websiteFields(text: string, existing: ItemData | null | undefined): ItemData {
  const hosts = parseHosts(text);
  if (!Array.isArray(existing?.['uris'])) return { websites: hosts.length > 0 ? hosts : undefined };
  const rules = readWebsites(existing);
  const next: WebsiteRule[] = hosts.map(
    (host) =>
      rules.find((rule) => fillsOnHost(rule) && hostOfWebsite(rule.uri) === host) ?? { uri: host, match: 'default' },
  );
  const written = writeWebsites([...next, ...rules.filter((rule) => !fillsOnHost(rule))]);
  return {
    websites: written.websites.length > 0 ? written.websites : undefined,
    uris: written.uris.length > 0 ? written.uris : undefined,
  };
}
