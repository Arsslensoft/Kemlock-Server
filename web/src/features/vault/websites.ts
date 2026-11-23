// A login's websites, each with its own match rule. The item JSON holds them the way the
// Kemlock app writes them (mobile/test/fixtures/logins/sync-with-uris.json): `uris` is a list of
// `{ uri, match? }` where `match` is Bitwarden's rule number (absent is Default), and `websites`
// lists the hosts. The web vault's own `urls` is kept in step so older readers still see them.
// Reading tolerates any of the three.
import type { MessageId } from '@/i18n';
import { hostOfWebsite, registrableDomain } from '@/lib/psl';
import type { ItemData } from './vault';

export type MatchRule = 'default' | 'domain' | 'host' | 'exact' | 'startsWith' | 'regex' | 'never';

export const MATCH_RULES: MatchRule[] = [
  'default',
  'domain',
  'host',
  'exact',
  'never',
  'startsWith',
  'regex',
];

export interface WebsiteRule {
  uri: string;
  match: MatchRule;
}

const NUMBERS: Record<Exclude<MatchRule, 'default'>, number> = {
  domain: 0,
  host: 1,
  startsWith: 2,
  exact: 3,
  regex: 4,
  never: 5,
};

function ruleOfNumber(value: unknown): MatchRule {
  if (typeof value === 'number') {
    const found = (Object.keys(NUMBERS) as Array<keyof typeof NUMBERS>).find(
      (k) => NUMBERS[k] === value,
    );
    return found ?? 'default';
  }
  if (typeof value === 'string' && (MATCH_RULES as string[]).includes(value)) {
    return value as MatchRule;
  }
  return 'default';
}

function strings(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === 'string') : [];
}

/** The websites of a login, from whichever form its JSON holds. */
export function readWebsites(data: ItemData | null | undefined): WebsiteRule[] {
  if (!data) return [];
  const uris = data['uris'];
  if (Array.isArray(uris)) {
    const out: WebsiteRule[] = [];
    for (const entry of uris) {
      if (typeof entry === 'string') {
        out.push({ uri: entry, match: 'default' });
      } else if (entry && typeof entry === 'object') {
        const record = entry as Record<string, unknown>;
        const uri = record['uri'];
        if (typeof uri === 'string') out.push({ uri, match: ruleOfNumber(record['match']) });
      }
    }
    return out;
  }
  const urls = strings(data['urls']);
  const list = urls.length > 0 ? urls : strings(data['websites']);
  return list.map((uri) => ({ uri, match: 'default' as const }));
}

/** The fields to merge into the item: the three forms, in step. A blank website is dropped. */
export function writeWebsites(rules: WebsiteRule[]): {
  uris: Array<{ uri: string; match?: number }>;
  urls: string[];
  websites: string[];
} {
  const kept = rules.map((r) => ({ ...r, uri: r.uri.trim() })).filter((r) => r.uri !== '');
  const hosts = new Set<string>();
  for (const rule of kept) {
    if (rule.match === 'regex') continue;
    const host = hostOfWebsite(rule.uri);
    if (host !== '') hosts.add(host);
  }
  return {
    uris: kept.map((r) =>
      r.match === 'default' ? { uri: r.uri } : { uri: r.uri, match: NUMBERS[r.match] },
    ),
    urls: kept.filter((r) => r.match !== 'regex').map((r) => r.uri),
    websites: [...hosts],
  };
}

export interface Hint {
  id: MessageId;
  values?: Record<string, string>;
}

/** What a rule does with this address, in words. */
export function hintOf(rule: WebsiteRule): Hint {
  const host = hostOfWebsite(rule.uri);
  if (host === '' && rule.match !== 'regex') return { id: 'sites.hint.empty' };
  const base = registrableDomain(host);
  switch (rule.match) {
    case 'domain':
      return { id: 'sites.hint.domain', values: { domain: base } };
    case 'host':
      return { id: 'sites.hint.host', values: { host } };
    case 'exact':
      return { id: 'sites.hint.exact', values: { host } };
    case 'startsWith':
      return { id: 'sites.hint.startsWith', values: { host } };
    case 'regex':
      return { id: 'sites.hint.regex' };
    case 'never':
      return { id: 'sites.hint.never' };
    default:
      return { id: 'sites.hint.default', values: { domain: base } };
  }
}

/** The rules Bitwarden calls dangerous when used carelessly. */
export function isRisky(rule: MatchRule): boolean {
  return rule === 'startsWith' || rule === 'regex';
}

/** The domains a phone's AutoFill offers this login on: it sees only a site's host. */
export function phoneDomains(rules: WebsiteRule[]): string[] {
  const out: string[] = [];
  for (const rule of rules) {
    const host = hostOfWebsite(rule.uri);
    if (host === '' || rule.match === 'never' || rule.match === 'regex') continue;
    const wide = rule.match === 'domain' || rule.match === 'default';
    const entry = wide ? registrableDomain(host) : host;
    if (!out.includes(entry)) out.push(entry);
  }
  return out;
}

const RULE_LABELS: Record<MatchRule, MessageId> = {
  default: 'sites.rule.default',
  domain: 'sites.rule.domain',
  host: 'sites.rule.host',
  exact: 'sites.rule.exact',
  never: 'sites.rule.never',
  startsWith: 'sites.rule.startsWith',
  regex: 'sites.rule.regex',
};

export function ruleLabel(rule: MatchRule): MessageId {
  return RULE_LABELS[rule];
}
