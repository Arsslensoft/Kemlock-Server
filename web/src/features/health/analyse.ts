// Vault health, worked out in this browser from the opened vault. The server never learns which
// items have a problem; the one network check (hibp.ts) sends only a 5-character hash prefix.
import type { MessageId } from '@/i18n';
import { hostOfWebsite } from '@/lib/psl';
import { passwordStrength } from '@/lib/password';
import { normaliseSite } from '@/features/duplicates/normalise';
import { type VaultItem, itemName, loginOf } from '@/features/vault/vault';
import { readWebsites } from '@/features/vault/websites';

export type IssueKind = 'exposed' | 'reused' | 'weak' | 'noCode' | 'expiring';
export type Severity = 'bad' | 'warn';

export interface Issue {
  /** Stable across runs, so "dealt with" sticks: the kind and the item ids. */
  id: string;
  kind: IssueKind;
  severity: Severity;
  itemIds: string[];
  /** The item, or what the issue is about. */
  title: string;
  detail: { id: MessageId; values: Record<string, string | number> };
}

/** Services that offer two-step login and are common enough to name. Local, and short on purpose. */
export const TWO_STEP_SITES = [
  'dropbox.com',
  'discord.com',
  'reddit.com',
  'namecheap.com',
  'github.com',
  'google.com',
  'microsoft.com',
  'amazon.com',
  'facebook.com',
  'twitter.com',
  'x.com',
  'paypal.com',
  'linkedin.com',
  'cloudflare.com',
  'gitlab.com',
  'slack.com',
  'zoom.us',
  'apple.com',
  'proton.me',
  'instagram.com',
];

const EXPIRY_WINDOW_DAYS = 60;

function loginsWithPassword(items: VaultItem[]): VaultItem[] {
  return items.filter((item) => item.kind === 'login' && loginOf(item).password !== '');
}

export function issueId(kind: IssueKind, ids: string[]): string {
  return `${kind}:${[...ids].sort().join('+')}`;
}

function sitesOf(item: VaultItem): string[] {
  return [
    ...new Set(readWebsites(item.data).map((rule) => normaliseSite(rule.uri)).filter((s) => s !== '')),
  ];
}

function describeWeak(password: string): { id: MessageId; values: Record<string, string | number> } {
  const allLower = /^[a-z]+$/.test(password);
  return allLower
    ? { id: 'health.weak.lower', values: { length: password.length } }
    : { id: 'health.weak.short', values: { length: password.length } };
}

export interface Analysis {
  issues: Issue[];
  good: Array<{ id: MessageId; values: Record<string, string | number> }>;
}

/**
 * Every problem the vault itself shows. `pwned` maps an item id to how many times its password is
 * in Pwned Passwords (absent when the lookup is off or did not run). `now` is a parameter so the
 * expiry check is testable.
 */
export function analyse(
  items: VaultItem[],
  pwned: ReadonlyMap<string, number> | undefined,
  now: Date,
): Analysis {
  const issues: Issue[] = [];
  const logins = loginsWithPassword(items);

  for (const item of logins) {
    const count = pwned?.get(item.id) ?? 0;
    if (count > 0) {
      issues.push({
        id: issueId('exposed', [item.id]),
        kind: 'exposed',
        severity: 'bad',
        itemIds: [item.id],
        title: itemName(item),
        detail: { id: 'health.exposed.detail', values: { count } },
      });
    }
  }

  const byPassword = new Map<string, VaultItem[]>();
  for (const item of logins) {
    const password = loginOf(item).password;
    byPassword.set(password, [...(byPassword.get(password) ?? []), item]);
  }
  for (const group of byPassword.values()) {
    if (group.length < 2) continue;
    issues.push({
      id: issueId('reused', group.map((item) => item.id)),
      kind: 'reused',
      severity: 'warn',
      itemIds: group.map((item) => item.id),
      title: group.map(itemName).join(', '),
      detail: { id: 'health.reused.detail', values: { count: group.length } },
    });
  }

  for (const item of logins) {
    const password = loginOf(item).password;
    if (passwordStrength(password) <= 1) {
      issues.push({
        id: issueId('weak', [item.id]),
        kind: 'weak',
        severity: 'warn',
        itemIds: [item.id],
        title: itemName(item),
        detail: describeWeak(password),
      });
    }
  }

  // Services that offer a code, with no code item for that site in the vault.
  const codeSites = new Set<string>();
  const codeNames: string[] = [];
  for (const item of items) {
    if (item.kind !== 'otp') continue;
    for (const site of sitesOf(item)) codeSites.add(site);
    codeNames.push(itemName(item).toLowerCase());
  }
  const missing = new Map<string, VaultItem>();
  for (const item of items) {
    if (item.kind !== 'login') continue;
    for (const site of sitesOf(item)) {
      if (!TWO_STEP_SITES.includes(site) || codeSites.has(site) || missing.has(site)) continue;
      const label = site.split('.')[0] ?? site;
      if (codeNames.some((name) => name.includes(label))) continue;
      missing.set(site, item);
    }
  }
  if (missing.size > 0) {
    const sites = [...missing.keys()];
    const ids = [...missing.values()].map((item) => item.id);
    issues.push({
      id: issueId('noCode', ids),
      kind: 'noCode',
      severity: 'warn',
      itemIds: ids,
      title: sites.slice(0, 4).join(', '),
      detail: { id: 'health.noCode.detail', values: { count: sites.length, sites: sites.join(', ') } },
    });
  }

  for (const item of items) {
    if (item.kind !== 'pgp-key') continue;
    const raw = item.data?.['expiresAt'] ?? item.data?.['expires'];
    if (typeof raw !== 'string') continue;
    const at = new Date(raw);
    if (Number.isNaN(at.getTime())) continue;
    const days = Math.ceil((at.getTime() - now.getTime()) / 86_400_000);
    if (days > EXPIRY_WINDOW_DAYS) continue;
    issues.push({
      id: issueId('expiring', [item.id]),
      kind: 'expiring',
      severity: 'warn',
      itemIds: [item.id],
      title: itemName(item),
      detail: { id: days < 0 ? 'health.expired.detail' : 'health.expiring.detail', values: { date: at.toISOString().slice(0, 10), days: Math.abs(days) } },
    });
  }

  const good: Analysis['good'] = [];
  good.push({ id: 'health.good.synced', values: { count: items.length } });
  const insecure = items.some(
    (item) =>
      item.kind === 'login' &&
      readWebsites(item.data).some(
        (rule) => /^http:\/\//i.test(rule.uri.trim()) && hostOfWebsite(rule.uri) !== 'localhost',
      ),
  );
  if (!insecure) good.push({ id: 'health.good.https', values: {} });

  return { issues, good };
}

/** Counts by kind, for the tiles. */
export function countByKind(issues: Issue[]): Record<IssueKind, number> {
  const counts: Record<IssueKind, number> = { exposed: 0, reused: 0, weak: 0, noCode: 0, expiring: 0 };
  for (const issue of issues) counts[issue.kind] += issue.kind === 'reused' || issue.kind === 'noCode' ? issue.itemIds.length : 1;
  return counts;
}
