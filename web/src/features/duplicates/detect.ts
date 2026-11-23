// Finds duplicates among the opened vault, in memory. Nothing here touches the network: items are
// grouped when they share a canonical tag input (normalise.ts), then each group is checked on the
// decrypted values, so a group is only ever shown when the values really match.
import type { MessageId } from '@/i18n';
import type { ItemData, VaultItem } from '@/features/vault/vault';
import { readWebsites } from '@/features/vault/websites';
import {
  type TagName,
  canonicalInput,
  normaliseCardNumber,
  normaliseCodes,
  normaliseCredentialId,
  normaliseExpiry,
  normaliseFingerprint,
  normaliseNote,
  normaliseSecret,
  normaliseSite,
  normaliseUsername,
} from './normalise';

export interface Tag {
  name: TagName;
  input: string;
}

function text(data: ItemData | null, key: string): string {
  const value = data?.[key];
  return typeof value === 'string' ? value : '';
}

function textList(data: ItemData | null, key: string): string[] {
  const value = data?.[key];
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === 'string') : [];
}

/** The tags of one item (docs/crypto.md): none for a kind that has no tag or an item with no value. */
export function tagsOf(item: VaultItem): Tag[] {
  const data = item.data;
  if (!data) return [];
  const tags: Tag[] = [];
  switch (item.kind) {
    case 'login': {
      const username = normaliseUsername(text(data, 'username'));
      const password = text(data, 'password');
      const seen = new Set<string>();
      for (const website of readWebsites(data)) {
        // A website whose rule is regex or never makes no tag.
        if (website.match === 'regex' || website.match === 'never') continue;
        const site = normaliseSite(website.uri);
        if (site === '' || seen.has(site)) continue;
        seen.add(site);
        tags.push({ name: 'account', input: canonicalInput('account', [site, username]) });
        if (password !== '') {
          tags.push({ name: 'cred', input: canonicalInput('cred', [site, username, password]) });
        }
      }
      break;
    }
    case 'otp': {
      const raw = text(data, 'secret') || text(data, 'value') || text(data, 'totp');
      const secret = raw === '' ? null : normaliseSecret(raw);
      if (secret) tags.push({ name: 'secret', input: canonicalInput('secret', [secret]) });
      break;
    }
    case 'passkey': {
      const rp = text(data, 'rpId');
      const id = text(data, 'credentialId');
      if (rp !== '' && id !== '') {
        tags.push({
          name: 'passkey',
          input: canonicalInput('passkey', [normaliseUsername(rp), normaliseCredentialId(id)]),
        });
      }
      break;
    }
    case 'card': {
      const number = normaliseCardNumber(text(data, 'number'));
      if (number !== '') {
        tags.push({
          name: 'card',
          input: canonicalInput('card', [number, normaliseExpiry(data['expMonth'], data['expYear'])]),
        });
      }
      break;
    }
    case 'note': {
      const body = normaliseNote(text(data, 'text'));
      if (body !== '') tags.push({ name: 'note', input: canonicalInput('note', [body]) });
      break;
    }
    case 'ssh-key':
    case 'pgp-key': {
      const fingerprint = normaliseFingerprint(text(data, 'fingerprint'));
      if (fingerprint !== '') tags.push({ name: 'key', input: canonicalInput('key', [fingerprint]) });
      break;
    }
    case 'backup-codes': {
      const codes = normaliseCodes(textList(data, 'codes'));
      if (codes.length > 0) tags.push({ name: 'codes', input: canonicalInput('codes', codes) });
      break;
    }
    case 'identity': {
      const name = normaliseUsername(text(data, 'fullName') || text(data, 'name'));
      const email = normaliseUsername(text(data, 'email'));
      if (name !== '' || email !== '') {
        tags.push({ name: 'identity', input: canonicalInput('identity', [name, email]) });
      }
      break;
    }
    default:
      break;
  }
  return tags;
}

export type Why =
  | 'cred'
  | 'account'
  | 'secret'
  | 'passkey'
  | 'card'
  | 'note'
  | 'key'
  | 'codes'
  | 'identity';

export const WHY_LABEL: Record<Why, MessageId> = {
  cred: 'dup.why.cred',
  account: 'dup.why.account',
  secret: 'dup.why.secret',
  passkey: 'dup.why.passkey',
  card: 'dup.why.card',
  note: 'dup.why.note',
  key: 'dup.why.key',
  codes: 'dup.why.codes',
  identity: 'dup.why.identity',
};

export interface DuplicateGroup {
  /** Stable for the same members: the sorted ids joined. */
  id: string;
  kind: string;
  why: Why;
  items: VaultItem[];
  /** Members in more than one place (the person's vault and a space, or two spaces). */
  crossOwner: boolean;
}

/** The kinds that group on a tag, and which tag. A login groups on `account` and refines on `cred`. */
const PRIMARY: Record<string, TagName> = {
  login: 'account',
  otp: 'secret',
  passkey: 'passkey',
  card: 'card',
  note: 'note',
  'ssh-key': 'key',
  'pgp-key': 'key',
  'backup-codes': 'codes',
  identity: 'identity',
};

/** `a` and `b` and ids in sorted order: how a group is named and remembered. */
export function groupId(items: VaultItem[]): string {
  return items
    .map((item) => item.id)
    .sort()
    .join('+');
}

function sharedInputs(a: Tag[], b: Tag[], name: TagName): boolean {
  return a.some((x) => x.name === name && b.some((y) => y.name === name && y.input === x.input));
}

/** Groups the opened, untrashed items that hold the same values. */
export function findDuplicates(items: VaultItem[]): DuplicateGroup[] {
  const candidates = items.filter((item) => item.data !== null && item.data['trashedAt'] === undefined);
  const byKind = new Map<string, VaultItem[]>();
  for (const item of candidates) {
    const key = item.kind === 'pgp-key' ? 'ssh-key' : item.kind;
    if (!(item.kind in PRIMARY)) continue;
    byKind.set(key, [...(byKind.get(key) ?? []), item]);
  }
  const groups: DuplicateGroup[] = [];
  for (const [kind, members] of byKind) {
    const primary = PRIMARY[kind];
    if (!primary) continue;
    const tags = new Map(members.map((item) => [item.id, tagsOf(item)] as const));
    // Union-find over items that share a primary tag input.
    const parent = new Map(members.map((item) => [item.id, item.id] as const));
    const find = (id: string): string => {
      let root = id;
      while (parent.get(root) !== root) root = parent.get(root) ?? root;
      return root;
    };
    const owners = new Map<string, string>();
    for (const item of members) {
      for (const tag of tags.get(item.id) ?? []) {
        if (tag.name !== primary) continue;
        const first = owners.get(tag.input);
        if (first === undefined) owners.set(tag.input, item.id);
        else parent.set(find(item.id), find(first));
      }
    }
    const components = new Map<string, VaultItem[]>();
    for (const item of members) {
      const root = find(item.id);
      components.set(root, [...(components.get(root) ?? []), item]);
    }
    for (const component of components.values()) {
      if (component.length < 2) continue;
      let why: Why = primary;
      if (primary === 'account') {
        const sameCredentials = component.every((item) =>
          component.some(
            (other) =>
              other.id !== item.id &&
              sharedInputs(tags.get(item.id) ?? [], tags.get(other.id) ?? [], 'cred'),
          ),
        );
        why = sameCredentials ? 'cred' : 'account';
      }
      const sorted = [...component].sort((a, b) =>
        String(b.data?.['updatedAt'] ?? '').localeCompare(String(a.data?.['updatedAt'] ?? '')),
      );
      groups.push({
        id: groupId(sorted),
        kind,
        why,
        items: sorted,
        crossOwner: new Set(sorted.map((item) => item.owner)).size > 1,
      });
    }
  }
  return groups.sort((a, b) => a.id.localeCompare(b.id));
}
