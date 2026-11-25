// Finds duplicates among the opened vault, in memory. Nothing here touches the network: items are
// grouped when they share a canonical tag input (normalise.ts), then each group is checked on the
// decrypted values, so a group is only ever shown when the values really match. Every item kind has
// a rule, and each group says which one made it:
//
//   login        same website, username and password (or: same website and username)
//   MFA code     same secret                 backup codes  same codes
//   note         same text                   passkey       same website and credential id
//   card         same number and expiry      identity      same document number (or name and email)
//   contact      same email and phone, or    file          same content hash (`file.sha256`)
//                the same PGP key
//   certificate  same fingerprint            SSH, PGP key  same fingerprint
import type { MessageId } from '@/i18n';
import type { ItemData, VaultItem } from '@/features/vault/vault';
import { readWebsites } from '@/features/vault/websites';
import {
  type TagName,
  canonicalInput,
  normaliseCardNumber,
  normaliseCodes,
  normaliseContentHash,
  normaliseCredentialId,
  normaliseDocumentNumber,
  normaliseExpiry,
  normaliseFingerprint,
  normaliseNote,
  normalisePhone,
  normaliseSecret,
  normaliseSite,
  normaliseUsername,
} from './normalise';

export interface Tag {
  name: TagName;
  input: string;
}

/** What is worked out about key items outside the item (their fingerprint), by item id. */
export type DerivedFacts = ReadonlyMap<string, { fingerprint: string }>;

function text(data: ItemData | null, key: string): string {
  const value = data?.[key];
  return typeof value === 'string' ? value : '';
}

/** The backup codes of an item: the app keeps `{code, used}`, an older writer plain strings. */
function codeTexts(data: ItemData | null): string[] {
  const value = data?.['codes'];
  if (!Array.isArray(value)) return [];
  const out: string[] = [];
  for (const entry of value) {
    if (typeof entry === 'string') out.push(entry);
    else if (entry && typeof entry === 'object' && typeof (entry as { code?: unknown }).code === 'string') {
      out.push((entry as { code: string }).code);
    }
  }
  return out;
}

/** The person an identity is: their given, middle and family names, else a stored full name. */
function personName(data: ItemData | null): string {
  const parts = ['givenName', 'middleName', 'familyName'].map((key) => text(data, key).trim()).filter(Boolean);
  return parts.length > 0 ? parts.join(' ') : text(data, 'fullName');
}

/** The numbers of an identity's documents (kemlock-core `IdentityDocument.number`). */
function documentNumbers(data: ItemData | null): string[] {
  const docs = data?.['documents'];
  if (!Array.isArray(docs)) return [];
  const out: string[] = [];
  for (const doc of docs) {
    const number = doc && typeof doc === 'object' ? (doc as { number?: unknown }).number : undefined;
    if (typeof number === 'string') out.push(number);
  }
  return out;
}

/** The fingerprint of a key item: one the item stores, else the one worked out in this browser. */
function fingerprintOf(item: VaultItem, facts: DerivedFacts | undefined): string {
  return text(item.data, 'fingerprint') || facts?.get(item.id)?.fingerprint || '';
}

/**
 * The tags of one item (docs/crypto.md): none for a kind that has no tag or an item with no value.
 * `facts` carries the fingerprints of key items, which are worked out from the stored halves
 * (WebCrypto is asynchronous) rather than stored.
 */
export function tagsOf(item: VaultItem, facts?: DerivedFacts): Tag[] {
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
    case 'pgp-key':
    case 'certificate': {
      const fingerprint = normaliseFingerprint(fingerprintOf(item, facts));
      if (fingerprint !== '') tags.push({ name: 'key', input: canonicalInput('key', [fingerprint]) });
      break;
    }
    case 'backup-codes': {
      const codes = normaliseCodes(codeTexts(data));
      if (codes.length > 0) tags.push({ name: 'codes', input: canonicalInput('codes', codes) });
      break;
    }
    case 'identity': {
      const name = normaliseUsername(personName(data));
      const email = normaliseUsername(text(data, 'email'));
      if (name !== '' || email !== '') {
        tags.push({ name: 'identity', input: canonicalInput('identity', [name, email]) });
      }
      const numbers = new Set(documentNumbers(data).map(normaliseDocumentNumber).filter((n) => n !== ''));
      for (const number of numbers) tags.push({ name: 'document', input: canonicalInput('document', [number]) });
      break;
    }
    case 'contact': {
      const email = normaliseUsername(text(data, 'email'));
      const phone = normalisePhone(text(data, 'phone'));
      if (email !== '' || phone !== '') {
        tags.push({ name: 'contact', input: canonicalInput('contact', [email, phone]) });
      }
      // A contact that holds a PGP key is told by the key too, as the Kemlock app does.
      const fingerprint = text(data, 'public') === '' ? '' : normaliseFingerprint(fingerprintOf(item, facts));
      if (fingerprint !== '') tags.push({ name: 'key', input: canonicalInput('key', [fingerprint]) });
      break;
    }
    case 'file': {
      // The file's entry (`file: { name, size, type?, key, … }`) may hold the SHA-256 of the plaintext.
      const entry = data['file'];
      const inEntry =
        entry && typeof entry === 'object' && !Array.isArray(entry) ? (entry as { sha256?: unknown }).sha256 : undefined;
      const hash = normaliseContentHash(typeof inEntry === 'string' ? inEntry : text(data, 'sha256'));
      if (hash !== '') tags.push({ name: 'file', input: canonicalInput('file', [hash]) });
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
  | 'certificate'
  | 'codes'
  | 'identity'
  | 'document'
  | 'contact'
  | 'contactEmail'
  | 'contactPhone'
  | 'contactOrKey'
  | 'file';

export const WHY_LABEL: Record<Why, MessageId> = {
  cred: 'dup.why.cred',
  account: 'dup.why.account',
  secret: 'dup.why.secret',
  passkey: 'dup.why.passkey',
  card: 'dup.why.card',
  note: 'dup.why.note',
  key: 'dup.why.key',
  certificate: 'dup.why.certificate',
  codes: 'dup.why.codes',
  identity: 'dup.why.identity',
  document: 'dup.why.document',
  contact: 'dup.why.contact',
  contactEmail: 'dup.why.contactEmail',
  contactPhone: 'dup.why.contactPhone',
  contactOrKey: 'dup.why.contactOrKey',
  file: 'dup.why.file',
};

/** What the matching values are, for the line in the merge preview that says they are the same. */
export const SAME_LABEL: Record<Why, MessageId> = {
  cred: 'dup.pick.userAndPassword',
  account: 'dup.pick.userAndPassword',
  secret: 'dup.same.secret',
  passkey: 'dup.same.passkey',
  card: 'dup.same.card',
  note: 'dup.same.note',
  key: 'dup.same.key',
  certificate: 'dup.same.certificate',
  codes: 'dup.same.codes',
  identity: 'dup.same.identity',
  document: 'dup.same.document',
  contact: 'dup.same.contact',
  contactEmail: 'dup.same.contactEmail',
  contactPhone: 'dup.same.contactPhone',
  contactOrKey: 'dup.same.contactOrKey',
  file: 'dup.same.file',
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

/** Kinds that are grouped, and the tag each groups on. A login groups on `account` and refines on `cred`. */
const PRIMARY: Record<string, TagName> = {
  login: 'account',
  otp: 'secret',
  passkey: 'passkey',
  card: 'card',
  note: 'note',
  'ssh-key': 'key',
  'pgp-key': 'key',
  certificate: 'key',
  'backup-codes': 'codes',
  identity: 'identity',
  contact: 'contact',
  file: 'file',
};

/**
 * The tags an item is grouped by. An identity is grouped by its document numbers alone: two papers
 * of one person (a passport and a licence) share a name and an email and are not copies. Its name
 * and email join it to an identity that has no document (see `joinByName`).
 */
function groupingTags(item: VaultItem, tags: Tag[]): Tag[] {
  if (item.kind === 'identity') return tags.filter((tag) => tag.name === 'document');
  // A contact is the same by its email and phone, or by the key it holds.
  if (item.kind === 'contact') return tags.filter((tag) => tag.name === 'contact' || tag.name === 'key');
  const primary = PRIMARY[item.kind];
  return tags.filter((tag) => tag.name === primary);
}

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

/** Whether every member of `component` shares a `name` tag with another member. */
function everyoneShares(component: VaultItem[], tags: Map<string, Tag[]>, name: TagName): boolean {
  return component.every((item) =>
    component.some(
      (other) => other.id !== item.id && sharedInputs(tags.get(item.id) ?? [], tags.get(other.id) ?? [], name),
    ),
  );
}

/** Why a component of one kind matched: which of the values the members share. */
function whyOf(kind: string, component: VaultItem[], tags: Map<string, Tag[]>): Why {
  switch (kind) {
    case 'login': {
      const sameCredentials = component.every((item) =>
        component.some(
          (other) =>
            other.id !== item.id && sharedInputs(tags.get(item.id) ?? [], tags.get(other.id) ?? [], 'cred'),
        ),
      );
      return sameCredentials ? 'cred' : 'account';
    }
    case 'otp':
      return 'secret';
    case 'passkey':
      return 'passkey';
    case 'card':
      return 'card';
    case 'note':
      return 'note';
    case 'ssh-key':
    case 'pgp-key':
      return 'key';
    case 'certificate':
      return 'certificate';
    case 'backup-codes':
      return 'codes';
    case 'identity':
      // The reason every member shares: the document number, else only their name and email.
      return everyoneShares(component, tags, 'document') ? 'document' : 'identity';
    case 'contact': {
      // Only a reason every member shares is given; when no one reason holds for all of them (one
      // pair is joined by their key and another by their email), both are named.
      if (everyoneShares(component, tags, 'contact')) {
        // Members that share the whole tag share its values, so the first says which it holds.
        const first = component[0];
        const email = normaliseUsername(text(first?.data ?? null, 'email'));
        const phone = normalisePhone(text(first?.data ?? null, 'phone'));
        if (email !== '' && phone !== '') return 'contact';
        return email !== '' ? 'contactEmail' : 'contactPhone';
      }
      return everyoneShares(component, tags, 'key') ? 'key' : 'contactOrKey';
    }
    default:
      return 'file';
  }
}

/** When an item was last changed, in epoch milliseconds (the app writes a number, older saves an ISO date). */
function updatedMs(item: VaultItem): number {
  const value = item.data?.['updatedAt'];
  if (typeof value === 'number') return value;
  const parsed = typeof value === 'string' ? Date.parse(value) : Number.NaN;
  return Number.isNaN(parsed) ? 0 : parsed;
}

/**
 * Joins the identities with no document to the identity that has them, by their name and email:
 * those with no document are copies of each other, and of the one identity with documents that
 * shares their name and email, since that is the one they left the papers off. When two identities
 * with documents (a passport and a licence) share the name and email, a copy without papers could be
 * of either, so it is joined to neither. Identities that both have documents are never joined by
 * name and email.
 */
function joinByName(
  members: VaultItem[],
  tags: Map<string, Tag[]>,
  find: (id: string) => string,
  join: (a: string, b: string) => void,
): void {
  const byName = new Map<string, { papers: VaultItem[]; bare: VaultItem[] }>();
  for (const item of members) {
    const own = tags.get(item.id) ?? [];
    const name = own.find((tag) => tag.name === 'identity');
    if (!name) continue;
    const bucket = byName.get(name.input) ?? { papers: [], bare: [] };
    (own.some((tag) => tag.name === 'document') ? bucket.papers : bucket.bare).push(item);
    byName.set(name.input, bucket);
  }
  for (const { papers, bare } of byName.values()) {
    const [first, ...rest] = bare;
    if (!first) continue;
    for (const other of rest) join(other.id, first.id);
    // The identities with papers that are one group already count as one.
    const roots = new Set(papers.map((item) => find(item.id)));
    const [one] = papers;
    if (one && roots.size === 1) join(first.id, one.id);
  }
}

/** Groups the opened, untrashed items that hold the same values. */
export function findDuplicates(items: VaultItem[], facts?: DerivedFacts): DuplicateGroup[] {
  const candidates = items.filter((item) => item.data !== null && item.data['trashedAt'] === undefined);
  const byKind = new Map<string, VaultItem[]>();
  for (const item of candidates) {
    if (!(item.kind in PRIMARY)) continue;
    byKind.set(item.kind, [...(byKind.get(item.kind) ?? []), item]);
  }
  const groups: DuplicateGroup[] = [];
  for (const [kind, members] of byKind) {
    const tags = new Map(members.map((item) => [item.id, tagsOf(item, facts)] as const));
    // Union-find over items that share a grouping tag input.
    const parent = new Map(members.map((item) => [item.id, item.id] as const));
    const find = (id: string): string => {
      let root = id;
      while (parent.get(root) !== root) root = parent.get(root) ?? root;
      return root;
    };
    const owners = new Map<string, string>();
    for (const item of members) {
      for (const tag of groupingTags(item, tags.get(item.id) ?? [])) {
        const first = owners.get(tag.input);
        if (first === undefined) owners.set(tag.input, item.id);
        else parent.set(find(item.id), find(first));
      }
    }
    if (kind === 'identity') joinByName(members, tags, find, (a, b) => parent.set(find(a), find(b)));
    const components = new Map<string, VaultItem[]>();
    for (const item of members) {
      const root = find(item.id);
      components.set(root, [...(components.get(root) ?? []), item]);
    }
    for (const component of components.values()) {
      if (component.length < 2) continue;
      // The most recently changed first; items changed in the same instant keep the id order.
      const sorted = [...component].sort((a, b) => updatedMs(b) - updatedMs(a) || a.id.localeCompare(b.id));
      groups.push({
        id: groupId(sorted),
        kind,
        why: whyOf(kind, sorted, tags),
        items: sorted,
        crossOwner: new Set(sorted.map((item) => item.owner)).size > 1,
      });
    }
  }
  return groups.sort((a, b) => a.id.localeCompare(b.id));
}
