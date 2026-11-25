// What a merge takes from the items that go, so that nothing a copy held is lost whatever its kind:
// a value the kept item lacks, from the newest copy that has it; the documents of an identity; the
// backup codes that were used; the favourite mark. Where copies hold different values for a field
// the person can tell apart, `fieldConflicts` lists them so the preview can ask which to keep.
// Pure, like merge.ts.
import type { MessageId } from '@/i18n';
import type { ItemData, VaultItem } from '@/features/vault/vault';
import { normaliseDocumentNumber } from './normalise';

/** A value as one string, with object keys in order, to tell two entries from each other. */
export function stable(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stable).join(',')}]`;
  if (value && typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, v]) => v !== undefined)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${stable(v)}`).join(',')}}`;
  }
  return JSON.stringify(value) ?? 'null';
}

/** Whether an item holds nothing under a member: absent, null, empty text or an empty list. */
export function lacks(value: unknown): boolean {
  return value === undefined || value === null || value === '' || (Array.isArray(value) && value.length === 0);
}

/**
 * The members a merge settles on its own (the picks, the unions, the copies of files), so the fill
 * leaves them: they are not "a value the kept item lacks".
 */
const SETTLED = new Set([
  'id',
  'name',
  'notes',
  'folder',
  'trashedAt',
  'updatedAt',
  'addedAt',
  'tags',
  'links',
  'fields',
  'favorite',
  'pinned',
  'password',
  'passwordHistory',
  'passkeys',
  'uris',
  'websites',
  'urls',
  'attachments',
  'file',
  'codes',
  'documents',
]);

/** Members that describe another and go with it: a private key's `protected` flag, a key's source. */
export const GOES_WITH: Record<string, Record<string, readonly string[]>> = {
  contact: { public: ['source', 'checkedAt', 'checkedFingerprint', 'checkedAddresses'] },
  'pgp-key': { private: ['protected'] },
};

/**
 * The members the kept item lacks, each from the newest copy that has it (`others` come newest
 * first), as the fields to write to the kept item. A key's private half brings its `protected` flag,
 * a contact's public key its source and checks, so a value never lands beside another's description.
 */
export function fillMissing(kept: VaultItem, others: readonly VaultItem[]): ItemData {
  const own = kept.data ?? {};
  const fields: ItemData = {};
  for (const donor of others) {
    for (const [key, value] of Object.entries(donor.data ?? {})) {
      if (SETTLED.has(key) || key in fields || !lacks(own[key]) || lacks(value)) continue;
      fields[key] = value;
      for (const also of GOES_WITH[kept.kind]?.[key] ?? []) {
        const extra = donor.data?.[also];
        if (extra !== undefined) fields[also] = extra;
      }
    }
  }
  return fields;
}

/** The fields the person can tell apart when copies disagree, by kind. */
export const CONFLICT_FIELDS: Readonly<Record<string, readonly string[]>> = {
  otp: ['label', 'issuer'],
  card: ['cardholder', 'code', 'pin'],
  identity: [
    'title',
    'givenName',
    'middleName',
    'familyName',
    'company',
    'email',
    'phone',
    'username',
    'birthDate',
    'address',
  ],
  contact: ['company', 'email', 'phone', 'address', 'public'],
  'ssh-key': ['algorithm', 'public', 'private'],
  'pgp-key': ['public', 'private'],
  certificate: ['certificate', 'algorithm', 'private'],
  'backup-codes': ['serviceName'],
};

/** The fields whose values the preview does not show. */
export const SECRET_FIELDS: ReadonlySet<string> = new Set(['private', 'code', 'pin']);

export const FIELD_LABELS: Readonly<Record<string, MessageId>> = {
  label: 'dup.field.label',
  issuer: 'dup.field.issuer',
  cardholder: 'dup.field.cardholder',
  code: 'dup.field.code',
  pin: 'dup.field.pin',
  title: 'dup.field.title',
  givenName: 'dup.field.givenName',
  middleName: 'dup.field.middleName',
  familyName: 'dup.field.familyName',
  company: 'dup.field.company',
  email: 'dup.field.email',
  phone: 'dup.field.phone',
  username: 'dup.field.username',
  birthDate: 'dup.field.birthDate',
  address: 'dup.field.address',
  public: 'dup.field.public',
  private: 'dup.field.private',
  algorithm: 'dup.field.algorithm',
  certificate: 'dup.field.certificate',
  serviceName: 'dup.field.serviceName',
};

/** One value of a field, and the items that hold it. */
export interface FieldOption {
  value: unknown;
  from: string[];
}

/** A field the copies hold different values for. */
export interface FieldConflict {
  key: string;
  options: FieldOption[];
}

/** The fields of `items` (of one kind) on which two or more of them hold different values. */
export function fieldConflicts(items: readonly VaultItem[]): FieldConflict[] {
  const kind = items[0]?.kind;
  const out: FieldConflict[] = [];
  for (const key of (kind ? CONFLICT_FIELDS[kind] : undefined) ?? []) {
    const options = new Map<string, FieldOption>();
    for (const item of items) {
      const value = item.data?.[key];
      if (lacks(value)) continue;
      const id = stable(value);
      const option = options.get(id) ?? { value, from: [] };
      option.from.push(item.id);
      options.set(id, option);
    }
    if (options.size > 1) out.push({ key, options: [...options.values()] });
  }
  return out;
}

/** The item whose value of a conflicting field the kept item ends up with, as picked or by default. */
export function chosenFrom(conflict: FieldConflict, valuesFrom: Readonly<Record<string, string>>, keepId: string): string {
  const picked = valuesFrom[conflict.key];
  if (picked !== undefined && conflict.options.some((option) => option.from.includes(picked))) return picked;
  const mine = conflict.options.find((option) => option.from.includes(keepId));
  return mine ? keepId : (conflict.options[0]?.from[0] ?? keepId);
}

/** How the preview shows a value of a field: a secret as dots, long text cut, an address in one line. */
export function showValue(key: string, value: unknown): string {
  const text =
    typeof value === 'string'
      ? value
      : value && typeof value === 'object'
        ? Object.values(value as Record<string, unknown>)
            .flatMap((part) => (Array.isArray(part) ? part : [part]))
            .filter((part): part is string | number => typeof part === 'string' || typeof part === 'number')
            .join(', ')
        : String(value ?? '');
  if (SECRET_FIELDS.has(key)) return '•'.repeat(Math.min(Math.max(text.length, 6), 16));
  return text.length > 60 ? `${text.slice(0, 57)}…` : text;
}

function asObjects(value: unknown): Array<Record<string, unknown>> {
  return Array.isArray(value)
    ? value.filter((entry): entry is Record<string, unknown> => Boolean(entry) && typeof entry === 'object')
    : [];
}

/**
 * The documents of an identity across the copies, the kept item's first, each number once however it
 * is spaced (`X 1234-567` and `x1234567` are one). `undefined` when the kept item holds them all.
 */
export function unionDocuments(kept: VaultItem, others: readonly VaultItem[]): unknown[] | undefined {
  const own = asObjects(kept.data?.['documents']);
  const seen = new Set<string>();
  const key = (doc: Record<string, unknown>): string => {
    const number = typeof doc['number'] === 'string' ? normaliseDocumentNumber(doc['number']) : '';
    return number !== '' ? `number:${number}` : stable(doc);
  };
  const out: Array<Record<string, unknown>> = [];
  for (const doc of own) {
    seen.add(key(doc));
    out.push(doc);
  }
  for (const donor of others) {
    for (const doc of asObjects(donor.data?.['documents'])) {
      if (seen.has(key(doc))) continue;
      seen.add(key(doc));
      out.push(doc);
    }
  }
  return out.length > own.length ? out : undefined;
}

/**
 * The backup codes with every code used in any copy marked used, and any code the kept item lacks
 * added. `undefined` when the kept item's codes are right as they are. A code used is never offered
 * again as unused by a merge.
 */
export function mergeCodes(kept: VaultItem, others: readonly VaultItem[]): unknown[] | undefined {
  const list = kept.data?.['codes'];
  if (!Array.isArray(list)) return undefined;
  const usedElsewhere = new Set<string>();
  const known = new Set<string>();
  for (const entry of list) {
    const code = codeOf(entry);
    if (code !== '') known.add(code);
  }
  const extra: Array<Record<string, unknown>> = [];
  for (const donor of others) {
    for (const entry of Array.isArray(donor.data?.['codes']) ? (donor.data?.['codes'] as unknown[]) : []) {
      const code = codeOf(entry);
      if (code === '') continue;
      const used = typeof entry === 'object' && entry !== null && (entry as { used?: unknown }).used === true;
      if (used) usedElsewhere.add(code);
      if (!known.has(code)) {
        known.add(code);
        extra.push(typeof entry === 'string' ? { code: entry, used: false } : { ...(entry as Record<string, unknown>) });
      }
    }
  }
  let changed = extra.length > 0;
  const merged: unknown[] = list.map((entry) => {
    const code = codeOf(entry);
    const isUsed = typeof entry === 'object' && entry !== null && (entry as { used?: unknown }).used === true;
    if (code === '' || isUsed || !usedElsewhere.has(code)) return entry;
    changed = true;
    return typeof entry === 'string' ? { code: entry, used: true } : { ...(entry as Record<string, unknown>), used: true };
  });
  // A code that came from a copy and was used there stays used.
  for (const entry of extra) {
    if (usedElsewhere.has(codeOf(entry))) entry['used'] = true;
  }
  return changed ? [...merged, ...extra] : undefined;
}

function codeOf(entry: unknown): string {
  if (typeof entry === 'string') return entry.trim();
  const code = entry && typeof entry === 'object' ? (entry as { code?: unknown }).code : undefined;
  return typeof code === 'string' ? code.trim() : '';
}

/** `true` when any of the items holds `member` as true (a favourite, a pinned entry). */
export function anyFlag(items: readonly VaultItem[], member: 'favorite' | 'pinned'): boolean {
  return items.some((item) => item.data?.[member] === true);
}
