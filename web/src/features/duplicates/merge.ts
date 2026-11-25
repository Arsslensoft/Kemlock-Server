// What a merge keeps. Pure: `planMerge` turns the person's picks into the writes, `mergeWrites`
// and `undoWrites` turn a plan into the one batch that applies or reverses it.
//
// Nothing is lost: a password that isn't kept joins the kept login's password history, the websites
// of every login are kept unless unticked, the linked items and custom fields of every item join the
// kept one's, and the other items go to the Trash for 30 days.
import { vaultIdOf } from '@/features/vault/listFilters';
import type { ItemData, SaveInput, VaultItem } from '@/features/vault/vault';
import { type WebsiteRule, readWebsites, writeWebsites } from '@/features/vault/websites';

export interface MergePicks {
  /** The item that stays; the others go to the Trash. */
  keepId: string;
  nameFrom: string;
  passwordFrom: string;
  folderFrom: string;
  notesFrom: string;
  /** Websites to keep, as `websiteKey`s. */
  websites: string[];
  /** Passkeys to keep, by credential id. */
  passkeys: string[];
}

/**
 * The members of an item that hold a list every merged item adds to: the items it is linked to
 * (`links`, `[{ id }]`) and its custom fields (`customFields`). A merge writes the union of the
 * lists of all its items to the kept one, whatever else it keeps.
 */
export const UNION_MEMBERS = ['links', 'customFields'] as const;

export const websiteKey = (rule: WebsiteRule): string => `${rule.uri.trim().toLowerCase()}|${rule.match}`;

function str(data: ItemData | null, key: string): string {
  const value = data?.[key];
  return typeof value === 'string' ? value : '';
}

export function passkeysOf(item: VaultItem): Array<Record<string, unknown>> {
  const list = item.data?.['passkeys'];
  return Array.isArray(list)
    ? list.filter((p): p is Record<string, unknown> => Boolean(p) && typeof p === 'object')
    : [];
}

export function passkeyId(passkey: Record<string, unknown>): string {
  const id = passkey['credentialId'];
  return typeof id === 'string' ? id : JSON.stringify(passkey);
}

/** Every distinct website across the items, in the order met. */
export function allWebsites(items: VaultItem[]): WebsiteRule[] {
  const seen = new Set<string>();
  const out: WebsiteRule[] = [];
  for (const item of items) {
    for (const rule of readWebsites(item.data)) {
      const key = websiteKey(rule);
      if (seen.has(key)) continue;
      seen.add(key);
      out.push(rule);
    }
  }
  return out;
}

/** Whether any of the items has linked items or custom fields, which the merge keeps from all. */
export function hasUnionMembers(items: VaultItem[]): boolean {
  return items.some((item) => UNION_MEMBERS.some((member) => Array.isArray(item.data?.[member]) && (item.data?.[member] as unknown[]).length > 0));
}

/** The vault each item is in, once each, in the order the items come (newest first). */
export function vaultsOf(items: VaultItem[]): string[] {
  return [...new Set(items.map((item) => vaultIdOf(item.owner)))];
}

/**
 * `picks` with the kept item moved to `vault`: the item of that vault whose name is picked, else
 * the newest one there. The name, and every other pick, stay as they are. `picks` come back as they
 * were when no item is in `vault`.
 */
export function keepInVault(items: VaultItem[], picks: MergePicks, vault: string): MergePicks {
  const there = items.filter((item) => vaultIdOf(item.owner) === vault);
  const keep = there.find((item) => item.id === picks.nameFrom) ?? there[0];
  return keep ? { ...picks, keepId: keep.id } : picks;
}

/** The first pick of every field: the most recently changed item (the group is sorted that way). */
export function defaultPicks(items: VaultItem[]): MergePicks {
  const first = items[0];
  const id = first?.id ?? '';
  const passkeys: string[] = [];
  for (const item of items) for (const p of passkeysOf(item)) passkeys.push(passkeyId(p));
  return {
    keepId: id,
    nameFrom: id,
    passwordFrom: id,
    folderFrom: id,
    notesFrom: id,
    websites: allWebsites(items).map(websiteKey),
    passkeys: [...new Set(passkeys)],
  };
}

export interface MergePlan {
  kept: VaultItem;
  trashed: VaultItem[];
  /** The fields written to the kept item. */
  fields: ItemData;
  /** What those fields were before, for Undo: `undefined` where there was none. */
  before: ItemData;
  /** The passwords that joined the history. */
  retired: number;
}

const pick = (items: VaultItem[], id: string): VaultItem | undefined =>
  items.find((item) => item.id === id);

/** A value as one string, with object keys in order, to tell two entries from each other. */
function stable(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stable).join(',')}]`;
  if (value && typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, v]) => v !== undefined)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${stable(v)}`).join(',')}}`;
  }
  return JSON.stringify(value) ?? 'null';
}

/**
 * The entries of `member` across `items`, the kept item's first, each distinct entry once. A link
 * to an item of the merge itself is dropped (an item is not linked to itself), and links stay
 * sorted by id as the item format keeps them.
 */
function unionOf(
  member: (typeof UNION_MEMBERS)[number],
  kept: VaultItem,
  items: VaultItem[],
  merged: Set<string>,
): unknown[] {
  const seen = new Set<string>();
  const out: unknown[] = [];
  for (const item of [kept, ...items.filter((other) => other.id !== kept.id)]) {
    const list = item.data?.[member];
    if (!Array.isArray(list)) continue;
    for (const entry of list) {
      const id = member === 'links' && entry && typeof entry === 'object' ? (entry as { id?: unknown }).id : undefined;
      if (typeof id === 'string' && merged.has(id.toLowerCase())) continue;
      const key = typeof id === 'string' ? id.toLowerCase() : stable(entry);
      if (seen.has(key)) continue;
      seen.add(key);
      out.push(entry);
    }
  }
  if (member === 'links') {
    const idOf = (entry: unknown): string =>
      entry && typeof entry === 'object' && typeof (entry as { id?: unknown }).id === 'string'
        ? (entry as { id: string }).id.toLowerCase()
        : '';
    out.sort((a, b) => (idOf(a) < idOf(b) ? -1 : idOf(a) > idOf(b) ? 1 : 0));
  }
  return out;
}

/** The writes of a merge of `items` (at least two) under `picks`. */
export function planMerge(items: VaultItem[], picks: MergePicks, now: Date): MergePlan | null {
  const kept = pick(items, picks.keepId);
  if (!kept || items.length < 2) return null;
  const trashed = items.filter((item) => item.id !== kept.id);
  const fields: ItemData = {};

  const name = str(pick(items, picks.nameFrom)?.data ?? null, 'name');
  if (name !== '') fields['name'] = name;

  const folder = pick(items, picks.folderFrom)?.data?.['folder'];
  fields['folder'] = typeof folder === 'string' && folder !== '' ? folder : undefined;

  const notesSource = pick(items, picks.notesFrom);
  const notes = notesSource?.data?.['notes'];
  fields['notes'] = typeof notes === 'string' && notes !== '' ? notes : undefined;

  let retired = 0;
  if (kept.kind === 'login') {
    const chosenPassword = str(pick(items, picks.passwordFrom)?.data ?? null, 'password');
    fields['password'] = chosenPassword;
    const history = Array.isArray(kept.data?.['passwordHistory'])
      ? [...(kept.data?.['passwordHistory'] as unknown[])]
      : [];
    const known = new Set(
      history.map((h) =>
        h && typeof h === 'object' ? String((h as Record<string, unknown>)['password']) : '',
      ),
    );
    known.add(chosenPassword);
    for (const item of items) {
      const password = str(item.data, 'password');
      if (password === '' || known.has(password)) continue;
      known.add(password);
      history.unshift({ password, replacedAt: now.toISOString() });
      retired += 1;
    }
    // Earlier passwords the other logins kept come along too.
    for (const item of trashed) {
      const theirs = item.data?.['passwordHistory'];
      if (!Array.isArray(theirs)) continue;
      for (const entry of theirs) {
        const password =
          entry && typeof entry === 'object' ? (entry as Record<string, unknown>)['password'] : undefined;
        if (typeof password !== 'string' || known.has(password)) continue;
        known.add(password);
        history.push(entry);
      }
    }
    fields['passwordHistory'] = history.length > 0 ? history : undefined;

    const websites = allWebsites(items).filter((rule) => picks.websites.includes(websiteKey(rule)));
    Object.assign(fields, writeWebsites(websites));

    const passkeys: Array<Record<string, unknown>> = [];
    const seen = new Set<string>();
    for (const item of items) {
      for (const passkey of passkeysOf(item)) {
        const id = passkeyId(passkey);
        if (seen.has(id) || !picks.passkeys.includes(id)) continue;
        seen.add(id);
        passkeys.push(passkey);
      }
    }
    fields['passkeys'] = passkeys.length > 0 ? passkeys : undefined;
  }

  const members = new Set(items.map((item) => item.id.toLowerCase()));
  for (const member of UNION_MEMBERS) {
    if (!items.some((item) => Array.isArray(item.data?.[member]))) continue;
    const union = unionOf(member, kept, items, members);
    fields[member] = union.length > 0 ? union : undefined;
  }

  const tags = new Set<string>();
  for (const item of items) {
    const list = item.data?.['tags'];
    if (Array.isArray(list)) for (const tag of list) if (typeof tag === 'string') tags.add(tag);
  }
  if (tags.size > 0) fields['tags'] = [...tags];

  const before: ItemData = {};
  for (const key of Object.keys(fields)) before[key] = kept.data?.[key];
  return { kept, trashed, fields, before, retired };
}

/** The name the kept item has once merged: the picked one, else its own. */
export function resultName(plan: MergePlan): string {
  const name = plan.fields['name'];
  if (typeof name === 'string' && name !== '') return name;
  const own = plan.kept.data?.['name'];
  return typeof own === 'string' ? own : '';
}

/** The saves of a merge: the kept item's new revision, the others into the Trash. */
export function mergeWrites(plan: MergePlan, now: Date): SaveInput[] {
  return [
    { existing: plan.kept, kind: plan.kept.kind, owner: plan.kept.owner, fields: plan.fields },
    ...plan.trashed.map((item) => ({
      existing: item,
      kind: item.kind,
      owner: item.owner,
      fields: { trashedAt: now.toISOString() },
    })),
  ];
}

/**
 * The saves that reverse a merge, from the items it returned (their revisions have moved on): the
 * kept item gets its old fields back and the others leave the Trash.
 */
export function undoWrites(plan: MergePlan, saved: VaultItem[]): SaveInput[] {
  return saved.map((item) =>
    item.id === plan.kept.id
      ? { existing: item, kind: item.kind, owner: item.owner, fields: plan.before }
      : { existing: item, kind: item.kind, owner: item.owner, fields: { trashedAt: undefined } },
  );
}
