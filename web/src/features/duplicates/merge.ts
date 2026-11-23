// What a merge keeps. Pure: `planMerge` turns the person's picks into the writes, `mergeWrites`
// and `undoWrites` turn a plan into the one batch that applies or reverses it.
//
// Nothing is lost: a password that isn't kept joins the kept login's password history, the websites
// of every login are kept unless unticked, and the other items go to the Trash for 30 days.
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
