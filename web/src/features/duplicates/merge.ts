// What a merge keeps. Pure: `planMerge` turns the person's picks into the writes, `mergeWrites`
// and `undoWrites` turn a plan into the one batch that applies or reverses it.
//
// Nothing is lost, whatever the kind: a password that isn't kept joins the kept login's password
// history, the websites of every login are kept unless unticked, the linked items and custom fields
// of every item join the kept one's, a value the kept item lacks comes from the newest copy that has
// it (mergeFill.ts), the files of a note are copied onto the kept note (attachmentCopy.ts), the
// items that pointed at an item that goes now point at the kept one (relink.ts), and the other items
// go to the Trash for 30 days.
import { vaultIdOf } from '@/features/vault/listFilters';
import { type ItemData, type SaveInput, type VaultItem, itemName } from '@/features/vault/vault';
import { type WebsiteRule, readWebsites, writeWebsites } from '@/features/vault/websites';
import { type AttachmentCopy, attachmentCopies } from './attachmentCopy';
import {
  GOES_WITH,
  anyFlag,
  chosenFrom,
  fieldConflicts,
  fillMissing,
  lacks,
  mergeCodes,
  stable,
  unionDocuments,
} from './mergeFill';
import { type MergeContext, type Relink, itemsNaming, planRelinks, undoFields } from './relink';

export type { MergeContext, Relink } from './relink';

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
  /**
   * For a field the copies hold different values for (`fieldConflicts`), the item whose value the
   * kept item holds. A field not named here keeps the kept item's own value.
   */
  valuesFrom: Record<string, string>;
}

/**
 * The members of an item that hold a list every merged item adds to: the items it is linked to
 * (`links`, `[{ id }]`) and its custom fields (`fields`, `[{ name, value, kind, adminField? }]`).
 * A merge writes the union of the lists of all its items to the kept one, whatever else it keeps.
 */
export const UNION_MEMBERS = ['links', 'fields'] as const;

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
  return items.some((item) =>
    UNION_MEMBERS.some((member) => Array.isArray(item.data?.[member]) && (item.data?.[member] as unknown[]).length > 0),
  );
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

/**
 * The first pick of every field: the most recently changed item (the group is sorted that way), or
 * for a password, folder or note the first that has one, so the default never drops what only a
 * later copy held.
 */
export function defaultPicks(items: VaultItem[]): MergePicks {
  const first = items[0];
  const id = first?.id ?? '';
  const firstWith = (key: string): string => items.find((item) => !lacks(item.data?.[key]))?.id ?? id;
  const passkeys: string[] = [];
  for (const item of items) for (const p of passkeysOf(item)) passkeys.push(passkeyId(p));
  return {
    keepId: id,
    nameFrom: id,
    passwordFrom: firstWith('password'),
    folderFrom: firstWith('folder'),
    notesFrom: firstWith('notes'),
    websites: allWebsites(items).map(websiteKey),
    passkeys: [...new Set(passkeys)],
    valuesFrom: {},
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
  /** The files to copy onto the kept note before it names them (see `applyCopies`). */
  copies: AttachmentCopy[];
  /** The other items the merge rewrites: the ones that pointed at an item that goes. */
  relinks: Relink[];
}

const pick = (items: VaultItem[], id: string): VaultItem | undefined =>
  items.find((item) => item.id === id);

/**
 * The entries of `member` across `items`, the kept item's first, each distinct entry once: a link
 * by the item it names, an admin's field by its definition (one value per item, the kept item's
 * wins), any other field by all it holds, so two values of one field both stay. A link to an item of
 * the merge itself is dropped (an item is not linked to itself), the items outside it that name one
 * of its items (`alsoLinked`) are added, and links stay sorted by id as the item format keeps them.
 */
function unionOf(
  member: (typeof UNION_MEMBERS)[number],
  kept: VaultItem,
  items: VaultItem[],
  merged: Set<string>,
  alsoLinked: readonly string[],
): unknown[] {
  const seen = new Set<string>();
  const out: unknown[] = [];
  const add = (entry: unknown) => {
    const id = member === 'links' && entry && typeof entry === 'object' ? (entry as { id?: unknown }).id : undefined;
    if (typeof id === 'string' && merged.has(id.toLowerCase())) return;
    const admin =
      member === 'fields' && entry && typeof entry === 'object' ? (entry as { adminField?: unknown }).adminField : undefined;
    const key =
      typeof id === 'string'
        ? id.toLowerCase()
        : typeof admin === 'string' && admin !== ''
          ? `admin:${admin}`
          : stable(entry);
    if (seen.has(key)) return;
    seen.add(key);
    out.push(entry);
  };
  for (const item of [kept, ...items.filter((other) => other.id !== kept.id)]) {
    const list = item.data?.[member];
    if (Array.isArray(list)) for (const entry of list) add(entry);
  }
  if (member === 'links') {
    for (const id of alsoLinked) add({ id });
    const idOf = (entry: unknown): string =>
      entry && typeof entry === 'object' && typeof (entry as { id?: unknown }).id === 'string'
        ? (entry as { id: string }).id.toLowerCase()
        : '';
    out.sort((a, b) => (idOf(a) < idOf(b) ? -1 : idOf(a) > idOf(b) ? 1 : 0));
  }
  return out;
}

/** The name a picked item gives the merged one: its own, else the one its issuer and label make. */
function nameOf(picked: VaultItem | undefined, kept: VaultItem): string {
  if (!picked) return '';
  const own = str(picked.data, 'name');
  if (own !== '') return own;
  // An item of the app with no `name` is known by its issuer and account: picking it names the
  // merged item that, rather than leaving the name it had.
  const derived = itemName(picked);
  return picked.id !== kept.id && derived !== picked.kind ? derived : '';
}

/**
 * The writes of a merge of `items` (at least two) under `picks`. With `ctx` (the whole vault and what
 * the person may write) it also rewrites the items that pointed at an item that goes.
 */
export function planMerge(items: VaultItem[], picks: MergePicks, now: Date, ctx?: MergeContext): MergePlan | null {
  const kept = pick(items, picks.keepId);
  if (!kept || items.length < 2) return null;
  const trashed = items.filter((item) => item.id !== kept.id);
  const fields: ItemData = {};

  // What the kept item lacks, from the newest copy that has it; then what the person picked for the
  // fields the copies disagree on.
  Object.assign(fields, fillMissing(kept, trashed));
  for (const conflict of fieldConflicts(items)) {
    const donor = pick(items, chosenFrom(conflict, picks.valuesFrom, kept.id));
    const value = donor?.data?.[conflict.key];
    if (!donor || donor.id === kept.id || lacks(value)) continue;
    fields[conflict.key] = value;
    for (const also of GOES_WITH[kept.kind]?.[conflict.key] ?? []) fields[also] = donor.data?.[also];
  }

  const name = nameOf(pick(items, picks.nameFrom), kept);
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

  if (kept.kind === 'identity') {
    const documents = unionDocuments(kept, trashed);
    if (documents) fields['documents'] = documents;
  }
  if (kept.kind === 'backup-codes') {
    // A code used in any copy stays used: a merge never offers it again.
    const codes = mergeCodes(kept, trashed);
    if (codes) fields['codes'] = codes;
  }
  for (const flag of ['favorite', 'pinned'] as const) {
    if (anyFlag(items, flag) && kept.data?.[flag] !== true) fields[flag] = true;
  }

  const members = new Set(items.map((item) => item.id.toLowerCase()));
  const naming = itemsNaming(members, ctx);
  for (const member of UNION_MEMBERS) {
    const held = items.some((item) => Array.isArray(item.data?.[member]));
    if (!held && !(member === 'links' && naming.length > 0)) continue;
    const union = unionOf(member, kept, items, members, member === 'links' ? naming.map((item) => item.id) : []);
    fields[member] = union.length > 0 ? union : undefined;
  }

  const tags = new Set<string>();
  for (const item of items) {
    const list = item.data?.['tags'];
    if (Array.isArray(list)) for (const tag of list) if (typeof tag === 'string') tags.add(tag);
  }
  if (tags.size > 0) fields['tags'] = [...tags];

  const listed = new Set(
    (Array.isArray(fields['links']) ? (fields['links'] as unknown[]) : []).flatMap((entry) => {
      const id = entry && typeof entry === 'object' ? (entry as { id?: unknown }).id : undefined;
      return typeof id === 'string' ? [id.toLowerCase()] : [];
    }),
  );
  const relinks = planRelinks(kept, new Set(trashed.map((item) => item.id.toLowerCase())), listed, ctx);

  const before: ItemData = {};
  for (const key of Object.keys(fields)) before[key] = kept.data?.[key];
  return { kept, trashed, fields, before, retired, copies: attachmentCopies(kept, trashed), relinks };
}

/**
 * The plan once its files are on the server: the kept note names its own attachments and the ones
 * just copied (`entries`, each with the id of the file made for it). Undo puts its own back.
 */
export function applyCopies(plan: MergePlan, entries: ReadonlyArray<Record<string, unknown>>): MergePlan {
  if (entries.length === 0) return plan;
  const own = Array.isArray(plan.kept.data?.['attachments']) ? (plan.kept.data?.['attachments'] as unknown[]) : [];
  return {
    ...plan,
    fields: { ...plan.fields, attachments: [...own, ...entries] },
    before: { ...plan.before, attachments: plan.kept.data?.['attachments'] },
  };
}

/** The name the kept item has once merged: the picked one, else its own. */
export function resultName(plan: MergePlan): string {
  const name = plan.fields['name'];
  if (typeof name === 'string' && name !== '') return name;
  const own = plan.kept.data?.['name'];
  return typeof own === 'string' ? own : '';
}

/** The items of a merge the person may not write: a merge writes every one of them. */
export function unwritable(items: readonly VaultItem[], canWrite: ((item: VaultItem) => boolean) | undefined): VaultItem[] {
  return canWrite ? items.filter((item) => !canWrite(item)) : [];
}

/**
 * The saves of a merge: the kept item's new revision, the others into the Trash, and the items that
 * pointed at an item that goes now pointing at the kept one: one batch, all or none.
 */
export function mergeWrites(plan: MergePlan, now: Date): SaveInput[] {
  return [
    { existing: plan.kept, kind: plan.kept.kind, owner: plan.kept.owner, fields: plan.fields },
    ...plan.trashed.map((item) => ({
      existing: item,
      kind: item.kind,
      owner: item.owner,
      fields: { trashedAt: now.toISOString() },
    })),
    ...plan.relinks.map(({ item, after }) => ({
      existing: item,
      kind: item.kind,
      owner: item.owner,
      fields: after,
    })),
  ];
}

/**
 * The saves that reverse a merge, from the items it returned (their revisions have moved on): the
 * kept item gets its old fields back and the others leave the Trash. An item the merge rewrote gets
 * back only the members that still hold what the merge wrote, as the item `current` finds it now
 * (by default, as the merge saved it): one edited or linked elsewhere since keeps what it holds.
 */
export function undoWrites(
  plan: MergePlan,
  saved: VaultItem[],
  current: (id: string) => VaultItem | undefined = (id) => saved.find((item) => item.id === id),
): SaveInput[] {
  const writes: SaveInput[] = saved
    .filter((item) => item.id === plan.kept.id || plan.trashed.some((other) => other.id === item.id))
    .map((item) =>
      item.id === plan.kept.id
        ? { existing: item, kind: item.kind, owner: item.owner, fields: plan.before }
        : { existing: item, kind: item.kind, owner: item.owner, fields: { trashedAt: undefined } },
    );
  for (const relink of plan.relinks) {
    const held = current(relink.item.id);
    const fields = undoFields(relink, held);
    if (held && fields) writes.push({ existing: held, kind: held.kind, owner: held.owner, fields });
  }
  return writes;
}
