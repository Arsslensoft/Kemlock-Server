// The vault as the web app holds it: items opened through the crypto worker, kept in memory,
// kept current by delta sync. No React in here, so it is tested with fakes.
//
// Item plaintext (test-vectors/kem1.json): a login is `{name, username, password, urls}`, a note
// `{name, text}`. The web app adds `favorite`, `notes`, `updatedAt` and `trashedAt`, and keeps
// any other field another app wrote when it saves an item again.
import type { Api, SyncResult } from '@/api/client';
import { isApiError } from '@/api/errors';
import type { ItemDto } from '@/api/types';
import type { CryptoPort, SealedItem } from '@/crypto-port';
import { decodeB64, encodeB64 } from '@/lib/b64url';

export type ItemData = {
  name?: string;
  notes?: string;
  favorite?: boolean;
  updatedAt?: string;
  /** Set while the item is in the Trash; the item is removed for good 30 days later. */
  trashedAt?: string;
  [field: string]: unknown;
};

export interface VaultItem {
  id: string;
  owner: string;
  kind: string;
  revision: number;
  keyVersion: number;
  /** The collection an item of a space is in; absent for an item of the account's own vault. */
  collectionId?: string;
  /** null when the worker couldn't open it (a different key, or a kind this app can't read). */
  data: ItemData | null;
  /** Sizes of what the server holds, for the "What the server holds" card. */
  sizes: { ciphertext: number; itemKey: number };
}

export const TRASH_DAYS = 30;

export class VaultStore {
  readonly items = new Map<string, VaultItem>();
  cursor: string | undefined;

  reset(): void {
    this.items.clear();
    this.cursor = undefined;
  }

  snapshot(): VaultItem[] {
    return [...this.items.values()];
  }
}

export const vaultStore = new VaultStore();

/** What opening and sealing items needs of the worker; the space operations are optional. */
export type VaultCrypto = Pick<CryptoPort, 'openItem' | 'sealItem'> &
  Partial<Pick<CryptoPort, 'openSpaceItem' | 'sealSpaceItem'>>;

export interface VaultDeps {
  api: Pick<Api, 'sync' | 'putItem' | 'putBatch'>;
  crypto: VaultCrypto;
  /**
   * Opens the space and collection keys of a space in the worker, so its items open. Called when
   * an item of a space does not open for want of them; absent when keys are not available.
   */
  ensureSpaceKeys?: (spaceId: string) => Promise<void>;
  now?: () => Date;
  newId?: () => string;
}

const SPACE_PREFIX = 'space:';

/** The space an `owner` names, or null for `user:<uuid>`. */
export function spaceOf(owner: string): string | null {
  return owner.startsWith(SPACE_PREFIX) ? owner.slice(SPACE_PREFIX.length) : null;
}

export interface ItemToSeal {
  id: string;
  owner: string;
  kind: string;
  revision: number;
  json: string;
  /** Required when `owner` is a space. */
  collectionId?: string | undefined;
}

/**
 * Seals one item for its owner: an item of the account's vault under the account's key, an item of
 * a space under the key of its collection (the worker holds both and answers the key version).
 */
export async function sealFor(crypto: VaultCrypto, item: ItemToSeal): Promise<SealedItem> {
  const space = spaceOf(item.owner);
  if (space === null) {
    return crypto.sealItem({
      id: item.id,
      owner: item.owner,
      kind: item.kind,
      revision: item.revision,
      json: item.json,
    });
  }
  if (!item.collectionId) throw new Error('an item of a space needs a collection');
  if (!crypto.sealSpaceItem) throw new Error('this build cannot seal an item of a space');
  return crypto.sealSpaceItem({
    spaceId: space,
    collectionId: item.collectionId,
    id: item.id,
    kind: item.kind,
    revision: item.revision,
    json: item.json,
  });
}

async function openJson(
  crypto: VaultCrypto,
  dto: ItemDto,
  ciphertext: Uint8Array,
  itemKey: Uint8Array,
): Promise<string> {
  const space = spaceOf(dto.owner);
  if (space === null) {
    return crypto.openItem({
      id: dto.id,
      owner: dto.owner,
      kind: dto.kind,
      revision: dto.revision,
      keyVersion: dto.keyVersion,
      ciphertext,
      itemKey,
    });
  }
  if (!dto.collectionId || !crypto.openSpaceItem) throw new Error('no key for this item');
  return crypto.openSpaceItem({
    spaceId: space,
    collectionId: dto.collectionId,
    id: dto.id,
    kind: dto.kind,
    revision: dto.revision,
    keyVersion: dto.keyVersion,
    ciphertext,
    itemKey,
  });
}

export async function openDto(
  crypto: VaultCrypto,
  dto: ItemDto,
  ensureSpaceKeys?: (spaceId: string) => Promise<void>,
): Promise<VaultItem | null> {
  if (dto.deleted || !dto.ciphertext || !dto.itemKey) return null;
  const ciphertext = decodeB64(dto.ciphertext);
  const itemKey = decodeB64(dto.itemKey);
  let data: ItemData | null = null;
  try {
    let json: string;
    try {
      json = await openJson(crypto, dto, ciphertext, itemKey);
    } catch (error) {
      // An item of a space opens once the worker holds that space's keys: load them, then once more.
      const space = spaceOf(dto.owner);
      if (space === null || !ensureSpaceKeys) throw error;
      await ensureSpaceKeys(space);
      json = await openJson(crypto, dto, ciphertext, itemKey);
    }
    const parsed: unknown = JSON.parse(json);
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) data = parsed as ItemData;
  } catch {
    data = null;
  }
  return {
    id: dto.id,
    owner: dto.owner,
    kind: dto.kind,
    revision: dto.revision,
    keyVersion: dto.keyVersion,
    ...(dto.collectionId ? { collectionId: dto.collectionId } : {}),
    data,
    sizes: { ciphertext: ciphertext.length, itemKey: itemKey.length },
  };
}

async function apply(deps: VaultDeps, store: VaultStore, dto: ItemDto): Promise<void> {
  const current = store.items.get(dto.id);
  if (current && current.revision >= dto.revision) return;
  if (dto.deleted) {
    store.items.delete(dto.id);
    return;
  }
  const item = await openDto(deps.crypto, dto, deps.ensureSpaceKeys);
  if (item) store.items.set(item.id, item);
}

/** Pulls every change since the stored cursor (everything, the first time) into the store. */
export async function syncVault(deps: VaultDeps, store: VaultStore): Promise<VaultItem[]> {
  let since = store.cursor;
  for (;;) {
    let result: SyncResult;
    try {
      result = await deps.api.sync(since, 500);
    } catch (error) {
      if (isApiError(error, 'full-sync-required') && since !== undefined) {
        store.reset();
        since = undefined;
        continue;
      }
      throw error;
    }
    if (result.notModified) break;
    for (const dto of result.page.items) await apply(deps, store, dto);
    store.cursor = result.page.cursor;
    since = result.page.cursor;
    if (!result.page.more) break;
  }
  return store.snapshot();
}

export function isTrashed(item: VaultItem): boolean {
  return Boolean(item.data?.trashedAt);
}

/** When a trashed item goes for good. */
export function goneOn(item: VaultItem): Date | null {
  const at = item.data?.trashedAt;
  if (!at) return null;
  const date = new Date(at);
  if (Number.isNaN(date.getTime())) return null;
  date.setUTCDate(date.getUTCDate() + TRASH_DAYS);
  return date;
}

export interface SaveInput {
  /** The item being edited; absent for a new one. */
  existing?: VaultItem;
  kind: string;
  /** `user:<uuid>` for a new item, or `space:<uuid>` to make it in a space; an edit keeps its owner. */
  owner: string;
  /** The collection of a new item of a space; an edit keeps its own. */
  collectionId?: string | undefined;
  /** The fields the form owns; other fields of `existing.data` survive. */
  fields: ItemData;
  /**
   * The item is an entry of the Kemlock app (a key or a contact): it carries its own `id`, the
   * item's, and `addedAt` and `updatedAt` as epoch milliseconds, as the app reads them.
   */
  entry?: boolean;
}

/** Seals and stores one item. A new item is revision 1; an edit is the previous revision plus one. */
export async function saveItem(
  deps: VaultDeps,
  store: VaultStore,
  input: SaveInput,
): Promise<VaultItem> {
  const { existing } = input;
  const id = existing?.id ?? (deps.newId ?? (() => globalThis.crypto.randomUUID()))();
  const revision = existing ? existing.revision + 1 : 1;
  const owner = existing?.owner ?? input.owner;
  const data: ItemData = {
    ...(existing?.data ?? {}),
    ...input.fields,
    updatedAt: (deps.now?.() ?? new Date()).toISOString(),
  };
  if (input.entry) {
    const at = (deps.now?.() ?? new Date()).getTime();
    data['id'] = id;
    data['addedAt'] = typeof data['addedAt'] === 'number' ? data['addedAt'] : at;
    data['updatedAt'] = at;
  }
  // A cleared optional field is removed, not kept as an empty string.
  for (const key of Object.keys(data)) if (data[key] === undefined) delete data[key];
  const collectionId = existing?.collectionId ?? input.collectionId;
  const sealed = await sealFor(deps.crypto, {
    id,
    owner,
    kind: input.kind,
    revision,
    json: JSON.stringify(data),
    collectionId,
  });
  const dto: ItemDto = {
    id,
    owner,
    kind: input.kind,
    format: 'kem1',
    revision,
    keyVersion: sealed.keyVersion,
    ciphertext: encodeB64(sealed.ciphertext),
    itemKey: encodeB64(sealed.itemKey),
    deleted: false,
    // An item of a space is written into its collection; an item of a vault has none.
    ...(spaceOf(owner) !== null && collectionId ? { collectionId } : {}),
  };
  await deps.api.putItem(dto, existing ? { ifMatch: existing.revision } : { ifNoneMatch: true });
  const saved: VaultItem = {
    id,
    owner,
    kind: input.kind,
    revision,
    keyVersion: sealed.keyVersion,
    ...(dto.collectionId ? { collectionId: dto.collectionId } : {}),
    data,
    sizes: { ciphertext: sealed.ciphertext.length, itemKey: sealed.itemKey.length },
  };
  store.items.set(id, saved);
  return saved;
}

/** Moves an item to the Trash: it stays, encrypted, with a `trashedAt` for 30 days. */
export function trashItem(deps: VaultDeps, store: VaultStore, item: VaultItem): Promise<VaultItem> {
  return saveItem(deps, store, {
    existing: item,
    kind: item.kind,
    owner: item.owner,
    fields: { trashedAt: (deps.now?.() ?? new Date()).toISOString() },
  });
}

export function restoreItem(
  deps: VaultDeps,
  store: VaultStore,
  item: VaultItem,
): Promise<VaultItem> {
  return saveItem(deps, store, {
    existing: item,
    kind: item.kind,
    owner: item.owner,
    fields: { trashedAt: undefined },
  });
}

function tombstone(item: VaultItem): ItemDto {
  return {
    id: item.id,
    owner: item.owner,
    kind: item.kind,
    format: 'kem1',
    revision: item.revision + 1,
    keyVersion: item.keyVersion,
    deleted: true,
    ...(item.collectionId ? { collectionId: item.collectionId } : {}),
  };
}

/** Deletes one item for good: a tombstone whose revision moves on, so every app sees it. */
export async function deleteForGood(
  deps: VaultDeps,
  store: VaultStore,
  item: VaultItem,
): Promise<void> {
  await deps.api.putItem(tombstone(item), { ifMatch: item.revision });
  store.items.delete(item.id);
}

/** Empties the Trash in batches of up to 500, all or none within a batch. */
export async function emptyTrash(
  deps: VaultDeps,
  store: VaultStore,
  items: VaultItem[],
): Promise<void> {
  for (let i = 0; i < items.length; i += 500) {
    const batch = items.slice(i, i + 500);
    await deps.api.putBatch({
      writes: batch.map((item) => ({ expectedRevision: item.revision, item: tombstone(item) })),
    });
    for (const item of batch) store.items.delete(item.id);
  }
}

/** What to show for an item that has no readable name. */
export function itemName(item: VaultItem): string {
  const name = item.data?.name;
  return typeof name === 'string' && name !== '' ? name : item.kind;
}

export function loginOf(item: VaultItem): { username: string; password: string; urls: string[] } {
  const data: ItemData = item.data ?? {};
  const username = data['username'];
  const password = data['password'];
  const rawUrls = data['urls'];
  return {
    username: typeof username === 'string' ? username : '',
    password: typeof password === 'string' ? password : '',
    urls: Array.isArray(rawUrls) ? rawUrls.filter((u): u is string => typeof u === 'string') : [],
  };
}

export function noteOf(item: VaultItem): string {
  const text = item.data?.['text'];
  return typeof text === 'string' ? text : '';
}
