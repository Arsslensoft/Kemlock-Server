// Moving an item to another vault: from the account's own vault into a space's collection, from a
// collection into another, or back to the account's own vault.
//
// An item's id belongs to its owner, so a move to another owner makes the item again under a new id,
// sealed under the key of its new place, and deletes the old one, in one batch that either does
// both or neither. The items that link to it name the new id in the same batch, so links survive.
// A move between two collections of the same space is a write of the same item that names the new
// collection (the server asks edit on both), so the item keeps its id and its files.
//
// A file is kept by the server under one item's id, so an item that holds files gets them again
// under the new id first: a stub of the item is written there (it must exist before it can take a
// file), the sealed bytes of each uploaded file are sent again as they are (fileCopy.ts), and the
// one batch then names the new files, moves the links and deletes the old item. If anything fails
// the files already sent are removed and the stub is deleted, so nothing is left half moved.
//
// No React in here: it is tested with fakes.
import type { ItemFiles } from '@/api/itemFiles';
import { saveBatch } from './batch';
import { filesOf, fileOf } from './details/files';
import { copyFiles, removeFiles, serverFileIds, withoutServerFiles } from './fileCopy';
import { renamedLinkFields } from './itemLinks';
import {
  type ItemData,
  type SaveInput,
  type VaultDeps,
  type VaultItem,
  type VaultStore,
  deleteForGood,
  isTrashed,
  saveItem,
  spaceOf,
} from './vault';

/** Where an item goes: `user:<uuid>` for the account's own vault, or a collection of a space. */
export interface MoveTarget {
  owner: string;
  /** Required when `owner` is a space. */
  collectionId?: string | undefined;
}

export type MoveRefusal =
  | 'unreadable'
  | 'trashed'
  | 'read-only'
  | 'same-place'
  | 'collection'
  | 'contact'
  | 'too-many-links';

export class MoveError extends Error {
  constructor(readonly reason: MoveRefusal) {
    super(`the item cannot be moved: ${reason}`);
    this.name = 'MoveError';
  }
}

/**
 * The most items whose links one move rewrites. A batch holds 500 writes: the moved item, its
 * tombstone, and these. More would not be one batch, and a move is all or none.
 */
export const MAX_RELINKS = 498;

/** Whether `item` holds a file (a File item, or a note with attachments). */
export function holdsFiles(item: VaultItem): boolean {
  return fileOf(item.data) !== undefined || filesOf(item.data).length > 0;
}

/** Why `item` can't be moved at all, or undefined when it can. `writable` is whether this person may change it. */
export function moveRefusal(item: VaultItem, writable = true): MoveRefusal | undefined {
  if (item.data === null) return 'unreadable';
  if (isTrashed(item)) return 'trashed';
  if (!writable) return 'read-only';
  return undefined;
}

/** Whether `target` is where `item` already is. */
export function isHere(item: VaultItem, target: MoveTarget): boolean {
  return item.owner === target.owner && (item.collectionId ?? '') === (target.collectionId ?? '');
}

/** Why `item` can't go to `target`, or undefined. A contact stays in the account's own vault. */
export function targetRefusal(item: VaultItem, target: MoveTarget): MoveRefusal | undefined {
  if (isHere(item, target)) return 'same-place';
  if (spaceOf(target.owner) !== null) {
    if (!target.collectionId) return 'collection';
    if (item.kind === 'contact') return 'contact';
  }
  return undefined;
}

export interface MoveOptions {
  /** The items connected to `item` that this person may write: each one now names the new id. */
  linked?: readonly VaultItem[] | undefined;
  /** Needed when the item holds uploaded files and changes owner. */
  files?: ItemFiles | undefined;
  /** Whether this person may change `item`; false refuses the move. */
  writable?: boolean | undefined;
}

/**
 * Moves `item` to `target` and returns it in its new place. Between two collections of one space
 * that is the same item (same id); to another owner it is a new id.
 */
export async function moveItem(
  deps: VaultDeps,
  store: VaultStore,
  item: VaultItem,
  target: MoveTarget,
  options: MoveOptions = {},
): Promise<VaultItem> {
  const refusal = moveRefusal(item, options.writable ?? true) ?? targetRefusal(item, target);
  if (refusal) throw new MoveError(refusal);

  if (item.owner === target.owner) {
    return saveItem(deps, store, {
      existing: item,
      kind: item.kind,
      owner: item.owner,
      recollect: target.collectionId,
      fields: {},
    });
  }

  const newId = (deps.newId ?? (() => globalThis.crypto.randomUUID()))();
  const moveDeps: VaultDeps = { ...deps, newId: () => newId };
  const relinks: SaveInput[] = [];
  for (const other of options.linked ?? []) {
    if (other.id === item.id || other.data === null) continue;
    const fields = renamedLinkFields(other, item.id, newId);
    if (fields) relinks.push({ existing: other, kind: other.kind, owner: other.owner, fields });
  }
  if (relinks.length > MAX_RELINKS) throw new MoveError('too-many-links');

  // The body is kept as it is; its own id is dropped so the new one is stamped in.
  const body: ItemData = { ...item.data, id: undefined };
  const oldFiles = serverFileIds(item.data);
  if (oldFiles.length === 0) {
    const [moved] = await saveBatch(
      moveDeps,
      store,
      [{ kind: item.kind, owner: target.owner, collectionId: target.collectionId, fields: body }, ...relinks],
      [item],
    );
    if (!moved) throw new Error('the move wrote nothing');
    return moved;
  }

  const files = options.files;
  if (!files) throw new Error('moving an item that holds files needs the files client');
  // The stub: the item where it is going, naming no file yet, so the server takes its files.
  const stub = await saveItem(moveDeps, store, {
    kind: item.kind,
    owner: target.owner,
    collectionId: target.collectionId,
    fields: withoutServerFiles(body),
  });
  let sent: string[] = [];
  try {
    const copied = await copyFiles(files, item.id, stub.id, item.data as ItemData);
    sent = copied.uploaded;
    const [moved] = await saveBatch(
      moveDeps,
      store,
      [{ existing: stub, kind: stub.kind, owner: stub.owner, fields: { ...copied.data, id: undefined } }, ...relinks],
      [item],
    );
    if (!moved) throw new Error('the move wrote nothing');
    // The old item is gone; what it kept on the server goes too, and may already have.
    await removeFiles(files, item.id, oldFiles);
    return moved;
  } catch (error) {
    await removeFiles(files, stub.id, sent);
    try {
      await deleteForGood(deps, store, stub);
    } catch {
      // The failure to show is the one that stopped the move, not this one.
    }
    throw error;
  }
}
