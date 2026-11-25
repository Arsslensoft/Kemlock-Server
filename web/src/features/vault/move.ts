// Moving an item to another vault: from the account's own vault into a space's collection, from a
// collection into another, or back to the account's own vault. An item's id belongs to its owner,
// so a move is a new item (a fresh id, sealed under the key of its new place) and the old one
// deleted, in one batch that either does both or neither. The items that link to it name the new
// id in the same batch, so links survive the move.
//
// A file can't move: its bytes sit on the server under the old item's id, and only the Kemlock app
// that wrote it holds the key to re-upload it under another. An item that holds files stays where it is.
//
// No React in here: it is tested with fakes.
import { saveBatch } from './batch';
import { filesOf, fileOf } from './details/files';
import { readLinks, writeLinks } from './links';
import { type SaveInput, type VaultDeps, type VaultItem, type VaultStore, isTrashed, spaceOf } from './vault';

/** Where an item goes: `user:<uuid>` for the account's own vault, or a collection of a space. */
export interface MoveTarget {
  owner: string;
  /** Required when `owner` is a space. */
  collectionId?: string | undefined;
}

export type MoveRefusal = 'files' | 'unreadable' | 'trashed' | 'same-place' | 'collection';

export class MoveError extends Error {
  constructor(readonly reason: MoveRefusal) {
    super(`the item cannot be moved: ${reason}`);
    this.name = 'MoveError';
  }
}

/** Whether `item` holds a file (a File item, or a note with attachments). */
export function holdsFiles(item: VaultItem): boolean {
  return fileOf(item.data) !== undefined || filesOf(item.data).length > 0;
}

/** Why `item` can't be moved at all, or undefined when it can. */
export function moveRefusal(item: VaultItem): MoveRefusal | undefined {
  if (item.data === null) return 'unreadable';
  if (isTrashed(item)) return 'trashed';
  if (holdsFiles(item)) return 'files';
  return undefined;
}

/** Whether `target` is where `item` already is. */
export function isHere(item: VaultItem, target: MoveTarget): boolean {
  return item.owner === target.owner && (item.collectionId ?? '') === (target.collectionId ?? '');
}

/**
 * Makes `item` again in `target` under a new id and deletes it where it was. `linked` are the
 * items that link to `item` and that the person may write: each one now names the new id. Returns
 * the item in its new place.
 */
export async function moveItem(
  deps: VaultDeps,
  store: VaultStore,
  item: VaultItem,
  target: MoveTarget,
  linked: readonly VaultItem[] = [],
): Promise<VaultItem> {
  const refusal = moveRefusal(item);
  if (refusal) throw new MoveError(refusal);
  if (isHere(item, target)) throw new MoveError('same-place');
  if (spaceOf(target.owner) !== null && !target.collectionId) throw new MoveError('collection');

  const newId = (deps.newId ?? (() => globalThis.crypto.randomUUID()))();
  const oldId = item.id.toLowerCase();
  const inputs: SaveInput[] = [
    {
      kind: item.kind,
      owner: target.owner,
      collectionId: target.collectionId,
      // The body is kept as it is; its own id is dropped so the new one is stamped in.
      fields: { ...item.data, id: undefined },
    },
  ];
  for (const other of linked) {
    if (other.id === item.id || other.data === null) continue;
    const ids = readLinks(other.data);
    if (!ids.includes(oldId)) continue;
    inputs.push({
      existing: other,
      kind: other.kind,
      owner: other.owner,
      fields: { links: writeLinks(other.data, [...ids.filter((id) => id !== oldId), newId]) },
    });
  }
  const saved = await saveBatch({ ...deps, newId: () => newId }, store, inputs, [item]);
  const moved = saved[0];
  if (!moved) throw new Error('the move wrote nothing');
  return moved;
}
