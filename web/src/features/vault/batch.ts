// Seals several items and writes them in one `items:batch` call, all or none: a merge's kept item
// and its trashed twin either both change or neither does. It follows saveItem (vault.ts) step for
// step; only the write differs.
import type { ItemDto } from '@/api/types';
import { encodeB64 } from '@/lib/b64url';
import {
  sealedData,
  type SaveInput,
  type VaultDeps,
  type VaultItem,
  type VaultStore,
  sealFor,
  spaceOf,
  tombstone,
} from './vault';

/**
 * Up to 500 saves, written atomically. Every `existing` item must be at the revision it was read at.
 * `removed` items are deleted for good in the same batch (a tombstone each), so a move that makes an
 * item in its new place and removes it from the old one either does both or neither.
 */
export async function saveBatch(
  deps: VaultDeps,
  store: VaultStore,
  inputs: SaveInput[],
  removed: VaultItem[] = [],
): Promise<VaultItem[]> {
  const now = deps.now?.() ?? new Date();
  const newId = deps.newId ?? (() => globalThis.crypto.randomUUID());
  const saved: VaultItem[] = [];
  const writes: Array<{ expectedRevision: number | null; item: ItemDto }> = [];
  for (const input of inputs) {
    const { existing } = input;
    const id = existing?.id ?? newId();
    const revision = existing ? existing.revision + 1 : 1;
    const owner = existing?.owner ?? input.owner;
    const data = sealedData(existing, id, input.fields, now);
    const collectionId = input.recollect ?? existing?.collectionId ?? input.collectionId;
    const sealed = await sealFor(deps.crypto, {
      id,
      owner,
      kind: input.kind,
      revision,
      json: JSON.stringify(data),
      collectionId,
    });
    const inCollection = spaceOf(owner) !== null && collectionId ? { collectionId } : {};
    writes.push({
      expectedRevision: existing ? existing.revision : null,
      item: {
        id,
        owner,
        kind: input.kind,
        format: 'kem1',
        revision,
        keyVersion: sealed.keyVersion,
        ciphertext: encodeB64(sealed.ciphertext),
        itemKey: encodeB64(sealed.itemKey),
        deleted: false,
        ...inCollection,
      },
    });
    saved.push({
      id,
      owner,
      kind: input.kind,
      revision,
      keyVersion: sealed.keyVersion,
      ...inCollection,
      data,
      sizes: { ciphertext: sealed.ciphertext.length, itemKey: sealed.itemKey.length },
    });
  }
  for (const item of removed) writes.push({ expectedRevision: item.revision, item: tombstone(item) });
  for (let i = 0; i < writes.length; i += 500) {
    await deps.api.putBatch({ writes: writes.slice(i, i + 500) });
  }
  for (const item of saved) store.items.set(item.id, item);
  for (const item of removed) store.items.delete(item.id);
  return saved;
}
