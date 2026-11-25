// The writes behind Duplicates and DuplicateMerge: one batch to merge, one to undo. A merge of notes
// first copies the files the kept note lacks onto it (attachmentCopy.ts); the batch then names them,
// so a merge that fails leaves no file behind and no item naming one the server lacks.
import { useMutation } from '@tanstack/react-query';
import { createFilesApi } from '@/api/files';
import { api, queryClient } from '@/app/services';
import { vaultCrypto } from '@/crypto-port';
import { vaultKey } from '@/features/vault/hooks';
import { saveBatch } from '@/features/vault/batch';
import { type VaultDeps, type VaultItem, vaultStore } from '@/features/vault/vault';
import { type FileTransport, copyAttachments, removeFiles } from './attachmentCopy';
import { type MergePlan, applyCopies, mergeWrites, undoWrites } from './merge';

const deps: VaultDeps = { api, crypto: vaultCrypto };

const files = createFilesApi(api);

/** The files route as a merge uses it: the sealed bytes of a file in, and out under another item. */
export const fileTransport: FileTransport = {
  download: async (itemId, fileId) => {
    const response = await api.raw({
      method: 'GET',
      path: `/kem/v1/items/${encodeURIComponent(itemId)}/files/${encodeURIComponent(fileId)}`,
    });
    return new Uint8Array(await response.arrayBuffer());
  },
  start: (itemId, size) => files.start(itemId, size),
  upload: (itemId, fileId, bytes) => files.upload(itemId, fileId, bytes),
  remove: (itemId, fileId) => files.remove(itemId, fileId),
};

function publish(): void {
  queryClient.setQueryData(vaultKey, vaultStore.snapshot());
}

export interface Merged {
  /** The plan as it was written: the kept note names the files that were copied. */
  plan: MergePlan;
  /** The items as saved, in the order of the plan: what Undo reverses. */
  saved: VaultItem[];
  /** The files made on the kept note's id, which Undo removes once the note names its own again. */
  copiedFiles: string[];
}

export function useMergeActions() {
  const merge = useMutation({
    mutationFn: async (plan: MergePlan): Promise<Merged> => {
      const copied = await copyAttachments(fileTransport, plan.kept.id, plan.copies);
      const written = applyCopies(plan, copied.entries);
      try {
        const saved = await saveBatch(deps, vaultStore, mergeWrites(written, new Date()));
        return { plan: written, saved, copiedFiles: copied.files };
      } catch (error) {
        await removeFiles(fileTransport, plan.kept.id, copied.files);
        throw error;
      }
    },
    onSuccess: publish,
    onError: () => queryClient.invalidateQueries({ queryKey: vaultKey }),
  });
  const undo = useMutation({
    mutationFn: async (merged: Merged) => {
      // An item the merge rewrote is read as the vault holds it now, to put back only what still holds.
      const restored = await saveBatch(
        deps,
        vaultStore,
        undoWrites(merged.plan, merged.saved, (id) => vaultStore.items.get(id)),
      );
      await removeFiles(fileTransport, merged.plan.kept.id, merged.copiedFiles);
      return restored;
    },
    onSuccess: publish,
    onError: () => queryClient.invalidateQueries({ queryKey: vaultKey }),
  });
  return { merge, undo };
}
