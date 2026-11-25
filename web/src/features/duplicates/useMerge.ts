// The writes behind Duplicates and DuplicateMerge: one batch to merge, one to undo. A merge of notes
// first copies the files the kept note lacks onto it (attachmentCopy.ts); the batch then names them,
// so a merge that fails leaves no file behind and no item naming one the server lacks.
import { useMutation } from '@tanstack/react-query';
import { api, queryClient } from '@/app/services';
import { vaultCrypto } from '@/crypto-port';
import { saveBatch } from '@/features/vault/batch';
import { removeFiles } from '@/features/vault/fileCopy';
import { itemFiles, vaultKey } from '@/features/vault/hooks';
import { type VaultDeps, type VaultItem, vaultStore } from '@/features/vault/vault';
import { copyAttachments } from './attachmentCopy';
import { type MergePlan, applyCopies, mergeWrites, undoWrites } from './merge';

const deps: VaultDeps = { api, crypto: vaultCrypto };

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
      const copied = await copyAttachments(itemFiles, plan.kept.id, plan.copies);
      const written = applyCopies(plan, copied.entries);
      try {
        const saved = await saveBatch(deps, vaultStore, mergeWrites(written, new Date()));
        return { plan: written, saved, copiedFiles: copied.files };
      } catch (error) {
        await removeFiles(itemFiles, plan.kept.id, copied.files);
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
      await removeFiles(itemFiles, merged.plan.kept.id, merged.copiedFiles);
      return restored;
    },
    onSuccess: publish,
    onError: () => queryClient.invalidateQueries({ queryKey: vaultKey }),
  });
  return { merge, undo };
}
