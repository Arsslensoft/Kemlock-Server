// The writes behind Duplicates and DuplicateMerge: one batch to merge, one to undo.
import { useMutation } from '@tanstack/react-query';
import { api, queryClient } from '@/app/services';
import { vaultCrypto } from '@/crypto-port';
import { vaultKey } from '@/features/vault/hooks';
import { saveBatch } from '@/features/vault/batch';
import { type VaultDeps, type VaultItem, vaultStore } from '@/features/vault/vault';
import { type MergePlan, mergeWrites, undoWrites } from './merge';

const deps: VaultDeps = { api, crypto: vaultCrypto };

function publish(): void {
  queryClient.setQueryData(vaultKey, vaultStore.snapshot());
}

export interface Merged {
  plan: MergePlan;
  /** The items as saved, in the order of the plan: what Undo reverses. */
  saved: VaultItem[];
}

export function useMergeActions() {
  const merge = useMutation({
    mutationFn: async (plan: MergePlan): Promise<Merged> => ({
      plan,
      saved: await saveBatch(deps, vaultStore, mergeWrites(plan, new Date())),
    }),
    onSuccess: publish,
    onError: () => queryClient.invalidateQueries({ queryKey: vaultKey }),
  });
  const undo = useMutation({
    mutationFn: (merged: Merged) =>
      saveBatch(deps, vaultStore, undoWrites(merged.plan, merged.saved)),
    onSuccess: publish,
    onError: () => queryClient.invalidateQueries({ queryKey: vaultKey }),
  });
  return { merge, undo };
}
