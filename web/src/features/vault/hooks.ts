// React Query wiring for the vault: the synced list, and the writes that keep it current.
import { queryOptions, useMutation, useQuery } from '@tanstack/react-query';
import { useCallback, useMemo } from 'react';
import { api, queryClient, session } from '@/app/services';
import { vaultCrypto } from '@/crypto-port';
import { spaceDeps } from '@/features/spaces/deps';
import { createSpaceKeyLoader, loadWritableCollections } from '@/features/spaces/keys';
import {
  type ItemData,
  type SaveInput,
  type VaultDeps,
  type VaultItem,
  deleteForGood,
  emptyTrash,
  isTrashed,
  restoreItem,
  saveItem,
  syncVault,
  trashItem,
  vaultStore,
} from './vault';

// Items of a space open once the worker holds the space's keys: the loader opens them on demand.
const spaceKeys = createSpaceKeyLoader(spaceDeps);
const deps: VaultDeps = { api, crypto: vaultCrypto, ensureSpaceKeys: spaceKeys.ensure };

export const vaultKey = ['vault'] as const;

export const vaultQuery = queryOptions({
  queryKey: vaultKey,
  queryFn: () => {
    // Locking clears this query while the page is still mounted, so it asks again at once. With the
    // keys gone no item would open, and the unreadable ones would stay in the store at their
    // revision: the sync after the next unlock finds nothing new and never opens them.
    if (session.getState().status !== 'unlocked') throw new Error('the vault is locked');
    return syncVault(deps, vaultStore);
  },
  staleTime: 15_000,
  refetchInterval: 30_000,
});

function publish(): void {
  queryClient.setQueryData(vaultKey, vaultStore.snapshot());
}

/** Forgets the opened items (on lock and sign-out). */
export function clearVault(): void {
  vaultStore.reset();
  spaceKeys.forget();
  queryClient.removeQueries({ queryKey: ['writable-collections'] });
  queryClient.removeQueries({ queryKey: vaultKey });
}

export function useVault() {
  const query = useQuery(vaultQuery);
  const all = query.data;
  return useMemo(() => {
    const items = all ?? [];
    return {
      active: items.filter((item) => !isTrashed(item)),
      trashed: items.filter(isTrashed),
      isLoading: query.isPending,
      error: query.error,
      refetch: query.refetch,
    };
  }, [all, query.isPending, query.error, query.refetch]);
}

/** The collections of the account's spaces that a new item may be saved to. */
export function useWritableCollections() {
  return useQuery({
    queryKey: ['writable-collections'] as const,
    queryFn: () => loadWritableCollections(spaceDeps),
    staleTime: 60_000,
  });
}

export function useVaultItem(id: string | undefined): {
  item: VaultItem | undefined;
  isLoading: boolean;
} {
  const query = useQuery(vaultQuery);
  const item = useMemo(() => query.data?.find((candidate) => candidate.id === id), [query.data, id]);
  return { item, isLoading: query.isPending };
}

/** A stale write means another app changed the item first: reload, then let the person retry. */
async function afterFailure(): Promise<void> {
  await queryClient.invalidateQueries({ queryKey: vaultKey });
}

export function useVaultActions() {
  const save = useMutation({
    mutationFn: (input: SaveInput) => saveItem(deps, vaultStore, input),
    onSuccess: publish,
    onError: afterFailure,
  });
  const trash = useMutation({
    mutationFn: (item: VaultItem) => trashItem(deps, vaultStore, item),
    onSuccess: publish,
    onError: afterFailure,
  });
  const restore = useMutation({
    mutationFn: (item: VaultItem) => restoreItem(deps, vaultStore, item),
    onSuccess: publish,
    onError: afterFailure,
  });
  const remove = useMutation({
    mutationFn: (item: VaultItem) => deleteForGood(deps, vaultStore, item),
    onSuccess: publish,
    onError: afterFailure,
  });
  const empty = useMutation({
    mutationFn: (items: VaultItem[]) => emptyTrash(deps, vaultStore, items),
    onSuccess: publish,
    onError: afterFailure,
  });
  return { save, trash, restore, remove, empty };
}

/** Stable text fields for a form: only strings the form owns. */
export function fieldsOf(data: ItemData | null | undefined, keys: string[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const key of keys) {
    const value = data?.[key];
    out[key] = typeof value === 'string' ? value : '';
  }
  return out;
}

export const useRefreshVault = () =>
  useCallback(() => queryClient.invalidateQueries({ queryKey: vaultKey }), []);
