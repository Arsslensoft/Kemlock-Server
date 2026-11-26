// React Query wiring for the vault: the synced list, and the writes that keep it current.
import { queryOptions, useMutation, useQuery } from '@tanstack/react-query';
import { useCallback, useMemo } from 'react';
import { api, queryClient, session } from '@/app/services';
import { vaultCrypto } from '@/crypto-port';
import { floorStore, spaceDeps } from '@/features/spaces/deps';
import { writableCollectionsKey } from '@/features/spaces/refresh';
import { createSpaceKeyLoader, loadWritableCollections } from '@/features/spaces/keys';
import { duplicatesViewStore } from '@/features/duplicates/viewState';
import { manifestKeeper, writeChecker } from '@/manifest/instance';
import { onForget } from '@/app/forget';
import { signedApi } from '@/api/signedWrites';
import { trackedApi } from '@/manifest/tracked';
import { forgetKeyFacts } from './keyFacts';
import { type KindCounts, countByKind } from './listFilters';
import { vaultFilterStore } from './vaultFilter';
import { canWriteItem } from './writeAccess';
import { type AdminFieldDef, type CustomFieldDefinitions, NO_DEFINITIONS, createCustomFieldsApi } from '@/api/customFields';
import { createItemFilesApi } from '@/api/itemFiles';
import { saveBatch } from './batch';
import { linkInputs, unlinkInputs } from './links';
import { type MoveTarget, moveItem } from './move';
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
// Every write this browser makes is signed by the account (docs/crypto.md, "Signed item writes"),
// and the signature of every item the server serves is checked before the item is taken in. The API
// the vault reads and writes through is also watched by the manifest keeper (src/manifest): what
// the server serves is checked against the signed manifest, and this browser's writes are signed in.
const deps: VaultDeps = {
  api: trackedApi(signedApi(api, vaultCrypto), manifestKeeper),
  crypto: vaultCrypto,
  ensureSpaceKeys: spaceKeys.ensure,
  writes: writeChecker,
  // What this browser has seen signed is kept across reloads, sealed by the worker.
  floors: {
    load: async (owner) => {
      const account = session.getState().userId;
      return account ? floorStore.load(account, owner) : {};
    },
    save: async (owner, floor) => {
      const account = session.getState().userId;
      if (account) await floorStore.save(account, owner, floor);
    },
  },
  served: (dto, opened, verdict) => manifestKeeper.served(dto, opened, verdict),
  rejected: (dto, verdict) => manifestKeeper.rejected(dto, verdict),
};

/** The files of items on this server: what a move or a copy sends again under another item, and what a download reads. */
export const itemFiles = createItemFilesApi(api);

const customFieldsApi = createCustomFieldsApi(api);

export const customFieldsKey = ['custom-fields'] as const;

/**
 * What the admin set up for custom fields, as it is now (`GET /kem/v1/custom-fields`): the fields
 * and whether people may add their own. Until it arrives, or when it can't be read (a server with
 * no such route), there are no admin fields and people may add their own.
 */
export function useCustomFieldDefinitions(): CustomFieldDefinitions {
  const query = useQuery({
    queryKey: customFieldsKey,
    queryFn: () => customFieldsApi.list(),
    staleTime: 60_000,
    retry: false,
  });
  return query.data ?? NO_DEFINITIONS;
}

/**
 * The fields the admin offers, as they are now: an item holds the name and type a field had when it
 * was saved, and the page shows the admin's current ones.
 */
export function useAdminFields(): AdminFieldDef[] {
  return useCustomFieldDefinitions().fields;
}

export const vaultKey = ['vault'] as const;

export const vaultQuery = queryOptions({
  queryKey: vaultKey,
  queryFn: async () => {
    // Locking clears this query while the page is still mounted, so it asks again at once. With the
    // keys gone no item would open, and the unreadable ones would stay in the store at their
    // revision: the sync after the next unlock finds nothing new and never opens them.
    if (session.getState().status !== 'unlocked') throw new Error('the vault is locked');
    const items = await syncVault(deps, vaultStore);
    // The ledger now holds all the server serves: check it against the manifests, without waiting.
    manifestKeeper.markComplete();
    void manifestKeeper.verify();
    return items;
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
  manifestKeeper.reset();
  spaceKeys.forget();
  forgetKeyFacts();
  // What the person had narrowed the lists to is theirs, not the next person's at this browser.
  vaultFilterStore.reset();
  duplicatesViewStore.reset();
  queryClient.removeQueries({ queryKey: writableCollectionsKey });
  queryClient.removeQueries({ queryKey: vaultKey });
}
onForget(clearVault);

export function useVault() {
  const query = useQuery(vaultQuery);
  const all = query.data;
  return useMemo(() => {
    const items = all ?? [];
    return {
      /** Every item that was opened, in the Trash or not: what a link is resolved against. */
      all: items,
      active: items.filter((item) => !isTrashed(item)),
      trashed: items.filter(isTrashed),
      isLoading: query.isPending,
      error: query.error,
      refetch: query.refetch,
    };
  }, [all, query.isPending, query.error, query.refetch]);
}

export interface SidebarCounts extends KindCounts {
  /** Items in the Trash. */
  trashed: number;
  isLoading: boolean;
}

/**
 * The numbers the sidebar shows: every item, how many of each kind (by stored kind id: `login`,
 * `otp`, `backup-codes`…; a kind with none is absent, so read `byKind[kind] ?? 0`) and how many
 * are in the Trash. Items in the Trash count in neither the total nor a kind.
 */
export function useKindCounts(): SidebarCounts {
  const { active, trashed, isLoading } = useVault();
  return useMemo(
    () => ({ ...countByKind(active), trashed: trashed.length, isLoading }),
    [active, trashed, isLoading],
  );
}

/** The collections of the account's spaces that a new item may be saved to. */
export function useWritableCollections() {
  return useQuery({
    queryKey: writableCollectionsKey,
    queryFn: () => loadWritableCollections(spaceDeps),
    staleTime: 60_000,
  });
}

/**
 * Whether this person may change an item: always one of the account's own vault, and one of a
 * space when they may edit its collection. While the collections load the answer is yes, and the
 * server has the last word (writeAccess.ts).
 */
export function useCanWrite(): (item: VaultItem) => boolean {
  const collections = useWritableCollections();
  return useMemo(() => (item) => canWriteItem(item, collections.data), [collections.data]);
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
  // Links are two-way: both items are written in one batch, so a link is on both or on neither.
  const link = useMutation({
    mutationFn: async ({ a, b, linked }: { a: VaultItem; b: VaultItem; linked: boolean }) => {
      const inputs = linked ? linkInputs(a, b) : unlinkInputs(a, b);
      if (inputs.length > 0) await saveBatch(deps, vaultStore, inputs);
    },
    onSuccess: publish,
    onError: afterFailure,
  });
  const move = useMutation({
    mutationFn: ({
      item,
      target,
      linked,
      writable,
    }: {
      item: VaultItem;
      target: MoveTarget;
      linked: VaultItem[];
      writable: boolean;
    }) => moveItem(deps, vaultStore, item, target, { linked, writable, files: itemFiles }),
    onSuccess: publish,
    onError: afterFailure,
  });
  return { save, trash, restore, remove, empty, link, move };
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
