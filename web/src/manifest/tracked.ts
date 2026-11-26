// The vault's API client, watched: a sync from scratch starts the manifest keeper over, and every
// item this browser writes goes into its ledger after the write and plans the next manifest. (What
// the sync serves reaches the keeper from the vault itself, which knows whether each envelope
// opened: `VaultDeps.served`.) Whatever the keeper does, a read or a write answers as it would
// without it: the keeper's own failures never reach the caller.
import type { Api } from '@/api/client';
import { isApiError } from '@/api/errors';
import type { ManifestKeeper } from './keeper';

/** The calls the vault makes, which `VaultDeps.api` is. */
export type VaultApi = Pick<Api, 'sync' | 'putItem' | 'putBatch'>;

export function trackedApi(
  api: VaultApi,
  keeper: Pick<ManifestKeeper, 'reset' | 'wrote'>,
): VaultApi {
  return {
    async sync(since, limit) {
      // A sync from scratch serves everything again: what was gathered before is stale.
      if (since === undefined) keeper.reset();
      try {
        return await api.sync(since, limit);
      } catch (error) {
        // The cursor is no longer good: the vault starts again from nothing, and so does the keeper.
        if (isApiError(error, 'full-sync-required')) keeper.reset();
        throw error;
      }
    },
    async putItem(item, precondition) {
      const result = await api.putItem(item, precondition);
      // Not waited for: signing is the keeper's business, not the write's.
      void keeper.wrote([item]).catch(() => undefined);
      return result;
    },
    async putBatch(request) {
      const items = await api.putBatch(request);
      void keeper.wrote(request.writes.map((write) => write.item)).catch(() => undefined);
      return items;
    },
  };
}
