// Seals imported items in this browser and writes them 500 at a time, all or none within a batch.
// Nothing of the file reaches the server in the clear: it sees ciphertext, as for any saved item.
import { saveBatch } from '@/features/vault/batch';
import type { VaultDeps, VaultStore } from '@/features/vault/vault';
import type { NewItem } from './toItems';

export const BATCH_SIZE = 500;

export interface ImportOutcome {
  imported: number;
}

/**
 * Writes `items` into `owner` (`user:<uuid>` or `space:<uuid>`). `onProgress` is told after each
 * batch. A failed batch throws and leaves earlier batches written: the next run would import
 * those again, so the caller says how many went in before it failed.
 */
export async function importItems(
  deps: VaultDeps,
  store: VaultStore,
  items: NewItem[],
  owner: string,
  onProgress?: (done: number, total: number) => void,
): Promise<ImportOutcome> {
  let done = 0;
  for (let start = 0; start < items.length; start += BATCH_SIZE) {
    const chunk = items.slice(start, start + BATCH_SIZE);
    const ids = chunk.map((item) => item.id);
    let next = 0;
    await saveBatch(
      { ...deps, newId: () => ids[next++] ?? globalThis.crypto.randomUUID() },
      store,
      chunk.map((item) => ({ kind: item.kind, owner, fields: item.data })),
    );
    done += chunk.length;
    onProgress?.(done, items.length);
  }
  return { imported: done };
}
