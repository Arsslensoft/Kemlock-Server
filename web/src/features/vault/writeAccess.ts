// Whether the person may change an item. An item of the account's own vault is theirs; an item of a
// space is theirs to change only in a collection they may edit and hold a key for, which is what
// `useWritableCollections` lists. A merge writes every item it touches, so it asks first.
import type { WritableCollection } from '@/features/spaces/keys';
import { type VaultItem, spaceOf } from './vault';

/**
 * Whether `item` is in the person's own vault, or in a collection they may write. While the
 * collections are not known (`undefined`) it is taken as writable: the server refuses a write that
 * isn't allowed, and the person is not stopped for a list that hasn't come yet.
 */
export function canWriteItem(
  item: Pick<VaultItem, 'owner' | 'collectionId'>,
  writable: readonly WritableCollection[] | undefined,
): boolean {
  const space = spaceOf(item.owner);
  if (space === null || writable === undefined) return true;
  return writable.some((collection) => collection.spaceId === space && collection.collectionId === item.collectionId);
}
