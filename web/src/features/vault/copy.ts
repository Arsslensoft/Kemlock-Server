// "Make a copy": the create form, filled in from an item. The copy is a new item, so it carries
// nothing that names the old one or belongs to its history: no id, no links, no files (their bytes
// are under the old item's id), no passkeys (a credential is one site's), no password history, no
// dates and not the Trash mark. The name, the values and the other fields stay.
//
// The form gets the draft as if it were the item being edited, but it is saved as a new item.
import type { ItemData, VaultItem } from './vault';

const DROPPED = [
  'id',
  'links',
  'linkedLoginId',
  'attachments',
  'file',
  'passkeys',
  'passwordHistory',
  'trashedAt',
  'updatedAt',
  'createdAt',
  'addedAt',
] as const;

/** The kinds that make no sense as a copy: a website makes a passkey, and a file needs its bytes again. */
export function canCopy(item: VaultItem): boolean {
  return item.data !== null && item.kind !== 'passkey' && item.kind !== 'file';
}

/** The body of a copy of `data`. */
export function copyData(data: ItemData): ItemData {
  const copy: ItemData = { ...data };
  for (const key of DROPPED) delete copy[key];
  return copy;
}

/** A stand-in for `item` that the create form fills itself from: it has no id and no revision. */
export function copyDraft(item: VaultItem): VaultItem {
  return {
    id: '',
    owner: item.owner,
    kind: item.kind,
    revision: 0,
    keyVersion: item.keyVersion,
    data: item.data ? copyData(item.data) : null,
    sizes: { ciphertext: 0, itemKey: 0 },
  };
}
