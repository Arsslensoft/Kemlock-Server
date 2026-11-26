// A copy of an item: the form of its kind opens filled from it (`/vault/new?copyOf=<id>`) and
// saves a new item. The copy keeps everything the person can see and everything an app that this
// one doesn't know wrote, and leaves behind what belongs to the original alone: its id, its
// links (a link is to that item), its passkeys and its password history (a passkey is made by a
// website, and the history is the original's), and its dates. Its name is its own, unchanged.
//
// Files. The server keeps a file under one item's id, so a copy can't name the original's. A File
// item is not copied (its bytes would have to be chosen again). A secure note's attachments are
// listed in the form, and saving sends each one's sealed bytes again under the copy (saveFlow.ts,
// `AttachmentEntry.copyOf`); the body of the copy never names the original's files.
import type { ItemData, VaultItem } from './vault';

const LEFT_BEHIND = [
  'id',
  'links',
  'linkedLoginId',
  'file',
  'attachments',
  'passkeys',
  'passwordHistory',
  'addedAt',
  'updatedAt',
  'trashedAt',
];

/** The body of a copy: that of `data`, without what belongs to the original alone. */
export function copyBase(data: ItemData | null | undefined): ItemData {
  const out: ItemData = {};
  for (const [key, value] of Object.entries(data ?? {})) {
    if (!LEFT_BEHIND.includes(key)) out[key] = value;
  }
  return out;
}

/** Whether "Make a copy" is offered: not for a passkey (a website makes it), a file, or an item that can't be read. */
export function canCopy(item: VaultItem): boolean {
  return item.data !== null && item.kind !== 'passkey' && item.kind !== 'file';
}

/**
 * The item a copy's form is filled from: the original with the body of a copy, and for a secure note
 * its attachments too, so the form lists them. It is never saved as it is.
 */
export function copySeed(source: VaultItem): VaultItem {
  const data = copyBase(source.data);
  const attachments = source.data?.['attachments'];
  if (source.kind === 'note' && Array.isArray(attachments)) data['attachments'] = attachments;
  return { ...source, data };
}

/**
 * The fields a copy is saved with: the body of the original (what the form doesn't show, such as
 * keys another app wrote, stays) with what the form wrote over it. Without a seed, the fields as they
 * are.
 */
export function copyFields(seed: VaultItem | undefined, fields: ItemData): ItemData {
  return seed ? { ...copyBase(seed.data), ...fields } : fields;
}
