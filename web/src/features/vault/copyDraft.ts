// A copy of an item: the form of its kind opens filled from it (`/vault/new?copyOf=<id>`) and
// saves a new item. The copy keeps everything the person can see and everything an app that this
// one doesn't know wrote, and leaves behind what belongs to the original alone: its id, its
// links (a link is to that item), its files (the form sends them again), its passkeys and its
// password history (a passkey is made by a website, and the history is the original's), and its
// dates.
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

/** The item a copy's form is filled from: the original with the body of a copy. It is never saved. */
export function copySeed(source: VaultItem): VaultItem {
  return { ...source, data: copyBase(source.data) };
}

/**
 * The fields a copy is saved with: the body of the original (what the form doesn't show, such as
 * keys another app wrote, stays) with what the form wrote over it. Without a seed, the fields as they
 * are.
 */
export function copyFields(seed: VaultItem | undefined, fields: ItemData): ItemData {
  return seed ? { ...copyBase(seed.data), ...fields } : fields;
}
