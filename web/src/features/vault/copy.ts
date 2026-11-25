// "Make a copy": the create form, filled in from an item, saved as a new item.
//
// A copy keeps everything the person typed or the item held: the name and values, the custom
// fields, tags, a TOTP secret, a note's attachment entries and every key an app wrote that this one
// doesn't read. It drops only what names the old item or belongs to its history: its id, links
// (the other items don't link back to a copy), passkeys (a credential is one site's), the password
// history, the dates and the Trash mark.
//
// The form is filled from `copyDraft`, but a form owns only some fields (a login form knows nothing
// of custom fields), so the save is `{ ...draft.data, ...formFields }` (`copyFields`): the form's
// values win, everything else comes through. A note's files are kept by the server under the old
// item's id, so `saveCopy` sends their sealed bytes again under the new one (fileCopy.ts).
import type { ItemFiles } from '@/api/itemFiles';
import { copyFiles, removeFiles, serverFileIds, withoutServerFiles } from './fileCopy';
import { type ItemData, type SaveInput, type VaultDeps, type VaultItem, type VaultStore, deleteForGood, saveItem } from './vault';

const DROPPED = [
  'id',
  'links',
  'linkedLoginId',
  'file',
  'passkeys',
  'passwordHistory',
  'trashedAt',
  'updatedAt',
  'createdAt',
  'addedAt',
] as const;

/** The kinds that make no sense as a copy: a website makes a passkey, and a file needs its bytes chosen again. */
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

/** What a form saves for a copy: the draft's body, with the fields the form owns on top. */
export function copyFields(draft: VaultItem, formFields: ItemData): ItemData {
  return { ...draft.data, ...formFields };
}

/**
 * Saves a copy. When its body names files that were uploaded (a note's attachments), the item is
 * saved first without them, each file's sealed bytes are sent again from `sourceId` to the new
 * item, and the item is saved again naming them. If a step fails the new files and the item are
 * removed, so a copy is whole or not there.
 */
export async function saveCopy(
  deps: VaultDeps,
  store: VaultStore,
  files: ItemFiles | undefined,
  input: SaveInput,
  sourceId: string,
): Promise<VaultItem> {
  if (serverFileIds(input.fields).length === 0) return saveItem(deps, store, input);
  if (!files) throw new Error('copying files needs the files client');
  const stub = await saveItem(deps, store, { ...input, fields: withoutServerFiles(input.fields) });
  let sent: string[] = [];
  try {
    const copied = await copyFiles(files, sourceId, stub.id, input.fields);
    sent = copied.uploaded;
    return await saveItem(deps, store, {
      existing: stub,
      kind: stub.kind,
      owner: stub.owner,
      entry: input.entry,
      fields: copied.data,
    });
  } catch (error) {
    await removeFiles(files, stub.id, sent);
    try {
      await deleteForGood(deps, store, stub);
    } catch {
      // The failure to show is the one that stopped the copy, not this one.
    }
    throw error;
  }
}
