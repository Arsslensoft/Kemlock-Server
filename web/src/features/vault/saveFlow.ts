// Saving what a form made, beyond the one item: the files it chose and the links it holds. No React
// in here: the writes are injected, so the order and the failures are tested with fakes.
//
// Files. The server takes a file only for an item that exists, and an item never names a file the
// server lacks. So the item is saved first, without the files just chosen; each file is then sealed
// (KMA1) and sent; the item is saved again naming them. A file the person removed is deleted from
// the server last, once the item no longer names it.
//
// Links. A link is two-way, so each item the form links to is written to name this one, and each
// item it no longer links to is written to drop it. An end that is right already is left alone, so
// a retry only does what is left. A failed end doesn't undo the save: it is reported by name.
import type { FilesApi } from '@/api/files';
import { readBytes } from '@/lib/files';
import { sha256Hex } from '@/lib/hash';
import { fileKeyBytes, kma1Length, sealKma1 } from '@/lib/kma1';
import type { AttachmentEntry } from './attachments';
import { planLinkWrites, writeLinks } from './links';
import { type ItemData, type SaveInput, type VaultItem, itemName } from './vault';

/** What a form hands over when it is submitted. */
export interface FormResult {
  /** The fields to save first. */
  fields: ItemData;
  /** The item is an entry of the Kemlock app (it carries its own id and `addedAt`). */
  entry: boolean;
  /** The ids the form links to now. */
  links: string[];
  /** The files the person chose, whose bytes are still to be sealed and sent. */
  uploads: AttachmentEntry[];
  /** The server ids of the files the person removed. */
  removedFiles: string[];
  /** The fields that name the files once they are on the server (each upload now carries its id). */
  withUploaded: (uploaded: AttachmentEntry[]) => ItemData;
  /** A new item that has nothing without its file is not kept when the file can't be sent. */
  rollbackOnFailure: boolean;
}

export interface SaveRequest {
  /** The item being edited, or the one an earlier try of this form saved. */
  existing?: VaultItem | undefined;
  kind: string;
  /** `user:<uuid>` or `space:<uuid>`; an edit keeps its owner. */
  owner: string;
  collectionId?: string | undefined;
  result: FormResult;
  /** The links the item had when the form opened. */
  linksBefore: string[];
}

export interface SaveDeps {
  save: (input: SaveInput) => Promise<VaultItem>;
  /** The item with this id as the vault holds it now. */
  lookup: (id: string) => VaultItem | undefined;
  files: FilesApi;
  /** Seals bytes as a KMA1 file under a key. */
  seal?: (key: Uint8Array, plain: Uint8Array) => Promise<Uint8Array>;
  read?: (file: Blob) => Promise<Uint8Array>;
  /** The SHA-256 of the plaintext bytes, lower-case hex. */
  hash?: (bytes: Uint8Array) => Promise<string>;
  /** Removes an item for good (the rollback of a new File item). */
  removeItem?: (item: VaultItem) => Promise<void>;
}

export interface SaveOutcome {
  item: VaultItem;
  /** The names of the items whose link could not be written. */
  linkFailures: string[];
}

/** A file could not be sent. The item was saved (`saved`), unless it was rolled back (undefined). */
export class UploadError extends Error {
  constructor(
    readonly reason: unknown,
    readonly saved: VaultItem | undefined,
  ) {
    super('a file could not be sent');
    this.name = 'UploadError';
  }
}

async function sendOne(deps: SaveDeps, itemId: string, entry: AttachmentEntry): Promise<AttachmentEntry> {
  const file = entry.file as Blob;
  const started = await deps.files.start(itemId, kma1Length(file.size));
  let sha256: string;
  try {
    const plain = await (deps.read ?? readBytes)(file);
    // Taken from the plaintext, before it is sealed: the body keeps it so duplicates can be found.
    sha256 = await (deps.hash ?? sha256Hex)(plain);
    const sealed = await (deps.seal ?? sealKma1)(fileKeyBytes(entry.key), plain);
    await deps.files.upload(itemId, started.fileId, sealed);
  } catch (error) {
    // The upload was started and never finished: don't leave it counting against the quota.
    await deps.files.remove(itemId, started.fileId).catch(() => undefined);
    throw error;
  }
  const { file: _sent, ...rest } = entry;
  return { ...rest, sha256, kemlockFile: started.fileId };
}

export async function saveWithExtras(deps: SaveDeps, request: SaveRequest): Promise<SaveOutcome> {
  const { result } = request;
  const base = { kind: request.kind, owner: request.owner, collectionId: request.collectionId, entry: result.entry };
  let item = await deps.save({ ...base, existing: request.existing, fields: result.fields });

  if (result.uploads.length > 0) {
    const uploaded: AttachmentEntry[] = [];
    try {
      for (const entry of result.uploads) uploaded.push(await sendOne(deps, item.id, entry));
    } catch (error) {
      let kept: VaultItem | undefined = item;
      if (result.rollbackOnFailure && deps.removeItem) {
        try {
          await deps.removeItem(item);
          kept = undefined;
        } catch {
          // It stays: the person sees the error and can try again on it.
        }
      }
      throw new UploadError(error, kept);
    }
    item = await deps.save({ ...base, existing: item, fields: result.withUploaded(uploaded) });
  }

  // The files the person removed go from the server last, now that no item names them. A file left
  // behind is only ciphertext the server already held.
  for (const fileId of result.removedFiles) await deps.files.remove(item.id, fileId).catch(() => undefined);

  const linkFailures: string[] = [];
  for (const write of planLinkWrites(item.id, request.linksBefore, result.links, deps.lookup)) {
    try {
      await deps.save({
        existing: write.item,
        kind: write.item.kind,
        owner: write.item.owner,
        fields: { links: writeLinks(write.item.data, write.links) },
      });
    } catch {
      linkFailures.push(itemName(write.item));
    }
  }
  return { item, linkFailures };
}
