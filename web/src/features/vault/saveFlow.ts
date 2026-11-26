// Saving what a form made, beyond the one item: the files it chose and the links it holds. No React
// in here: the writes are injected, so the order and the failures are tested with fakes.
//
// Files. The server takes a file only for an item that exists, and an item never names a file the
// server lacks. So the item is saved first, without the files just chosen; each file is then sealed
// (KMA1) and sent; the item is saved again naming them. A file the person removed is deleted from
// the server last, once the item no longer names it.
//
// A retry does not send a file twice. When something fails after the item was saved, the error
// carries the item and the files that are on the server already; the next Save is given them, so it
// updates that item rather than making another, and skips every file the saved body names (or the
// error carried) by its attachment id.
//
// Links. A link is two-way, so each item the form links to is written to name this one, and each
// item it no longer links to is written to drop it. An end that is right already is left alone, so
// a retry only does what is left. A failed end doesn't undo the save: it is reported by name.
import type { FilesApi } from '@/api/files';
import type { ItemFiles } from '@/api/itemFiles';
import { readBytes } from '@/lib/files';
import { sha256Hex } from '@/lib/hash';
import { fileKeyBytes, kma1Length, sealKma1 } from '@/lib/kma1';
import { type AttachmentEntry, namedEntries } from './attachments';
import { removeFiles, resendFile, withServerFile } from './fileCopy';
import { linkWriteFields, planLinkWrites } from './links';
import { type ItemData, type SaveInput, type VaultItem, itemName } from './vault';

/** What a form hands over when it is submitted. */
export interface FormResult {
  /** The fields to save first. */
  fields: ItemData;
  /** The item is an entry of the Kemlock app (it carries its own id and `addedAt`). */
  entry: boolean;
  /** The ids the form links to now. */
  links: string[];
  /** Every file the form holds, stored or just chosen: what the item keeps once it is saved. */
  files: AttachmentEntry[];
  /** The files the person chose, whose bytes are still to be sealed and sent. */
  uploads: AttachmentEntry[];
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
  /** The server's ids of the files the item named when the form opened. */
  filesBefore?: string[];
  /** Files an earlier try already sent (an `UploadError` carried them): they are not sent again. */
  uploaded?: AttachmentEntry[];
}

export interface SaveDeps {
  save: (input: SaveInput) => Promise<VaultItem>;
  /** The item with this id as the vault holds it now. */
  lookup: (id: string) => VaultItem | undefined;
  /** The files route. A copy of a note also reads the sealed bytes of the original's files (`download`). */
  files: FilesApi & Partial<Pick<ItemFiles, 'download'>>;
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

/**
 * Saving a file, or the item that names it, failed. `saved` is the item as it stands on the server
 * (undefined when it was rolled back), so the next Save updates it; `uploaded` are the files that
 * are on the server for it already, which the next Save is handed so it doesn't send them again.
 */
export class UploadError extends Error {
  constructor(
    readonly reason: unknown,
    readonly saved: VaultItem | undefined,
    readonly uploaded: AttachmentEntry[] = [],
  ) {
    super('a file could not be sent');
    this.name = 'UploadError';
  }
}

/**
 * A file of another item (a copy of a note) sent again under this one: its sealed bytes go as they
 * are, so the key, the name and the hash the entry holds stay true. Nothing is decrypted.
 */
async function resend(deps: SaveDeps, itemId: string, entry: AttachmentEntry): Promise<AttachmentEntry> {
  const from = entry.copyOf as NonNullable<AttachmentEntry['copyOf']>;
  const { download } = deps.files;
  if (!download) throw new Error('sending a file again needs the sealed bytes of the original');
  const started: string[] = [];
  let sent: string;
  try {
    sent = await resendFile({ ...deps.files, download }, from.itemId, itemId, from.fileId, started);
  } catch (error) {
    // The upload was started and never finished: don't leave it counting against the quota.
    await removeFiles(deps.files, itemId, started);
    throw error;
  }
  const { copyOf: _from, file: _file, raw, ...rest } = entry;
  return { ...rest, kemlockFile: sent, ...(raw !== undefined ? { raw: withServerFile(raw, sent) } : {}) };
}

async function sendOne(deps: SaveDeps, itemId: string, entry: AttachmentEntry): Promise<AttachmentEntry> {
  if (entry.copyOf !== undefined) return resend(deps, itemId, entry);
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
  const { file: _sent, raw: _raw, origin: _origin, ...rest } = entry;
  return { ...rest, sha256, kemlockFile: started.fileId };
}

/** Takes back files that were sent for an item that is not kept. */
async function discard(deps: SaveDeps, itemId: string, sent: readonly AttachmentEntry[]): Promise<void> {
  for (const entry of sent) {
    if (entry.kemlockFile !== undefined) await deps.files.remove(itemId, entry.kemlockFile).catch(() => undefined);
  }
}

/**
 * A new item that is nothing without its file is not kept: the files that went up come off the
 * server and so does the item. If the item can't be removed it stays, and the error says so.
 */
async function rollBack(
  deps: SaveDeps,
  item: VaultItem,
  sent: readonly AttachmentEntry[],
  reason: unknown,
  held: AttachmentEntry[],
): Promise<UploadError> {
  await discard(deps, item.id, sent);
  try {
    await (deps.removeItem as (item: VaultItem) => Promise<void>)(item);
    return new UploadError(reason, undefined);
  } catch {
    return new UploadError(reason, item, held);
  }
}

export async function saveWithExtras(deps: SaveDeps, request: SaveRequest): Promise<SaveOutcome> {
  const { result } = request;
  const base = { kind: request.kind, owner: request.owner, collectionId: request.collectionId, entry: result.entry };

  // Files the server holds already for these entries, by attachment id: an earlier try sent them
  // (the error carried them) or the saved body names them.
  const held = new Map<string, AttachmentEntry>();
  for (const entry of namedEntries(request.existing?.data)) held.set(entry.id, entry);
  for (const entry of request.uploaded ?? []) held.set(entry.id, entry);
  const already = result.uploads.map((entry) => held.get(entry.id)).filter((e): e is AttachmentEntry => e !== undefined);
  const todo = result.uploads.filter((entry) => !held.has(entry.id));

  let item = await deps.save({
    ...base,
    existing: request.existing,
    fields: already.length > 0 ? { ...result.fields, ...result.withUploaded(already) } : result.fields,
  });
  const sent: AttachmentEntry[] = [];
  let named = already;

  if (todo.length > 0) {
    try {
      for (const entry of todo) sent.push(await sendOne(deps, item.id, entry));
    } catch (error) {
      if (result.rollbackOnFailure && deps.removeItem) throw await rollBack(deps, item, sent, error, already);
      // The files that did go up are named by the item, so a retry only sends what is left.
      if (sent.length > 0) {
        try {
          item = await deps.save({ ...base, existing: item, fields: result.withUploaded([...already, ...sent]) });
          named = [...already, ...sent];
        } catch {
          // The item can't name them, so they come off the server and the next Save sends them again.
          await discard(deps, item.id, sent);
        }
      }
      throw new UploadError(error, item, named);
    }
    named = [...already, ...sent];
    try {
      item = await deps.save({ ...base, existing: item, fields: result.withUploaded(named) });
    } catch (error) {
      if (result.rollbackOnFailure && deps.removeItem) throw await rollBack(deps, item, sent, error, named);
      // The item is saved and the files are on the server: the next Save names them.
      throw new UploadError(error, item, named);
    }
  }

  // The files the person removed go from the server last, now that no item names them. A file left
  // behind is only ciphertext the server already held.
  const kept = new Set<string>();
  for (const entry of [...result.files, ...named]) if (entry.kemlockFile !== undefined) kept.add(entry.kemlockFile);
  for (const fileId of request.filesBefore ?? []) {
    if (!kept.has(fileId)) await deps.files.remove(item.id, fileId).catch(() => undefined);
  }

  const linkFailures: string[] = [];
  for (const write of planLinkWrites(item.id, request.linksBefore, result.links, deps.lookup)) {
    try {
      await deps.save({
        existing: write.item,
        kind: write.item.kind,
        owner: write.item.owner,
        fields: linkWriteFields(write),
      });
    } catch {
      linkFailures.push(itemName(write.item));
    }
  }
  return { item, linkFailures };
}
