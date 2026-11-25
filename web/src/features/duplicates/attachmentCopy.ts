// A secure note's attachments are files on the server, named in the note's body. When notes are
// merged, each file the kept note lacks is copied onto it, so trashing the other note takes none of
// them away. The `KMA1` bytes are sealed under the file's own key, which the entry carries, and are
// not bound to the note: the same bytes, uploaded under the kept note's id with the same entry, open
// with the same key. Nothing here decrypts a file.
//
// The copy happens before the merge's batch, and the batch names the new files, so a failure leaves
// nothing named that the server lacks: what was started is deleted and the merge is not made.
import type { VaultItem } from '@/features/vault/vault';

/** One attachment of an item that goes, to be copied onto the kept one. */
export interface AttachmentCopy {
  /** The item it is on now. */
  from: VaultItem;
  /** Its entry in that item's `attachments`, as written. */
  entry: Record<string, unknown>;
}

/** What the files route offers, as far as a copy needs it. */
export interface FileTransport {
  /** The `KMA1` bytes of a file of an item. */
  download(itemId: string, fileId: string): Promise<Uint8Array>;
  /** Starts the upload of a file `size` bytes long; answers its id on the server. */
  start(itemId: string, size: number): Promise<{ fileId: string }>;
  /** Sends the bytes of a started upload. */
  upload(itemId: string, fileId: string, bytes: Uint8Array): Promise<unknown>;
  /** Deletes a file of an item. */
  remove(itemId: string, fileId: string): Promise<void>;
}

function entries(item: VaultItem): Array<Record<string, unknown>> {
  const list = item.data?.['attachments'];
  return Array.isArray(list)
    ? list.filter((entry): entry is Record<string, unknown> => Boolean(entry) && typeof entry === 'object' && !Array.isArray(entry))
    : [];
}

const text = (entry: Record<string, unknown>, key: string): string =>
  typeof entry[key] === 'string' ? (entry[key] as string) : '';

/** The file's id on the server, which an entry names as `kemlockFile`. */
export function serverFileOf(entry: Record<string, unknown>): string {
  return text(entry, 'kemlockFile') || text(entry, 'fileId');
}

/** How an attachment is told from another: the id its entry carries, else its file on the server. */
const identity = (entry: Record<string, unknown>): string => text(entry, 'id') || `file:${serverFileOf(entry)}`;

/**
 * The attachments of the items that go that the kept item lacks, the newest item's first, each
 * once. An entry that names no file on the server (it was never uploaded) has nothing to copy.
 */
export function attachmentCopies(kept: VaultItem, others: readonly VaultItem[]): AttachmentCopy[] {
  const seen = new Set(entries(kept).map(identity));
  const out: AttachmentCopy[] = [];
  for (const from of others) {
    for (const entry of entries(from)) {
      if (serverFileOf(entry) === '' || seen.has(identity(entry))) continue;
      seen.add(identity(entry));
      out.push({ from, entry });
    }
  }
  return out;
}

/** What the copies came to: the entries to add to the kept note, and the files it now holds. */
export interface Copied {
  entries: Array<Record<string, unknown>>;
  /** The ids of the files made on the server, for Undo to remove and a failed merge to clean up. */
  files: string[];
}

/**
 * Copies each file onto the kept note, one after another. If one fails, every file started so far is
 * deleted and the error is thrown: nothing was named, so nothing is left behind.
 */
export async function copyAttachments(
  transport: FileTransport,
  keptId: string,
  copies: readonly AttachmentCopy[],
): Promise<Copied> {
  const entriesOut: Array<Record<string, unknown>> = [];
  const files: string[] = [];
  try {
    for (const { from, entry } of copies) {
      const bytes = await transport.download(from.id, serverFileOf(entry));
      const started = await transport.start(keptId, bytes.length);
      files.push(started.fileId);
      await transport.upload(keptId, started.fileId, bytes);
      const next: Record<string, unknown> = { ...entry, kemlockFile: started.fileId };
      if ('fileId' in next) next['fileId'] = started.fileId;
      entriesOut.push(next);
    }
  } catch (error) {
    await removeFiles(transport, keptId, files);
    throw error;
  }
  return { entries: entriesOut, files };
}

/** Deletes files of an item, each on its own: one that can't be deleted doesn't stop the others. */
export async function removeFiles(transport: FileTransport, itemId: string, files: readonly string[]): Promise<void> {
  for (const fileId of files) {
    try {
      await transport.remove(itemId, fileId);
    } catch {
      // The file stays on the server, unnamed; one that won't delete doesn't hold up the merge or its undo.
    }
  }
}
