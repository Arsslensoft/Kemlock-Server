// Giving an item's files to another item: a move to another owner and a copy of a note both make a
// new item that must hold its own files, because the server keeps a file under one item's id.
//
// The sealed `KMA1` bytes are sent again exactly as they are: a file's chunks are not bound to the
// item (docs/crypto.md, "Files"), so they open with the same key under the new item. Nothing is
// decrypted and the key in the body does not change; only the server's file id does.
//
// A body names a file by `kemlockFile` (what the Kemlock app writes) or `fileId`, in `file` for a
// File item and in each entry of `attachments` for a note. An entry that was never uploaded has
// neither and is left as it is. No React in here: it is tested with a fake files client.
import type { ItemData } from './vault';

const KEYS = ['kemlockFile', 'fileId'] as const;

function isEntry(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export function serverIdOf(entry: Record<string, unknown>): string {
  for (const key of KEYS) {
    const value = entry[key];
    if (typeof value === 'string' && value !== '') return value;
  }
  return '';
}

/** Every file entry of a body: `file`, then each of `attachments`. */
function entriesOf(data: ItemData): Record<string, unknown>[] {
  const out: Record<string, unknown>[] = [];
  if (isEntry(data['file'])) out.push(data['file']);
  const list = data['attachments'];
  if (Array.isArray(list)) for (const entry of list) if (isEntry(entry)) out.push(entry);
  return out;
}

/** The server's ids of the files a body names: the ones that were uploaded, each once. */
export function serverFileIds(data: ItemData | null | undefined): string[] {
  if (!data) return [];
  return [...new Set(entriesOf(data).map(serverIdOf).filter((id) => id !== ''))];
}

/** A copy of `data` with each file entry rewritten by `change` (the entry itself is never mutated). */
function mapEntries(data: ItemData, change: (entry: Record<string, unknown>) => Record<string, unknown>): ItemData {
  const out: ItemData = { ...data };
  if (isEntry(data['file'])) out['file'] = change(data['file']);
  const list = data['attachments'];
  if (Array.isArray(list)) out['attachments'] = list.map((entry) => (isEntry(entry) ? change(entry) : entry));
  return out;
}

/** The body with no server file ids: every entry keeps its name, size and key, and names no file. */
export function withoutServerFiles(data: ItemData): ItemData {
  return mapEntries(data, (entry) => {
    const copy = { ...entry };
    for (const key of KEYS) delete copy[key];
    return copy;
  });
}

/**
 * The body with each server file id replaced by `ids.get(old)`. An id with no new one is dropped, and
 * so is an id key that holds nothing at all: an entry that was never uploaded names no file, not even
 * with a member set to `undefined`.
 */
export function withServerFiles(data: ItemData, ids: ReadonlyMap<string, string>): ItemData {
  return mapEntries(data, (entry) => {
    const copy = { ...entry };
    for (const key of KEYS) {
      const old = copy[key];
      if (old === undefined) {
        delete copy[key];
        continue;
      }
      if (typeof old !== 'string' || old === '') continue;
      const next = ids.get(old);
      if (next === undefined) delete copy[key];
      else copy[key] = next;
    }
    return copy;
  });
}

/** Removes files from an item, and does not mind when one is already gone. */
export async function removeFiles(files: Pick<FileResender, 'remove'>, itemId: string, ids: readonly string[]): Promise<void> {
  await Promise.allSettled(ids.map((id) => files.remove(itemId, id)));
}

/** What sending a file again needs of the files route (`ItemFiles` has all of it). */
export interface FileResender {
  /** The `KMA1` bytes of a file of an item, still sealed. */
  download(itemId: string, fileId: string): Promise<Uint8Array>;
  /** Starts the upload of a file `size` bytes long; answers its id on the server. */
  start(itemId: string, size: number): Promise<{ fileId: string }>;
  /** Sends the bytes of a started upload. */
  upload(itemId: string, fileId: string, bytes: Uint8Array): Promise<unknown>;
  /** Removes a file of an item. */
  remove(itemId: string, fileId: string): Promise<void>;
}

/**
 * Sends the sealed bytes of file `fileId` of item `fromId` again under item `toId`, which must
 * exist on the server already, and answers the new file's id. The new file's id is added to
 * `started` before its bytes go, so a caller whose send fails can take back every file it started
 * (`removeFiles`), this one included. Every place that gives a file to another item (a move, a
 * copy, a merge) sends it through here.
 */
export async function resendFile(
  files: FileResender,
  fromId: string,
  toId: string,
  fileId: string,
  started: string[],
): Promise<string> {
  const sealed = await files.download(fromId, fileId);
  const next = await files.start(toId, sealed.length);
  started.push(next.fileId);
  await files.upload(toId, next.fileId, sealed);
  return next.fileId;
}

/** `entry` as it was, naming the file the server holds for it now (and `fileId` too when it had that key). */
export function withServerFile(entry: Record<string, unknown>, id: string): Record<string, unknown> {
  return { ...entry, kemlockFile: id, ...('fileId' in entry ? { fileId: id } : {}) };
}

export interface CopiedFiles {
  /** The body of `data` with the new file ids. */
  data: ItemData;
  /** The new files, in the order they were made. */
  uploaded: string[];
}

/**
 * Sends each file `data` names under `toId`, which must exist on the server already. The body that
 * comes back names the new files. If any of them fails, the ones already sent are removed and the
 * error is thrown.
 */
export async function copyFiles(files: FileResender, fromId: string, toId: string, data: ItemData): Promise<CopiedFiles> {
  const ids = new Map<string, string>();
  const uploaded: string[] = [];
  try {
    for (const old of serverFileIds(data)) {
      ids.set(old, await resendFile(files, fromId, toId, old, uploaded));
    }
  } catch (error) {
    await removeFiles(files, toId, uploaded);
    throw error;
  }
  return { data: withServerFiles(data, ids), uploaded };
}
