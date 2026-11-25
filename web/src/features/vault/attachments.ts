// The files an item holds, as the form edits them. The body names each one the way the Kemlock app
// writes an attachment (kemlock-core `NoteAttachment`):
//
//   { id, name, size, type?, key, addedAt, sha256?, kemlockFile? }
//
// `id` is 16 random bytes in base64url, `size` the bytes before encryption, `key` the file's own
// AES-256 key in base64, `sha256` the SHA-256 of the bytes before encryption (lower-case hex, written
// by this web vault when it uploads) and `kemlockFile` the id of the file on the server. A secure note holds any
// number, in `attachments`; a File item holds one, in `file`. The server never sees a name, a type
// or a key: they are inside the sealed body. The bytes are a `KMA1` file (src/lib/kma1.ts).
//
// A file the person just chose has no `kemlockFile` yet, and the form still holds its bytes in
// `file`: the item is saved first (the server takes a file only for an item that exists), the
// bytes are sent, and the item is saved again naming the file. A body never names a file the
// server lacks.
import { z } from 'zod';
import { fileKeyText, newAttachmentId, newFileKey } from '@/lib/kma1';
import type { ItemData } from './vault';

export interface AttachmentEntry {
  id: string;
  name: string;
  /** Bytes, before encryption. */
  size: number;
  type?: string | undefined;
  /** The file's own key, base64. */
  key: string;
  /** Epoch ms. */
  addedAt: number;
  /** The SHA-256 of the file's bytes before encryption, lower-case hex. The duplicate finder reads it. */
  sha256?: string | undefined;
  /** The file's id on the server, once it was uploaded. */
  kemlockFile?: string | undefined;
  /** The bytes still to encrypt and upload: only on a file chosen in this form. */
  file?: Blob | undefined;
  /** Keys of a stored attachment this form doesn't know, kept as they were. */
  extra?: Record<string, unknown> | undefined;
}

export const attachmentSchema = z.object({
  id: z.string(),
  name: z.string().max(500, 'error.tooLong'),
  size: z.number(),
  type: z.string().optional(),
  key: z.string(),
  addedAt: z.number(),
  sha256: z.string().optional(),
  kemlockFile: z.string().optional(),
  file: z.custom<Blob>((value) => typeof Blob !== 'undefined' && value instanceof Blob).optional(),
  extra: z.record(z.string(), z.unknown()).optional(),
});

/** How many files a note holds, as the Kemlock app limits it. */
export const MAX_ATTACHMENTS = 100;

const KNOWN = new Set(['id', 'name', 'size', 'type', 'key', 'addedAt', 'sha256', 'kemlockFile']);

function entryOf(raw: unknown): AttachmentEntry | undefined {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) return undefined;
  const body = raw as Record<string, unknown>;
  const text = (key: string) => (typeof body[key] === 'string' ? (body[key] as string) : '');
  const size = body['size'];
  const addedAt = body['addedAt'];
  const server = text('kemlockFile');
  if (text('name') === '' && server === '') return undefined;
  const extra = Object.fromEntries(Object.entries(body).filter(([key]) => !KNOWN.has(key)));
  return {
    id: text('id'),
    name: text('name'),
    size: typeof size === 'number' && Number.isFinite(size) && size >= 0 ? size : 0,
    ...(text('type') !== '' ? { type: text('type') } : {}),
    key: text('key'),
    addedAt: typeof addedAt === 'number' && Number.isFinite(addedAt) ? addedAt : 0,
    ...(text('sha256') !== '' ? { sha256: text('sha256') } : {}),
    ...(server !== '' ? { kemlockFile: server } : {}),
    ...(Object.keys(extra).length > 0 ? { extra } : {}),
  };
}

/** The attachments of a secure note. */
export function readAttachments(data: ItemData | null | undefined): AttachmentEntry[] {
  const list = data?.['attachments'];
  if (!Array.isArray(list)) return [];
  return list.map(entryOf).filter((entry): entry is AttachmentEntry => entry !== undefined);
}

/** The file of a File item. */
export function readFileEntry(data: ItemData | null | undefined): AttachmentEntry | undefined {
  return entryOf(data?.['file']);
}

/** An entry for a file the person just chose: its own id and key, and its bytes still to send. */
export function newAttachment(file: File, now: number = Date.now()): AttachmentEntry {
  return {
    id: newAttachmentId(),
    name: file.name,
    size: file.size,
    ...(file.type !== '' ? { type: file.type } : {}),
    key: fileKeyText(newFileKey()),
    addedAt: now,
    file,
  };
}

/** What the body holds for an entry: the keys of the app's attachment, and what it didn't know. */
export function entryBody(entry: AttachmentEntry): Record<string, unknown> {
  return {
    ...(entry.extra ?? {}),
    id: entry.id,
    name: entry.name,
    size: entry.size,
    ...(entry.type !== undefined ? { type: entry.type } : {}),
    key: entry.key,
    addedAt: entry.addedAt,
    ...(entry.sha256 !== undefined ? { sha256: entry.sha256 } : {}),
    ...(entry.kemlockFile !== undefined ? { kemlockFile: entry.kemlockFile } : {}),
  };
}

/** The entries the server holds, or the app wrote: those with no bytes still to send. */
export function storedEntries(entries: readonly AttachmentEntry[]): AttachmentEntry[] {
  return entries.filter((entry) => entry.file === undefined);
}

/** The entries whose bytes still have to be encrypted and uploaded. */
export function pendingEntries(entries: readonly AttachmentEntry[]): AttachmentEntry[] {
  return entries.filter((entry) => entry.file !== undefined);
}

/** The server's ids of the files the person removed: stored before, and not in `after`. */
export function removedServerFiles(
  before: readonly AttachmentEntry[],
  after: readonly AttachmentEntry[],
): string[] {
  const kept = new Set(after.map((entry) => entry.id));
  return before
    .filter((entry) => !kept.has(entry.id) && entry.kemlockFile !== undefined)
    .map((entry) => entry.kemlockFile as string);
}

/** The `attachments` member for a note: its stored entries, and nothing when it has none. */
export function noteAttachmentFields(entries: readonly AttachmentEntry[]): ItemData {
  const stored = storedEntries(entries).map(entryBody);
  return { attachments: stored.length > 0 ? stored : undefined };
}

const UNITS = ['B', 'KB', 'MB', 'GB', 'TB'];

/** `2.4 MB`: decimal units, one decimal from a megabyte up. */
export function formatSize(bytes: number): string {
  let value = bytes;
  let unit = 0;
  while (value >= 1000 && unit < UNITS.length - 1) {
    value /= 1000;
    unit += 1;
  }
  const digits = unit >= 2 && value < 100 ? 1 : 0;
  const number = new Intl.NumberFormat('en', { maximumFractionDigits: digits, minimumFractionDigits: digits });
  return `${number.format(value)} ${UNITS[unit]}`;
}

/** `PDF` for `lease.pdf`; the media type's subtype when the name has no extension. */
export function typeLabel(entry: Pick<AttachmentEntry, 'name' | 'type'>): string {
  const sub = entry.type?.split('/')[1]?.split(/[;+]/)[0] ?? '';
  const ext = entry.name.includes('.') ? (entry.name.split('.').pop() ?? '') : '';
  const label = ext.length > 0 && ext.length <= 5 ? ext : sub;
  return label ? label.toUpperCase() : '';
}
