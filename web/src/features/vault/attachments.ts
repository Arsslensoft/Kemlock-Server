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
  /**
   * A stored entry as the body holds it, written back exactly as it was: no key added, none
   * reordered, no missing value filled in. The members above are what the form shows of it.
   */
  raw?: Record<string, unknown> | undefined;
  /** Where the entry was in the body's list, so it is matched to its place when written back. */
  origin?: number | undefined;
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
  raw: z.record(z.string(), z.unknown()).optional(),
  origin: z.number().optional(),
});

/** How many files a note holds, as the Kemlock app limits it. */
export const MAX_ATTACHMENTS = 100;

/** The entry a body's object shows, or undefined for what this form can't show (it stays in the body). */
function entryOf(raw: unknown, origin?: number): AttachmentEntry | undefined {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) return undefined;
  const body = raw as Record<string, unknown>;
  const text = (key: string) => (typeof body[key] === 'string' ? (body[key] as string) : '');
  const size = body['size'];
  const addedAt = body['addedAt'];
  const server = text('kemlockFile');
  if (text('name') === '' && server === '') return undefined;
  return {
    id: text('id'),
    name: text('name'),
    size: typeof size === 'number' && Number.isFinite(size) && size >= 0 ? size : 0,
    ...(text('type') !== '' ? { type: text('type') } : {}),
    key: text('key'),
    addedAt: typeof addedAt === 'number' && Number.isFinite(addedAt) ? addedAt : 0,
    ...(text('sha256') !== '' ? { sha256: text('sha256') } : {}),
    ...(server !== '' ? { kemlockFile: server } : {}),
    raw: body,
    ...(origin !== undefined ? { origin } : {}),
  };
}

/** The attachments of a secure note. */
export function readAttachments(data: ItemData | null | undefined): AttachmentEntry[] {
  const list = data?.['attachments'];
  if (!Array.isArray(list)) return [];
  const out: AttachmentEntry[] = [];
  list.forEach((raw, index) => {
    const entry = entryOf(raw, index);
    if (entry) out.push(entry);
  });
  return out;
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

/**
 * What the body holds for an entry. A stored entry is written back as it was read; a new one gets
 * the keys of the app's attachment.
 */
export function entryBody(entry: AttachmentEntry): Record<string, unknown> {
  if (entry.raw !== undefined) return entry.raw;
  return {
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

/** The entries of a body that the server holds a file for: those that name a `kemlockFile`. */
export function namedEntries(data: ItemData | null | undefined): AttachmentEntry[] {
  const file = readFileEntry(data);
  return [...readAttachments(data), ...(file ? [file] : [])].filter((entry) => entry.kemlockFile !== undefined);
}

/** The server's ids of the files a body names. */
export function serverFileIds(data: ItemData | null | undefined): string[] {
  return namedEntries(data).map((entry) => entry.kemlockFile as string);
}

/**
 * The `attachments` member for a note: its stored entries, each where it was in the list, and
 * after them the new ones. An object the form can't show (not an attachment this app knows) stays
 * where it was, and a note left with none writes nothing.
 */
export function noteAttachmentFields(
  entries: readonly AttachmentEntry[],
  existing?: ItemData | null,
): ItemData {
  const stored = storedEntries(entries);
  const original = existing?.['attachments'];
  const out: unknown[] = [];
  const placed = new Set<AttachmentEntry>();
  if (Array.isArray(original)) {
    original.forEach((raw, index) => {
      if (entryOf(raw, index) === undefined) {
        out.push(raw);
        return;
      }
      const kept = stored.find((entry) => entry.origin === index && !placed.has(entry));
      if (kept) {
        placed.add(kept);
        out.push(entryBody(kept));
      }
    });
  }
  for (const entry of stored) if (!placed.has(entry)) out.push(entryBody(entry));
  return { attachments: out.length > 0 ? out : undefined };
}

const UNITS = ['B', 'KB', 'MB', 'GB', 'TB'];

/** `2.4 MB`: decimal units, one decimal from a megabyte up, the number written for `locale`. */
export function formatSize(bytes: number, locale = 'en'): string {
  let value = bytes;
  let unit = 0;
  while (value >= 1000 && unit < UNITS.length - 1) {
    value /= 1000;
    unit += 1;
  }
  const digits = unit >= 2 && value < 100 ? 1 : 0;
  const number = new Intl.NumberFormat(locale, { maximumFractionDigits: digits, minimumFractionDigits: digits });
  return `${number.format(value)} ${UNITS[unit]}`;
}

const KINDS_BY_EXTENSION: Record<string, string> = {
  txt: 'Text',
  md: 'Text',
  pdf: 'PDF',
  png: 'Image',
  jpg: 'Image',
  jpeg: 'Image',
  gif: 'Image',
  webp: 'Image',
  svg: 'Image',
  mp3: 'Audio',
  wav: 'Audio',
  m4a: 'Audio',
  flac: 'Audio',
  mp4: 'Video',
  mov: 'Video',
  webm: 'Video',
  mkv: 'Video',
};

/**
 * What kind of file it is, in a word: "Text", "PDF", "Image", "Audio", "Video"; any other file by
 * its extension in capitals (`ZIP`), or by its media type's subtype when it has no extension.
 */
export function typeLabel(entry: Pick<AttachmentEntry, 'name' | 'type'>): string {
  const media = entry.type ?? '';
  if (media === 'application/pdf') return 'PDF';
  if (media === 'text/plain') return 'Text';
  const family = media.split('/')[0];
  if (family === 'image' || family === 'audio' || family === 'video') {
    return family.charAt(0).toUpperCase() + family.slice(1);
  }
  const ext = entry.name.includes('.') ? (entry.name.split('.').pop() ?? '').toLowerCase() : '';
  const known = KINDS_BY_EXTENSION[ext];
  if (known !== undefined) return known;
  const sub = media.split('/')[1]?.split(/[;+]/)[0] ?? '';
  const label = ext.length > 0 && ext.length <= 5 ? ext : sub;
  return label ? label.toUpperCase() : '';
}
