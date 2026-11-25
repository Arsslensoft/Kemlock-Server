// The files an item holds. The body names each one the way the Kemlock app writes an attachment
// (kemlock-core `NoteAttachment`): `{ id, name, size, type?, key, addedAt, kemlockFile }`, where
// `key` is the file's own AES-256 key and `kemlockFile` the id of the file on the server. A File
// item holds one, in `file`; a secure note holds any number, in `attachments`. The server never
// sees a name, a type or a key: they are inside the sealed body.
import type { ItemData } from '../vault';

export interface AttachedFile {
  /** The attachment's id in the body. */
  id: string;
  name: string;
  /** Bytes, before encryption. */
  size: number;
  /** The media type, when the picker knew it. */
  type: string;
  /** The file's own key, base64. */
  key: string;
  /** The file's id on the server, when it was uploaded. */
  serverId: string;
}

function attached(raw: unknown): AttachedFile | undefined {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) return undefined;
  const entry = raw as Record<string, unknown>;
  const text = (key: string) => (typeof entry[key] === 'string' ? (entry[key] as string) : '');
  const size = entry['size'];
  const serverId = text('kemlockFile') || text('fileId');
  if (text('name') === '' && serverId === '') return undefined;
  return {
    id: text('id'),
    name: text('name'),
    size: typeof size === 'number' && Number.isFinite(size) && size >= 0 ? size : 0,
    type: text('type'),
    key: text('key'),
    serverId,
  };
}

/** The attachments of a secure note. */
export function filesOf(data: ItemData | null | undefined): AttachedFile[] {
  const list = data?.['attachments'];
  if (!Array.isArray(list)) return [];
  return list.map(attached).filter((file): file is AttachedFile => file !== undefined);
}

/** The file of a File item, from `file` (or the first of `attachments`). */
export function fileOf(data: ItemData | null | undefined): AttachedFile | undefined {
  return attached(data?.['file']) ?? filesOf(data)[0];
}

export type SizeUnit = 'b' | 'kb' | 'mb' | 'gb' | 'tb';
const UNITS: SizeUnit[] = ['b', 'kb', 'mb', 'gb', 'tb'];

/**
 * `2.4 MB`: decimal units, one decimal from a megabyte up. The number is written for `locale` and
 * `unit` words the whole, so a message can put them in the order the language wants.
 */
export function formatSize(bytes: number, locale: string, unit: (name: SizeUnit, value: string) => string): string {
  let value = bytes;
  let index = 0;
  while (value >= 1000 && index < UNITS.length - 1) {
    value /= 1000;
    index += 1;
  }
  const digits = index >= 2 && value < 100 ? 1 : 0;
  const number = new Intl.NumberFormat(locale, { maximumFractionDigits: digits, minimumFractionDigits: digits });
  return unit(UNITS[index] ?? 'b', number.format(value));
}

/** Fetches, opens and saves one file; rejects when it can't. */
export type DownloadFile = (file: AttachedFile) => Promise<void>;
