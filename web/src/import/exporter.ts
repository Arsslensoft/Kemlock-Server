// Export: which items go in, the CSV written here, and the file handed to the browser.
//
// CSV uses Bitwarden's CSV columns, which every password manager can import, and only holds
// logins and notes (the other kinds have no column). A value is quoted when it needs it. Another
// member of a space can name an item or write a note, and a spreadsheet reads a cell that starts
// with `=`, `+`, `-` or `@` as a formula, so, unless the person turns the option off ("Protect
// against spreadsheet formulas", on by default), those cells get a `'` in front. That changes the
// text, which is why it is a choice. The password and the one-time code secret are never changed,
// since a `'` there would change the secret, and the export warning says so.
import type { VaultItem } from '@/features/vault/vault';
import { readWebsites } from '@/features/vault/websites';
import type { ExportItem } from './contract';

export const CSV_COLUMNS = [
  'folder',
  'favorite',
  'type',
  'name',
  'notes',
  'fields',
  'reprompt',
  'login_uri',
  'login_username',
  'login_password',
  'login_totp',
] as const;

/** What a spreadsheet takes for the start of a formula: `=`, `+`, `-`, `@`, a tab or a carriage return. */
const FORMULA_START = /^[=+\-@\t\r]/;

/** The text with a `'` in front when a spreadsheet would run it as a formula. */
export function neutralise(value: string): string {
  return FORMULA_START.test(value) ? `'${value}` : value;
}

function cell(value: string): string {
  return /[",\r\n]/.test(value) ? `"${value.replace(/"/g, '""')}"` : value;
}

function text(item: VaultItem, key: string): string {
  const value = item.data?.[key];
  return typeof value === 'string' ? value : '';
}

export interface CsvResult {
  csv: string;
  written: number;
  /** Items of a kind CSV has no column for. */
  left: number;
}

/** Logins and notes as CSV. Rows end with CRLF, as RFC 4180 asks. */
export function toCsv(items: VaultItem[], options: { protectFormulas?: boolean } = {}): CsvResult {
  // On unless the caller says otherwise.
  const protect = options.protectFormulas !== false;
  const guard = (value: string) => (protect ? neutralise(value) : value);
  const rows: string[] = [CSV_COLUMNS.join(',')];
  let written = 0;
  let left = 0;
  for (const item of items) {
    if (!item.data || (item.kind !== 'login' && item.kind !== 'note')) {
      left += 1;
      continue;
    }
    const isLogin = item.kind === 'login';
    const uris = isLogin ? readWebsites(item.data).map((rule) => rule.uri) : [];
    const values = [
      guard(text(item, 'folder')),
      item.data['favorite'] === true ? '1' : '',
      isLogin ? 'login' : 'note',
      guard(text(item, 'name')),
      guard(isLogin ? text(item, 'notes') : text(item, 'text')),
      '',
      '0',
      guard(uris.join('\n')),
      guard(isLogin ? text(item, 'username') : ''),
      // Written as they are: a `'` in front would change the secret.
      isLogin ? text(item, 'password') : '',
      isLogin ? text(item, 'totp') : '',
    ];
    rows.push(values.map(cell).join(','));
    written += 1;
  }
  return { csv: `${rows.join('\r\n')}\r\n`, written, left };
}

/** The opened, readable items of `owners`, in the shape the worker's exporters take. */
export function exportItemsOf(items: VaultItem[], owners: ReadonlySet<string>): ExportItem[] {
  return items
    .filter((item) => item.data !== null && owners.has(item.owner))
    .map((item) => ({ id: item.id, kind: item.kind, data: item.data as Record<string, unknown> }));
}

export function exportFilename(prefix: string, extension: string, now: Date): string {
  return `${prefix}-${now.toISOString().slice(0, 10)}.${extension}`;
}

/** Hands bytes to the browser as a download. Returns false where no document is available. */
export function download(bytes: Uint8Array | string, filename: string, mime: string): boolean {
  if (typeof document === 'undefined') return false;
  const part: BlobPart = typeof bytes === 'string' ? bytes : new Uint8Array(bytes);
  const url = URL.createObjectURL(new Blob([part], { type: mime }));
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
  return true;
}
