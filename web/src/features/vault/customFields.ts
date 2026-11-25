// The custom fields of an item, for the detail page. The body holds `fields`, a list of
// `{ name, value, kind }` (the shape the import writes, crates/kemlock-import `CustomField`):
// `kind` is `text`, `hidden`, `boolean` (a checkbox, its value `"true"` or `"false"`) or `linked`.
// A field the admin defined also names it (`adminField`), and shows an "Admin" tag.
//
// Reading is lenient: a field this app can't read is skipped, never an error, and nothing here
// writes. No React in here.
import type { ItemData } from './vault';

export type CustomFieldKind = 'text' | 'hidden' | 'checkbox';

export interface CustomField {
  name: string;
  /** The text to show. A checkbox holds `true` or `false`. */
  value: string;
  kind: CustomFieldKind;
  /** Defined by the admin: its name and type are theirs, the person filled in the value. */
  admin: boolean;
}

function kindOf(raw: unknown): CustomFieldKind {
  switch (typeof raw === 'string' ? raw.toLowerCase() : raw) {
    case 'hidden':
    case 'password':
    case 1:
      return 'hidden';
    case 'boolean':
    case 'checkbox':
    case 2:
      return 'checkbox';
    default:
      return 'text';
  }
}

function valueOf(raw: unknown, kind: CustomFieldKind): string {
  if (kind === 'checkbox') return raw === true || raw === 'true' ? 'true' : 'false';
  if (typeof raw === 'string') return raw;
  if (typeof raw === 'number') return String(raw);
  return '';
}

function isAdmin(entry: Record<string, unknown>): boolean {
  if (entry['admin'] === true) return true;
  const ref = entry['adminField'] ?? entry['adminFieldId'] ?? entry['adminId'];
  return typeof ref === 'string' && ref !== '';
}

/** The custom fields of an item body, in the order it holds them. */
export function readCustomFields(data: ItemData | null | undefined): CustomField[] {
  const raw = data?.['fields'];
  if (!Array.isArray(raw)) return [];
  const out: CustomField[] = [];
  for (const entry of raw) {
    if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) continue;
    const field = entry as Record<string, unknown>;
    const name = typeof field['name'] === 'string' ? field['name'].trim() : '';
    if (name === '') continue;
    const kind = kindOf(field['kind'] ?? field['type']);
    const value = valueOf(field['value'], kind);
    // An empty field says nothing; a checkbox always does.
    if (value === '' && kind !== 'checkbox') continue;
    out.push({ name, value, kind, admin: isAdmin(field) });
  }
  return out;
}
