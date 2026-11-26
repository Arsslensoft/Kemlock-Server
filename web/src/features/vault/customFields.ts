// The custom fields of an item, for the detail page. The body holds `fields`, a list of
// `{ name, value, kind }` (the shape the import writes, crates/kemlock-import `CustomField`):
// `kind` is `text`, `hidden`, `boolean` (a checkbox, its value `"true"` or `"false"`) or `linked`.
// A field the admin defined also holds `adminField`, the id of the admin's definition, and shows an
// "Admin" tag; the admin's current name and type for it come from `resolveAdminFields`.
//
// Reading is lenient: a field this app can't read is skipped, never an error, and nothing here
// writes. No React in here.
import type { AdminFieldDef, CustomFieldType } from '@/api/customFields';
import { typeOf } from './forms/extras';
import type { ItemData } from './vault';

export type CustomFieldKind = CustomFieldType;

export interface CustomField {
  name: string;
  /** The text to show. A checkbox holds `true` or `false`. */
  value: string;
  kind: CustomFieldKind;
  /** The id of the admin's definition, when the admin defined the field. */
  adminField?: string | undefined;
  /** Defined by the admin: its name and type are theirs, the person filled in the value. */
  admin: boolean;
}

/** The type a stored `kind` means (forms/extras.ts reads it too); one this app doesn't know shows as text. */
const kindOf = (raw: unknown): CustomFieldKind => typeOf(raw) ?? 'text';

function valueOf(raw: unknown, kind: CustomFieldKind): string {
  if (kind === 'checkbox') return raw === true || raw === 'true' ? 'true' : 'false';
  if (typeof raw === 'string') return raw;
  if (typeof raw === 'number') return String(raw);
  return '';
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
    const reference = field['adminField'];
    const adminField = typeof reference === 'string' && reference !== '' ? reference : undefined;
    out.push({ name, value, kind, adminField, admin: adminField !== undefined });
  }
  return out;
}

/**
 * Names and types of the admin's fields as the admin has them now. An item holds the name and type a
 * field had when it was saved; the admin may have renamed it or changed its type since. A field
 * whose definition isn't in `defs` (deleted, or the list didn't load) keeps what the item holds.
 */
export function resolveAdminFields(fields: readonly CustomField[], defs: readonly AdminFieldDef[]): CustomField[] {
  return fields.map((field) => {
    const def = field.adminField === undefined ? undefined : defs.find((d) => d.id === field.adminField);
    if (!def) return field;
    return { ...field, name: def.name, kind: def.type, value: def.type === 'checkbox' ? valueOf(field.value, 'checkbox') : field.value };
  });
}
