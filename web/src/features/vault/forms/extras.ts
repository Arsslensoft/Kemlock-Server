// What every form but the passkey and the file shares: custom fields and linked items. Both are
// optional additions to the item body (docs/crypto.md, "Item bodies"), so an item that has neither
// is written exactly as it was before, and an app that doesn't know them keeps them.
//
//   fields  [{ name, value, kind: "text" | "hidden" | "boolean", adminField? }]
//   links   [{ id }] sorted by id
//
// `adminField` is the id of the admin's definition. Its name and type are the admin's; the person
// fills in the value. Nothing is required.
import { z } from 'zod';
import { type AdminFieldDef, type CustomFieldType, appliesTo } from '@/api/customFields';
import type { MessageId } from '@/i18n';
import { formLinks, linksFields } from '../links';
import type { ItemData, VaultItem } from '../vault';

export interface FieldValue {
  /** Names the row in the form; never stored. */
  key: string;
  name: string;
  type: CustomFieldType;
  /** A checkbox holds `true` or `false`. */
  value: string;
  /** The admin's field this one was made from, when it was. */
  adminField?: string | undefined;
  /** Where the field was in the body's list; absent for a field added in the form. */
  origin?: number | undefined;
}

export interface ExtrasValues {
  fields: FieldValue[];
  links: string[];
}

let counter = 0;

/** A key for a new row. */
export function newFieldKey(): string {
  counter += 1;
  return `field-${counter}`;
}

const BODY_KIND: Record<CustomFieldType, string> = { text: 'text', hidden: 'hidden', checkbox: 'boolean' };

/** The type a stored `kind` means: the importer writes `boolean`, a number or `password` for the others. */
function typeOf(kind: unknown): CustomFieldType | undefined {
  switch (typeof kind === 'string' ? kind.toLowerCase() : kind) {
    case undefined:
    case 'text':
    case 0:
      return 'text';
    case 'hidden':
    case 'password':
    case 1:
      return 'hidden';
    case 'boolean':
    case 'checkbox':
    case 2:
      return 'checkbox';
    default:
      // Linked fields (3) and kinds from a newer app are not edited here; they stay as they were.
      return undefined;
  }
}

function asEntries(data: ItemData | null | undefined): unknown[] {
  const raw = data?.['fields'];
  return Array.isArray(raw) ? raw : [];
}

function editable(
  entry: unknown,
): { name: string; type: CustomFieldType; value: string; adminField?: string } | undefined {
  if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) return undefined;
  const field = entry as Record<string, unknown>;
  const type = typeOf(field['kind'] ?? field['type']);
  const name = field['name'];
  if (type === undefined || typeof name !== 'string' || name.trim() === '') return undefined;
  const raw = field['value'];
  const value =
    type === 'checkbox'
      ? raw === true || raw === 'true'
        ? 'true'
        : 'false'
      : typeof raw === 'string'
        ? raw
        : typeof raw === 'number'
          ? String(raw)
          : '';
  const admin = field['adminField'];
  return { name, type, value, ...(typeof admin === 'string' && admin !== '' ? { adminField: admin } : {}) };
}

/** The custom fields a form edits: those of the body it can read, in the order it holds them. */
export function readFieldValues(data: ItemData | null | undefined): FieldValue[] {
  const out: FieldValue[] = [];
  asEntries(data).forEach((entry, origin) => {
    const field = editable(entry);
    if (field) out.push({ key: newFieldKey(), ...field, origin });
  });
  return out;
}

/** What the person needs to fix in a row, if anything: a value with no name to go with it. */
export function fieldProblem(field: FieldValue): MessageId | undefined {
  if (field.adminField) return undefined;
  const filled = field.type === 'checkbox' ? field.value === 'true' : field.value !== '';
  return field.name.trim() === '' && filled ? 'itemForm.fields.nameNeeded' : undefined;
}

function checkboxText(value: string): string {
  return value === 'true' ? 'true' : 'false';
}

/** The entry for a row the person added: the keys the importer and the item page read. */
function newEntry(row: FieldValue): Record<string, unknown> {
  return {
    name: row.name.trim(),
    value: row.type === 'checkbox' ? checkboxText(row.value) : row.value,
    kind: BODY_KIND[row.type],
    ...(row.adminField ? { adminField: row.adminField } : {}),
  };
}

/** The row as the original entry reads: nothing the person changed. */
function untouched(parsed: NonNullable<ReturnType<typeof editable>>, row: FieldValue): boolean {
  return (
    row.name === parsed.name &&
    row.value === parsed.value &&
    row.type === parsed.type &&
    (row.adminField ?? undefined) === parsed.adminField
  );
}

/** The original entry with only what was edited changed: its other keys, and their order, stay. */
function edited(original: Record<string, unknown>, parsed: NonNullable<ReturnType<typeof editable>>, row: FieldValue) {
  const out: Record<string, unknown> = { ...original, name: row.name.trim() };
  if (row.type === 'checkbox') {
    out['value'] = typeof original['value'] === 'boolean' ? row.value === 'true' : checkboxText(row.value);
  } else {
    out['value'] = row.value;
  }
  if (row.type !== parsed.type) {
    // A new type is written the way the importer writes it, in the key the entry already used.
    const used = 'type' in original && !('kind' in original) ? 'type' : 'kind';
    out[used] = BODY_KIND[row.type];
  }
  if (row.adminField && original['adminField'] !== row.adminField) out['adminField'] = row.adminField;
  return out;
}

/**
 * The `fields` member for the form's rows, built on the entries the body holds. An entry the person
 * did not change is written as it was, the same object. An edited one keeps its other keys. A
 * removed row (or one whose name was cleared) is dropped, and an entry this form cannot edit (a
 * linked field, a kind from a newer app, one with no name) stays where it was. Rows added in the form
 * come after, in the order they were added.
 */
export function writeFieldValues(values: readonly FieldValue[], existing: ItemData | null | undefined): ItemData {
  const original = asEntries(existing);
  const byOrigin = new Map<number, FieldValue>();
  const added: FieldValue[] = [];
  for (const row of values) {
    if (row.origin !== undefined && row.origin < original.length) byOrigin.set(row.origin, row);
    else added.push(row);
  }
  const out: unknown[] = [];
  original.forEach((entry, index) => {
    const parsed = editable(entry);
    if (parsed === undefined) {
      out.push(entry);
      return;
    }
    const row = byOrigin.get(index);
    if (row === undefined || row.name.trim() === '') return;
    out.push(untouched(parsed, row) ? entry : edited(entry as Record<string, unknown>, parsed, row));
  });
  for (const row of added) if (row.name.trim() !== '') out.push(newEntry(row));
  return { fields: out.length > 0 ? out : undefined };
}

/** The admin's fields offered for a kind that the item does not hold yet. */
export function adminChoices(
  definitions: readonly AdminFieldDef[],
  kind: string,
  values: readonly FieldValue[],
): AdminFieldDef[] {
  const held = new Set(values.map((field) => field.adminField).filter((id): id is string => id !== undefined));
  return definitions.filter((field) => appliesTo(field, kind) && !held.has(field.id));
}

export function addAdminField(values: readonly FieldValue[], def: AdminFieldDef): FieldValue[] {
  return [
    ...values,
    {
      key: newFieldKey(),
      name: def.name,
      type: def.type,
      value: def.type === 'checkbox' ? 'false' : '',
      adminField: def.id,
    },
  ];
}

export function addOwnField(values: readonly FieldValue[]): FieldValue[] {
  return [...values, { key: newFieldKey(), name: '', type: 'text', value: '' }];
}

export function removeField(values: readonly FieldValue[], key: string): FieldValue[] {
  return values.filter((field) => field.key !== key);
}

/** Changes one row. A new type resets what the value could not mean any more. */
export function changeField(
  values: readonly FieldValue[],
  key: string,
  patch: Partial<Pick<FieldValue, 'name' | 'type' | 'value'>>,
): FieldValue[] {
  return values.map((field) => {
    if (field.key !== key) return field;
    const next = { ...field, ...patch };
    if (patch.type !== undefined && patch.type !== field.type) {
      next.value = patch.type === 'checkbox' ? 'false' : field.type === 'checkbox' ? '' : field.value;
    }
    return next;
  });
}

export const fieldValueSchema = z.object({
  key: z.string(),
  name: z.string().max(200, 'error.tooLong'),
  type: z.enum(['text', 'hidden', 'checkbox']),
  value: z.string().max(10000, 'error.tooLong'),
  adminField: z.string().optional(),
  origin: z.number().optional(),
});

/** The members every form's schema carries for fields and links. */
export const extrasShape = {
  fields: z
    .array(fieldValueSchema)
    .max(100, 'error.tooLong')
    .refine((fields) => fields.every((field) => fieldProblem(field) === undefined), 'itemForm.fields.nameNeeded'),
  links: z.array(z.string()),
};

export function extrasDefaults(item?: VaultItem): ExtrasValues {
  return { fields: readFieldValues(item?.data), links: formLinks(item?.data) };
}

/** The `fields` and `links` members a form writes. */
export function extrasFields(values: ExtrasValues, existing?: VaultItem): ItemData {
  return { ...writeFieldValues(values.fields, existing?.data), ...linksFields(existing?.data, values.links) };
}
