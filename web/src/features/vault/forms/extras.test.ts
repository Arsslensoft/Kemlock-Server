import { describe, expect, it } from 'vitest';
import type { AdminFieldDef } from '@/api/customFields';
import type { ItemData, VaultItem } from '../vault';
import {
  type FieldValue,
  addAdminField,
  addOwnField,
  adminChoices,
  changeField,
  extrasDefaults,
  extrasFields,
  extrasShape,
  fieldProblem,
  readFieldValues,
  removeField,
  writeFieldValues,
} from './extras';

const A = '11111111-1111-4111-8111-111111111111';
const B = '22222222-2222-4222-8222-222222222222';

function item(data: ItemData): VaultItem {
  return {
    id: A,
    owner: 'user:u',
    kind: 'login',
    revision: 1,
    keyVersion: 1,
    data,
    sizes: { ciphertext: 0, itemKey: 0 },
  };
}

const EMPLOYEE: AdminFieldDef = { id: 'f-emp', name: 'Employee ID', type: 'text', kinds: 'all' };
const QUESTION: AdminFieldDef = { id: 'f-q', name: 'Security question', type: 'hidden', kinds: ['login'] };
const AGREED: AdminFieldDef = { id: 'f-ok', name: 'Reviewed', type: 'checkbox', kinds: ['card'] };

describe('reading the custom fields of a body', () => {
  it('reads text, hidden and checkbox fields, as the importer and the item page write them', () => {
    const rows = readFieldValues({
      fields: [
        { name: 'Recovery email', value: 'a@b.co', kind: 'text' },
        { name: 'Pin', value: '1234', kind: 'hidden' },
        { name: 'Newsletter', value: 'true', kind: 'boolean' },
        { name: 'Employee ID', value: '42', kind: 'text', adminField: 'f-emp' },
      ],
    });
    expect(rows.map(({ name, type, value, adminField }) => ({ name, type, value, adminField }))).toEqual([
      { name: 'Recovery email', type: 'text', value: 'a@b.co', adminField: undefined },
      { name: 'Pin', type: 'hidden', value: '1234', adminField: undefined },
      { name: 'Newsletter', type: 'checkbox', value: 'true', adminField: undefined },
      { name: 'Employee ID', type: 'text', value: '42', adminField: 'f-emp' },
    ]);
    expect(new Set(rows.map((row) => row.key)).size).toBe(4);
  });

  it('leaves a linked field and one with no name alone, and reads none from a body with none', () => {
    expect(readFieldValues({ fields: [{ name: 'L', value: 'x', kind: 'linked' }, { name: '', value: 'y' }, 'z'] })).toEqual([]);
    expect(readFieldValues({})).toEqual([]);
    expect(readFieldValues(null)).toEqual([]);
  });
});

describe('writing the custom fields of a body', () => {
  it('writes name, value and kind, with adminField only for an admin field', () => {
    let rows = addOwnField([]);
    const own = rows[0];
    rows = changeField(rows, own?.key ?? '', { name: ' Recovery email ', value: 'a@b.co' });
    rows = addAdminField(rows, QUESTION);
    rows = changeField(rows, rows[1]?.key ?? '', { value: 'Biscuit' });
    expect(writeFieldValues(rows, null)).toEqual({
      fields: [
        { name: 'Recovery email', value: 'a@b.co', kind: 'text' },
        { name: 'Security question', value: 'Biscuit', kind: 'hidden', adminField: 'f-q' },
      ],
    });
  });

  it('stores a checkbox as the kind boolean with true or false', () => {
    const rows = addAdminField([], AGREED);
    expect(writeFieldValues(rows, null)).toEqual({
      fields: [{ name: 'Reviewed', value: 'false', kind: 'boolean', adminField: 'f-ok' }],
    });
    const ticked = changeField(rows, rows[0]?.key ?? '', { value: 'true' });
    expect(writeFieldValues(ticked, null)).toEqual({
      fields: [{ name: 'Reviewed', value: 'true', kind: 'boolean', adminField: 'f-ok' }],
    });
  });

  it('leaves the member out when there is nothing to write', () => {
    expect(writeFieldValues([], null)).toEqual({ fields: undefined });
    expect(writeFieldValues(addOwnField([]), null)).toEqual({ fields: undefined });
  });

  it('keeps the entries it cannot edit where they were', () => {
    const existing = { fields: [{ name: 'Linked', value: 'x', kind: 'linked' }, { name: 'A', value: '1', kind: 'text' }, 'odd'] };
    const rows = readFieldValues(existing);
    expect(writeFieldValues(rows, existing)).toEqual({
      fields: [{ name: 'Linked', value: 'x', kind: 'linked' }, { name: 'A', value: '1', kind: 'text' }, 'odd'],
    });
  });

  it('writes an entry nobody changed back as the same object, with every key and in the same order', () => {
    const first = { value: '42', name: 'Employee ID', kind: 'text', adminField: 'f-emp', note: 'kept' };
    const second = { name: 'PIN', value: 5, type: 'password', shown: false };
    const existing = { fields: [first, second] };
    const written = writeFieldValues(readFieldValues(existing), existing)['fields'] as unknown[];
    expect(written[0]).toBe(first);
    expect(written[1]).toBe(second);
    expect(Object.keys(written[0] as object)).toEqual(['value', 'name', 'kind', 'adminField', 'note']);
  });

  it('changes only what was edited in an entry, and keeps its other keys and the order of the list', () => {
    const existing = {
      fields: [
        { name: 'A', value: '1', kind: 'text', vendor: 'x' },
        { name: 'Linked', value: 'x', kind: 'linked' },
        { name: 'B', value: 'old', kind: 'hidden', adminField: 'f-q' },
        { name: 'Ok', value: true, kind: 'boolean' },
      ],
    };
    const rows = readFieldValues(existing);
    const edit = (index: number, patch: Partial<FieldValue>) => {
      const row = rows[index] as FieldValue;
      rows[index] = { ...row, ...patch };
    };
    // The rows are the entries the form can edit: A, B and Ok (the linked field has none).
    edit(0, { value: '2' });
    edit(1, { value: 'new', type: 'text' });
    const written = writeFieldValues(rows, existing)['fields'] as Array<Record<string, unknown>>;
    expect(written).toEqual([
      { name: 'A', value: '2', kind: 'text', vendor: 'x' },
      { name: 'Linked', value: 'x', kind: 'linked' },
      { name: 'B', value: 'new', kind: 'text', adminField: 'f-q' },
      { name: 'Ok', value: true, kind: 'boolean' },
    ]);
    // A checkbox the person ticks stays a boolean where the entry held one.
    edit(2, { value: 'false' });
    expect(writeFieldValues(rows, existing)['fields']).toMatchObject([{}, {}, {}, { value: false }]);
  });

  it('drops a removed field, and puts a new one after the others', () => {
    const existing = { fields: [{ name: 'A', value: '1', kind: 'text' }, { name: 'Linked', value: 'x', kind: 'linked' }, { name: 'B', value: '2', kind: 'text' }] };
    let rows = readFieldValues(existing);
    rows = removeField(rows, rows[0]?.key ?? '');
    rows = addOwnField(rows);
    const added = rows[rows.length - 1] as FieldValue;
    rows = changeField(rows, added.key, { name: 'C', value: '3' });
    expect(writeFieldValues(rows, existing)['fields']).toEqual([
      { name: 'Linked', value: 'x', kind: 'linked' },
      { name: 'B', value: '2', kind: 'text' },
      { name: 'C', value: '3', kind: 'text' },
    ]);
  });

  it('removes a field when its row is removed', () => {
    const rows = addAdminField(addOwnField([]), EMPLOYEE);
    expect(removeField(rows, rows[0]?.key ?? '')).toHaveLength(1);
    expect(writeFieldValues(removeField(rows, rows[1]?.key ?? ''), null)).toEqual({ fields: undefined });
  });
});

describe('the rows of the form', () => {
  it('offers the admin fields for the kind that are not on the item yet', () => {
    const defs = [EMPLOYEE, QUESTION, AGREED];
    expect(adminChoices(defs, 'login', []).map((field) => field.id)).toEqual(['f-emp', 'f-q']);
    expect(adminChoices(defs, 'card', []).map((field) => field.id)).toEqual(['f-emp', 'f-ok']);
    const held = addAdminField([], EMPLOYEE);
    expect(adminChoices(defs, 'login', held).map((field) => field.id)).toEqual(['f-q']);
  });

  it('starts an admin field with an empty value, or false for a checkbox, and an own field as empty text', () => {
    expect(addAdminField([], EMPLOYEE)[0]).toMatchObject({ name: 'Employee ID', type: 'text', value: '', adminField: 'f-emp' });
    expect(addAdminField([], AGREED)[0]).toMatchObject({ type: 'checkbox', value: 'false' });
    expect(addOwnField([])[0]).toMatchObject({ name: '', type: 'text', value: '' });
  });

  it('resets the value when a field changes to or from a checkbox', () => {
    const rows = changeField(addOwnField([]), 'x', {});
    const key = rows[0]?.key ?? '';
    const typed = changeField(rows, key, { value: 'hello' });
    expect(changeField(typed, key, { type: 'checkbox' })[0]?.value).toBe('false');
    expect(changeField(typed, key, { type: 'hidden' })[0]?.value).toBe('hello');
    const ticked = changeField(typed, key, { type: 'checkbox' });
    expect(changeField(ticked, key, { type: 'text' })[0]?.value).toBe('');
  });

  it('says an own field with a value needs a name, and an admin field never does', () => {
    const own = changeField(addOwnField([]), 'x', {});
    const key = own[0]?.key ?? '';
    expect(fieldProblem(own[0] ?? ({} as never))).toBeUndefined();
    const filled = changeField(own, key, { value: 'something' })[0];
    expect(fieldProblem(filled ?? ({} as never))).toBe('itemForm.fields.nameNeeded');
    const admin = addAdminField([], EMPLOYEE)[0];
    expect(fieldProblem(admin ?? ({} as never))).toBeUndefined();
  });

  it('is checked by the schema the forms share', () => {
    const bad = addOwnField([]);
    bad[0] = { ...(bad[0] as NonNullable<(typeof bad)[number]>), value: 'x' };
    expect(extrasShape.fields.safeParse(bad).success).toBe(false);
    expect(extrasShape.fields.safeParse([]).success).toBe(true);
    expect(extrasShape.links.safeParse([A]).success).toBe(true);
  });
});

describe('the fields and links a form writes', () => {
  it('opens with what the body holds', () => {
    const values = extrasDefaults(item({ fields: [{ name: 'A', value: '1', kind: 'text' }], links: [{ id: B }] }));
    expect(values.fields).toHaveLength(1);
    expect(values.links).toEqual([B]);
  });

  it('writes nothing new for an item that has neither, so it stays byte for byte', () => {
    const fields = extrasFields({ fields: [], links: [] }, item({ name: 'GitHub' }));
    expect(fields['fields']).toBeUndefined();
    expect(fields['links']).toBeUndefined();
  });

  it('writes both members', () => {
    const rows = addAdminField([], EMPLOYEE);
    const fields = extrasFields({ fields: rows, links: [B, A] }, undefined);
    expect(fields['links']).toEqual([{ id: A }, { id: B }]);
    expect(fields['fields']).toEqual([{ name: 'Employee ID', value: '', kind: 'text', adminField: 'f-emp' }]);
  });
});
