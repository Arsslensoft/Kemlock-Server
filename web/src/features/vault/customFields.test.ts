import { describe, expect, it } from 'vitest';
import type { AdminFieldDef } from '@/api/customFields';
import { readCustomFields, resolveAdminFields } from './customFields';

describe('readCustomFields', () => {
  it('reads the fields the import writes, in order', () => {
    expect(
      readCustomFields({
        fields: [
          { name: 'Recovery email', value: 'sam.backup@example.org', kind: 'text' },
          { name: 'Security question', value: 'blue', kind: 'hidden' },
          { name: 'Paid', value: 'true', kind: 'boolean' },
        ],
      }),
    ).toEqual([
      { name: 'Recovery email', value: 'sam.backup@example.org', kind: 'text', admin: false },
      { name: 'Security question', value: 'blue', kind: 'hidden', admin: false },
      { name: 'Paid', value: 'true', kind: 'checkbox', admin: false },
    ]);
  });

  it('marks a field the admin defined by `adminField`, the id of its definition, and by nothing else', () => {
    const fields = readCustomFields({
      fields: [
        { name: 'Employee ID', value: '42', kind: 'text', adminField: 'f1' },
        { name: 'A guess', value: 'x', kind: 'text', admin: true },
        { name: 'Another guess', value: 'x', kind: 'text', adminFieldId: 'f2', adminId: 'f3' },
        { name: 'Mine', value: 'x', kind: 'text', adminField: '' },
      ],
    });
    expect(fields.map((f) => f.admin)).toEqual([true, false, false, false]);
    expect(fields[0]?.adminField).toBe('f1');
  });

  it('reads a checkbox as true or false, whatever it was saved as', () => {
    const values = readCustomFields({
      fields: [
        { name: 'a', value: true, kind: 'boolean' },
        { name: 'b', value: 'false', kind: 'checkbox' },
        { name: 'c', value: '', kind: 'boolean' },
        { name: 'd', value: 'yes', kind: 'boolean' },
      ],
    }).map((f) => f.value);
    expect(values).toEqual(['true', 'false', 'false', 'false']);
  });

  it('takes the numbers Bitwarden uses for the kind, and any other kind as text', () => {
    const kinds = readCustomFields({
      fields: [
        { name: 'a', value: 'x', kind: 1 },
        { name: 'b', value: 'x', kind: 2 },
        { name: 'c', value: 'x', kind: 'linked' },
        { name: 'd', value: 'x' },
      ],
    }).map((f) => f.kind);
    expect(kinds).toEqual(['hidden', 'checkbox', 'text', 'text']);
  });

  it('skips a field with no name or no value, and what it cannot read', () => {
    expect(
      readCustomFields({
        fields: [
          { name: '  ', value: 'x' },
          { name: 'Empty', value: '' },
          { name: 'Number', value: 7 },
          'junk',
          null,
          ['x'],
        ],
      }),
    ).toEqual([{ name: 'Number', value: '7', kind: 'text', admin: false }]);
  });

  it('is empty for an item with none, or one that could not be read', () => {
    expect(readCustomFields({})).toEqual([]);
    expect(readCustomFields({ fields: 'nope' })).toEqual([]);
    expect(readCustomFields(null)).toEqual([]);
  });
});

describe('resolveAdminFields', () => {
  const defs: AdminFieldDef[] = [
    { id: 'f1', name: 'Staff number', type: 'text', kinds: 'all' },
    { id: 'f2', name: 'Badge', type: 'checkbox', kinds: 'all' },
  ];
  const stored = readCustomFields({
    fields: [
      { name: 'Employee ID', value: '42', kind: 'text', adminField: 'f1' },
      { name: 'Old name', value: 'blue', kind: 'hidden', adminField: 'f2' },
      { name: 'Deleted by the admin', value: 'x', kind: 'hidden', adminField: 'zz' },
      { name: 'Mine', value: 'y', kind: 'text' },
    ],
  });

  it('shows the name and type the admin has now, and leaves the person\'s value', () => {
    const resolved = resolveAdminFields(stored, defs);
    expect(resolved[0]).toMatchObject({ name: 'Staff number', kind: 'text', value: '42', admin: true });
    // A text value under a field that is a checkbox now reads as unchecked.
    expect(resolved[1]).toMatchObject({ name: 'Badge', kind: 'checkbox', value: 'false', admin: true });
  });

  it('keeps what the item holds for a field the admin no longer has, and for the person\'s own', () => {
    const resolved = resolveAdminFields(stored, defs);
    expect(resolved[2]).toMatchObject({ name: 'Deleted by the admin', kind: 'hidden', value: 'x', admin: true });
    expect(resolved[3]).toMatchObject({ name: 'Mine', kind: 'text', admin: false });
  });

  it('changes nothing while the definitions are not there', () => {
    expect(resolveAdminFields(stored, [])).toEqual(stored);
  });
});
