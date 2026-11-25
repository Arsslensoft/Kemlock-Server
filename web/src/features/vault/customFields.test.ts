import { describe, expect, it } from 'vitest';
import { readCustomFields } from './customFields';

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

  it('marks the fields the admin defined', () => {
    const fields = readCustomFields({
      fields: [
        { name: 'Employee ID', value: '42', kind: 'text', adminField: 'f1' },
        { name: 'Cost center', value: 'R&D', kind: 'text', admin: true },
        { name: 'Mine', value: 'x', kind: 'text', adminField: '' },
      ],
    });
    expect(fields.map((f) => f.admin)).toEqual([true, true, false]);
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
