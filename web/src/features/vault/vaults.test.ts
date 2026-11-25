import { describe, expect, it } from 'vitest';
import { SPACE, vaultItem } from '@/test/tools-fixtures';
import { FAMILY_ID, WORDS } from '@/test/vault-fixtures';
import { vaultLabel, vaultOptions } from './vaults';

const OTHER = '11111111-1111-4111-8111-111111111111';

describe('vaultOptions', () => {
  it('is Personal, then each space the person is in, by name', () => {
    const options = vaultOptions(
      [
        { id: OTHER, name: 'Example Co', state: 'confirmed' },
        { id: FAMILY_ID, name: 'Family', state: 'confirmed' },
      ],
      [],
      WORDS,
    );
    expect(options).toEqual([
      { id: 'personal', label: 'Personal' },
      { id: OTHER, label: 'Example Co' },
      { id: FAMILY_ID, label: 'Family' },
    ]);
  });

  it('leaves out a space the person was only invited to, unless an item of it is here', () => {
    const invited = [{ id: OTHER, name: 'Example Co', state: 'invited' }];
    expect(vaultOptions(invited, [], WORDS).map((option) => option.id)).toEqual(['personal']);
    const withItem = vaultOptions(invited, [{ owner: `space:${OTHER}` }], WORDS);
    expect(withItem.map((option) => option.label)).toEqual(['Personal', 'Example Co']);
  });

  it('calls a space with no readable name, or no row yet, "A space"', () => {
    expect(vaultOptions([{ id: FAMILY_ID, name: null, state: 'confirmed' }], [], WORDS)[1]?.label).toBe('A space');
    expect(vaultOptions([], [vaultItem('note', {}, { owner: SPACE })], WORDS)[1]).toEqual({
      id: FAMILY_ID,
      label: 'A space',
    });
  });

  it('lists a space once however many items it has', () => {
    const items = [vaultItem('note', {}, { owner: SPACE }), vaultItem('note', {}, { owner: SPACE })];
    expect(vaultOptions([{ id: FAMILY_ID, name: 'Family', state: 'confirmed' }], items, WORDS)).toHaveLength(2);
  });
});

describe('vaultLabel', () => {
  const options = vaultOptions([{ id: FAMILY_ID, name: 'Family', state: 'confirmed' }], [], WORDS);

  it("names the vault of an owner: Personal or the space's name", () => {
    expect(vaultLabel('user:00000000-0000-4000-8000-0000000000aa', options, WORDS)).toBe('Personal');
    expect(vaultLabel(SPACE, options, WORDS)).toBe('Family');
  });

  it('falls back to "A space" for a space it knows nothing of', () => {
    expect(vaultLabel(`space:${OTHER}`, options, WORDS)).toBe('A space');
  });
});
