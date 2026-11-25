// What a merge keeps of the linked items and custom fields, whatever the kind, and the vault pick.
import { describe, expect, it } from 'vitest';
import { SPACE, vaultItem } from '@/test/tools-fixtures';
import {
  defaultPicks,
  hasUnionMembers,
  keepInVault,
  mergeWrites,
  planMerge,
  resultName,
  undoWrites,
  vaultsOf,
} from './merge';

const NOW = new Date('2026-11-25T10:00:00Z');
const X = '00000000-0000-4000-8000-0000000000a1';
const Y = '00000000-0000-4000-8000-0000000000a2';
const Z = '00000000-0000-4000-8000-0000000000a3';

describe('linked items', () => {
  it('joins every item\'s links on the kept item, each once, sorted by id', () => {
    const a = vaultItem('contact', { name: 'Alex', email: 'a@b.c', links: [{ id: Z }, { id: X }] });
    const b = vaultItem('contact', { name: 'Alex C.', email: 'a@b.c', links: [{ id: Y }, { id: X }] });
    const plan = planMerge([a, b], defaultPicks([a, b]), NOW);
    expect(plan?.fields['links']).toEqual([{ id: X }, { id: Y }, { id: Z }]);
  });

  it('drops a link between the merged items themselves, in any letter case', () => {
    const idA = '00000000-0000-4000-8000-0000000000ab';
    const idB = '00000000-0000-4000-8000-0000000000cd';
    const a = vaultItem('note', { name: 'A', text: 'x', links: [{ id: idB.toUpperCase() }, { id: X }] }, { id: idA });
    const b = vaultItem('note', { name: 'B', text: 'x', links: [{ id: idA }] }, { id: idB });
    const plan = planMerge([a, b], defaultPicks([a, b]), NOW);
    expect(plan?.fields['links']).toEqual([{ id: X }]);
  });

  it('removes the member when nothing is left to link to', () => {
    const idA = '00000000-0000-4000-8000-0000000000ab';
    const idB = '00000000-0000-4000-8000-0000000000cd';
    const a = vaultItem('note', { name: 'A', text: 'x', links: [{ id: idB }] }, { id: idA });
    const b = vaultItem('note', { name: 'B', text: 'x', links: [{ id: idA }] }, { id: idB });
    const plan = planMerge([a, b], defaultPicks([a, b]), NOW);
    expect('links' in (plan?.fields ?? {})).toBe(true);
    expect(plan?.fields['links']).toBeUndefined();
  });

  it('keeps what the entry carried besides its id', () => {
    const a = vaultItem('note', { name: 'A', text: 'x', links: [{ id: X, addedAt: 5 }] });
    const b = vaultItem('note', { name: 'B', text: 'x', links: [{ id: X }, { id: Y }] });
    expect(planMerge([a, b], defaultPicks([a, b]), NOW)?.fields['links']).toEqual([{ id: X, addedAt: 5 }, { id: Y }]);
  });

  it('touches neither member of an item that has none, so it stays byte for byte', () => {
    const a = vaultItem('card', { name: 'Travel', number: '4111111111111111' });
    const b = vaultItem('card', { name: 'Mastercard', number: '4111111111111111' });
    const plan = planMerge([a, b], defaultPicks([a, b]), NOW);
    expect('links' in (plan?.fields ?? {})).toBe(false);
    expect('fields' in (plan?.fields ?? {})).toBe(false);
    expect(hasUnionMembers([a, b])).toBe(false);
  });

  it('is reversed by Undo: the kept item gets its own links back', () => {
    const a = vaultItem('note', { name: 'A', text: 'x', links: [{ id: X }] });
    const b = vaultItem('note', { name: 'B', text: 'x', links: [{ id: Y }] });
    const plan = planMerge([a, b], defaultPicks([a, b]), NOW);
    if (!plan) throw new Error('no plan');
    expect(plan.fields['links']).toEqual([{ id: X }, { id: Y }]);
    const saved = [
      { ...a, revision: 2 },
      { ...b, revision: 2 },
    ];
    expect(undoWrites(plan, saved)[0]?.fields['links']).toEqual([{ id: X }]);
    // The trashed twin keeps its own links, so a restore brings its connection back.
    expect(mergeWrites(plan, NOW)[1]?.fields).toEqual({ trashedAt: NOW.toISOString() });
  });
});

describe('custom fields', () => {
  it("joins the fields of every item, the kept item's first, each distinct field once", () => {
    const pin = { name: 'PIN', value: '1234', kind: 'hidden' };
    const rack = { name: 'Rack', value: 'A3', kind: 'text' };
    const admin = { name: 'Cost centre', value: 'X9', kind: 'text', adminField: 'cc' };
    const a = vaultItem('card', { name: 'A', fields: [pin, admin] });
    const b = vaultItem('card', { name: 'B', fields: [{ kind: 'hidden', value: '1234', name: 'PIN' }, rack] });
    const plan = planMerge([a, b], defaultPicks([a, b]), NOW);
    expect(plan?.fields['fields']).toEqual([pin, admin, rack]);
  });

  it('keeps both values of a field the copies disagree on, so nothing is lost', () => {
    const a = vaultItem('card', { name: 'A', fields: [{ name: 'PIN', value: '1111', kind: 'hidden' }] });
    const b = vaultItem('card', { name: 'B', fields: [{ name: 'PIN', value: '2222', kind: 'hidden' }] });
    const fields = planMerge([a, b], defaultPicks([a, b]), NOW)?.fields['fields'] as Array<{ value: string }>;
    expect(fields.map((field) => field.value)).toEqual(['1111', '2222']);
  });

  it("keeps one value of an admin's field, the kept item's, since the admin fixed it to one", () => {
    const a = vaultItem('card', { name: 'A', fields: [{ name: 'Cost centre', value: 'X9', kind: 'text', adminField: 'cc' }] });
    const b = vaultItem('card', { name: 'B', fields: [{ name: 'Cost centre', value: 'Y1', kind: 'text', adminField: 'cc' }] });
    const fields = planMerge([a, b], defaultPicks([a, b]), NOW)?.fields['fields'] as Array<{ value: string }>;
    expect(fields.map((field) => field.value)).toEqual(['X9']);
  });

  it('are taken from the other item when the kept one has none', () => {
    const a = vaultItem('note', { name: 'A', text: 'x' });
    const b = vaultItem('note', { name: 'B', text: 'x', fields: [{ name: 'Room', value: '5', kind: 'text' }] });
    expect(hasUnionMembers([a, b])).toBe(true);
    expect(planMerge([a, b], defaultPicks([a, b]), NOW)?.fields['fields']).toEqual([
      { name: 'Room', value: '5', kind: 'text' },
    ]);
  });
});

describe('the kept item of copies in two vaults', () => {
  const mine = vaultItem('contact', { name: 'Alex Chen', email: 'a@b.c', updatedAt: 3 });
  const family = vaultItem('contact', { name: 'Alex C.', email: 'a@b.c', updatedAt: 2 }, { owner: SPACE });
  const mineToo = vaultItem('contact', { name: 'Alex', email: 'a@b.c', updatedAt: 1 });

  it('lists the vaults a group is in, once each, in the order of the items', () => {
    expect(vaultsOf([mine, family, mineToo])).toEqual(['personal', '00000000-0000-4000-8000-0000000000bb']);
  });

  it('keeps the item in the vault the person picks, and the name they picked', () => {
    const picks = { ...defaultPicks([mine, family]), nameFrom: family.id };
    const inFamily = keepInVault([mine, family], picks, '00000000-0000-4000-8000-0000000000bb');
    expect(inFamily.keepId).toBe(family.id);
    expect(inFamily.nameFrom).toBe(family.id);

    const inPersonal = keepInVault([mine, family], picks, 'personal');
    expect(inPersonal.keepId).toBe(mine.id);
    // The name stays the Family copy's: the kept item is renamed, and says so.
    const plan = planMerge([mine, family], inPersonal, NOW);
    expect(plan?.kept.id).toBe(mine.id);
    expect(plan?.trashed.map((item) => item.id)).toEqual([family.id]);
    expect(plan && resultName(plan)).toBe('Alex C.');
  });

  it('keeps the newest copy of that vault when the name is from the other', () => {
    const picks = { ...defaultPicks([mine, family, mineToo]), nameFrom: family.id };
    expect(keepInVault([mine, family, mineToo], picks, 'personal').keepId).toBe(mine.id);
  });

  it('leaves the picks as they were for a vault no item is in', () => {
    const picks = defaultPicks([mine, family]);
    expect(keepInVault([mine, family], picks, 'nowhere')).toBe(picks);
  });

  it('writes the kept item in its own vault and trashes the other where it is', () => {
    const plan = planMerge([mine, family], keepInVault([mine, family], defaultPicks([mine, family]), '00000000-0000-4000-8000-0000000000bb'), NOW);
    if (!plan) throw new Error('no plan');
    const writes = mergeWrites(plan, NOW);
    expect(writes.map((write) => write.owner)).toEqual([SPACE, mine.owner]);
    expect(writes[1]?.fields).toEqual({ trashedAt: NOW.toISOString() });
  });
});

describe('the name of the merged item', () => {
  it('is the picked name, else the kept item\'s own', () => {
    const a = vaultItem('note', { name: 'A', text: 'x' });
    const b = vaultItem('note', { name: 'B', text: 'x' });
    const plan = planMerge([a, b], { ...defaultPicks([a, b]), nameFrom: b.id }, NOW);
    expect(plan && resultName(plan)).toBe('B');
    const unnamed = vaultItem('otp', { secret: 'JBSWY3DP' });
    const other = vaultItem('otp', { secret: 'JBSWY3DP' });
    const second = planMerge([unnamed, other], defaultPicks([unnamed, other]), NOW);
    expect(second && resultName(second)).toBe('');
  });
});
