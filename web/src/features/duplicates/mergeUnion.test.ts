// What a merge keeps of the linked items and custom fields, whatever the kind, how it keeps the
// links of the other items whole, and the vault pick.
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
import { rewriteLinks } from './relink';

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

describe('the items that pointed at an item that goes', () => {
  // `a` stays and `b` goes; the others are third items the person may or may not write.
  const A = '00000000-0000-4000-8000-0000000000e1';
  const B = '00000000-0000-4000-8000-0000000000e2';
  const P = '00000000-0000-4000-8000-0000000000f1';
  const Q = '00000000-0000-4000-8000-0000000000f2';
  const R = '00000000-0000-4000-8000-0000000000f3';
  const S = '00000000-0000-4000-8000-0000000000f4';

  function pair(aLinks?: unknown[], bLinks?: unknown[]) {
    const a = vaultItem('contact', { name: 'Alex', email: 'a@b.c', updatedAt: 2, ...(aLinks ? { links: aLinks } : {}) }, { id: A });
    const b = vaultItem('contact', { name: 'Alex C.', email: 'a@b.c', updatedAt: 1, ...(bLinks ? { links: bLinks } : {}) }, { id: B });
    return [a, b] as const;
  }
  const linked = (id: string, links: unknown[], more: Record<string, unknown> = {}) =>
    vaultItem('login', { name: id, username: 'u', links, ...more }, { id });

  it('now name the kept item instead, each once and sorted, never themselves', () => {
    const [a, b] = pair();
    const p = linked(P, [{ id: B }, { id: Q }]);
    const q = linked(Q, [{ id: B }, { id: A }, { id: Q }]);
    const plan = planMerge([a, b], defaultPicks([a, b]), NOW, { all: [a, b, p, q] });
    const byId = new Map((plan?.relinks ?? []).map((relink) => [relink.item.id, relink]));
    expect(byId.get(P)?.after['links']).toEqual([{ id: A }, { id: Q }]);
    // q named both: the kept item once, and not q itself.
    expect(byId.get(Q)?.after['links']).toEqual([{ id: A }]);
    // What they held is recorded for Undo.
    expect(byId.get(P)?.before['links']).toEqual([{ id: B }, { id: Q }]);
  });

  it('are listed on the kept item, which then links to every one of them', () => {
    const [a, b] = pair([{ id: P }], [{ id: Q }]);
    const p = linked(P, []);
    const q = linked(Q, [{ id: B }]);
    const r = linked(R, [{ id: B }]);
    const plan = planMerge([a, b], defaultPicks([a, b]), NOW, { all: [a, b, p, q, r] });
    // a linked p, b linked q, r names b without b naming r: the kept item links to all three.
    expect(plan?.fields['links']).toEqual([{ id: P }, { id: Q }, { id: R }]);
  });

  it('link back to the kept item when it now links to them and they do not name it', () => {
    const [a, b] = pair([{ id: P }], [{ id: Q }]);
    const p = linked(P, []);
    const q = linked(Q, [{ id: S }]);
    const plan = planMerge([a, b], defaultPicks([a, b]), NOW, { all: [a, b, p, q] });
    const byId = new Map((plan?.relinks ?? []).map((relink) => [relink.item.id, relink]));
    expect(byId.get(P)?.after['links']).toEqual([{ id: A }]);
    expect(byId.get(Q)?.after['links']).toEqual([{ id: A }, { id: S }]);
  });

  it('are left alone when they already name the kept item and nothing that goes', () => {
    const [a, b] = pair([{ id: P }]);
    const p = linked(P, [{ id: A }]);
    const plan = planMerge([a, b], defaultPicks([a, b]), NOW, { all: [a, b, p] });
    expect(plan?.relinks).toEqual([]);
    expect(plan?.fields['links']).toEqual([{ id: P }]);
  });

  it('are not written when the person may not change them, but the kept item still links to them', () => {
    const [a, b] = pair();
    const mine = linked(P, [{ id: B }]);
    const theirs = linked(Q, [{ id: B }]);
    const plan = planMerge([a, b], defaultPicks([a, b]), NOW, {
      all: [a, b, mine, theirs],
      canWrite: (item) => item.id !== Q,
    });
    expect(plan?.relinks.map((relink) => relink.item.id)).toEqual([P]);
    expect(plan?.fields['links']).toEqual([{ id: P }, { id: Q }]);
  });

  it('are written in the same batch as the merge, after the kept item and the trashed ones', () => {
    const [a, b] = pair();
    const p = linked(P, [{ id: B }]);
    const plan = planMerge([a, b], defaultPicks([a, b]), NOW, { all: [a, b, p] });
    if (!plan) throw new Error('no plan');
    const writes = mergeWrites(plan, NOW);
    expect(writes.map((write) => write.existing?.id)).toEqual([A, B, P]);
    expect(writes[2]?.fields).toEqual({ links: [{ id: A }] });
  });

  it('count in the plan, for the preview to say how many now point at the kept item', () => {
    const [a, b] = pair();
    const plan = planMerge([a, b], defaultPicks([a, b]), NOW, { all: [a, b, linked(P, [{ id: B }]), linked(Q, [{ id: B }])] });
    expect(plan?.relinks).toHaveLength(2);
    expect(planMerge([a, b], defaultPicks([a, b]), NOW)?.relinks).toEqual([]);
  });

  it('are found among the trashed items too, which the vault list holds apart', () => {
    const [a, b] = pair();
    const trashed = linked(P, [{ id: B }], { trashedAt: '2026-11-01T00:00:00Z' });
    expect(planMerge([a, b], defaultPicks([a, b]), NOW, { all: [a, b, trashed] })?.relinks).toHaveLength(1);
  });

  it('follow the kept item for an MFA code\'s linked login and a login\'s account', () => {
    const a = vaultItem('login', { name: 'GitHub', username: 'sam', password: 'pw', urls: ['github.com'], updatedAt: 2 }, { id: A });
    const b = vaultItem('login', { name: 'github.com', username: 'sam', password: 'pw', urls: ['gist.github.com'], updatedAt: 1 }, { id: B });
    const code = vaultItem('otp', { name: 'GitHub code', secret: 'JBSWY3DPEHPK3PXP', linkedLoginId: B }, { id: P });
    const other = vaultItem('otp', { name: 'Elsewhere', secret: 'MFRGGZDFMZTWQ2LK', linkedLoginId: R }, { id: Q });
    const plan = planMerge([a, b], defaultPicks([a, b]), NOW, { all: [a, b, code, other] });
    expect(plan?.relinks.map((relink) => relink.item.id)).toEqual([P]);
    expect(plan?.relinks[0]?.after).toEqual({ linkedLoginId: A });
    expect(plan?.relinks[0]?.before).toEqual({ linkedLoginId: B });

    // The other way: logins whose `accountId` names an MFA code that goes.
    const c1 = vaultItem('otp', { name: 'c1', secret: 'JBSWY3DPEHPK3PXP', updatedAt: 2 }, { id: A });
    const c2 = vaultItem('otp', { name: 'c2', secret: 'JBSWY3DPEHPK3PXP', updatedAt: 1 }, { id: B });
    const viaB = vaultItem('login', { name: 'l1', username: 'u', accountId: B }, { id: P });
    const viaOther = vaultItem('login', { name: 'l2', username: 'u', accountId: R }, { id: Q });
    const second = planMerge([c1, c2], defaultPicks([c1, c2]), NOW, { all: [c1, c2, viaB, viaOther] });
    expect(second?.relinks.map((relink) => [relink.item.id, relink.after['accountId']])).toEqual([[P, A]]);
  });

  it('give a kept login with no account the one of the login that goes', () => {
    const a = vaultItem('login', { name: 'GitHub', username: 'sam', password: 'pw', urls: ['github.com'], updatedAt: 2 }, { id: A });
    const b = vaultItem('login', { name: 'gh', username: 'sam', password: 'pw', urls: ['github.com'], accountId: R, updatedAt: 1 }, { id: B });
    const plan = planMerge([a, b], defaultPicks([a, b]), NOW);
    expect(plan?.fields['accountId']).toBe(R);
    expect('accountId' in (plan?.before ?? {})).toBe(true);
  });

  describe('Undo', () => {
    function merged() {
      const [a, b] = pair();
      const p = linked(P, [{ id: B }, { id: Q }]);
      const code = vaultItem('otp', { name: 'code', secret: 'JBSWY3DPEHPK3PXP', linkedLoginId: B, links: [{ id: B }] }, { id: R });
      const plan = planMerge([a, b], defaultPicks([a, b]), NOW, { all: [a, b, p, code] });
      if (!plan) throw new Error('no plan');
      // As the vault holds the items after the merge's batch.
      const after = plan.relinks.map((relink) => ({
        ...relink.item,
        revision: relink.item.revision + 1,
        data: { ...relink.item.data, ...relink.after },
      }));
      const saved = [{ ...a, revision: 2 }, { ...b, revision: 2 }, ...after];
      return { plan, saved, after };
    }

    it('puts back what the merge changed while it still holds what the merge wrote', () => {
      const { plan, saved, after } = merged();
      const writes = undoWrites(plan, saved, (id) => after.find((item) => item.id === id));
      const byId = new Map(writes.map((write) => [write.existing?.id, write]));
      expect(byId.get(P)?.fields).toEqual({ links: [{ id: B }, { id: Q }] });
      expect(byId.get(R)?.fields).toEqual({ links: [{ id: B }], linkedLoginId: B });
      // The merged items come back as before: the kept one restored, the other out of the Trash.
      expect(byId.get(A)?.fields).toEqual(plan.before);
      expect(byId.get(B)?.fields).toEqual({ trashedAt: undefined });
    });

    it('leaves a member alone that was edited or linked elsewhere since', () => {
      const { plan, saved, after } = merged();
      const since = after.map((item) =>
        item.id === P
          ? { ...item, revision: item.revision + 1, data: { ...item.data, links: [{ id: A }, { id: S }] } }
          : item.id === R
            ? { ...item, revision: item.revision + 1, data: { ...item.data, linkedLoginId: S } }
            : item,
      );
      const writes = undoWrites(plan, saved, (id) => since.find((item) => item.id === id));
      const byId = new Map(writes.map((write) => [write.existing?.id, write]));
      // p was linked on since: nothing of its links is put back. r's links still hold, its login does not.
      expect(byId.has(P)).toBe(false);
      expect(byId.get(R)?.fields).toEqual({ links: [{ id: B }] });
      // The write is made on the revision the vault holds now, not the one the merge saved.
      expect(byId.get(R)?.existing?.revision).toBe(since.find((item) => item.id === R)?.revision);
    });

    it('skips an item that is gone', () => {
      const { plan, saved } = merged();
      const writes = undoWrites(plan, saved, () => undefined);
      expect(writes.map((write) => write.existing?.id).sort()).toEqual([A, B].sort());
    });
  });
});

describe('rewriteLinks', () => {
  it('drops the ids, adds the one, and leaves nothing when nothing is left', () => {
    const item = vaultItem('login', { name: 'p', links: [{ id: X, addedAt: 1 }, { id: Y }] }, { id: Z });
    expect(rewriteLinks(item, new Set([Y.toLowerCase()]), undefined)).toEqual([{ id: X, addedAt: 1 }]);
    expect(rewriteLinks(item, new Set([X, Y]), undefined)).toBeUndefined();
    expect(rewriteLinks(item, new Set([X, Y]), Z)).toBeUndefined();
    expect(rewriteLinks(item, new Set(), X)).toEqual([{ id: X, addedAt: 1 }, { id: Y }]);
  });
});
