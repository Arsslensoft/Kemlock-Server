import { describe, expect, it } from 'vitest';
import {
  LinkError,
  formLinkCandidates,
  formLinks,
  incomingLinks,
  isLinked,
  legacyLink,
  linkCandidates,
  linkInputs,
  linkWriteFields,
  linkedItems,
  linksFields,
  linksOf,
  planLinkWrites,
  readLinks,
  unlinkInputs,
  writeLinks,
} from './links';
import type { ItemData, VaultItem } from './vault';

const A = '11111111-1111-4111-8111-111111111111';
const B = '22222222-2222-4222-8222-222222222222';
const C = '33333333-3333-4333-8333-333333333333';

function item(id: string, kind: string, data: ItemData | null): VaultItem {
  return { id, owner: 'user:u', kind, revision: 2, keyVersion: 1, data, sizes: { ciphertext: 0, itemKey: 0 } };
}

describe('readLinks and writeLinks', () => {
  it('read ids sorted and unique, and skip what is not a UUID', () => {
    const data = { links: [{ id: C }, { id: A.toUpperCase() }, { id: A }, { id: 'nope' }, 'x', null, { id: 7 }] };
    expect(readLinks(data)).toEqual([A, C]);
    expect(readLinks({})).toEqual([]);
    expect(readLinks(null)).toEqual([]);
  });

  it('write {id} entries sorted by id, and nothing at all for no links', () => {
    expect(writeLinks({}, [C, A, A])).toEqual([{ id: A }, { id: C }]);
    expect(writeLinks({ links: [{ id: A }] }, [])).toBeUndefined();
  });

  it('keep an entry they cannot read, after the others, and the member when only those are left', () => {
    const odd = { who: 'knows', note: 'a link of another shape' };
    const data = { links: [{ id: C }, odd, 'x', { id: 'not-a-uuid' }] };
    expect(writeLinks(data, [A, C])).toEqual([{ id: A }, { id: C }, odd, 'x', { id: 'not-a-uuid' }]);
    expect(writeLinks(data, [])).toEqual([odd, 'x', { id: 'not-a-uuid' }]);
    expect(writeLinks({ links: ['x'] }, [])).toEqual(['x']);
  });

  it('keep what an entry already carried', () => {
    const data = { links: [{ id: A, since: 5 }] };
    expect(writeLinks(data, [B, A])).toEqual([{ id: A, since: 5 }, { id: B }]);
  });
});

describe('linking and unlinking two items', () => {
  it('writes both ends, and nothing for an end that already names the other', () => {
    const a = item(A, 'login', { name: 'GitHub' });
    const b = item(B, 'otp', { issuer: 'GitHub' });
    const both = linkInputs(a, b);
    expect(both.map((input) => input.existing?.id)).toEqual([A, B]);
    expect(both[0]?.fields['links']).toEqual([{ id: B }]);
    expect(both[1]?.fields['links']).toEqual([{ id: A }]);

    const half = item(A, 'login', { name: 'GitHub', links: [{ id: B }] });
    expect(linkInputs(half, b).map((input) => input.existing?.id)).toEqual([B]);
    expect(isLinked(half, b)).toBe(true);
  });

  it('removes both ends, whichever still names the other', () => {
    const a = item(A, 'login', { links: [{ id: B }, { id: C }] });
    const b = item(B, 'otp', { links: [{ id: A }] });
    const inputs = unlinkInputs(a, b);
    expect(inputs).toHaveLength(2);
    expect(inputs[0]?.fields['links']).toEqual([{ id: C }]);
    expect(inputs[1]?.fields['links']).toBeUndefined();
    expect('links' in (inputs[1]?.fields ?? {})).toBe(true);
  });

  it('refuses an item linked to itself and an item that cannot be read', () => {
    const a = item(A, 'login', {});
    expect(() => linkInputs(a, a)).toThrow(LinkError);
    expect(() => linkInputs(a, item(B, 'login', null))).toThrow(LinkError);
  });
});

describe('linkedItems and linkCandidates', () => {
  const login = item(A, 'login', { name: 'GitHub', links: [{ id: B }] });
  const code = item(B, 'otp', { issuer: 'GitHub', links: [{ id: A }] });
  const half = item(C, 'backup-codes', { serviceName: 'GitHub', links: [{ id: A }] });
  const stranger = item('44444444-4444-4444-8444-444444444444', 'note', { name: 'Recovery plan' });
  const trashed = item('55555555-5555-4555-8555-555555555555', 'note', { name: 'Old', trashedAt: '2026-11-01T00:00:00Z' });
  const all = [login, code, half, stranger, trashed];

  it('shows a link that only one end holds', () => {
    expect(linkedItems(login, all).map((other) => other.id)).toEqual([B, C]);
  });

  it('offers items not linked yet, not trashed, not itself, that can be written, narrowed by the query', () => {
    expect(linkCandidates(login, all, '').map((other) => other.id)).toEqual([stranger.id]);
    expect(linkCandidates(login, all, 'recovery').map((other) => other.id)).toEqual([stranger.id]);
    expect(linkCandidates(login, all, 'zzz')).toEqual([]);
    expect(linkCandidates(login, all, '', () => false)).toEqual([]);
  });

  it('serves a form for an item that does not exist yet', () => {
    const offered = formLinkCandidates(all, { chosen: [B], query: '' }).map((other) => other.id);
    expect(offered).toEqual([A, C, stranger.id].sort());
    expect(formLinkCandidates(all, { selfId: A, chosen: [], query: 'github' }).map((other) => other.id)).toEqual([B, C]);
  });
});

describe('what a form holds and writes', () => {
  it('shows the login a code the importer made names in linkedLoginId, beside links', () => {
    expect(formLinks({ links: [{ id: B }], linkedLoginId: A })).toEqual([A, B]);
    expect(formLinks({ linkedLoginId: 'nope' })).toEqual([]);
  });

  it('keeps the login of a code in linkedLoginId, out of links, and drops it when unlinked', () => {
    const existing = { linkedLoginId: A, links: [{ id: B }] };
    const kept = linksFields(existing, [A, B]);
    expect(kept).toEqual({ links: [{ id: B }] });
    expect('linkedLoginId' in kept).toBe(false);
    const unlinked = linksFields(existing, [B]);
    expect(unlinked['links']).toEqual([{ id: B }]);
    expect('linkedLoginId' in unlinked && unlinked['linkedLoginId'] === undefined).toBe(true);
  });

  it('puts the login in links only when links held it already, or the person linked it again', () => {
    expect(linksFields({ linkedLoginId: A, links: [{ id: A }] }, [A])).toEqual({ links: [{ id: A }] });
    // Unlinked and linked again by a later save: the old id is gone, so it is an ordinary link.
    expect(linksFields({ links: [{ id: B }] }, [A, B])).toEqual({ links: [{ id: A }, { id: B }] });
  });

  it('leaves the member out for an item with no links', () => {
    const fields = linksFields({}, []);
    expect(fields['links']).toBeUndefined();
    expect('linkedLoginId' in fields).toBe(false);
  });
});

describe('linkedLoginId as a link', () => {
  const login = item(A, 'login', { name: 'GitHub' });
  const code = item(B, 'otp', { issuer: 'GitHub', linkedLoginId: A });

  it('is read as a link by both ends', () => {
    expect(legacyLink(code.data)).toBe(A);
    expect(legacyLink({ linkedLoginId: 'nope' })).toBeUndefined();
    expect(linksOf(code.data)).toEqual([A]);
    expect(readLinks(code.data)).toEqual([]);
    expect(isLinked(code, login)).toBe(true);
    expect(linkedItems(login, [login, code]).map((other) => other.id)).toEqual([B]);
    expect(linkCandidates(login, [login, code], '').map((other) => other.id)).toEqual([]);
    expect(incomingLinks(A, [login, code])).toEqual([B]);
    expect(incomingLinks(B, [login, code])).toEqual([]);
  });

  it('needs only the login written to link the two: the code already names the login', () => {
    expect(linkInputs(login, code).map((input) => input.existing?.id)).toEqual([A]);
  });

  it('is cleared from the code when the two are unlinked from either side', () => {
    for (const [first, second] of [
      [login, code],
      [code, login],
    ] as const) {
      const inputs = unlinkInputs(first, second);
      const written = inputs.find((input) => input.existing?.id === B);
      expect(written?.fields['links']).toBeUndefined();
      expect('linkedLoginId' in (written?.fields ?? {})).toBe(true);
      expect(written?.fields['linkedLoginId']).toBeUndefined();
      expect(inputs.some((input) => input.existing?.id === A)).toBe(false);
    }
  });

  it('is cleared by the plan when the form drops the code, and is not asked to name the login again', () => {
    const lookup = (id: string) => [login, code].find((other) => other.id === id);
    const [removal] = planLinkWrites(A, [B], [], lookup);
    expect(removal).toMatchObject({ links: [], clearLegacy: true });
    expect(linkWriteFields(removal as NonNullable<typeof removal>)).toEqual({ links: undefined, linkedLoginId: undefined });
    expect(planLinkWrites(A, [B], [B], lookup)).toEqual([]);
  });
});

describe('planLinkWrites', () => {
  const lookupIn = (items: VaultItem[]) => (id: string) => items.find((other) => other.id === id);

  it('writes the new item into each item it links to', () => {
    const b = item(B, 'otp', {});
    const c = item(C, 'note', { links: [{ id: B }] });
    const writes = planLinkWrites(A, [], [B, C], lookupIn([b, c]));
    expect(writes.map((write) => [write.item.id, write.links])).toEqual([
      [B, [A]],
      [C, [B, A]],
    ]);
  });

  it('takes the new item out of an item it no longer links to', () => {
    const b = item(B, 'otp', { links: [{ id: A }, { id: C }] });
    const writes = planLinkWrites(A, [B], [], lookupIn([b]));
    expect(writes).toEqual([{ item: b, links: [C], clearLegacy: false }]);
  });

  it('leaves out an end that is right already, so a retry does what is left', () => {
    const b = item(B, 'otp', { links: [{ id: A }] });
    const c = item(C, 'note', {});
    expect(planLinkWrites(A, [], [B, C], lookupIn([b, c])).map((write) => write.item.id)).toEqual([C]);
    expect(planLinkWrites(A, [B], [B], lookupIn([b]))).toEqual([]);
  });

  it('skips an item that is gone, one that cannot be read and the item itself', () => {
    const unreadable = item(C, 'note', null);
    expect(planLinkWrites(A, [], [B, C, A], lookupIn([unreadable]))).toEqual([]);
  });
});
