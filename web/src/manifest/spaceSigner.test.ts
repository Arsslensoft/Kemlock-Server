import { describe, expect, it, vi } from 'vitest';
import type { GrantDto, GroupDto, MemberViewDto } from '@/api/spaces';
import { encodeB64, utf8 } from '@/lib/b64url';
import { canEditSomewhere, createSpaceSigner } from './spaceSigner';

const SPACE = '44444444-4444-4444-8444-444444444444';
const SIGNER = '55555555-5555-4555-8555-555555555555';
const ME = '66666666-6666-4666-8666-666666666666';

function bundleOf(account: string): Uint8Array {
  const out = new Uint8Array(17 + 16 + 4 + 1600 + 1984);
  out.set(utf8('kemlock/v1/bundle'), 0);
  out.set(Uint8Array.from(account.replace(/-/g, '').match(/../g)?.map((pair) => Number.parseInt(pair, 16)) ?? []), 17);
  return out;
}

const member = (
  user: string,
  state: MemberViewDto['state'],
  bundle = bundleOf(user),
  role: MemberViewDto['role'] = 'owner',
): MemberViewDto =>
  ({
    user,
    state,
    role,
    publicBundle: encodeB64(bundle),
    bundleSignature: encodeB64(utf8('signature')),
  }) as MemberViewDto;

interface View {
  collections: Array<{ id: string }>;
  grants: GrantDto[];
  groups: GroupDto[];
}

const VIEW: View = { collections: [{ id: 'c1' }], grants: [], groups: [] };

function setup(
  members: MemberViewDto[],
  over: { verified?: boolean; own?: string | null; account?: string | null; view?: View } = {},
) {
  const crypto = {
    verifyBundle: vi.fn(async () => over.verified ?? true),
    fingerprint: vi.fn(async (bundle: Uint8Array) => `fp:${bundle[17]}`),
    ownFingerprint: vi.fn(async () => {
      if (over.own === null) throw new Error('locked');
      return over.own ?? `fp:${bundleOf(ME)[17]}`;
    }),
  };
  const spaces = { members: vi.fn(async () => members), get: vi.fn(async () => (over.view ?? VIEW) as never) };
  const signer = createSpaceSigner({ spaces, crypto, accountId: () => over.account ?? ME });
  return { signer, crypto, spaces };
}

describe('the signer of a space manifest', () => {
  it('is the bundle of a confirmed member whose bundle is its own', async () => {
    const run = setup([member(SIGNER, 'confirmed')]);
    expect(await run.signer(SPACE, SIGNER)).toEqual(bundleOf(SIGNER));
    expect(run.spaces.members).toHaveBeenCalledWith(SPACE);
    expect(run.crypto.verifyBundle).toHaveBeenCalled();
  });

  it('is nobody who is not listed, not confirmed, or whose bundle is another account’s or badly signed', async () => {
    expect(await setup([]).signer(SPACE, SIGNER)).toBeNull();
    expect(await setup([member(SIGNER, 'accepted')]).signer(SPACE, SIGNER)).toBeNull();
    expect(await setup([member(SIGNER, 'revoked')]).signer(SPACE, SIGNER)).toBeNull();
    expect(await setup([member(SIGNER, 'confirmed', bundleOf(ME))]).signer(SPACE, SIGNER)).toBeNull();
    expect(await setup([member(SIGNER, 'confirmed')], { verified: false }).signer(SPACE, SIGNER)).toBeNull();
    expect(await setup([{ ...member(SIGNER, 'confirmed'), publicBundle: 'not base64!' }]).signer(SPACE, SIGNER)).toBeNull();
  });

  it('is a member taken out since only for a write signed before, and never one who never was confirmed', async () => {
    const gone = member(SIGNER, 'revoked');
    expect(await setup([gone]).signer(SPACE, SIGNER, { former: true })).toEqual(bundleOf(SIGNER));
    expect(await setup([gone]).signer(SPACE, SIGNER)).toBeNull();
    expect(await setup([member(SIGNER, 'accepted')]).signer(SPACE, SIGNER, { former: true })).toBeNull();
    expect(await setup([gone], { verified: false }).signer(SPACE, SIGNER, { former: true })).toBeNull();
  });

  it('holds this account to the bundle its own keys make', async () => {
    const mine = member(ME, 'confirmed');
    expect(await setup([mine]).signer(SPACE, ME)).toEqual(bundleOf(ME));
    // The member list carries a bundle that is not the one these keys make.
    expect(await setup([mine], { own: 'fp:other' }).signer(SPACE, ME)).toBeNull();
    // And keys that are not open can not vouch for it.
    expect(await setup([mine], { own: null }).signer(SPACE, ME)).toBeNull();
  });

  it("is nobody who may not edit any collection of the space", async () => {
    const plain = member(SIGNER, 'confirmed', bundleOf(SIGNER), 'member');
    expect(await setup([plain]).signer(SPACE, SIGNER)).toBeNull();
    expect(await setup([plain], { view: { ...VIEW, collections: [] } }).signer(SPACE, SIGNER)).toBeNull();
    const granted: View = { ...VIEW, grants: [{ collection: 'c1', grantee: `user:${SIGNER}`, permission: 'edit' }] };
    expect(await setup([plain], { view: granted }).signer(SPACE, SIGNER)).toEqual(bundleOf(SIGNER));
  });

  it('lets a failure to reach the member list through, as no verdict', async () => {
    const run = setup([]);
    run.spaces.members.mockRejectedValueOnce(new Error('offline'));
    await expect(run.signer(SPACE, SIGNER)).rejects.toThrow('offline');
  });
});

describe('canEditSomewhere', () => {
  const view = (grants: Array<{ collection: string; grantee: string; permission: never }>, groups = [] as Array<{ id: string; members: string[] }>) => ({
    collections: [{ id: 'c1' }, { id: 'c2' }],
    grants: grants as never,
    groups,
  });
  const plain = { user: SIGNER, role: 'member' as const };

  it('is true for an owner or admin whenever there is a collection, and false for a space with none', () => {
    expect(canEditSomewhere({ user: SIGNER, role: 'owner' }, view([]))).toBe(true);
    expect(canEditSomewhere({ user: SIGNER, role: 'admin' }, view([]))).toBe(true);
    expect(canEditSomewhere({ user: SIGNER, role: 'owner' }, { collections: [], grants: [], groups: [] })).toBe(false);
  });

  it('is true for an editing grant, to the member or to a group they are in, and only for those', () => {
    const grant = (grantee: string, permission: string, collection = 'c2') => ({ collection, grantee, permission: permission as never });
    expect(canEditSomewhere(plain, view([grant(`user:${SIGNER}`, 'edit')]))).toBe(true);
    expect(canEditSomewhere(plain, view([grant(`user:${SIGNER}`, 'manage')]))).toBe(true);
    expect(canEditSomewhere(plain, view([grant(`user:${SIGNER}`, 'view')]))).toBe(false);
    expect(canEditSomewhere(plain, view([grant(`user:${ME}`, 'edit')]))).toBe(false);
    expect(canEditSomewhere(plain, view([grant('group:g1', 'edit-hide-passwords')], [{ id: 'g1', members: [SIGNER] }]))).toBe(true);
    expect(canEditSomewhere(plain, view([grant('group:g1', 'edit')], [{ id: 'g1', members: [ME] }]))).toBe(false);
    // A grant on a collection that is not there does not count.
    expect(canEditSomewhere(plain, view([grant(`user:${SIGNER}`, 'edit', 'gone')]))).toBe(false);
  });
});
