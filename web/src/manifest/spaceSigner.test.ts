// @vitest-environment node
import { describe, expect, it, vi } from 'vitest';
import type { GrantDto, GroupDto, MemberViewDto } from '@/api/spaces';
import type { ChainMember, ChainView } from '@/crypto/types';
import type { SpaceTrust } from '@/features/spaces/chain';
import { encodeB64, utf8 } from '@/lib/b64url';
import { fingerprintBytes, fingerprintText } from '@/sharing/bundle';
import { memoryPinStore } from '@/spaces/anchors';
import { NO_CHAIN, fakeSpaceCrypto } from '@/test/fake-space-crypto';
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
  signature = 'signature',
): MemberViewDto =>
  ({
    user,
    state,
    role,
    custom: [],
    userKeyVersion: 0,
    publicBundle: encodeB64(bundle),
    bundleSignature: encodeB64(utf8(signature)),
  }) as unknown as MemberViewDto;

interface View {
  collections: Array<{ id: string }>;
  grants: GrantDto[];
  groups: GroupDto[];
}

const VIEW: View = { collections: [{ id: 'c1' }], grants: [], groups: [] };

/** The pinned fingerprint of an account's bundle: what a person compared in this browser. */
async function pinned(user: string): Promise<string> {
  return fingerprintText(await fingerprintBytes(bundleOf(user)));
}

async function setup(
  members: MemberViewDto[],
  over: {
    own?: string | null;
    account?: string | null;
    view?: View;
    trust?: SpaceTrust;
    pin?: string[];
  } = {},
) {
  const crypto = {
    fingerprint: vi.fn(async (bundle: Uint8Array) => `fp:${bundle[17]}`),
    ownFingerprint: vi.fn(async () => {
      if (over.own === null) throw new Error('locked');
      return over.own ?? `fp:${bundleOf(ME)[17]}`;
    }),
  };
  const spaces = { members: vi.fn(async () => members), get: vi.fn(async () => (over.view ?? VIEW) as never) };
  const chain = vi.fn(async (_space: string, _me: string): Promise<SpaceTrust> => over.trust ?? { kind: 'unchained' });
  // The worker's own checks, with this account's own fingerprint and the pins a person made.
  const traced = fakeSpaceCrypto();
  traced.ownFingerprintText = await pinned(ME);
  const pins = memoryPinStore();
  for (const user of over.pin ?? []) await pins.save(ME, user, await pinned(user));
  const signer = createSpaceSigner({
    spaces,
    crypto,
    accountId: () => (over.account === undefined ? ME : over.account),
    chain,
    trace: { crypto: traced, pins },
  });
  return { signer, crypto, spaces, chain, traced };
}

describe('the signer of a space with a chain', () => {
  const chained = (members: ChainMember[], view: Partial<ChainView> = {}): SpaceTrust => ({
    kind: 'verified',
    view: {
      ...NO_CHAIN,
      chained: true,
      head: { seq: 3, link: 'bGluaw' },
      members,
      collections: [{ id: 'c1', keyVersion: 1, marked: false, nameHash: 'h', nameVersion: 1 }],
      grants: [{ collection: 'c1', grantee: `user:${SIGNER}`, permission: 'edit' }],
      ...view,
    },
  });
  const confirmed = (id: string, over: Partial<ChainMember> = {}): ChainMember => ({
    id,
    role: 'member',
    custom: [],
    status: 'confirmed',
    invitedBy: ME,
    bundle: encodeB64(bundleOf(id)),
    bundleVersion: 0,
    ...over,
  });

  it('is the bundle the chain records for a confirmed member with edit, never the server’s', async () => {
    // The server lists another bundle for the signer: only the chain's is used, and the member
    // list isn't even read.
    const lists = [member(SIGNER, 'confirmed', bundleOf(ME))];
    const run = await setup(lists, { trust: chained([confirmed(SIGNER)]) });
    expect(await run.signer(SPACE, SIGNER)).toEqual(bundleOf(SIGNER));
    expect(run.chain).toHaveBeenCalledWith(SPACE, ME);
    expect(run.spaces.members).not.toHaveBeenCalled();
  });

  it('is nobody the chain doesn’t show confirmed, with a bundle that is their own, and with edit', async () => {
    const lists = [member(SIGNER, 'confirmed')];
    const none = async (trust: SpaceTrust) => (await setup(lists, { trust })).signer(SPACE, SIGNER);
    expect(await none(chained([]))).toBeNull();
    expect(await none(chained([confirmed(SIGNER, { status: 'invited' })]))).toBeNull();
    expect(await none(chained([confirmed(SIGNER, { status: 'removed' })]))).toBeNull();
    const bundleless: ChainMember = { id: SIGNER, role: 'member', custom: [], status: 'confirmed', invitedBy: ME };
    expect(await none(chained([bundleless]))).toBeNull();
    expect(await none(chained([confirmed(SIGNER, { bundle: encodeB64(bundleOf(ME)) })]))).toBeNull();
    expect(await none(chained([confirmed(SIGNER, { bundle: 'not base64!' })]))).toBeNull();
    // No grant gives edit: an owner's or admin's role alone gives no access to items.
    expect(await none(chained([confirmed(SIGNER, { role: 'owner' })], { grants: [] }))).toBeNull();
    const viewing = [{ collection: 'c1', grantee: `user:${SIGNER}`, permission: 'view' }];
    expect(await none(chained([confirmed(SIGNER)], { grants: viewing }))).toBeNull();
    // A grant on a collection the chain doesn't have counts for nothing.
    const gone = [{ collection: 'gone', grantee: `user:${SIGNER}`, permission: 'edit' }];
    expect(await none(chained([confirmed(SIGNER)], { grants: gone }))).toBeNull();
  });

  it('counts an editing grant to a group the chain holds the signer in', async () => {
    const trust = chained([confirmed(SIGNER)], {
      grants: [{ collection: 'c1', grantee: 'group:g1', permission: 'edit-hide-passwords' }],
      groups: [{ id: 'g1', members: [SIGNER], nameHash: 'h', nameVersion: 1 }],
    });
    expect(await (await setup([], { trust })).signer(SPACE, SIGNER)).toEqual(bundleOf(SIGNER));
    const other = chained([confirmed(SIGNER)], {
      grants: [{ collection: 'c1', grantee: 'group:g1', permission: 'edit' }],
      groups: [{ id: 'g1', members: [ME], nameHash: 'h', nameVersion: 1 }],
    });
    expect(await (await setup([], { trust: other })).signer(SPACE, SIGNER)).toBeNull();
  });

  it('is nobody while the chain is refused, can’t be read, or waits for first contact', async () => {
    const lists = [member(SIGNER, 'confirmed')];
    const waiting: SpaceTrust = {
      kind: 'first-contact',
      view: { ...NO_CHAIN, chained: true, trusted: false, members: [confirmed(SIGNER)] },
    };
    for (const trust of [
      waiting,
      { kind: 'unverified', reason: 'forked', seq: 3 } as SpaceTrust,
      { kind: 'unverified', reason: 'unreachable', seq: null } as SpaceTrust,
    ]) {
      const run = await setup(lists, { trust });
      expect(await run.signer(SPACE, SIGNER)).toBeNull();
      expect(run.spaces.members).not.toHaveBeenCalled();
    }
  });

  it('is a member the chain shows removed only for a write signed before', async () => {
    const trust = chained([confirmed(SIGNER, { status: 'removed' })]);
    const run = await setup([], { trust });
    expect(await run.signer(SPACE, SIGNER, { former: true })).toEqual(bundleOf(SIGNER));
    expect(await run.signer(SPACE, SIGNER)).toBeNull();
  });

  it('says whether the signer it answered for was taken out, for a write that counts only up to what was accepted', async () => {
    const former = { former: true };
    const gone = await setup([member(SIGNER, 'revoked')], { pin: [SIGNER] });
    await gone.signer(SPACE, SIGNER, former);
    expect(gone.signer.standing?.(SPACE, SIGNER)).toBe('removed');
    const here = await setup([member(SIGNER, 'confirmed', bundleOf(SIGNER), 'owner')], { pin: [SIGNER] });
    await here.signer(SPACE, SIGNER, former);
    expect(here.signer.standing?.(SPACE, SIGNER)).toBe('member');
    // Nothing said of a signer it was not asked about.
    expect(here.signer.standing?.(SPACE, ME)).toBeUndefined();
  });

  it('holds this account to the bundle its own keys make', async () => {
    const trust = chained([confirmed(ME)], {
      grants: [{ collection: 'c1', grantee: `user:${ME}`, permission: 'manage' }],
    });
    expect(await (await setup([], { trust })).signer(SPACE, ME)).toEqual(bundleOf(ME));
    expect(await (await setup([], { trust, own: 'fp:other' })).signer(SPACE, ME)).toBeNull();
    expect(await (await setup([], { trust, own: null })).signer(SPACE, ME)).toBeNull();
  });
});

describe('the signer of a space with no chain', () => {
  it('is the bundle of a confirmed member the browser can trace, who may edit', async () => {
    const run = await setup([member(SIGNER, 'confirmed')], { pin: [SIGNER] });
    expect(await run.signer(SPACE, SIGNER)).toEqual(bundleOf(SIGNER));
    expect(run.spaces.members).toHaveBeenCalledWith(SPACE);
    expect(run.chain).toHaveBeenCalledWith(SPACE, ME);
  });

  it('is nobody whose keys nobody confirmed that this browser can trace', async () => {
    // Listed, confirmed, may edit, and a bundle of their own: but no pin and no confirmation.
    const run = await setup([member(SIGNER, 'confirmed')]);
    expect(await run.signer(SPACE, SIGNER)).toBeNull();
    // A bundle that is another account's isn't traced either, whatever is pinned.
    const swapped = member(SIGNER, 'confirmed', bundleOf(ME));
    expect(await (await setup([{ ...swapped, user: SIGNER }], { pin: [SIGNER] })).signer(SPACE, SIGNER)).toBeNull();
  });

  it('is nobody who is not listed, not confirmed, or whose bundle is another account’s or badly signed', async () => {
    expect(await (await setup([], { pin: [SIGNER] })).signer(SPACE, SIGNER)).toBeNull();
    expect(await (await setup([member(SIGNER, 'accepted')], { pin: [SIGNER] })).signer(SPACE, SIGNER)).toBeNull();
    expect(await (await setup([member(SIGNER, 'revoked')], { pin: [SIGNER] })).signer(SPACE, SIGNER)).toBeNull();
    expect(
      await (await setup([member(SIGNER, 'confirmed', bundleOf(ME))], { pin: [SIGNER] })).signer(SPACE, SIGNER),
    ).toBeNull();
    const bad = member(SIGNER, 'confirmed', bundleOf(SIGNER), 'owner', 'bad-bundle-signature');
    expect(await (await setup([bad], { pin: [SIGNER] })).signer(SPACE, SIGNER)).toBeNull();
    const junk = { ...member(SIGNER, 'confirmed'), publicBundle: 'not base64!' };
    expect(await (await setup([junk], { pin: [SIGNER] })).signer(SPACE, SIGNER)).toBeNull();
  });

  it('is a member taken out since only for a write signed before, and never one who never was confirmed', async () => {
    const gone = member(SIGNER, 'revoked');
    const former = { former: true };
    expect(await (await setup([gone], { pin: [SIGNER] })).signer(SPACE, SIGNER, former)).toEqual(bundleOf(SIGNER));
    expect(await (await setup([gone], { pin: [SIGNER] })).signer(SPACE, SIGNER)).toBeNull();
    const accepted = member(SIGNER, 'accepted');
    expect(await (await setup([accepted], { pin: [SIGNER] })).signer(SPACE, SIGNER, former)).toBeNull();
    // Keys nobody confirmed that this browser can trace are not vouched, taken out or not.
    expect(await (await setup([gone])).signer(SPACE, SIGNER, former)).toBeNull();
  });

  it('says whether the signer it answered for was taken out, for a write that counts only up to what was accepted', async () => {
    const former = { former: true };
    const gone = await setup([member(SIGNER, 'revoked')], { pin: [SIGNER] });
    await gone.signer(SPACE, SIGNER, former);
    expect(gone.signer.standing?.(SPACE, SIGNER)).toBe('removed');
    const here = await setup([member(SIGNER, 'confirmed', bundleOf(SIGNER), 'owner')], { pin: [SIGNER] });
    await here.signer(SPACE, SIGNER, former);
    expect(here.signer.standing?.(SPACE, SIGNER)).toBe('member');
    // Nothing said of a signer it was not asked about.
    expect(here.signer.standing?.(SPACE, ME)).toBeUndefined();
  });

  it('holds this account to the bundle its own keys make', async () => {
    const mine = member(ME, 'confirmed');
    expect(await (await setup([mine])).signer(SPACE, ME)).toEqual(bundleOf(ME));
    // The member list carries a bundle that is not the one these keys make.
    expect(await (await setup([mine], { own: 'fp:other' })).signer(SPACE, ME)).toBeNull();
    // And keys that are not open can not vouch for it.
    expect(await (await setup([mine], { own: null })).signer(SPACE, ME)).toBeNull();
  });

  it('is nobody who may not edit any collection of the space', async () => {
    const plain = member(SIGNER, 'confirmed', bundleOf(SIGNER), 'member');
    expect(await (await setup([plain], { pin: [SIGNER] })).signer(SPACE, SIGNER)).toBeNull();
    expect(
      await (await setup([plain], { pin: [SIGNER], view: { ...VIEW, collections: [] } })).signer(SPACE, SIGNER),
    ).toBeNull();
    const granted: View = { ...VIEW, grants: [{ collection: 'c1', grantee: `user:${SIGNER}`, permission: 'edit' }] };
    expect(await (await setup([plain], { pin: [SIGNER], view: granted })).signer(SPACE, SIGNER)).toEqual(
      bundleOf(SIGNER),
    );
  });

  it('lets a failure to reach the member list through, as no verdict', async () => {
    const run = await setup([]);
    run.spaces.members.mockRejectedValueOnce(new Error('offline'));
    await expect(run.signer(SPACE, SIGNER)).rejects.toThrow('offline');
  });

  it('is nobody when no one is signed in', async () => {
    const run = await setup([member(SIGNER, 'confirmed')], { account: null, pin: [SIGNER] });
    expect(await run.signer(SPACE, SIGNER)).toBeNull();
    expect(run.chain).not.toHaveBeenCalled();
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
