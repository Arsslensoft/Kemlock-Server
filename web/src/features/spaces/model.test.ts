// @vitest-environment node
import { describe, expect, it } from 'vitest';
import type { MemberViewDto } from '@/api/spaces';
import { decodeB64, fromUtf8 } from '@/lib/b64url';
import { checkedFingerprint, fingerprintText, fingerprintBytes } from '@/sharing/bundle';
import { memoryPinStore } from '@/spaces/anchors';
import { makeBundleB64 } from '@/test/bundles';
import { fakeSpaceCrypto } from '@/test/fake-space-crypto';
import {
  FINANCE,
  INFRA,
  LEE,
  ME,
  OPS,
  SPACE,
  THEO,
  confirmedMembers,
  detail,
  fakeSpacesApi,
  fingerprintTextOf,
  memberView,
  members,
} from './fixtures';
import {
  type SpaceDeps,
  canManageUsers,
  collectionsOfMember,
  confirmMember,
  createCollection,
  createSpace,
  grantAccess,
  inviteMember,
  loadSpaceDetail,
  loadSpaceList,
  pinMember,
  reachedBy,
  renameCollection,
  setGroupMembers,
} from './model';
import { MemberNotVerified } from './verify';

function deps() {
  const api = fakeSpacesApi();
  const crypto = fakeSpaceCrypto();
  let n = 0;
  const spaceDeps: SpaceDeps = {
    api,
    crypto,
    newId: () => `99999999-0000-4000-8000-${String(++n).padStart(12, '0')}`,
  };
  return { api, crypto, spaceDeps };
}

describe('who reaches a collection', () => {
  const { view } = detail();
  it('counts direct grants and group members', () => {
    expect([...reachedBy(INFRA, view.grants, view.groups)]).toEqual([LEE]);
    expect([...reachedBy(FINANCE, view.grants, view.groups)]).toEqual([THEO]);
  });

  it('lists the collections of one member', () => {
    expect(collectionsOfMember(LEE, view.collections, view.grants, view.groups)).toEqual([INFRA]);
    expect(collectionsOfMember(ME, view.collections, view.grants, view.groups)).toEqual([]);
  });

  it('lets owners, admins and custom managers manage members', () => {
    expect(canManageUsers({ role: 'owner', custom: [] })).toBe(true);
    expect(canManageUsers({ role: 'custom', custom: ['manage-users'] })).toBe(true);
    expect(canManageUsers({ role: 'custom', custom: ['manage-groups'] })).toBe(false);
    expect(canManageUsers({ role: 'member', custom: [] })).toBe(false);
  });
});

describe('the space list', () => {
  it('opens the name of each space it holds the key to', async () => {
    const { spaceDeps, crypto } = deps();
    const rows = await loadSpaceList(spaceDeps);
    expect(rows).toEqual([
      { id: SPACE, name: 'Example Co', role: 'owner', state: 'confirmed', keysPending: false },
    ]);
    expect(crypto.calls).toContain(`openSpace:${SPACE}`);
  });

  it('leaves the name closed when no key was sealed to me', async () => {
    const { spaceDeps, api } = deps();
    const summary = (await api.list())[0];
    if (!summary) throw new Error('fixture');
    api.list.mockResolvedValueOnce([{ ...summary, member: { ...summary.member, sealedSpaceKey: null } }]);
    expect((await loadSpaceList(spaceDeps))[0]?.name).toBeNull();
  });
});

describe('making a space', () => {
  it('seals both names and keys here and sends only ciphertext', async () => {
    const { spaceDeps, api } = deps();
    await createSpace(spaceDeps, { name: 'Example Co', firstCollection: 'Infrastructure' });
    const body = api.create.mock.calls[0]?.[0];
    expect(body?.id).toBe('99999999-0000-4000-8000-000000000001');
    expect(body?.collection.id).toBe('99999999-0000-4000-8000-000000000002');
    expect(fromUtf8(decodeB64(body?.sealedSpaceKey ?? ''))).toBe(`space-key:${body?.id}`);
    // Each box goes with the maker's signature over it.
    expect(fromUtf8(decodeB64(body?.sealedSpaceKeySignature ?? ''))).toBe(`space-key-signature:${body?.id}`);
    expect(fromUtf8(decodeB64(body?.collection.sealedKeySignature ?? ''))).toBe(
      `collection-key-signature:${body?.collection.id}`,
    );
    expect(body?.name).not.toContain('Example');
    expect(fromUtf8(decodeB64(body?.name ?? ''))).toContain('Example Co');
  });
});

describe('reading one space', () => {
  it('opens the space key, every collection key and each name', async () => {
    const { spaceDeps, crypto } = deps();
    const loaded = await loadSpaceDetail(spaceDeps, SPACE);
    expect(loaded.readable).toBe(true);
    expect(loaded.name).toBe('Example Co');
    expect(loaded.collections.map((c) => c.title)).toEqual(['Infrastructure', 'Finance']);
    expect(loaded.groups.map((g) => g.title)).toEqual(['Ops']);
    expect(crypto.calls).toContain(`openCollection:${INFRA}`);
  });

  it('is not readable, with no names, when the key can not be opened', async () => {
    const { spaceDeps, crypto } = deps();
    crypto.openSpace = () => Promise.reject(new Error('no'));
    const loaded = await loadSpaceDetail(spaceDeps, SPACE);
    expect(loaded.readable).toBe(false);
    expect(loaded.name).toBeNull();
    expect(loaded.collections[0]?.title).toBeNull();
  });
});

describe('confirming a member', () => {
  async function fingerprintOf(user: string) {
    const bundle = decodeB64(memberView(user, 'x@example.co').publicBundle);
    const bytes = await fingerprintBytes(bundle);
    return checkedFingerprint(bundle, async () => fingerprintText(bytes));
  }

  it('seals the space key and the granted collections, then sends the signed statement', async () => {
    const { spaceDeps, api, crypto } = deps();
    const fp = await fingerprintOf(THEO);
    if (!fp) throw new Error('fixture');
    const theo = members().find((m) => m.user === THEO);
    if (!theo) throw new Error('fixture');
    await confirmMember(spaceDeps, detail(), theo, fp);
    const [space, user, body] = api.confirm.mock.calls[0] ?? [];
    expect(space).toBe(SPACE);
    expect(user).toBe(THEO);
    expect(body?.collectionKeys.map((k) => k.collection)).toEqual([FINANCE]);
    expect(decodeB64(body?.fingerprint ?? '')).toHaveLength(64);
    // Every key sealed to the member is signed by the confirmer, who verifies as the sealer.
    expect(decodeB64(body?.sealedSpaceKeySignature ?? '').length).toBeGreaterThan(0);
    expect(body?.collectionKeys.every((k) => k.signature.length > 0)).toBe(true);
    // The worker builds the statement and signs it under the one context it signs.
    const statement = JSON.parse(fromUtf8(decodeB64(body?.statement ?? ''))) as string[];
    expect(statement[2]).toBe(THEO);
    expect(crypto.calls).toContain('confirmationStatement');
    expect(crypto.calls).toContain('sign:confirm');
    expect(crypto.calls).toContain(`sealCollectionKeyTo:${FINANCE}`);
  });

  it('refuses a fingerprint the two ways of working it out disagree on', async () => {
    const { spaceDeps, api } = deps();
    const fp = await fingerprintOf(THEO);
    if (!fp) throw new Error('fixture');
    const theo = members().find((m) => m.user === THEO);
    if (!theo) throw new Error('fixture');
    await expect(confirmMember(spaceDeps, detail(), theo, { ...fp, consistent: false })).rejects.toThrow();
    expect(api.confirm).not.toHaveBeenCalled();
  });

  it('seals nothing to a bundle that is another account’s', async () => {
    const { spaceDeps, api, crypto } = deps();
    const fp = await fingerprintOf(THEO);
    if (!fp) throw new Error('fixture');
    // Theo's entry carries Lee's bundle: the fingerprint on screen is of Lee's keys.
    const theo = memberView(THEO, 'theo@example.co', { state: 'accepted', publicBundle: memberView(LEE, 'x').publicBundle });
    const lees = await fingerprintBytes(decodeB64(theo.publicBundle));
    await expect(
      confirmMember(spaceDeps, detail(), theo, { ...fp, bytes: lees, text: fingerprintText(lees) }),
    ).rejects.toMatchObject({ reason: 'wrong-account' });
    expect(api.confirm).not.toHaveBeenCalled();
    expect(crypto.calls.some((c) => c.startsWith('seal'))).toBe(false);
  });

  it('seals nothing when the bundle changed after the fingerprint was shown', async () => {
    const { spaceDeps, api } = deps();
    const fp = await fingerprintOf(THEO);
    if (!fp) throw new Error('fixture');
    const theo = memberView(THEO, 'theo@example.co', { state: 'accepted', publicBundle: makeBundleB64(THEO, 1, 0x55) });
    await expect(confirmMember(spaceDeps, detail(), theo, fp)).rejects.toMatchObject({
      reason: 'confirmation-differs',
    });
    expect(api.confirm).not.toHaveBeenCalled();
  });

  it('seals nothing to a bundle at another key version than the member’s', async () => {
    const { spaceDeps, api } = deps();
    const theo = memberView(THEO, 'theo@example.co', {
      state: 'accepted',
      publicBundle: makeBundleB64(THEO, 2),
      userKeyVersion: 1,
    });
    const bytes = await fingerprintBytes(decodeB64(theo.publicBundle));
    await expect(
      confirmMember(spaceDeps, detail(), theo, { bytes, text: fingerprintText(bytes), consistent: true }),
    ).rejects.toMatchObject({ reason: 'wrong-key-version' });
    expect(api.confirm).not.toHaveBeenCalled();
  });

});

/** A detail whose members can be sealed to: Lee's confirmation is mine, and my own keys are mine. */
async function sealable() {
  const crypto = fakeSpaceCrypto();
  const roster = await confirmedMembers();
  crypto.ownFingerprintText = await fingerprintTextOf(roster[0] as MemberViewDto);
  return { crypto, loaded: detail({ members: roster }) };
}

describe('pinning a member', () => {
  async function shown(user: string, fill = 0x11) {
    const bundle = decodeB64(memberView(user, 'x@example.co', { publicBundle: makeBundleB64(user, 1, fill) }).publicBundle);
    const bytes = await fingerprintBytes(bundle);
    return { text: fingerprintText(bytes), bytes, consistent: true };
  }

  it('keeps the fingerprint a person compared, and nothing else', async () => {
    const { spaceDeps } = deps();
    const pins = memoryPinStore();
    const lee = memberView(LEE, 'lee@example.co');
    await pinMember({ ...spaceDeps, pins }, ME, lee, await shown(LEE));
    expect(await pins.load(ME, LEE)).toBe((await shown(LEE)).text);
    // The fingerprint on screen must be of the bundle listed now, and worked out the same twice.
    await expect(pinMember({ ...spaceDeps, pins }, ME, lee, await shown(LEE, 0x44))).rejects.toBeInstanceOf(
      MemberNotVerified,
    );
    await expect(
      pinMember({ ...spaceDeps, pins }, ME, lee, { ...(await shown(LEE)), consistent: false }),
    ).rejects.toThrow();
  });

  it('lists the confirmed members it can not trace, and who to compare', async () => {
    const { spaceDeps, crypto } = deps();
    crypto.ownFingerprintText = await fingerprintTextOf(memberView(ME, 'sam@example.co'));
    const loaded = await loadSpaceDetail(spaceDeps, SPACE);
    // Lee has no confirmation: comparing Lee's own fingerprint puts it right.
    expect(loaded.unverified).toEqual([{ user: LEE, compare: LEE }]);
    const pins = memoryPinStore();
    await pinMember({ ...spaceDeps, pins }, ME, memberView(LEE, 'lee@example.co'), await shown(LEE));
    expect((await loadSpaceDetail({ ...spaceDeps, pins }, SPACE)).unverified).toBeUndefined();
  });
});

describe('collections, groups and grants', () => {
  it('invites with the custom permissions only for the custom role', async () => {
    const { spaceDeps, api } = deps();
    await inviteMember(spaceDeps, SPACE, {
      email: ' ana@example.co ',
      role: 'member',
      custom: ['manage-users'],
      grants: [{ collection: INFRA, permission: 'view' }],
    });
    expect(api.invite).toHaveBeenCalledWith(SPACE, {
      email: 'ana@example.co',
      role: 'member',
      custom: [],
      grants: [{ collection: INFRA, permission: 'view' }],
    });
  });

  it('makes a collection with its key sealed to its maker', async () => {
    const { spaceDeps, api } = deps();
    await createCollection(spaceDeps, detail(), { name: 'Support' });
    const body = api.createCollection.mock.calls[0]?.[1];
    expect(body?.keys?.map((k) => k.user)).toEqual([ME]);
    expect(body?.parent).toBeNull();
  });

  it('renames a collection under the space key', async () => {
    const { spaceDeps, api } = deps();
    await renameCollection(spaceDeps, detail(), INFRA, 'Ops infra');
    const body = api.editCollection.mock.calls[0]?.[2];
    expect(fromUtf8(decodeB64(body?.name ?? ''))).toContain('Ops infra');
  });

  it('seals a collection key only to confirmed members a grant newly reaches', async () => {
    const { spaceDeps, api } = deps();
    const { crypto, loaded } = await sealable();
    const withCrypto = { ...spaceDeps, crypto };
    // Lee already reaches Infrastructure through Ops; Theo (not confirmed) and Sam are new.
    await grantAccess(withCrypto, loaded, { collection: INFRA, grantee: `user:${THEO}`, permission: 'view' });
    expect(api.grant.mock.calls[0]?.[1].keys).toEqual([]);
    await grantAccess(withCrypto, loaded, { collection: INFRA, grantee: `user:${ME}`, permission: 'manage' });
    expect(api.grant.mock.calls[1]?.[1].keys?.map((k) => k.user)).toEqual([ME]);
  });

  it('seals the keys of a group’s collections to the members it adds', async () => {
    const { spaceDeps, api } = deps();
    const { crypto, loaded } = await sealable();
    await setGroupMembers({ ...spaceDeps, crypto }, loaded, OPS, [LEE, ME]);
    const body = api.editGroup.mock.calls[0]?.[2];
    expect(body?.keys?.map((k) => [k.collection, k.user])).toEqual([[INFRA, ME]]);
    expect(body?.members).toEqual([LEE, ME]);
  });

  it('seals nothing to a member whose listed keys are not the ones confirmed', async () => {
    const { spaceDeps, api } = deps();
    // The server lists a bundle of its own for Lee, under Lee's id, with Lee's old confirmation.
    const { crypto, loaded } = await sealable();
    const swapped = loaded.members.map((m) =>
      m.user === LEE ? { ...m, publicBundle: makeBundleB64(LEE, 1, 0x77) } : m,
    );
    const grant = grantAccess({ ...spaceDeps, crypto }, { ...loaded, members: swapped }, {
      collection: FINANCE,
      grantee: `user:${LEE}`,
      permission: 'view',
    });
    await expect(grant).rejects.toBeInstanceOf(MemberNotVerified);
    await expect(grant).rejects.toMatchObject({ reason: 'confirmation-differs' });
    expect(crypto.calls.some((c) => c.startsWith('sealCollectionKeyTo'))).toBe(false);
    expect(api.grant).not.toHaveBeenCalled();
  });

  it('seals nothing when a group change would add a member nobody confirmed', async () => {
    const { spaceDeps, api } = deps();
    const { crypto, loaded } = await sealable();
    const unconfirmed = loaded.members.map((m) => (m.user === LEE ? { ...m, confirmation: null } : m));
    await expect(
      setGroupMembers({ ...spaceDeps, crypto }, { ...loaded, members: unconfirmed }, OPS, [ME, LEE, THEO]),
    ).resolves.toBeDefined();
    // Lee was already in the group, Theo isn't confirmed, and I am me: nothing new to check for Lee.
    expect(api.editGroup).toHaveBeenCalledTimes(1);
    api.editGroup.mockClear();
    const other = unconfirmed.map((m) => (m.user === THEO ? { ...m, state: 'confirmed' as const } : m));
    await expect(
      setGroupMembers({ ...spaceDeps, crypto }, { ...loaded, members: other }, OPS, [LEE, THEO]),
    ).rejects.toMatchObject({ reason: 'no-confirmation' });
    expect(api.editGroup).not.toHaveBeenCalled();
  });
});
