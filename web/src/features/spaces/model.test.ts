// @vitest-environment node
import { describe, expect, it } from 'vitest';
import { ApiError } from '@/api/errors';
import type { MemberViewDto, ServedItemDto } from '@/api/spaces';
import type { ChainView } from '@/crypto/types';
import { decodeB64, encodeB64, fromUtf8 } from '@/lib/b64url';
import { checkedFingerprint, fingerprintText, fingerprintBytes } from '@/sharing/bundle';
import { memoryAnchorStore, memoryPinStore } from '@/spaces/anchors';
import { makeBundleB64 } from '@/test/bundles';
import { NO_CHAIN, fakeSpaceCrypto } from '@/test/fake-space-crypto';
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
  ChainConflict,
  type SpaceDeps,
  SpaceNotChecked,
  canManageUsers,
  changeRole,
  collectionsOfMember,
  confirmMember,
  createCollection,
  createGroup,
  createSpace,
  deleteCollection,
  deleteGroup,
  grantAccess,
  inviteMember,
  itemsToReseal,
  keysAwaitReplacement,
  loadSpaceDetail,
  loadSpaceList,
  offboardMember,
  pinMember,
  reachedBy,
  renameCollection,
  replaceKeys,
  resealItems,
  revokeGrant,
  sealPending,
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

// ---- a space with a chain ---------------------------------------------------------------------

const NEW_SPACE = '99999999-0000-4000-8000-000000000001';

/** What the worker reports once the chain verifies: Sam owns it, Lee is in Ops, Theo is invited. */
function chained(over: Partial<ChainView> = {}): ChainView {
  return {
    ...NO_CHAIN,
    chained: true,
    head: { seq: 4, link: 'bGluaw' },
    epoch: 1,
    links: ['l0', 'l1', 'l2', 'l3', 'l4'],
    trusted: true,
    members: [
      { id: ME, role: 'owner', custom: [], status: 'confirmed', invitedBy: ME, bundleVersion: 1 },
      { id: THEO, role: 'member', custom: [], status: 'invited', invitedBy: ME },
      { id: LEE, role: 'member', custom: [], status: 'confirmed', invitedBy: ME, bundleVersion: 1 },
    ],
    space: { keyVersion: 1, marked: false, nameHash: 'h', nameVersion: 1 },
    collections: [
      { id: INFRA, keyVersion: 1, marked: false, nameHash: 'h', nameVersion: 1 },
      { id: FINANCE, keyVersion: 1, marked: false, nameHash: 'h', nameVersion: 1 },
    ],
    groups: [{ id: OPS, members: [LEE], nameHash: 'h', nameVersion: 1 }],
    grants: [{ collection: INFRA, grantee: `group:${OPS}`, permission: 'edit' }],
    ...over,
  };
}

function chainedDeps(chain: ChainView = chained()) {
  const { api, crypto, spaceDeps } = deps();
  crypto.chain = chain;
  const anchors = memoryAnchorStore();
  const withChain: SpaceDeps = { ...spaceDeps, anchors, now: () => 1_700_000_000 };
  const loaded = detail({ trust: { kind: 'verified', view: chain } });
  return { api, crypto, anchors, spaceDeps: withChain, loaded };
}

describe('making a space', () => {
  it('makes a chain: the create record, the boxes and the names, signed and sealed here', async () => {
    const { spaceDeps, api, crypto } = chainedDeps(chained({ head: { seq: 0, link: 'bGluaw' } }));
    await createSpace(spaceDeps, { name: 'Example Co', firstCollection: 'Infrastructure' });
    expect(crypto.calls).toContain('newChainedSpace:1700000000');
    // Nothing is made the old way, where the server would hold an unchained space.
    expect(api.create).not.toHaveBeenCalled();
    expect(crypto.calls).not.toContain('newSpace');
    const [space, body] = api.appendChain.mock.calls[0] ?? [];
    expect(space).toBe(NEW_SPACE);
    expect(body?.records).toHaveLength(1);
    expect(body?.seals.map((s) => s.key)).toEqual([
      'collection:99999999-0000-4000-8000-000000000002',
      'space',
    ]);
    // The request carries exactly what the append route takes, and no key or plain name.
    expect(Object.keys(body ?? {}).sort()).toEqual(['names', 'records', 'seals']);
    expect(body?.names.map((n) => n.target)).toEqual([
      'collection:99999999-0000-4000-8000-000000000002',
      'space',
    ]);
    expect(JSON.stringify(body)).not.toContain('Example Co');
  });

  it('verifies the chain at once, which keeps this browser’s anchor', async () => {
    const { spaceDeps, anchors } = chainedDeps(chained({ head: { seq: 0, link: 'bGluaw' }, links: ['bGluaw'], epoch: 1 }));
    await createSpace(spaceDeps, { name: 'Example Co', firstCollection: 'Infrastructure' });
    expect(await anchors.load(ME, NEW_SPACE)).toEqual({ seq: 0, epoch: 1, links: ['bGluaw'] });
  });

  it('says so when what the server serves back isn’t verified as mine', async () => {
    const { spaceDeps, crypto } = chainedDeps();
    // The server serves no chain at all.
    crypto.chain = NO_CHAIN;
    await expect(
      createSpace(spaceDeps, { name: 'Example Co', firstCollection: 'Infrastructure' }),
    ).rejects.toBeInstanceOf(SpaceNotChecked);
  });
});

describe('changing a space that has a chain', () => {
  /** The one record the fake worker makes for a change, and the plain routes left alone. */
  function expectOnlyRecords(api: ReturnType<typeof chainedDeps>['api']) {
    expect(api.appendChain).toHaveBeenCalledTimes(1);
    const body = api.appendChain.mock.calls[0]?.[1];
    expect(body?.records).toHaveLength(1);
    for (const route of [
      'invite',
      'confirm',
      'changeRole',
      'revoke',
      'remove',
      'createCollection',
      'editCollection',
      'deleteCollection',
      'createGroup',
      'editGroup',
      'deleteGroup',
      'grant',
      'revokeGrant',
    ] as const) {
      expect(api[route], route).not.toHaveBeenCalled();
    }
  }

  it('invites the account the server looked up, as a record', async () => {
    const { spaceDeps, api, crypto, loaded } = chainedDeps();
    await inviteMember(
      spaceDeps,
      SPACE,
      {
        email: ' theo@example.co ',
        role: 'custom',
        custom: ['manage-groups'],
        grants: [{ collection: INFRA, permission: 'view' }],
      },
      loaded,
    );
    expect(api.lookup).toHaveBeenCalledWith(SPACE, 'theo@example.co');
    expect(crypto.changes).toEqual([
      {
        action: 'invite',
        member: THEO,
        role: 'custom',
        custom: ['manage-groups'],
        grants: [{ collection: INFRA, permission: 'view' }],
      },
    ]);
    expectOnlyRecords(api);
  });

  it('confirms with the fingerprint the person compared, as a record', async () => {
    const { spaceDeps, api, crypto, loaded } = chainedDeps();
    const theo = members().find((m) => m.user === THEO);
    if (!theo) throw new Error('fixture');
    const bundle = decodeB64(theo.publicBundle);
    const bytes = await fingerprintBytes(bundle);
    const fp = await checkedFingerprint(bundle, async () => fingerprintText(bytes));
    if (!fp) throw new Error('fixture');
    await confirmMember(spaceDeps, loaded, theo, fp);
    expect(crypto.changes).toEqual([
      {
        action: 'confirm',
        member: THEO,
        bundle: theo.publicBundle,
        bundleSignature: theo.bundleSignature,
        fingerprint: encodeB64(bytes),
      },
    ]);
    // No key is sealed by the page, and no statement is signed by it: the worker does both.
    expect(crypto.calls.some((c) => c.startsWith('seal') && !c.startsWith('sealLocal'))).toBe(false);
    expect(crypto.calls).not.toContain('sign:confirm');
    expectOnlyRecords(api);

    // A fingerprint of other keys than the bundle's still stops before anything is built.
    crypto.changes.length = 0;
    const other = await fingerprintBytes(decodeB64(makeBundleB64(THEO, 1, 0x55)));
    await expect(
      confirmMember(spaceDeps, loaded, theo, { text: fingerprintText(other), bytes: other, consistent: true }),
    ).rejects.toBeInstanceOf(MemberNotVerified);
    expect(crypto.changes).toEqual([]);
  });

  it('confirms a member’s newer keys again, from the bundle the server lists, as a record', async () => {
    const { spaceDeps, crypto, loaded } = chainedDeps();
    const newer = makeBundleB64(LEE, 2);
    const lee = memberView(LEE, 'lee@example.co', {
      publicBundle: newer,
      userKeyVersion: 2,
      needsReconfirmation: true,
    });
    const bytes = await fingerprintBytes(decodeB64(newer));
    await confirmMember(spaceDeps, loaded, lee, {
      text: fingerprintText(bytes),
      bytes,
      consistent: true,
    });
    expect(crypto.changes).toEqual([
      {
        action: 'confirm',
        member: LEE,
        bundle: newer,
        bundleSignature: lee.bundleSignature,
        fingerprint: encodeB64(bytes),
      },
    ]);
  });

  it('makes collections, groups and grants as records', async () => {
    const { spaceDeps, api, crypto, loaded } = chainedDeps();
    await createCollection(spaceDeps, loaded, { name: 'Support', parent: INFRA });
    await renameCollection(spaceDeps, loaded, INFRA, 'Ops infra');
    await deleteCollection(spaceDeps, loaded, FINANCE);
    await createGroup(spaceDeps, loaded, { name: 'Eng', members: [LEE] });
    await deleteGroup(spaceDeps, loaded, OPS);
    await grantAccess(spaceDeps, loaded, { collection: FINANCE, grantee: `user:${LEE}`, permission: 'view' });
    await revokeGrant(spaceDeps, loaded, INFRA, `group:${OPS}`);
    await changeRole(spaceDeps, loaded, LEE, 'admin', ['manage-users']);
    expect(crypto.changes).toEqual([
      { action: 'collection', collection: '99999999-0000-4000-8000-000000000001', name: 'Support', parent: INFRA },
      { action: 'rename', target: `collection:${INFRA}`, name: 'Ops infra' },
      { action: 'collection-delete', collection: FINANCE },
      { action: 'group', group: '99999999-0000-4000-8000-000000000002', name: 'Eng', members: [LEE] },
      { action: 'group-delete', group: OPS },
      { action: 'grant', collection: FINANCE, grantee: `user:${LEE}`, permission: 'view' },
      { action: 'ungrant', collection: INFRA, grantee: `group:${OPS}` },
      // Custom permissions go only with the custom role.
      { action: 'role', member: LEE, role: 'admin', custom: [] },
    ]);
    expect(api.appendChain).toHaveBeenCalledTimes(8);
    expect(api.createCollection).not.toHaveBeenCalled();
    expect(api.editCollection).not.toHaveBeenCalled();
    expect(api.grant).not.toHaveBeenCalled();
    expect(api.revokeGrant).not.toHaveBeenCalled();
  });

  it('changes a group by who it adds and who it drops, and does nothing when nothing changes', async () => {
    const { spaceDeps, api, crypto, loaded } = chainedDeps();
    await setGroupMembers(spaceDeps, loaded, OPS, [ME]);
    expect(crypto.changes).toEqual([{ action: 'group-members', group: OPS, add: [ME], remove: [LEE] }]);
    expect(await setGroupMembers(spaceDeps, loaded, OPS, [LEE])).toBe(false);
    expect(api.appendChain).toHaveBeenCalledTimes(1);
    expect(api.editGroup).not.toHaveBeenCalled();
  });

  it('removes a member as one record, and says whether keys now wait to be replaced', async () => {
    const marked = chained({ space: { keyVersion: 1, marked: true, nameHash: 'h', nameVersion: 1 } });
    const { spaceDeps, api, crypto, loaded } = chainedDeps(marked);
    const outcome = await offboardMember(spaceDeps, loaded, LEE, 'revoke');
    expect(crypto.changes).toEqual([{ action: 'remove', member: LEE }]);
    expect(outcome).toEqual({ exposed: [], keysPending: true });
    expect(api.revoke).not.toHaveBeenCalled();
    expect(api.remove).not.toHaveBeenCalled();
    // Removing and revoking are the same record in a space with a chain.
    await offboardMember(spaceDeps, loaded, LEE, 'remove');
    expect(crypto.changes.map((c) => c.action)).toEqual(['remove', 'remove']);
  });

  it('shows the reason when the chain’s rules refuse the change, and appends nothing', async () => {
    const { spaceDeps, api, crypto, loaded } = chainedDeps();
    crypto.built = { ok: false, reason: 'not allowed', seq: 5 };
    await expect(createCollection(spaceDeps, loaded, { name: 'Support' })).rejects.toMatchObject({
      name: 'ChainRefused',
      reason: 'not allowed',
    });
    expect(api.appendChain).not.toHaveBeenCalled();
  });

  it('reads the chain again and builds once more when the head moved, then shows a second conflict', async () => {
    const { spaceDeps, api, crypto, loaded } = chainedDeps();
    const conflict = () =>
      new ApiError(409, {
        type: 'urn:kemlock:problem:space-chain-conflict',
        title: 'The chain’s head isn’t the one the records follow',
        status: 409,
      });
    api.appendChain.mockRejectedValueOnce(conflict());
    await createGroup(spaceDeps, loaded, { name: 'Eng', members: [] });
    expect(crypto.changes).toHaveLength(2);
    expect(api.appendChain).toHaveBeenCalledTimes(2);
    expect(crypto.calls.filter((c) => c.startsWith('verifySpaceChain'))).toHaveLength(1);

    crypto.changes.length = 0;
    api.appendChain.mockRejectedValue(conflict());
    await expect(createGroup(spaceDeps, loaded, { name: 'Eng', members: [] })).rejects.toBeInstanceOf(
      ChainConflict,
    );
    expect(crypto.changes).toHaveLength(2);
    // Another failure is not read as a conflict.
    api.appendChain.mockRejectedValue(new ApiError(500, { type: 'x', title: 'x', status: 500 }));
    await expect(createGroup(spaceDeps, loaded, { name: 'Eng', members: [] })).rejects.toBeInstanceOf(ApiError);
  });

  it('signs nothing for a space that isn’t checked or whose keys aren’t open', async () => {
    const { spaceDeps, api, crypto, loaded } = chainedDeps();
    const waiting = { ...loaded, trust: { kind: 'first-contact' as const, view: chained({ trusted: false }) } };
    const closed = { ...loaded, readable: false };
    for (const space of [waiting, closed]) {
      await expect(createCollection(spaceDeps, space, { name: 'Support' })).rejects.toBeInstanceOf(
        SpaceNotChecked,
      );
      await expect(grantAccess(spaceDeps, space, { collection: INFRA, grantee: `user:${ME}`, permission: 'view' })).rejects.toBeInstanceOf(
        SpaceNotChecked,
      );
      await expect(offboardMember(spaceDeps, space, LEE, 'remove')).rejects.toBeInstanceOf(SpaceNotChecked);
    }
    expect(crypto.changes).toEqual([]);
    expect(api.appendChain).not.toHaveBeenCalled();
  });

  it('shares keys it holds only when there is something to share', async () => {
    const { spaceDeps, api, crypto, loaded } = chainedDeps();
    // The worker has nothing for anyone: no record is made.
    expect(await sealPending(spaceDeps, loaded)).toBe(false);
    expect(crypto.changes).toEqual([{ action: 'seal' }]);
    expect(api.appendChain).not.toHaveBeenCalled();
    crypto.built = { ok: true, records: [{ entry: 'ZW50cnk', signature: 'c2ln' }], seals: [], names: [] };
    expect(await sealPending(spaceDeps, loaded)).toBe(true);
    expect(api.appendChain).toHaveBeenCalledTimes(1);
    // A space with no chain, or one that isn't checked, is left alone.
    expect(await sealPending(spaceDeps, detail())).toBe(false);
  });
});

describe('replacing the keys of a space that has a chain', () => {
  /** An item as the server serves it. */
  function served(id: string, collection: string, over: Partial<ServedItemDto> = {}): ServedItemDto {
    return {
      id,
      owner: `space:${SPACE}`,
      kind: 'login',
      format: 'kem1' as const,
      revision: 1,
      keyVersion: 1,
      ciphertext: 'Y2lwaGVy',
      itemKey: 'a2V5',
      deleted: false,
      collectionId: collection,
      ...over,
    };
  }

  const MARKED = chained({
    space: { keyVersion: 1, marked: true, nameHash: 'h', nameVersion: 1 },
    collections: [
      { id: INFRA, keyVersion: 1, marked: true, nameHash: 'h', nameVersion: 1 },
      { id: FINANCE, keyVersion: 1, marked: false, nameHash: 'h', nameVersion: 1 },
    ],
  });
  const ITEM = '50000000-0000-4000-8000-000000000001';

  it('knows when keys wait: the chain says so, not the server’s flags', () => {
    expect(keysAwaitReplacement(detail({ trust: { kind: 'verified', view: MARKED } }))).toBe(true);
    expect(keysAwaitReplacement(detail({ trust: { kind: 'verified', view: chained() } }))).toBe(false);
    expect(keysAwaitReplacement(detail())).toBe(false);
  });

  it('gives the worker the live items of the marked collections and every name, and sends what it makes', async () => {
    const { spaceDeps, api, crypto } = chainedDeps(MARKED);
    const loaded = detail({ trust: { kind: 'verified', view: MARKED } });
    api.sync.mockResolvedValueOnce({
      cursor: 'c1',
      more: true,
      items: [
        served(ITEM, INFRA),
        // Not of a marked collection, held already, a tombstone, another owner's: none is given.
        served('50000000-0000-4000-8000-000000000002', FINANCE),
        served('50000000-0000-4000-8000-000000000003', INFRA, { held: true }),
      ],
    });
    api.sync.mockResolvedValueOnce({
      cursor: 'c2',
      more: false,
      items: [
        served('50000000-0000-4000-8000-000000000004', INFRA, { deleted: true, ciphertext: null, itemKey: null }),
        served('50000000-0000-4000-8000-000000000005', INFRA, { owner: `user:${ME}` }),
      ],
    });
    const phases: string[] = [];
    const result = await replaceKeys(spaceDeps, loaded, (p) => phases.push(p.phase));

    expect(api.sync.mock.calls.map((c) => c[0])).toEqual([undefined, 'c1']);
    const given = crypto.replacements[0];
    expect(given?.items.map((i) => i.id)).toEqual([ITEM]);
    expect(given?.items[0]).toMatchObject({ collection: INFRA, revision: 1, keyVersion: 1 });
    expect(given?.names.map((n) => n.target)).toEqual([
      'space',
      `collection:${INFRA}`,
      `collection:${FINANCE}`,
      `group:${OPS}`,
    ]);
    // The record and the item sealed again go up in one request, as the next revision.
    expect(api.appendChain).toHaveBeenCalledTimes(1);
    const body = api.appendChain.mock.calls[0]?.[1];
    expect(body?.records).toHaveLength(1);
    expect(body?.writes?.map((w) => [w.collection, w.expectedRevision, w.item.revision, w.item.keyVersion])).toEqual([
      [INFRA, 1, 2, 2],
    ]);
    expect(body?.held).toBeUndefined();
    expect(api.putBatch).not.toHaveBeenCalled();
    expect(result).toEqual({ rewritten: 1, held: 0 });
    expect(phases).toContain('reading');
    expect(phases).toContain('sealing');
    expect(phases).toContain('sending');
  });

  it('names the items the worker could not seal again as held', async () => {
    const { spaceDeps, api, crypto } = chainedDeps(MARKED);
    const loaded = detail({ trust: { kind: 'verified', view: MARKED } });
    api.sync.mockResolvedValueOnce({ cursor: 'c', more: false, items: [served(ITEM, INFRA)] });
    crypto.replaced = { ok: true, records: [{ entry: 'ZW50cnk', signature: 'c2ln' }], seals: [], names: [], held: [ITEM] };
    expect(await replaceKeys(spaceDeps, loaded)).toEqual({ rewritten: 0, held: 1 });
    const body = api.appendChain.mock.calls[0]?.[1];
    expect(body?.held).toEqual([ITEM]);
    expect(body?.writes).toBeUndefined();
  });

  it('sends what does not fit in the request in batches after it, and says how far it is', async () => {
    const { spaceDeps, api, crypto } = chainedDeps(MARKED);
    const loaded = detail({ trust: { kind: 'verified', view: MARKED } });
    api.sync.mockResolvedValueOnce({ cursor: 'c', more: false, items: [served(ITEM, INFRA)] });
    const big = (n: number) => ({
      collection: INFRA,
      expectedRevision: 1,
      item: { ...served(`50000000-0000-4000-8000-00000000010${n}`, INFRA, { revision: 2, keyVersion: 2, ciphertext: 'A'.repeat(3 * 1024 * 1024) }) } as never,
    });
    crypto.replaced = {
      ok: true,
      records: [{ entry: 'ZW50cnk', signature: 'c2ln' }],
      seals: [],
      names: [],
      writes: [big(1), big(2), big(3)],
    };
    const sent: Array<[number, number]> = [];
    const result = await replaceKeys(spaceDeps, loaded, (p) => {
      if (p.phase === 'sending') sent.push([p.done, p.total]);
    });
    // One item fits beside the record, the other two follow in a batch, and are named held in the
    // request so the replacement is complete: their write under the new version releases them.
    const request = api.appendChain.mock.calls[0]?.[1];
    expect(request?.writes).toHaveLength(1);
    expect(request?.held).toEqual([
      '50000000-0000-4000-8000-000000000102',
      '50000000-0000-4000-8000-000000000103',
    ]);
    expect(api.putBatch).toHaveBeenCalledTimes(1);
    expect(api.putBatch.mock.calls[0]?.[0].writes.map((w) => w.expectedRevision)).toEqual([1, 1]);
    expect(sent).toEqual([
      [1, 3],
      [3, 3],
    ]);
    expect(result).toEqual({ rewritten: 3, held: 0 });
  });

  it('lists what it wrote in the signed manifest, the item in the request and the ones in batches', async () => {
    const { spaceDeps, api, crypto } = chainedDeps(MARKED);
    const listed: string[][] = [];
    const withKeeper = { ...spaceDeps, wrote: async (items: Array<{ id: string }>) => void listed.push(items.map((i) => i.id)) };
    const loaded = detail({ trust: { kind: 'verified', view: MARKED } });
    api.sync.mockResolvedValueOnce({ cursor: 'c', more: false, items: [served(ITEM, INFRA)] });
    await replaceKeys(withKeeper, loaded);
    expect(listed).toEqual([[ITEM]]);
    expect(crypto.replacements).toHaveLength(1);
    // A keeper that fails never fails the replacement.
    api.sync.mockResolvedValueOnce({ cursor: 'c', more: false, items: [served(ITEM, INFRA)] });
    const broken = { ...spaceDeps, wrote: () => Promise.reject(new Error('no')) };
    await expect(replaceKeys(broken, loaded)).resolves.toEqual({ rewritten: 1, held: 0 });
  });

  it('shows the reason when the chain’s rules refuse the replacement, and sends nothing', async () => {
    const { spaceDeps, api, crypto } = chainedDeps(MARKED);
    const loaded = detail({ trust: { kind: 'verified', view: MARKED } });
    crypto.replaced = { ok: false, reason: 'not allowed', seq: 6 };
    await expect(replaceKeys(spaceDeps, loaded)).rejects.toMatchObject({ name: 'ChainRefused' });
    expect(api.appendChain).not.toHaveBeenCalled();
  });

  it('does nothing for a space with no keys waiting or no chain', async () => {
    const { spaceDeps, api, crypto } = chainedDeps();
    expect(await replaceKeys(spaceDeps, detail({ trust: { kind: 'verified', view: chained() } }))).toEqual({
      rewritten: 0,
      held: 0,
    });
    expect(await replaceKeys(spaceDeps, detail())).toEqual({ rewritten: 0, held: 0 });
    expect(api.sync).not.toHaveBeenCalled();
    expect(crypto.replacements).toEqual([]);
  });
});

describe('sealing again what a replacement left under an old key', () => {
  const REPLACED = chained({
    collections: [
      { id: INFRA, keyVersion: 2, marked: false, nameHash: 'h', nameVersion: 1 },
      { id: FINANCE, keyVersion: 1, marked: false, nameHash: 'h', nameVersion: 1 },
    ],
  });
  const item = (n: number, collection: string, keyVersion: number, over: Partial<ServedItemDto> = {}): ServedItemDto => ({
    id: `50000000-0000-4000-8000-00000000020${n}`,
    owner: `space:${SPACE}`,
    kind: 'login',
    format: 'kem1',
    revision: 1,
    keyVersion,
    ciphertext: 'Y2lwaGVy',
    itemKey: 'a2V5',
    deleted: false,
    collectionId: collection,
    ...over,
  });

  it('finds, from the server, the live items under a version older than their collection\'s', async () => {
    const { spaceDeps, api, loaded } = chainedDeps(REPLACED);
    api.sync.mockResolvedValueOnce({
      cursor: 'c',
      more: false,
      items: [
        item(1, INFRA, 1),
        // Held ones are found too: a write under the current version releases them.
        item(2, INFRA, 1, { held: true }),
        // Current, of a collection never replaced, deleted, another owner's: not found.
        item(3, INFRA, 2),
        item(4, FINANCE, 1),
        item(5, INFRA, 1, { deleted: true, ciphertext: null, itemKey: null }),
        item(6, INFRA, 1, { owner: `user:${ME}` }),
      ],
    });
    const found = await itemsToReseal(spaceDeps, loaded);
    expect(found.map((i) => i.id)).toEqual([
      '50000000-0000-4000-8000-000000000201',
      '50000000-0000-4000-8000-000000000202',
    ]);
    // A space whose keys were never replaced is not read at all.
    api.sync.mockClear();
    expect(await itemsToReseal(spaceDeps, detail({ trust: { kind: 'verified', view: chained() } }))).toEqual([]);
    expect(api.sync).not.toHaveBeenCalled();
  });

  it('seals them again in the worker and writes them in batches, listing them in the manifest', async () => {
    const { spaceDeps, api, crypto } = chainedDeps(REPLACED);
    const loaded = detail({ trust: { kind: 'verified', view: REPLACED } });
    const listed: string[][] = [];
    const withKeeper = { ...spaceDeps, wrote: async (items: Array<{ id: string }>) => void listed.push(items.map((i) => i.id)) };
    api.sync.mockResolvedValueOnce({ cursor: 'c', more: false, items: [item(1, INFRA, 1), item(2, INFRA, 1)] });
    const phases: Array<[string, number, number]> = [];
    const result = await resealItems(withKeeper, loaded, (p) => phases.push([p.phase, p.done, p.total]));
    expect(crypto.resealings[0]?.map((i) => i.id)).toEqual([
      '50000000-0000-4000-8000-000000000201',
      '50000000-0000-4000-8000-000000000202',
    ]);
    expect(api.putBatch).toHaveBeenCalledTimes(1);
    expect(api.putBatch.mock.calls[0]?.[0].writes.map((w) => [w.expectedRevision, w.item.revision, w.item.keyVersion])).toEqual([
      [1, 2, 2],
      [1, 2, 2],
    ]);
    expect(api.appendChain).not.toHaveBeenCalled();
    expect(listed).toEqual([['50000000-0000-4000-8000-000000000201', '50000000-0000-4000-8000-000000000202']]);
    expect(result).toEqual({ rewritten: 2, stuck: 0 });
    expect(phases.at(-1)).toEqual(['sending', 2, 2]);
  });

  it('counts the items this browser can not seal again, and writes the rest', async () => {
    const { spaceDeps, api, crypto } = chainedDeps(REPLACED);
    const loaded = detail({ trust: { kind: 'verified', view: REPLACED } });
    api.sync.mockResolvedValueOnce({ cursor: 'c', more: false, items: [item(1, INFRA, 1), item(2, INFRA, 1)] });
    crypto.resealed = { ok: true, records: [], seals: [], names: [], held: ['50000000-0000-4000-8000-000000000202'], writes: [] };
    expect(await resealItems(spaceDeps, loaded)).toEqual({ rewritten: 0, stuck: 1 });
    expect(api.putBatch).not.toHaveBeenCalled();
  });

  it('does nothing when no item is under an old key, or the space has no chain', async () => {
    const { spaceDeps, api, crypto } = chainedDeps(REPLACED);
    api.sync.mockResolvedValueOnce({ cursor: 'c', more: false, items: [item(3, INFRA, 2)] });
    expect(await resealItems(spaceDeps, detail({ trust: { kind: 'verified', view: REPLACED } }))).toEqual({
      rewritten: 0,
      stuck: 0,
    });
    expect(await resealItems(spaceDeps, detail())).toEqual({ rewritten: 0, stuck: 0 });
    expect(crypto.resealings).toEqual([]);
  });
});
