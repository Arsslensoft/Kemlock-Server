// @vitest-environment node
import { describe, expect, it, vi } from 'vitest';
import { ApiError } from '@/api/errors';
import { writeFields } from '@/api/signedWrites';
import type { MemberViewDto, ServedItemDto } from '@/api/spaces';
import type { ChainView } from '@/crypto/types';
import { decodeB64, encodeB64, fromUtf8, utf8 } from '@/lib/b64url';
import { type Manifest, ciphertextHash } from '@/manifest/format';
import { checkedFingerprint, fingerprintText, fingerprintBytes, uuidBytes } from '@/sharing/bundle';
import { memoryAnchorStore, memoryPinStore } from '@/spaces/anchors';
import { makeBundleB64 } from '@/test/bundles';
import { writeSignatureText } from '@/test/fake-crypto';
import { NO_CHAIN, fakeBoxSignature, fakeSpaceCrypto } from '@/test/fake-space-crypto';
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
  spaceView,
} from './fixtures';
import {
  ChainConflict,
  type SpaceDeps,
  SpaceNotChecked,
  canManageUsers,
  canReplaceKeys,
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

  it('asks to compare the member who sealed a key it can not trace, and opens the keys once it matched', async () => {
    const { spaceDeps, api, crypto } = deps();
    crypto.ownFingerprintText = await fingerprintTextOf(memberView(ME, 'sam@example.co'));
    // Lee, an admin nobody confirmed, sealed the Infrastructure key served to me.
    const roster = members().map((m) => (m.user === LEE ? { ...m, role: 'admin' as const } : m));
    api.members.mockResolvedValue(roster);
    const lee = roster.find((m) => m.user === LEE) as MemberViewDto;
    const box = utf8('ck-infra');
    const signature = fakeBoxSignature({
      sealerBundle: decodeB64(lee.publicBundle),
      spaceId: SPACE,
      collectionId: INFRA,
      keyVersion: 1,
      recipientId: uuidBytes(ME),
      sealed: box,
    });
    api.get.mockResolvedValue(
      spaceView({
        collectionKeys: [
          {
            collection: INFRA,
            keyVersion: 1,
            sealed: encodeB64(box),
            sealedBy: { account: LEE, keyVersion: 1, signature: encodeB64(signature) },
          },
        ],
      }),
    );

    // Nothing opens, and the page is told whose fingerprint to compare.
    const closed = await loadSpaceDetail(spaceDeps, SPACE);
    expect(closed.readable).toBe(false);
    expect(closed.compare).toBe(LEE);
    expect(crypto.calls).not.toContain(`openCollection:${INFRA}`);

    // The person compared Lee's fingerprint here and it matched: the space opens.
    const pins = memoryPinStore();
    await pinMember({ ...spaceDeps, pins }, ME, lee, await shown(LEE));
    const open = await loadSpaceDetail({ ...spaceDeps, pins }, SPACE);
    expect(open.readable).toBe(true);
    expect(open.compare).toBeUndefined();
    expect(crypto.calls).toContain(`openCollection:${INFRA}`);
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

  it('signs nothing for a space that isn’t checked', async () => {
    const { spaceDeps, api, crypto, loaded } = chainedDeps();
    const waiting = { ...loaded, trust: { kind: 'first-contact' as const, view: chained({ trusted: false }) } };
    await expect(createCollection(spaceDeps, waiting, { name: 'Support' })).rejects.toBeInstanceOf(
      SpaceNotChecked,
    );
    await expect(
      grantAccess(spaceDeps, waiting, { collection: INFRA, grantee: `user:${ME}`, permission: 'view' }),
    ).rejects.toBeInstanceOf(SpaceNotChecked);
    await expect(offboardMember(spaceDeps, waiting, LEE, 'remove')).rejects.toBeInstanceOf(SpaceNotChecked);
    expect(crypto.changes).toEqual([]);
    expect(api.appendChain).not.toHaveBeenCalled();
  });

  it('lets an admin whose space key isn’t open yet make the records that need no key', async () => {
    const { spaceDeps, api, crypto, loaded } = chainedDeps();
    const closed = { ...loaded, readable: false };
    // A name or a key of the space is made with the space key, which isn't open: refused.
    await expect(createCollection(spaceDeps, closed, { name: 'Support' })).rejects.toBeInstanceOf(
      SpaceNotChecked,
    );
    await expect(renameCollection(spaceDeps, closed, INFRA, 'Ops')).rejects.toBeInstanceOf(SpaceNotChecked);
    await expect(createGroup(spaceDeps, closed, { name: 'Eng', members: [] })).rejects.toBeInstanceOf(
      SpaceNotChecked,
    );
    expect(crypto.changes).toEqual([]);
    // An invitation, a role, a grant, a removal need none.
    await inviteMember(spaceDeps, SPACE, { email: 'theo@example.co', role: 'member', custom: [], grants: [] }, closed);
    await changeRole(spaceDeps, closed, LEE, 'admin', []);
    await grantAccess(spaceDeps, closed, { collection: FINANCE, grantee: `user:${LEE}`, permission: 'view' });
    await offboardMember(spaceDeps, closed, LEE, 'remove');
    expect(crypto.changes.map((c) => c.action)).toEqual(['invite', 'role', 'grant', 'remove']);
    expect(api.appendChain).toHaveBeenCalledTimes(4);
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

/** The signed manifest of the space as it lists `items`: each with its revision and ciphertext hash. */
async function manifestOf(items: ServedItemDto[]): Promise<Manifest> {
  return {
    owner: `space:${SPACE}`,
    counter: 1,
    entries: await Promise.all(
      items.map(async (item) => ({
        id: item.id,
        revision: item.revision,
        hash: await ciphertextHash(decodeB64(item.ciphertext ?? '')),
        deleted: false,
      })),
    ),
  };
}

/** An item as the server serves it. */
function served(id: string, collection: string, over: Partial<ServedItemDto> = {}): ServedItemDto {
  return {
    id,
    owner: `space:${SPACE}`,
    kind: 'login',
    format: 'kem1',
    revision: 1,
    keyVersion: 1,
    ciphertext: 'Y2lwaGVy',
    itemKey: 'a2V5',
    deleted: false,
    collectionId: collection,
    ...over,
  };
}

describe('replacing the keys of a space that has a chain', () => {
  const MARKED = chained({
    space: { keyVersion: 1, marked: true, nameHash: 'h', nameVersion: 1 },
    collections: [
      { id: INFRA, keyVersion: 1, marked: true, nameHash: 'h', nameVersion: 1 },
      { id: FINANCE, keyVersion: 1, marked: false, nameHash: 'h', nameVersion: 1 },
    ],
  });
  const ITEM = '50000000-0000-4000-8000-000000000001';
  const UNLISTED = '50000000-0000-4000-8000-000000000002';

  /** A space whose keys wait, with `listed` in its manifest and `others` served beside them. */
  async function waiting(listed: ServedItemDto[], others: ServedItemDto[] = []) {
    const run = chainedDeps(MARKED);
    const manifest = await manifestOf(listed);
    const spaceDeps: SpaceDeps = { ...run.spaceDeps, acceptedManifest: async () => manifest };
    run.api.sync.mockResolvedValue({ cursor: 'c', more: false, items: [...listed, ...others] });
    return { ...run, spaceDeps, loaded: detail({ trust: { kind: 'verified', view: MARKED } }) };
  }

  it('knows when keys wait: the chain says so, not the server’s flags', () => {
    expect(keysAwaitReplacement(detail({ trust: { kind: 'verified', view: MARKED } }))).toBe(true);
    expect(keysAwaitReplacement(detail({ trust: { kind: 'verified', view: chained() } }))).toBe(false);
    expect(keysAwaitReplacement(detail())).toBe(false);
  });

  it('is for a member who can edit what waits, or an owner or admin when the space key does', () => {
    const only = (collections: ChainView['collections']) =>
      detail({ trust: { kind: 'verified', view: chained({ collections, grants: [] }) } });
    const waitingCollection = [{ id: INFRA, keyVersion: 1, marked: true, nameHash: 'h', nameVersion: 1 }];
    // Owner of a space whose space key is marked.
    expect(canReplaceKeys(detail({ trust: { kind: 'verified', view: MARKED } }))).toBe(true);
    // Only a collection waits and the owner holds no editing grant on it: the role gives none.
    expect(canReplaceKeys(only(waitingCollection))).toBe(false);
    const granted = detail({
      trust: {
        kind: 'verified',
        view: chained({
          collections: waitingCollection,
          grants: [{ collection: INFRA, grantee: `user:${ME}`, permission: 'edit' }],
        }),
      },
    });
    expect(canReplaceKeys(granted)).toBe(true);
    // Through a group the owner is in; and not with keys that aren't open.
    const viaGroup = detail({
      trust: {
        kind: 'verified',
        view: chained({
          collections: waitingCollection,
          grants: [{ collection: INFRA, grantee: `group:${OPS}`, permission: 'edit' }],
          groups: [{ id: OPS, members: [ME], nameHash: 'h', nameVersion: 1 }],
        }),
      },
    });
    expect(canReplaceKeys(viaGroup)).toBe(true);
    expect(canReplaceKeys({ ...granted, readable: false })).toBe(false);
    expect(canReplaceKeys(detail())).toBe(false);
  });

  it('gives the worker the items the manifest lists as they are and every name, in one request', async () => {
    const listed = served(ITEM, INFRA);
    const { spaceDeps, api, crypto, loaded } = await waiting(
      [listed],
      [
        // A revision the manifest doesn't list, another collection's, held already, a tombstone and
        // another owner's: none is given to the worker, and only the first is named held.
        served(UNLISTED, INFRA, { revision: 2 }),
        served('50000000-0000-4000-8000-000000000003', FINANCE),
        served('50000000-0000-4000-8000-000000000004', INFRA, { held: true }),
        served('50000000-0000-4000-8000-000000000005', INFRA, { deleted: true, ciphertext: null, itemKey: null }),
        served('50000000-0000-4000-8000-000000000006', INFRA, { owner: `user:${ME}` }),
      ],
    );
    const phases: string[] = [];
    const result = await replaceKeys(spaceDeps, loaded, (p) => phases.push(p.phase));

    expect(crypto.replacements[0]?.items.map((i) => i.id)).toEqual([ITEM]);
    expect(crypto.replacements[0]?.names.map((n) => n.target)).toEqual([
      'space',
      `collection:${INFRA}`,
      `collection:${FINANCE}`,
      `group:${OPS}`,
    ]);
    // One request: the record, the item sealed again as the next revision, the unlisted one held.
    expect(api.appendChain).toHaveBeenCalledTimes(1);
    const body = api.appendChain.mock.calls[0]?.[1];
    expect(body?.records).toHaveLength(1);
    expect(body?.writes?.map((w) => [w.collection, w.expectedRevision, w.item.revision, w.item.keyVersion])).toEqual([
      [INFRA, 1, 2, 2],
    ]);
    expect(body?.held).toEqual([UNLISTED]);
    // Nothing goes after it.
    expect(api.putBatch).not.toHaveBeenCalled();
    expect(result).toEqual({ rewritten: 1, held: 1 });
    expect(phases).toEqual(expect.arrayContaining(['reading', 'sealing', 'sending']));
  });

  it('sends each re-written item signed by its writer, the signature binding its collection', async () => {
    const { spaceDeps, api, crypto, loaded } = await waiting([served(ITEM, INFRA)]);
    await replaceKeys(spaceDeps, loaded);
    const writes = api.appendChain.mock.calls[0]?.[1].writes ?? [];
    expect(writes).toHaveLength(1);
    for (const { collection, item: sent } of writes) {
      expect(sent.collectionId).toBe(collection);
      expect(sent.writer).toBe(crypto.writer);
      expect(sent.writerKeyVersion).toBe(1);
      expect(sent.writeSignature).toBe(
        encodeB64(utf8(writeSignatureText(crypto.writer, 1, writeFields(sent)))),
      );
    }
  });

  it('names no item held in a collection the record doesn’t replace', async () => {
    const { spaceDeps, api, crypto, loaded } = await waiting([], [served(UNLISTED, INFRA, { revision: 2 })]);
    // The worker left INFRA's key alone (it holds no key of it): its items stay as they are.
    crypto.replaced = { ok: true, records: [{ entry: 'ZW50cnk', signature: 'c2ln' }], seals: [], names: [], rotated: ['space'] };
    expect(await replaceKeys(spaceDeps, loaded)).toEqual({ rewritten: 0, held: 0 });
    expect(api.appendChain.mock.calls[0]?.[1].held).toBeUndefined();
  });

  it('sends nothing when the space has no manifest to say which items to seal again', async () => {
    const { spaceDeps, api, crypto, loaded } = await waiting([]);
    api.sync.mockResolvedValue({ cursor: 'c', more: false, items: [served(ITEM, INFRA)] });
    await expect(replaceKeys({ ...spaceDeps, acceptedManifest: async () => null }, loaded)).rejects.toMatchObject({
      name: 'ReplaceBlocked',
      reason: 'no-manifest',
    });
    expect(crypto.replacements).toEqual([]);
    expect(api.appendChain).not.toHaveBeenCalled();
  });

  it('sends nothing when an item the manifest lists can’t be opened here', async () => {
    const { spaceDeps, api, crypto, loaded } = await waiting([served(ITEM, INFRA)]);
    crypto.replaced = { ok: true, records: [{ entry: 'ZW50cnk', signature: 'c2ln' }], seals: [], names: [], held: [ITEM] };
    await expect(replaceKeys(spaceDeps, loaded)).rejects.toMatchObject({ reason: 'unreadable', count: 1 });
    expect(api.appendChain).not.toHaveBeenCalled();
    expect(api.putBatch).not.toHaveBeenCalled();
  });

  it('sends nothing when the request would not fit in what the route reads', async () => {
    const { spaceDeps, api, crypto, loaded } = await waiting([served(ITEM, INFRA)]);
    const big = {
      collection: INFRA,
      expectedRevision: 1,
      item: { ...served(ITEM, INFRA, { revision: 2, keyVersion: 2, ciphertext: 'A'.repeat(9 * 1024 * 1024) }) } as never,
    };
    crypto.replaced = {
      ok: true,
      records: [{ entry: 'ZW50cnk', signature: 'c2ln' }],
      seals: [],
      names: [],
      writes: [big],
    };
    await expect(replaceKeys(spaceDeps, loaded)).rejects.toMatchObject({ name: 'ReplaceBlocked', reason: 'too-large' });
    expect(api.appendChain).not.toHaveBeenCalled();
    // No second path: what doesn't fit is not sent in batches after the record.
    expect(api.putBatch).not.toHaveBeenCalled();
  });

  it('reads the items, the names and the manifest again when the head moved, and builds on those', async () => {
    const { spaceDeps, api, crypto, loaded } = await waiting([served(ITEM, INFRA)]);
    api.appendChain.mockRejectedValueOnce(
      new ApiError(409, { type: 'urn:kemlock:problem:space-chain-conflict', title: 'x', status: 409 }),
    );
    const manifests = vi.fn(spaceDeps.acceptedManifest ?? (async () => null));
    await replaceKeys({ ...spaceDeps, acceptedManifest: manifests }, loaded);
    expect(crypto.replacements).toHaveLength(2);
    expect(api.sync.mock.calls.filter((c) => c[0] === undefined)).toHaveLength(2);
    expect(api.get).toHaveBeenCalledTimes(2);
    expect(manifests).toHaveBeenCalledTimes(2);
    expect(api.appendChain).toHaveBeenCalledTimes(2);
  });

  it('lists what it wrote in the signed manifest, and a failing keeper never fails it', async () => {
    const { spaceDeps, loaded } = await waiting([served(ITEM, INFRA)]);
    const listed: string[][] = [];
    const withKeeper = { ...spaceDeps, wrote: async (items: Array<{ id: string }>) => void listed.push(items.map((i) => i.id)) };
    await replaceKeys(withKeeper, loaded);
    expect(listed).toEqual([[ITEM]]);
    const broken = { ...spaceDeps, wrote: () => Promise.reject(new Error('no')) };
    await expect(replaceKeys(broken, loaded)).resolves.toEqual({ rewritten: 1, held: 0 });
  });

  it('shows the reason when the chain’s rules refuse the replacement, and sends nothing', async () => {
    const { spaceDeps, api, crypto, loaded } = await waiting([served(ITEM, INFRA)]);
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
  const item = (n: number, collection: string, keyVersion: number, over: Partial<ServedItemDto> = {}) =>
    served(`50000000-0000-4000-8000-00000000020${n}`, collection, { keyVersion, ...over });

  it('finds, from the server, the live items under a version older than their collection’s, held ones left out', async () => {
    const { spaceDeps, api, loaded } = chainedDeps(REPLACED);
    api.sync.mockResolvedValueOnce({
      cursor: 'c',
      more: false,
      items: [
        item(1, INFRA, 1),
        // A hold made on purpose, by this vault or an app, isn't released from here.
        item(2, INFRA, 1, { held: true }),
        // Current, of a collection never replaced, deleted, another owner's: not found.
        item(3, INFRA, 2),
        item(4, FINANCE, 1),
        item(5, INFRA, 1, { deleted: true, ciphertext: null, itemKey: null }),
        item(6, INFRA, 1, { owner: `user:${ME}` }),
      ],
    });
    const found = await itemsToReseal(spaceDeps, loaded);
    expect(found.map((i) => i.id)).toEqual(['50000000-0000-4000-8000-000000000201']);
    // A space whose keys were never replaced is not read at all.
    api.sync.mockClear();
    expect(await itemsToReseal(spaceDeps, detail({ trust: { kind: 'verified', view: chained() } }))).toEqual([]);
    expect(api.sync).not.toHaveBeenCalled();
  });

  /** A space with items under version 1 of INFRA, `listed` of them in the manifest. */
  async function leftOver(all: ServedItemDto[], listed: ServedItemDto[]) {
    const run = chainedDeps(REPLACED);
    const manifest = await manifestOf(listed);
    const spaceDeps: SpaceDeps = { ...run.spaceDeps, acceptedManifest: async () => manifest };
    run.api.sync.mockResolvedValueOnce({ cursor: 'c', more: false, items: all });
    return { ...run, spaceDeps, loaded: detail({ trust: { kind: 'verified', view: REPLACED } }) };
  }

  it('seals again the ones the manifest lists, in batches, and lists them in the manifest', async () => {
    const all = [item(1, INFRA, 1), item(2, INFRA, 1)];
    const { spaceDeps, api, crypto, loaded } = await leftOver(all, all);
    const listed: string[][] = [];
    const withKeeper = { ...spaceDeps, wrote: async (items: Array<{ id: string }>) => void listed.push(items.map((i) => i.id)) };
    const phases: Array<[string, number, number]> = [];
    const result = await resealItems(withKeeper, loaded, (p) => phases.push([p.phase, p.done, p.total]));
    expect(crypto.resealings[0]?.map((i) => i.id)).toEqual(all.map((i) => i.id));
    expect(api.putBatch).toHaveBeenCalledTimes(1);
    expect(api.putBatch.mock.calls[0]?.[0].writes.map((w) => [w.expectedRevision, w.item.revision, w.item.keyVersion])).toEqual([
      [1, 2, 2],
      [1, 2, 2],
    ]);
    expect(api.appendChain).not.toHaveBeenCalled();
    expect(listed).toEqual([all.map((i) => i.id)]);
    expect(result).toEqual({ rewritten: 2, stuck: 0 });
    expect(phases.at(-1)).toEqual(['sending', 2, 2]);
  });

  it('signs what it seals again, the signature binding the collection of each item', async () => {
    const all = [item(1, INFRA, 1), item(2, INFRA, 1)];
    const { spaceDeps, api, crypto, loaded } = await leftOver(all, all);
    await resealItems(spaceDeps, loaded);
    const writes = api.putBatch.mock.calls[0]?.[0].writes ?? [];
    expect(writes).toHaveLength(2);
    for (const { item: sent } of writes) {
      expect(sent.collectionId).toBe(INFRA);
      expect(sent.writer).toBe(crypto.writer);
      expect(sent.writerKeyVersion).toBe(1);
      expect(sent.writeSignature).toBe(
        encodeB64(utf8(writeSignatureText(crypto.writer, 1, writeFields(sent)))),
      );
    }
  });

  it('leaves out what the manifest doesn’t list as it is, which a removed member may have written', async () => {
    const listed = item(1, INFRA, 1);
    const { spaceDeps, api, crypto, loaded } = await leftOver([listed, item(2, INFRA, 1, { revision: 7 })], [listed]);
    expect(await resealItems(spaceDeps, loaded)).toEqual({ rewritten: 1, stuck: 1 });
    expect(crypto.resealings[0]?.map((i) => i.id)).toEqual([listed.id]);
    expect(api.putBatch.mock.calls[0]?.[0].writes).toHaveLength(1);
  });

  it('counts the items this browser can not seal again, and writes the rest', async () => {
    const all = [item(1, INFRA, 1), item(2, INFRA, 1)];
    const { spaceDeps, api, crypto, loaded } = await leftOver(all, all);
    crypto.resealed = { ok: true, records: [], seals: [], names: [], held: [all[1]?.id ?? ''], writes: [] };
    expect(await resealItems(spaceDeps, loaded)).toEqual({ rewritten: 0, stuck: 1 });
    expect(api.putBatch).not.toHaveBeenCalled();
  });

  it('does nothing when no item is under an old key, there is no manifest, or the space has no chain', async () => {
    const run = chainedDeps(REPLACED);
    run.api.sync.mockResolvedValue({ cursor: 'c', more: false, items: [item(3, INFRA, 2), item(1, INFRA, 1)] });
    const loaded = detail({ trust: { kind: 'verified', view: REPLACED } });
    // No manifest: nothing is taken as accepted.
    expect(await resealItems(run.spaceDeps, loaded)).toEqual({ rewritten: 0, stuck: 1 });
    expect(run.crypto.resealings).toEqual([]);
    expect(await resealItems(run.spaceDeps, detail())).toEqual({ rewritten: 0, stuck: 0 });
  });
});
