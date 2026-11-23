// @vitest-environment node
import { describe, expect, it } from 'vitest';
import { decodeB64, fromUtf8 } from '@/lib/b64url';
import { checkedFingerprint, fingerprintText, fingerprintBytes } from '@/sharing/bundle';
import { fakeSpaceCrypto } from '@/test/fake-space-crypto';
import {
  FINANCE,
  INFRA,
  LEE,
  ME,
  OPS,
  SPACE,
  THEO,
  detail,
  fakeSpacesApi,
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
  reachedBy,
  renameCollection,
  setGroupMembers,
} from './model';

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
    // Lee already reaches Infrastructure through Ops; Theo (not confirmed) and Sam are new.
    await grantAccess(spaceDeps, detail(), { collection: INFRA, grantee: `user:${THEO}`, permission: 'view' });
    expect(api.grant.mock.calls[0]?.[1].keys).toEqual([]);
    await grantAccess(spaceDeps, detail(), { collection: INFRA, grantee: `user:${ME}`, permission: 'manage' });
    expect(api.grant.mock.calls[1]?.[1].keys?.map((k) => k.user)).toEqual([ME]);
  });

  it('seals the keys of a group’s collections to the members it adds', async () => {
    const { spaceDeps, api } = deps();
    await setGroupMembers(spaceDeps, detail(), OPS, [LEE, ME]);
    const body = api.editGroup.mock.calls[0]?.[2];
    expect(body?.keys?.map((k) => [k.collection, k.user])).toEqual([[INFRA, ME]]);
    expect(body?.members).toEqual([LEE, ME]);
  });
});
