// Spaces as the page works with them: what to read, how to open names, and the sealing each
// membership change needs. No React in here, so the logic is tested with fakes.
//
// A confirmation is the one step that puts keys in someone's hands, so it only happens with a
// fingerprint the browser worked out itself from the member's bundle (src/sharing/bundle.ts),
// never one the server sent.
import type {
  CollectionDto,
  CollectionPermission,
  CustomPermission,
  GrantDto,
  GroupDto,
  MemberDto,
  MemberViewDto,
  SpaceRole,
  SpaceSummaryDto,
  SpaceViewDto,
  SpacesApi,
} from '@/api/spaces';
import { decodeB64, encodeB64 } from '@/lib/b64url';
import { type Fingerprint, parseBundle, uuidBytes } from '@/sharing/bundle';
import type { SpaceCrypto } from '@/spaces/crypto';

export interface SpaceDeps {
  api: SpacesApi;
  crypto: SpaceCrypto;
  newId?: () => string;
}

const newId = (deps: SpaceDeps) => (deps.newId ?? (() => globalThis.crypto.randomUUID()))();

// ---- the list ---------------------------------------------------------------------------

export interface SpaceRow {
  id: string;
  /** null while the name can't be opened (the space key isn't mine yet, or no worker support). */
  name: string | null;
  role: SpaceRole;
  state: MemberDto['state'];
  keysPending: boolean;
}

async function openSpaceName(
  crypto: SpaceCrypto,
  summary: SpaceSummaryDto,
): Promise<string | null> {
  const sealed = summary.member.sealedSpaceKey;
  if (!sealed) return null;
  try {
    await crypto.openSpace({
      spaceId: summary.space.id,
      keyVersion: summary.member.keyVersion ?? summary.space.keyVersion,
      sealed: decodeB64(sealed),
    });
    return await crypto.openName({
      spaceId: summary.space.id,
      keyVersion: summary.space.keyVersion,
      kind: 'space',
      id: summary.space.id,
      ciphertext: decodeB64(summary.space.name),
    });
  } catch {
    return null;
  }
}

export async function loadSpaceList(deps: SpaceDeps): Promise<SpaceRow[]> {
  const summaries = await deps.api.list();
  return Promise.all(
    summaries.map(async (summary) => ({
      id: summary.space.id,
      name: await openSpaceName(deps.crypto, summary),
      role: summary.member.role,
      state: summary.member.state,
      keysPending: summary.space.keysPendingSince !== null,
    })),
  );
}

export interface NewSpaceInput {
  name: string;
  firstCollection: string;
}

/** Makes a space: the space key and first collection key are made and sealed to me here. */
export async function createSpace(deps: SpaceDeps, input: NewSpaceInput): Promise<SpaceViewDto> {
  const spaceId = newId(deps);
  const collectionId = newId(deps);
  const keys = await deps.crypto.newSpace({
    spaceId,
    collectionId,
    spaceName: input.name,
    collectionName: input.firstCollection,
  });
  return deps.api.create({
    id: spaceId,
    name: encodeB64(keys.name),
    sealedSpaceKey: encodeB64(keys.sealedSpaceKey),
    collection: {
      id: collectionId,
      name: encodeB64(keys.collection.name),
      sealedKey: encodeB64(keys.collection.sealedKey),
    },
  });
}

// ---- one space ----------------------------------------------------------------------------

export interface TitledCollection extends CollectionDto {
  title: string | null;
}
export interface TitledGroup extends GroupDto {
  title: string | null;
}

export interface SpaceDetail {
  view: SpaceViewDto;
  members: MemberViewDto[];
  /** null when the space key can't be opened here. */
  name: string | null;
  collections: TitledCollection[];
  groups: TitledGroup[];
  /** Whether the worker opened the space key: without it nothing can be sealed to anyone. */
  readable: boolean;
}

export async function loadSpaceDetail(deps: SpaceDeps, spaceId: string): Promise<SpaceDetail> {
  const [view, members] = await Promise.all([deps.api.get(spaceId), deps.api.members(spaceId)]);
  const { space, me } = view;
  let readable = false;
  if (me.sealedSpaceKey) {
    try {
      await deps.crypto.openSpace({
        spaceId,
        keyVersion: me.keyVersion ?? space.keyVersion,
        sealed: decodeB64(me.sealedSpaceKey),
      });
      for (const copy of view.collectionKeys) {
        await deps.crypto.openCollection({
          spaceId,
          collectionId: copy.collection,
          keyVersion: copy.keyVersion,
          sealed: decodeB64(copy.sealed),
        });
      }
      readable = true;
    } catch {
      readable = false;
    }
  }
  const title = async (kind: 'space' | 'collection' | 'group', id: string, name: string) => {
    if (!readable) return null;
    try {
      return await deps.crypto.openName({
        spaceId,
        keyVersion: space.keyVersion,
        kind,
        id,
        ciphertext: decodeB64(name),
      });
    } catch {
      return null;
    }
  };
  return {
    view,
    members,
    readable,
    name: await title('space', space.id, space.name),
    collections: await Promise.all(
      view.collections.map(async (c) => ({ ...c, title: await title('collection', c.id, c.name) })),
    ),
    groups: await Promise.all(
      view.groups.map(async (g) => ({ ...g, title: await title('group', g.id, g.name) })),
    ),
  };
}

// ---- who reaches what ------------------------------------------------------------------------

/** The accounts that can open a collection through these grants and groups. */
export function reachedBy(
  collection: string,
  grants: GrantDto[],
  groups: Array<Pick<GroupDto, 'id' | 'members'>>,
): Set<string> {
  const reached = new Set<string>();
  for (const grant of grants) {
    if (grant.collection !== collection) continue;
    const [kind, id] = grant.grantee.split(':');
    if (kind === 'user' && id) reached.add(id);
    if (kind === 'group') {
      for (const user of groups.find((g) => g.id === id)?.members ?? []) reached.add(user);
    }
  }
  return reached;
}

/** The collections one account is granted, directly or through a group. */
export function collectionsOfMember(
  user: string,
  collections: Array<Pick<CollectionDto, 'id'>>,
  grants: GrantDto[],
  groups: Array<Pick<GroupDto, 'id' | 'members'>>,
): string[] {
  return collections
    .map((c) => c.id)
    .filter((id) => reachedBy(id, grants, groups).has(user));
}

export function canManageUsers(me: Pick<MemberDto, 'role' | 'custom'>): boolean {
  return me.role === 'owner' || me.role === 'admin' || me.custom.includes('manage-users');
}

export function canManageGroups(me: Pick<MemberDto, 'role' | 'custom'>): boolean {
  return me.role === 'owner' || me.role === 'admin' || me.custom.includes('manage-groups');
}

export function canCreateCollections(me: Pick<MemberDto, 'role' | 'custom'>): boolean {
  return me.role === 'owner' || me.role === 'admin' || me.custom.includes('create-collections');
}

export function memberLabel(members: MemberViewDto[], user: string): string {
  const member = members.find((m) => m.user === user);
  return member ? member.name || member.email : user;
}

// ---- keys for someone -----------------------------------------------------------------------

function kx1Of(member: MemberViewDto): Uint8Array {
  const parsed = parseBundle(decodeB64(member.publicBundle));
  if (!parsed) throw new Error("the member's key bundle can't be read");
  return parsed.kx1;
}

async function collectionKeyFor(
  deps: SpaceDeps,
  spaceId: string,
  collectionId: string,
  member: MemberViewDto,
): Promise<string> {
  return encodeB64(
    await deps.crypto.sealCollectionKeyTo({
      spaceId,
      collectionId,
      recipientKx1: kx1Of(member),
      recipientId: uuidBytes(member.user),
    }),
  );
}

// ---- membership ----------------------------------------------------------------------------

export interface InviteInput {
  email: string;
  role: SpaceRole;
  custom: CustomPermission[];
  grants: Array<{ collection: string; permission: CollectionPermission }>;
}

export function inviteMember(deps: SpaceDeps, spaceId: string, input: InviteInput) {
  return deps.api.invite(spaceId, {
    email: input.email.trim(),
    role: input.role,
    custom: input.role === 'custom' ? input.custom : [],
    grants: input.grants,
  });
}

export async function confirmMember(
  deps: SpaceDeps,
  detail: SpaceDetail,
  member: MemberViewDto,
  fingerprint: Fingerprint,
): Promise<MemberDto> {
  if (!fingerprint.consistent) {
    throw new Error('the fingerprint worked out here differs from the worker’s');
  }
  const spaceId = detail.view.space.id;
  const recipientKx1 = kx1Of(member);
  const recipientId = uuidBytes(member.user);
  const sealedSpaceKey = await deps.crypto.sealSpaceKeyTo({ spaceId, recipientKx1, recipientId });
  const collectionKeys: Array<{ collection: string; sealed: string }> = [];
  for (const collection of collectionsOfMember(
    member.user,
    detail.view.collections,
    detail.view.grants,
    detail.view.groups,
  )) {
    collectionKeys.push({
      collection,
      sealed: await collectionKeyFor(deps, spaceId, collection, member),
    });
  }
  // What the confirmer signs (docs/crypto.md, "Member confirmation"): that they compared this
  // fingerprint for this member of this space. The worker builds the 134 bytes, with the
  // confirmer as the unlocked account, and signs nothing else under context `confirm`.
  const statement = await deps.crypto.confirmationStatement({
    space: spaceId,
    member: member.user,
    memberKeyVersion: member.userKeyVersion,
    fingerprint: fingerprint.bytes,
  });
  const signature = await deps.crypto.signStatement(statement, 'confirm');
  return deps.api.confirm(spaceId, member.user, {
    fingerprint: encodeB64(fingerprint.bytes),
    statement: encodeB64(statement),
    signature: encodeB64(signature),
    sealedSpaceKey: encodeB64(sealedSpaceKey),
    collectionKeys,
  });
}

// ---- collections, groups, grants -------------------------------------------------------------

export async function createCollection(
  deps: SpaceDeps,
  detail: SpaceDetail,
  input: { name: string; parent?: string },
) {
  const spaceId = detail.view.space.id;
  const id = newId(deps);
  const made = await deps.crypto.newCollection({ spaceId, collectionId: id, name: input.name });
  return deps.api.createCollection(spaceId, {
    id,
    parent: input.parent ?? null,
    name: encodeB64(made.name),
    // The maker gets Manage, and the key sealed to them is all anyone else's grant adds to.
    keys: [{ user: detail.view.me.user, sealed: encodeB64(made.sealedKey) }],
  });
}

export async function renameCollection(
  deps: SpaceDeps,
  detail: SpaceDetail,
  collection: string,
  name: string,
) {
  const spaceId = detail.view.space.id;
  const sealed = await deps.crypto.sealName({
    spaceId,
    keyVersion: detail.view.space.keyVersion,
    kind: 'collection',
    id: collection,
    name,
  });
  return deps.api.editCollection(spaceId, collection, { name: encodeB64(sealed) });
}

export async function createGroup(
  deps: SpaceDeps,
  detail: SpaceDetail,
  input: { name: string; members: string[] },
) {
  const spaceId = detail.view.space.id;
  const id = newId(deps);
  const sealed = await deps.crypto.sealName({
    spaceId,
    keyVersion: detail.view.space.keyVersion,
    kind: 'group',
    id,
    name: input.name,
  });
  return deps.api.createGroup(spaceId, { id, name: encodeB64(sealed), members: input.members });
}

/** Keys for the confirmed members a change newly lets into a collection. */
async function keysForNewcomers(
  deps: SpaceDeps,
  detail: SpaceDetail,
  collection: string,
  before: Set<string>,
  after: Set<string>,
): Promise<Array<{ collection: string; user: string; sealed: string }>> {
  const keys: Array<{ collection: string; user: string; sealed: string }> = [];
  for (const user of after) {
    if (before.has(user)) continue;
    const member = detail.members.find((m) => m.user === user);
    if (!member || member.state !== 'confirmed') continue;
    keys.push({
      collection,
      user,
      sealed: await collectionKeyFor(deps, detail.view.space.id, collection, member),
    });
  }
  return keys;
}

/** Replaces a group's members, sealing the keys of its collections to those it newly adds. */
export async function setGroupMembers(
  deps: SpaceDeps,
  detail: SpaceDetail,
  group: string,
  members: string[],
) {
  const { grants, groups, collections } = detail.view;
  const changed = groups.map((g) => (g.id === group ? { ...g, members } : g));
  const keys: Array<{ collection: string; user: string; sealed: string }> = [];
  for (const collection of collections) {
    if (!grants.some((g) => g.collection === collection.id && g.grantee === `group:${group}`)) continue;
    keys.push(
      ...(await keysForNewcomers(
        deps,
        detail,
        collection.id,
        reachedBy(collection.id, grants, groups),
        reachedBy(collection.id, grants, changed),
      )),
    );
  }
  return deps.api.editGroup(detail.view.space.id, group, { members, keys });
}

export async function grantAccess(
  deps: SpaceDeps,
  detail: SpaceDetail,
  input: { collection: string; grantee: string; permission: CollectionPermission },
) {
  const { grants, groups } = detail.view;
  const after = [
    ...grants.filter((g) => !(g.collection === input.collection && g.grantee === input.grantee)),
    { ...input },
  ];
  const keys = await keysForNewcomers(
    deps,
    detail,
    input.collection,
    reachedBy(input.collection, grants, groups),
    reachedBy(input.collection, after, groups),
  );
  return deps.api.grant(detail.view.space.id, {
    ...input,
    keys: keys.map((k) => ({ user: k.user, sealed: k.sealed })),
  });
}
