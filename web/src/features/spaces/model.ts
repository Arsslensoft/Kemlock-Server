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
import { type Fingerprint, fingerprintBytes } from '@/sharing/bundle';
import type { AnchorStore, PinStore } from '@/spaces/anchors';
import type { SpaceCrypto } from '@/spaces/crypto';
import {
  type SpaceTrust,
  checkSpaceChain,
  nameVersionOf,
  openChainedKey,
  openChainedKeys,
  overlayChain,
} from './chain';
import type { BoxStore } from '@/spaces/boxstore';
import { lazyContext, openKeyBox, openUnchainedKeys, signedInAccount } from './boxes';
import { MemberNotVerified, type Recipient, checkBundle, verifiedRecipient } from './verify';

export interface SpaceDeps {
  api: SpacesApi;
  crypto: SpaceCrypto;
  newId?: () => string;
  /** Where this browser keeps the anchors of the chains it verified; its IndexedDB when left out. */
  anchors?: AnchorStore;
  /** Where it keeps the members whose fingerprint a person compared here. */
  pins?: PinStore;
  /** Where it keeps the key boxes it accepted, so one sealed before keys were signed is flagged once. */
  boxes?: BoxStore;
  /** The id of the account signed in here, from the session; the server's word for it is only checked against it. */
  account?: () => string | null;
}

/**
 * A change that needs the space's keys, asked of a space whose chain can't be used for it: one
 * that isn't checked (`kind` says how far it got), or one whose chain the web vault can't add
 * records to yet.
 */
export class SpaceNotChecked extends Error {
  readonly kind: SpaceTrust['kind'];

  constructor(kind: SpaceTrust['kind']) {
    super(`the space can't be changed here (${kind})`);
    this.name = 'SpaceNotChecked';
    this.kind = kind;
  }
}

/** Refuses a change to a space that has a chain: its changes are signed records. */
function requireUnchained(detail: Pick<SpaceDetail, 'trust'>): void {
  if (detail.trust && detail.trust.kind !== 'unchained') throw new SpaceNotChecked(detail.trust.kind);
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
  /** How far the space's chain can be trusted, when it has one or couldn't be checked. */
  trust?: Exclude<SpaceTrust['kind'], 'unchained'>;
}

async function openSpaceName(
  deps: SpaceDeps,
  summary: SpaceSummaryDto,
): Promise<{ name: string | null; trust: SpaceTrust }> {
  const spaceId = summary.space.id;
  let me: string;
  try {
    me = signedInAccount(deps, summary.member.user);
  } catch {
    // The server names someone else as me: nothing about this space is opened or shown as checked.
    return { name: null, trust: { kind: 'unverified', reason: 'account', seq: null } };
  }
  const trust = await checkSpaceChain(deps, spaceId, me);
  const sealed = summary.member.sealedSpaceKey;
  if (!sealed || trust.kind === 'unverified' || trust.kind === 'first-contact') {
    return { name: null, trust };
  }
  try {
    const servedVersion = summary.member.keyVersion ?? summary.space.keyVersion;
    let keyVersion = summary.space.keyVersion;
    if (trust.kind === 'verified') {
      // Through the chain, at the version it gives, and the name only as the chain committed it.
      await openChainedKey(deps, spaceId, trust.view, null, servedVersion, sealed);
      keyVersion = nameVersionOf(trust.view, 'space', spaceId);
    } else {
      await openKeyBox(lazyContext(deps, spaceId, me), {
        key: 'space',
        version: servedVersion,
        sealed,
        sealedBy: summary.member.sealedBy,
      });
    }
    return {
      name: await deps.crypto.openName({
        spaceId,
        keyVersion,
        kind: 'space',
        id: spaceId,
        ciphertext: decodeB64(summary.space.name),
      }),
      trust,
    };
  } catch {
    return { name: null, trust };
  }
}

export async function loadSpaceList(deps: SpaceDeps): Promise<SpaceRow[]> {
  const summaries = await deps.api.list();
  return Promise.all(
    summaries.map(async (summary) => {
      const { name, trust } = await openSpaceName(deps, summary);
      return {
        id: summary.space.id,
        name,
        role: summary.member.role,
        state: summary.member.state,
        keysPending: summary.space.keysPendingSince !== null,
        ...(trust.kind === 'unverified' || trust.kind === 'first-contact'
          ? { trust: trust.kind }
          : {}),
      };
    }),
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
    sealedSpaceKeySignature: encodeB64(keys.sealedSpaceKeySignature),
    collection: {
      id: collectionId,
      name: encodeB64(keys.collection.name),
      sealedKey: encodeB64(keys.collection.sealedKey),
      sealedKeySignature: encodeB64(keys.collection.sealedKeySignature),
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
  /**
   * How far the space's chain can be trusted. For a space with a verified chain the members,
   * roles, collections, groups and grants above are the chain's; for one that is unverified or
   * waits for first contact nothing is opened and nothing is shown as checked. Left out, as it
   * is in a test that doesn't care, the space is taken as one with no chain.
   */
  trust?: SpaceTrust;
  /**
   * The confirmed members of a space with no chain whose keys this browser can't trace to a
   * confirmation it trusts (src/features/spaces/verify.ts), and, for each, the member whose
   * fingerprint a person could compare to put that right. Confirming them again does too.
   */
  unverified?: Array<{ user: string; compare?: string }>;
  /**
   * The keys of a space with no chain that were sealed before keys were signed (`space`, or
   * `collection:<id>`): this browser accepted them once, and they are replaced when the keys are or
   * when an owner confirms this account again (docs/crypto.md, "Signed key boxes").
   */
  legacyKeys?: string[];
}

export async function loadSpaceDetail(deps: SpaceDeps, spaceId: string): Promise<SpaceDetail> {
  const [served, servedMembers] = await Promise.all([deps.api.get(spaceId), deps.api.members(spaceId)]);
  const me = signedInAccount(deps, served.me.user);
  const trust = await checkSpaceChain(deps, spaceId, me);
  let view = served;
  let members = servedMembers;
  let readable = false;
  let legacyKeys: string[] = [];
  let nameVersion = (_kind: 'space' | 'collection' | 'group', _id: string) => served.space.keyVersion;
  if (trust.kind === 'verified') {
    // The space as its chain gives it; keys open at the chain's version, under its commitments.
    const chain = trust.view;
    ({ view, members } = overlayChain(served, servedMembers, chain));
    nameVersion = (kind, id) => nameVersionOf(chain, kind, id);
    try {
      await openChainedKeys(deps, spaceId, chain, served);
      readable = true;
    } catch {
      readable = false;
    }
  } else if (trust.kind === 'unchained' && served.me.sealedSpaceKey) {
    // Each key opens only after its sealer's signature is checked (boxes.ts); one sealed before keys
    // were signed is accepted once and flagged.
    try {
      const ctx = {
        ...lazyContext(deps, spaceId, me),
        members: async () => servedMembers,
        access: async () => ({ grants: served.grants, groups: served.groups }),
      };
      legacyKeys = await openUnchainedKeys(ctx, {
        me: served.me,
        spaceKeyVersion: served.space.keyVersion,
        collectionKeys: served.collectionKeys,
      });
      readable = true;
    } catch {
      readable = false;
    }
  }
  const unverified: NonNullable<SpaceDetail['unverified']> = [];
  if (trust.kind === 'unchained') {
    for (const member of members) {
      if (member.state !== 'confirmed' || member.user === view.me.user) continue;
      try {
        await recipientOf(deps, { view, members }, member);
      } catch (error) {
        if (!(error instanceof MemberNotVerified)) throw error;
        unverified.push({
          user: member.user,
          ...(error.compare ? { compare: error.compare.user } : {}),
        });
      }
    }
  }
  const { space } = view;
  const title = async (kind: 'space' | 'collection' | 'group', id: string, name: string) => {
    if (!readable) return null;
    try {
      return await deps.crypto.openName({
        spaceId,
        keyVersion: nameVersion(kind, id),
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
    trust,
    ...(legacyKeys.length > 0 ? { legacyKeys } : {}),
    ...(unverified.length > 0 ? { unverified } : {}),
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

/**
 * The key a member's keys are sealed to, once checked: their bundle is theirs, at their key
 * version, and someone I can trace confirmed exactly these keys (src/features/spaces/verify.ts).
 * Throws MemberNotVerified otherwise, and nothing is sealed.
 */
const verifiedBefore = new WeakMap<MemberViewDto[], Map<string, Promise<Recipient>>>();

function recipientOf(
  deps: SpaceDeps,
  detail: Pick<SpaceDetail, 'view' | 'members'>,
  member: MemberViewDto,
): Promise<Recipient> {
  // One check per member for one loaded roster, however many collections a change touches.
  let known = verifiedBefore.get(detail.members);
  if (!known) {
    known = new Map();
    verifiedBefore.set(detail.members, known);
  }
  let checked = known.get(member.user);
  if (!checked) {
    checked = verifiedRecipient(
      {
        crypto: deps.crypto,
        spaceId: detail.view.space.id,
        members: detail.members,
        me: signedInAccount(deps, detail.view.me.user),
        pins: deps.pins,
      },
      member,
    );
    known.set(member.user, checked);
  }
  return checked;
}

/** A collection key sealed to a member, and the signature of this account over the box. */
async function collectionKeyFor(
  deps: SpaceDeps,
  spaceId: string,
  collectionId: string,
  recipient: Recipient,
): Promise<{ sealed: string; signature: string }> {
  const box = await deps.crypto.sealCollectionKeyTo({
    spaceId,
    collectionId,
    recipientKx1: recipient.kx1,
    recipientId: recipient.id,
  });
  return { sealed: encodeB64(box.sealed), signature: encodeB64(box.signature) };
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
  requireUnchained(detail);
  const spaceId = detail.view.space.id;
  // The bundle the person compared is the member's own at their current key version, and is what
  // the fingerprint on screen is of; a bundle that is another account's, or has since changed,
  // gets no key.
  const { bytes, parsed } = await checkBundle(deps.crypto, member);
  const shown = await fingerprintBytes(bytes);
  if (
    shown.length !== fingerprint.bytes.length ||
    shown.some((byte, i) => byte !== fingerprint.bytes[i])
  ) {
    throw new MemberNotVerified(member, 'confirmation-differs');
  }
  const recipient: Recipient = { kx1: parsed.kx1, id: parsed.accountId };
  const sealedSpaceKey = await deps.crypto.sealSpaceKeyTo({
    spaceId,
    recipientKx1: recipient.kx1,
    recipientId: recipient.id,
  });
  const collectionKeys: Array<{ collection: string; sealed: string; signature: string }> = [];
  for (const collection of collectionsOfMember(
    member.user,
    detail.view.collections,
    detail.view.grants,
    detail.view.groups,
  )) {
    collectionKeys.push({
      collection,
      ...(await collectionKeyFor(deps, spaceId, collection, recipient)),
    });
  }
  // What the confirmer signs (docs/crypto.md, "Member confirmation"): that they compared this
  // fingerprint for this member of this space. The worker builds the 134 bytes, with the
  // confirmer as the unlocked account, and signs nothing else under context `confirm`.
  const statement = await deps.crypto.confirmationStatement({
    space: spaceId,
    member: member.user,
    memberKeyVersion: parsed.keyVersion,
    fingerprint: fingerprint.bytes,
  });
  const signature = await deps.crypto.signStatement(statement, 'confirm');
  return deps.api.confirm(spaceId, member.user, {
    fingerprint: encodeB64(fingerprint.bytes),
    statement: encodeB64(statement),
    signature: encodeB64(signature),
    sealedSpaceKey: encodeB64(sealedSpaceKey.sealed),
    sealedSpaceKeySignature: encodeB64(sealedSpaceKey.signature),
    collectionKeys,
  });
}

/**
 * Pins a member: a person compared their fingerprint, here, with what their own app shows, and it
 * matched. Confirmations they made are then trusted in this browser, and so are they as a
 * recipient, for as long as their keys are the ones compared.
 */
export async function pinMember(
  deps: SpaceDeps,
  me: string,
  member: MemberViewDto,
  fingerprint: Fingerprint,
): Promise<void> {
  if (!fingerprint.consistent) {
    throw new Error('the fingerprint worked out here differs from the worker’s');
  }
  if (!deps.pins) throw new Error('this browser keeps no pins');
  const { bytes } = await checkBundle(deps.crypto, member);
  const shown = await fingerprintBytes(bytes);
  if (shown.length !== fingerprint.bytes.length || shown.some((byte, i) => byte !== fingerprint.bytes[i])) {
    throw new MemberNotVerified(member, 'confirmation-differs');
  }
  await deps.pins.save(me, member.user, fingerprint.text);
}

// ---- collections, groups, grants -------------------------------------------------------------

export async function createCollection(
  deps: SpaceDeps,
  detail: SpaceDetail,
  input: { name: string; parent?: string },
) {
  requireUnchained(detail);
  const spaceId = detail.view.space.id;
  const id = newId(deps);
  const made = await deps.crypto.newCollection({ spaceId, collectionId: id, name: input.name });
  return deps.api.createCollection(spaceId, {
    id,
    parent: input.parent ?? null,
    name: encodeB64(made.name),
    // The maker gets Manage, and the key sealed to them is all anyone else's grant adds to.
    keys: [
      {
        user: detail.view.me.user,
        sealed: encodeB64(made.sealedKey),
        signature: encodeB64(made.sealedKeySignature),
      },
    ],
  });
}

export async function renameCollection(
  deps: SpaceDeps,
  detail: SpaceDetail,
  collection: string,
  name: string,
) {
  requireUnchained(detail);
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
  requireUnchained(detail);
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
): Promise<Array<{ collection: string; user: string; sealed: string; signature: string }>> {
  requireUnchained(detail);
  const keys: Array<{ collection: string; user: string; sealed: string; signature: string }> = [];
  for (const user of after) {
    if (before.has(user)) continue;
    const member = detail.members.find((m) => m.user === user);
    if (!member || member.state !== 'confirmed') continue;
    // Checked before anything is sealed: a member whose keys can't be traced to a confirmation
    // stops the whole change, and the person is asked to confirm them again.
    const recipient = await recipientOf(deps, detail, member);
    keys.push({
      collection,
      user,
      ...(await collectionKeyFor(deps, detail.view.space.id, collection, recipient)),
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
  const keys: Array<{ collection: string; user: string; sealed: string; signature: string }> = [];
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
    keys: keys.map((k) => ({ user: k.user, sealed: k.sealed, signature: k.signature })),
  });
}
