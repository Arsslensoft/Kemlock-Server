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
  OffboardedDto,
  ServedItemDto,
  SpaceRole,
  SpaceSummaryDto,
  SpaceViewDto,
  SpacesApi,
} from '@/api/spaces';
import { isApiError } from '@/api/errors';
import type { ItemDto } from '@/api/types';
import type { ChainBuilt, ChainChange, ChainReplacement, ChainView } from '@/crypto/types';
import { decodeB64, encodeB64 } from '@/lib/b64url';
import { type Manifest, ciphertextHash } from '@/manifest/format';
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
import { KeyBoxRefused, lazyContext, openKeyBox, openUnchainedKeys, signedInAccount } from './boxes';
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
  /** The time in Unix seconds, for the records this browser signs. */
  now?: () => number;
  /**
   * Told of the items of a space this browser wrote outside the vault's own writes (a key
   * replacement's), so the space's signed manifest lists them (src/manifest/keeper.ts).
   */
  wrote?: (items: ItemDto[]) => Promise<void>;
  /**
   * The last verified manifest of a space (src/manifest/keeper.ts): what an item has to match to be
   * re-written by a key replacement. Null when there is none; left out, it is none.
   */
  acceptedManifest?: (spaceId: string) => Promise<Manifest | null>;
  /**
   * The bundle `account` had at `version`, from the server's bundle history, when it is the one
   * this browser pinned while it was current (src/manifest/bundleHistory.ts); null for anything else.
   */
  pastBundle?: (account: string, version: number) => Promise<Uint8Array | null>;
}

/** Tells the manifest keeper, when there is one, of items this browser wrote. Never throws. */
function wrote(deps: SpaceDeps, items: ItemDto[]): void {
  if (items.length > 0) void deps.wrote?.(items)?.catch(() => undefined);
}

/**
 * A change asked of a space whose chain can't be used for it: one that isn't checked (`kind` says
 * how far it got), or one whose keys this browser couldn't open, so nothing can be signed.
 */
export class SpaceNotChecked extends Error {
  readonly kind: SpaceTrust['kind'];

  constructor(kind: SpaceTrust['kind']) {
    super(`the space can't be changed here (${kind})`);
    this.name = 'SpaceNotChecked';
    this.kind = kind;
  }
}

/** The chain's rules refuse a change (docs/crypto.md, "Verification": the reason names which). */
export class ChainRefused extends Error {
  readonly reason: string;
  readonly seq: number | null;

  constructor(reason: string, seq: number | null) {
    super(`the space's chain refuses the change (${reason})`);
    this.name = 'ChainRefused';
    this.reason = reason;
    this.seq = seq;
  }
}

/**
 * A key replacement that can't be made from here, and nothing was sent: the space is too large for
 * one request (the replaced keys and every item sealed again must land together, or the items
 * stay under keys nobody can open), or items the signed manifest lists can't be opened here, or
 * the space has no manifest to say which items to re-write.
 */
export class ReplaceBlocked extends Error {
  readonly reason: 'too-large' | 'unreadable' | 'no-manifest';
  readonly count: number;

  constructor(reason: ReplaceBlocked['reason'], count = 0) {
    super(`the keys can't be replaced from the web vault (${reason})`);
    this.name = 'ReplaceBlocked';
    this.reason = reason;
    this.count = count;
  }
}

/** Someone else added records to the space's chain at the same time, twice running. */
export class ChainConflict extends Error {
  constructor() {
    super('the space changed while the change was being made');
    this.name = 'ChainConflict';
  }
}

/**
 * Whether a change to this space is made as signed records (a space with a verified chain), or the
 * old way (a space with no chain). A space whose chain isn't checked is refused: nothing may be
 * sealed or signed for it. A change that makes a name or a key (`needsKeys`, the default) also
 * needs the space's keys open here; one that doesn't (an invitation, a role, a removal, a grant, a
 * confirmation) is made by an Admin who is still waiting for the space key, as the chain allows.
 */
function isChained(detail: Pick<SpaceDetail, 'trust' | 'readable'>, needsKeys = true): boolean {
  const trust = detail.trust;
  if (!trust || trust.kind === 'unchained') return false;
  if (trust.kind !== 'verified' || (needsKeys && !detail.readable)) {
    throw new SpaceNotChecked(trust.kind);
  }
  return true;
}

const newId = (deps: SpaceDeps) => (deps.newId ?? (() => globalThis.crypto.randomUUID()))();

const unixNow = (deps: SpaceDeps) => (deps.now ?? (() => Math.floor(Date.now() / 1000)))();

/** What an append gave: whether any record went in, and the chain as it verifies now. */
interface Appended {
  appended: boolean;
  chain: ChainView;
}

/** What `make` hands `appendBuilt`: the worker's answer, and the items to name held beside it. */
interface Made {
  built: ChainBuilt;
  held?: string[];
}

/**
 * The most one append request may weigh: the route reads 32 MiB from a member who may replace
 * keys (routes/space_chain.rs; 8 MiB from anyone else), less a margin for what the transport adds.
 * Each re-written item carries its signature (about 4.5 KiB), so this is roughly 5,000 items of
 * ordinary size.
 */
const MAX_REQUEST_BYTES = 32 * 1024 * 1024 - 256 * 1024;

/**
 * Makes records in the worker (`make`), appends them to the space's chain, and verifies the chain
 * again, which keeps this browser's anchor and the worker's state up to date. When the head moved
 * meanwhile (409), the chain is read and verified again and `make` runs again, on the new head
 * (it reads whatever it depends on again); a second conflict is shown. Resolves with the verified
 * chain, and whether any record was appended (a `seal` with nothing to share makes none).
 *
 * A key replacement's re-written items go up with its `keys` record, in one request and so one
 * transaction: once the new version is in the chain nobody can open an item left under the old one.
 * A request over the route's limit is never sent (`ReplaceBlocked`, `too-large`).
 */
async function appendBuilt(
  deps: SpaceDeps,
  detail: Pick<SpaceDetail, 'view'>,
  make: () => Promise<Made>,
): Promise<Appended> {
  const spaceId = detail.view.space.id;
  const me = detail.view.me.user;
  const attempt = async (): Promise<boolean> => {
    const { built, held = [] } = await make();
    if (!built.ok) throw new ChainRefused(built.reason, built.seq);
    if (built.records.length === 0) return false;
    const writes = built.writes ?? [];
    const request = {
      records: built.records,
      seals: built.seals,
      names: built.names,
      ...(held.length > 0 ? { held } : {}),
      ...(writes.length > 0 ? { writes } : {}),
    };
    if (JSON.stringify(request).length > MAX_REQUEST_BYTES) throw new ReplaceBlocked('too-large');
    await deps.api.appendChain(spaceId, request);
    wrote(
      deps,
      writes.map((write) => write.item),
    );
    return true;
  };
  const verified = async (): Promise<ChainView> => {
    const trust = await checkSpaceChain(deps, spaceId, me);
    if (trust.kind !== 'verified') throw new SpaceNotChecked(trust.kind);
    return trust.view;
  };
  let appended: boolean;
  try {
    appended = await attempt();
  } catch (error) {
    if (!isApiError(error, 'space-chain-conflict')) throw error;
    await verified();
    try {
      appended = await attempt();
    } catch (again) {
      if (isApiError(again, 'space-chain-conflict')) throw new ChainConflict();
      throw again;
    }
  }
  return { appended, chain: await verified() };
}

/** Makes the records of one change in the worker and appends them (see `appendBuilt`). */
function appendChange(
  deps: SpaceDeps,
  detail: Pick<SpaceDetail, 'view'>,
  change: ChainChange,
): Promise<Appended> {
  const spaceId = detail.view.space.id;
  return appendBuilt(deps, detail, async () => ({
    built: await deps.crypto.buildChainRecords({ spaceId, at: unixNow(deps), change }),
  }));
}

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

/**
 * Makes a space as a chain (docs/crypto.md, "Space chain"): the worker signs the `create` record
 * with my own key and seals the space key and the first collection's key to me, and the server
 * appends it and stores the boxes and names the record commits. Nothing the server can make up is
 * in it, so the space is mine from its first record. The chain is verified at once, which keeps
 * its anchor: this account's own key made it, so there is nothing to compare.
 */
export async function createSpace(deps: SpaceDeps, input: NewSpaceInput): Promise<SpaceViewDto> {
  const spaceId = newId(deps);
  const collectionId = newId(deps);
  const made = await deps.crypto.newChainedSpace({
    spaceId,
    collectionId,
    spaceName: input.name,
    collectionName: input.firstCollection,
    at: unixNow(deps),
  });
  await deps.api.appendChain(spaceId, {
    records: made.records,
    seals: made.seals,
    names: made.names,
  });
  const view = await deps.api.get(spaceId);
  const trust = await checkSpaceChain(deps, spaceId, view.me.user);
  if (trust.kind !== 'verified') {
    // The server took the record but what it serves back doesn't verify as this account's own.
    throw new SpaceNotChecked(trust.kind);
  }
  return view;
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
  /**
   * The member whose fingerprint a person should compare so the keys of a space with no chain open:
   * the member who sealed one of them, or the root of the confirmations that lead to them, whom this
   * browser can't trace yet (`startPin` asks for it).
   */
  compare?: string;
}

export async function loadSpaceDetail(deps: SpaceDeps, spaceId: string): Promise<SpaceDetail> {
  const [served, servedMembers] = await Promise.all([deps.api.get(spaceId), deps.api.members(spaceId)]);
  const me = signedInAccount(deps, served.me.user);
  const trust = await checkSpaceChain(deps, spaceId, me);
  let view = served;
  let members = servedMembers;
  let readable = false;
  let legacyKeys: string[] = [];
  let compare: string | undefined;
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
    } catch (error) {
      readable = false;
      // A sealer nobody here has compared: what would put it right is a person comparing their
      // fingerprint, as for first contact with a chain.
      if (error instanceof KeyBoxRefused && error.compare) compare = error.compare.user;
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
    ...(compare ? { compare } : {}),
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

/**
 * Invites an account. For a space with a chain, the account is looked up by its email (the inviter
 * needs its id) and the invitation is an `invite` record; the server mails the invitee when the
 * record lands. `detail` says which kind of space this is: left out, the space has no chain.
 */
export async function inviteMember(
  deps: SpaceDeps,
  spaceId: string,
  input: InviteInput,
  detail?: Pick<SpaceDetail, 'view' | 'trust' | 'readable'>,
): Promise<unknown> {
  const custom = input.role === 'custom' ? input.custom : [];
  if (detail && isChained(detail, false)) {
    const found = await deps.api.lookup(spaceId, input.email.trim());
    return appendChange(deps, detail, {
      action: 'invite',
      member: found.account,
      role: input.role,
      custom,
      grants: input.grants,
    });
  }
  return deps.api.invite(spaceId, {
    email: input.email.trim(),
    role: input.role,
    custom,
    grants: input.grants,
  });
}

export async function confirmMember(
  deps: SpaceDeps,
  detail: SpaceDetail,
  member: MemberViewDto,
  fingerprint: Fingerprint,
): Promise<unknown> {
  if (!fingerprint.consistent) {
    throw new Error('the fingerprint worked out here differs from the worker’s');
  }
  const chained = isChained(detail, false);
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
  if (chained) {
    // A record: the worker rebuilds the statement and signs it, seals the keys it holds to the
    // member (to the bundle the chain will record) and checks the fingerprint is this bundle's.
    return appendChange(deps, detail, {
      action: 'confirm',
      member: member.user,
      bundle: member.publicBundle,
      bundleSignature: member.bundleSignature,
      fingerprint: encodeB64(fingerprint.bytes),
    });
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
//
// A space with a chain changes by records the worker signs, checked against the chain's own rules
// (who may do what is the verifier's call, and a refusal is a `ChainRefused` with its reason). A
// space with none changes through the server's own routes, as it always did.

export async function createCollection(
  deps: SpaceDeps,
  detail: SpaceDetail,
  input: { name: string; parent?: string },
): Promise<unknown> {
  const spaceId = detail.view.space.id;
  const id = newId(deps);
  if (isChained(detail)) {
    // The maker is granted Manage, and the key is sealed to everyone the grants reach.
    return appendChange(deps, detail, {
      action: 'collection',
      collection: id,
      name: input.name,
      ...(input.parent ? { parent: input.parent } : {}),
    });
  }
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
): Promise<unknown> {
  if (isChained(detail)) {
    return appendChange(deps, detail, { action: 'rename', target: `collection:${collection}`, name });
  }
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

export async function deleteCollection(
  deps: SpaceDeps,
  detail: SpaceDetail,
  collection: string,
): Promise<unknown> {
  if (isChained(detail, false)) {
    return appendChange(deps, detail, { action: 'collection-delete', collection });
  }
  await deps.api.deleteCollection(detail.view.space.id, collection);
  return true;
}

export async function createGroup(
  deps: SpaceDeps,
  detail: SpaceDetail,
  input: { name: string; members: string[] },
): Promise<unknown> {
  const spaceId = detail.view.space.id;
  const id = newId(deps);
  if (isChained(detail)) {
    return appendChange(deps, detail, {
      action: 'group',
      group: id,
      name: input.name,
      members: input.members,
    });
  }
  const sealed = await deps.crypto.sealName({
    spaceId,
    keyVersion: detail.view.space.keyVersion,
    kind: 'group',
    id,
    name: input.name,
  });
  return deps.api.createGroup(spaceId, { id, name: encodeB64(sealed), members: input.members });
}

export async function deleteGroup(
  deps: SpaceDeps,
  detail: SpaceDetail,
  group: string,
): Promise<unknown> {
  if (isChained(detail, false)) return appendChange(deps, detail, { action: 'group-delete', group });
  await deps.api.deleteGroup(detail.view.space.id, group);
  return true;
}

/** Keys for the confirmed members a change newly lets into a collection. */
async function keysForNewcomers(
  deps: SpaceDeps,
  detail: SpaceDetail,
  collection: string,
  before: Set<string>,
  after: Set<string>,
): Promise<Array<{ collection: string; user: string; sealed: string; signature: string }>> {
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
): Promise<unknown> {
  const { grants, groups, collections } = detail.view;
  if (isChained(detail, false)) {
    const current = groups.find((g) => g.id === group)?.members ?? [];
    const add = members.filter((m) => !current.includes(m));
    const remove = current.filter((m) => !members.includes(m));
    if (add.length === 0 && remove.length === 0) return false;
    return appendChange(deps, detail, { action: 'group-members', group, add, remove });
  }
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
): Promise<unknown> {
  if (isChained(detail, false)) return appendChange(deps, detail, { action: 'grant', ...input });
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

export async function revokeGrant(
  deps: SpaceDeps,
  detail: SpaceDetail,
  collection: string,
  grantee: string,
): Promise<unknown> {
  if (isChained(detail, false)) return appendChange(deps, detail, { action: 'ungrant', collection, grantee });
  await deps.api.revokeGrant(detail.view.space.id, collection, grantee);
  return true;
}

// ---- roles and offboarding -----------------------------------------------------------------

export async function changeRole(
  deps: SpaceDeps,
  detail: SpaceDetail,
  user: string,
  role: SpaceRole,
  custom: CustomPermission[],
): Promise<unknown> {
  if (isChained(detail, false)) {
    return appendChange(deps, detail, {
      action: 'role',
      member: user,
      role,
      custom: role === 'custom' ? custom : [],
    });
  }
  return deps.api.changeRole(detail.view.space.id, user, role, custom);
}

/**
 * Revokes or removes a member. In a space with a chain both are the same record, `remove`: the
 * member ends up in no group and with no grant, and every key they held is marked for replacement.
 * What the chain says of the keys is the outcome, since the chain, not the server, is what marks
 * them.
 */
export async function offboardMember(
  deps: SpaceDeps,
  detail: SpaceDetail,
  user: string,
  kind: 'revoke' | 'remove',
): Promise<OffboardedDto> {
  const spaceId = detail.view.space.id;
  if (isChained(detail, false)) {
    const { chain } = await appendChange(deps, detail, { action: 'remove', member: user });
    return {
      exposed: [],
      keysPending: chain.space.marked || chain.collections.some((c) => c.marked),
    };
  }
  return kind === 'remove' ? deps.api.remove(spaceId, user) : deps.api.revoke(spaceId, user);
}

/**
 * Shares the keys this account holds with the members who are awaiting them ("Using the state",
 * "Sealing"): a member confirmed by someone who didn't hold a key waits for the next holder to
 * open the space. Makes no record when no one awaits a key this browser holds. Says whether it did.
 */
export async function sealPending(deps: SpaceDeps, detail: SpaceDetail): Promise<boolean> {
  if (detail.trust?.kind !== 'verified' || !detail.readable) return false;
  const { appended } = await appendChange(deps, detail, { action: 'seal' });
  return appended;
}

// ---- replacing the keys a removal marked -------------------------------------------------------

/** Items a batch write takes at most. */
const BATCH_SIZE = 500;

/** Whether the verified chain of this space has keys that wait to be replaced. */
export function keysAwaitReplacement(detail: Pick<SpaceDetail, 'trust'>): boolean {
  const trust = detail.trust;
  if (trust?.kind !== 'verified') return false;
  const { space, collections } = trust.view;
  return space.marked || collections.some((c) => c.marked);
}

/** Whether a grant, directly or through a group, lets `user` edit `collection`, as the chain has it. */
function editsByChain(user: string, collection: string, chain: ChainView): boolean {
  return chain.grants.some((grant) => {
    if (grant.collection !== collection) return false;
    if (!['edit', 'edit-hide-passwords', 'manage'].includes(grant.permission)) return false;
    const [kind, id] = grant.grantee.split(':');
    if (kind === 'user') return id === user;
    if (kind === 'group') return chain.groups.find((g) => g.id === id)?.members.includes(user) ?? false;
    return false;
  });
}

/**
 * Whether this account may replace the keys that wait, from here: the space's keys are open, and it
 * can edit a collection whose key is marked, or is an owner or admin and the space key is. The
 * worker leaves any other key alone, since an account that can't seal a collection's items again
 * would leave them under a key nobody can open.
 */
export function canReplaceKeys(detail: SpaceDetail): boolean {
  const trust = detail.trust;
  if (trust?.kind !== 'verified' || !detail.readable) return false;
  const { role, user } = detail.view.me;
  if (trust.view.space.marked && (role === 'owner' || role === 'admin')) return true;
  return trust.view.collections.some((c) => c.marked && editsByChain(user, c.id, trust.view));
}

export interface ReplaceProgress {
  /** `reading` the space's items, `sealing` them again in the worker, `sending` them. */
  phase: 'reading' | 'sealing' | 'sending';
  done: number;
  /** 0 while it isn't known yet. */
  total: number;
}

export interface Replaced {
  /** Items sealed again under their new key versions. */
  rewritten: number;
  /** Items named held: not in the signed manifest, so not taken as accepted. */
  held: number;
}

/** The live kem1 items of the space that `wanted` takes, as the server serves them. */
async function scanItems(
  deps: SpaceDeps,
  spaceId: string,
  wanted: (dto: ServedItemDto & { collectionId: string }) => boolean,
  progress: (p: ReplaceProgress) => void,
): Promise<ChainReplacement['items']> {
  const items: ChainReplacement['items'] = [];
  let since: string | undefined;
  let seen = 0;
  for (;;) {
    const page = await deps.api.sync(since, 500);
    for (const dto of page.items) {
      seen += 1;
      if (
        dto.owner === `space:${spaceId}` &&
        !dto.deleted &&
        dto.format === 'kem1' &&
        dto.collectionId &&
        dto.ciphertext &&
        dto.itemKey &&
        wanted({ ...dto, collectionId: dto.collectionId })
      ) {
        items.push({
          id: dto.id,
          collection: dto.collectionId,
          kind: dto.kind,
          revision: dto.revision,
          keyVersion: dto.keyVersion,
          ciphertext: dto.ciphertext,
          itemKey: dto.itemKey,
        });
      }
    }
    progress({ phase: 'reading', done: seen, total: 0 });
    if (!page.more) return items;
    since = page.cursor;
  }
}

/**
 * Splits items into those the last verified manifest of the space lists as they are (same id,
 * revision and ciphertext hash, not deleted), which are the ones accepted, and the rest. A removed
 * member's write under a key they kept, or anything newer than the manifest, is in the rest
 * ("Using the state", "Items": only what was accepted and listed is written again).
 */
async function acceptedOf(
  manifest: Manifest,
  items: ChainReplacement['items'],
): Promise<{ accepted: ChainReplacement['items']; rest: ChainReplacement['items'] }> {
  const entries = new Map(manifest.entries.map((entry) => [entry.id, entry]));
  const accepted: ChainReplacement['items'] = [];
  const rest: ChainReplacement['items'] = [];
  for (const item of items) {
    const entry = entries.get(item.id);
    const listed =
      entry !== undefined &&
      !entry.deleted &&
      entry.revision === item.revision &&
      entry.hash === (await ciphertextHash(decodeB64(item.ciphertext)));
    (listed ? accepted : rest).push(item);
  }
  return { accepted, rest };
}

/**
 * Replaces the keys that wait for it ("Removal and replacement"), all or nothing. The worker makes
 * the `keys` record and seals again every item of the replaced collections that the space's last
 * verified manifest lists as it is served; those it doesn't list are named held, which is all the
 * chain allows for an item nobody vouches for. Both go in one request, so the new versions and the
 * items under them land together: once they are in the chain nobody can open an item left under an
 * old version. When that can't be (the request is too large, an item the manifest lists doesn't
 * open here, the space has no manifest) nothing is sent and `ReplaceBlocked` says why. The items
 * and the names are read again if the head moved and the records are made again. `progress` says
 * how far it is.
 */
export async function replaceKeys(
  deps: SpaceDeps,
  detail: SpaceDetail,
  progress: (p: ReplaceProgress) => void = () => undefined,
): Promise<Replaced> {
  if (!isChained(detail) || !keysAwaitReplacement(detail)) return { rewritten: 0, held: 0 };
  const spaceId = detail.view.space.id;
  let counts: Replaced = { rewritten: 0, held: 0 };
  const sent = await appendBuilt(deps, detail, async () => {
    // Everything this depends on is read now, so a retry after a conflict builds on the new state.
    const trust = await checkSpaceChain(deps, spaceId, detail.view.me.user);
    if (trust.kind !== 'verified') throw new SpaceNotChecked(trust.kind);
    const marked = new Set(trust.view.collections.filter((c) => c.marked).map((c) => c.id));
    const served = await deps.api.get(spaceId);
    const live = await scanItems(
      deps,
      spaceId,
      // Items already held stay held: they aren't live, and the replacement doesn't name them.
      (dto) => marked.has(dto.collectionId) && !dto.held,
      progress,
    );
    const manifest = await deps.acceptedManifest?.(spaceId);
    if (!manifest && live.length > 0) throw new ReplaceBlocked('no-manifest', live.length);
    const { accepted, rest } = manifest ? await acceptedOf(manifest, live) : { accepted: [], rest: [] };
    // What the server holds of each name, to be sealed again when the space key is replaced.
    const names = [
      { target: 'space', sealed: served.space.name },
      ...served.collections.map((c) => ({ target: `collection:${c.id}`, sealed: c.name })),
      ...served.groups.map((g) => ({ target: `group:${g.id}`, sealed: g.name })),
    ];
    progress({ phase: 'sealing', done: 0, total: accepted.length });
    const built = await deps.crypto.buildKeyReplacement({
      spaceId,
      at: unixNow(deps),
      replacement: { items: accepted, names },
    });
    // An item the manifest lists that this unlock can't open can't be named held: it is the
    // member's own, and held it would be lost.
    if (built.ok && (built.held?.length ?? 0) > 0) {
      throw new ReplaceBlocked('unreadable', built.held?.length ?? 0);
    }
    // Only items of a collection the record replaces can be named held; the worker leaves a key
    // alone that it doesn't hold or can't edit, and the items of it stay as they are.
    const replaced = new Set(built.ok ? (built.rotated ?? []) : []);
    const unlisted = rest.filter((item) => replaced.has(`collection:${item.collection}`));
    counts = { rewritten: built.ok ? (built.writes?.length ?? 0) : 0, held: unlisted.length };
    return { built, held: unlisted.map((item) => item.id) };
  });
  if (!sent.appended) return { rewritten: 0, held: 0 };
  progress({ phase: 'sending', done: counts.rewritten, total: counts.rewritten });
  return counts;
}

// ---- sealing again what a replacement left under an old key ------------------------------------

/**
 * The live kem1 items of the space that are still under an older key version than their
 * collection's current one, and not held: what a replacement that stopped halfway left. (A held
 * item is a hold made on purpose, by this vault or an app, and isn't released from here.) Read from
 * the server's sync, so it is the same after a reload or on another device. A space whose keys were
 * never replaced has none, and isn't read.
 */
export async function itemsToReseal(
  deps: SpaceDeps,
  detail: Pick<SpaceDetail, 'view' | 'trust'>,
  progress: (p: ReplaceProgress) => void = () => undefined,
): Promise<ChainReplacement['items']> {
  const trust = detail.trust;
  if (trust?.kind !== 'verified' || !trust.view.collections.some((c) => c.keyVersion > 1)) return [];
  const versions = new Map(trust.view.collections.map((c) => [c.id, c.keyVersion]));
  return scanItems(
    deps,
    detail.view.space.id,
    (dto) => !dto.held && dto.keyVersion < (versions.get(dto.collectionId) ?? 0),
    progress,
  );
}

export interface Resealed {
  /** Items sealed again under their collection's current key version. */
  rewritten: number;
  /** Items this browser can't seal again: not in the signed manifest, or it holds no old key. */
  stuck: number;
}

/**
 * Seals again the items `itemsToReseal` finds that the last verified manifest lists as they are,
 * and writes them as the next revision under the current key version, in batches. The worker does
 * it with the old key it still holds from this unlock, so it works only in the session that
 * replaced the keys: after a reload the old key is gone and these items wait for the device that
 * replaced the keys, or an app that holds it. What it can't is counted as stuck. The space's signed
 * manifest lists what was written. `progress` says how far it is.
 */
export async function resealItems(
  deps: SpaceDeps,
  detail: SpaceDetail,
  progress: (p: ReplaceProgress) => void = () => undefined,
): Promise<Resealed> {
  if (!isChained(detail)) return { rewritten: 0, stuck: 0 };
  const spaceId = detail.view.space.id;
  const found = await itemsToReseal(deps, detail, progress);
  if (found.length === 0) return { rewritten: 0, stuck: 0 };
  const manifest = await deps.acceptedManifest?.(spaceId);
  const { accepted, rest } = manifest ? await acceptedOf(manifest, found) : { accepted: [], rest: found };
  if (accepted.length === 0) return { rewritten: 0, stuck: rest.length };
  progress({ phase: 'sealing', done: 0, total: accepted.length });
  const built = await deps.crypto.buildReseal({ spaceId, items: accepted });
  if (!built.ok) throw new ChainRefused(built.reason, built.seq);
  const writes = built.writes ?? [];
  let done = 0;
  progress({ phase: 'sending', done, total: writes.length });
  for (let at = 0; at < writes.length; at += BATCH_SIZE) {
    const batch = writes.slice(at, at + BATCH_SIZE);
    await deps.api.putBatch({
      writes: batch.map((write) => ({ expectedRevision: write.expectedRevision, item: write.item })),
    });
    wrote(
      deps,
      batch.map((write) => write.item),
    );
    done += batch.length;
    progress({ phase: 'sending', done, total: writes.length });
  }
  return { rewritten: writes.length, stuck: (built.held ?? []).length + rest.length };
}
