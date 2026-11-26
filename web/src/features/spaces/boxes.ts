// Who sealed the keys this account is handed, for a space with no chain (docs/crypto.md, "Signed key
// boxes"). A sealed box is anonymous: whoever knows my public key can seal anything to it, and a
// server that makes a collection key of its own and serves it to me would read what I then write to
// that collection. A space with a verified chain commits every box in the chain and needs none of
// this; here, before a key is opened, the member who sealed it must have signed it, and I must be
// able to trace that member to myself or to a fingerprint a person compared:
//
//  1. a signed box opens when the sealer's signature verifies over the statement rebuilt here (the
//     space, key version and recipient are what is being opened, not what the server says), under
//     the key of the sealer's bundle, and the sealer is me, or a confirmed member whose bundle
//     passes `verify.ts` (it traces to me or to a pin), at the key version the signature names, who
//     held authority to seal that key;
//  2. a box this browser already accepted (the same SHA-256 for the same space, key and version)
//     opens again without asking who sealed it, so a sealer who left or changed keys doesn't lock a
//     member out of a key they hold;
//  3. a box made before keys were signed has no signature. It is accepted and remembered once per
//     (space, key, version), flagged "sealed before keys were signed", unless this browser already
//     accepted a different box for it, or any signed box of the space (every box made since keys
//     were signed carries a signature, so an unsigned one this browser hadn't already accepted is
//     a signature taken away, or a key the server made). An owner or admin replaces such boxes with
//     signed ones by re-sealing the keys, and a key replacement or a new confirmation does too.
//
// Anything else is refused, and the space's keys show as "can't be checked".
import type { GrantDto, GroupDto, KeyCopyDto, MemberDto, MemberViewDto, SealedByDto } from '@/api/spaces';
import { decodeB64, encodeB64 } from '@/lib/b64url';
import { parseBundle, uuidBytes } from '@/sharing/bundle';
import { type BoxStore, type KeyRef, memoryBoxStore } from '@/spaces/boxstore';
import type { SpaceDeps } from './model';
import { MemberNotVerified, verifiedRecipient } from './verify';

export type BoxRefusal =
  /** The sealer isn't a member the server lists. */
  | 'sealer-unknown'
  /** The sealer's keys can't be traced to me or to a fingerprint a person compared. */
  | 'sealer-not-verified'
  /** The signature names another key version of the sealer than their bundle is at. */
  | 'sealer-version'
  /** The sealer couldn't have been allowed to seal this key. */
  | 'sealer-not-allowed'
  /** The signature isn't the sealer's over this box. */
  | 'bad-signature'
  /** An unsigned box that isn't the one accepted before for this key and version. */
  | 'unsigned-changed'
  /** An unsigned box of a key whose signed box was accepted at this version or a later one. */
  | 'unsigned-downgrade';

/** A key box this browser won't open, and why. */
export class KeyBoxRefused extends Error {
  readonly key: KeyRef;
  readonly reason: BoxRefusal;
  /**
   * For a sealer this browser couldn't trace: the member whose fingerprint a person could compare so
   * they can (the sealer, or the root of the confirmations that lead to them), as `MemberNotVerified`
   * names it. Comparing is how a space with no chain is first trusted here, as first contact is for a
   * chain.
   */
  readonly compare: MemberViewDto | undefined;

  constructor(key: KeyRef, reason: BoxRefusal, compare?: MemberViewDto) {
    super(`the ${key} key box can't be checked (${reason})`);
    this.name = 'KeyBoxRefused';
    this.key = key;
    this.reason = reason;
    this.compare = compare;
  }
}

/** The server names an account as mine that isn't the one signed in here. */
export class WrongAccount extends Error {
  constructor() {
    super('the server names another account as this one');
    this.name = 'WrongAccount';
  }
}

/**
 * The id of the account signed in here, which keys what this browser keeps (the accepted key boxes,
 * the chain anchors, the pins). The server's `me.user` is its word, so it is only checked against
 * that id and never used in its place: a server that served another id would get an empty record
 * and have a forged box accepted as the first one. Throws `WrongAccount` when they differ.
 */
export function signedInAccount(deps: SpaceDeps, served: string): string {
  if (!deps.account) return served;
  const own = deps.account();
  if (!own || own !== served) throw new WrongAccount();
  return own;
}

/** The key a box holds: the space's own key, or one collection's. */
export type BoxKey = 'space' | { collection: string };

export const keyRef = (key: BoxKey): KeyRef =>
  key === 'space' ? 'space' : `collection:${key.collection}`;

/** What opening needs of the space: the page's dependencies, who I am, and the server's roster. */
export interface BoxContext {
  deps: SpaceDeps;
  spaceId: string;
  /** This account's id. */
  me: string;
  /** The members as the server lists them; fetched only when a box has to be checked. */
  members: () => Promise<MemberViewDto[]>;
  /** The grants and groups as the server lists them; needed only for a collection key's sealer. */
  access: () => Promise<{ grants: GrantDto[]; groups: GroupDto[] }>;
}

/** A box about to be opened. */
export interface BoxToOpen {
  key: BoxKey;
  /** The version of the key it holds. */
  version: number;
  /** The box, base64url. */
  sealed: string;
  /** Who sealed it and their signature, as the server serves them. */
  sealedBy: SealedByDto | null | undefined;
}

const fallbacks = new WeakMap<object, BoxStore>();

function storeOf(deps: SpaceDeps): BoxStore {
  if (deps.boxes) return deps.boxes;
  let kept = fallbacks.get(deps);
  if (!kept) {
    kept = memoryBoxStore();
    fallbacks.set(deps, kept);
  }
  return kept;
}

async function sha256(bytes: Uint8Array): Promise<string> {
  const digest = await globalThis.crypto.subtle.digest('SHA-256', bytes as BufferSource);
  return encodeB64(new Uint8Array(digest));
}

/** Which of a collection's grants reach `user`, directly or through a group. */
function grantsOf(
  user: string,
  collection: string,
  grants: GrantDto[],
  groups: GroupDto[],
): { holds: boolean; manage: boolean } {
  let holds = false;
  let manage = false;
  for (const grant of grants) {
    if (grant.collection !== collection) continue;
    const [kind, id] = grant.grantee.split(':');
    const reaches =
      kind === 'user'
        ? id === user
        : kind === 'group' && (groups.find((g) => g.id === id)?.members.includes(user) ?? false);
    if (!reaches) continue;
    holds = true;
    if (grant.permission === 'manage') manage = true;
  }
  return { holds, manage };
}

/**
 * Whether `sealer` could be allowed to seal this key to someone, by the roles and grants the server
 * lists (docs/crypto.md, "Signed key boxes"): the server's word on who is who, which only narrows
 * what a sealer who really is a member could have done, since nobody but the sealer can sign.
 */
async function mayGrant(ctx: BoxContext, sealer: MemberViewDto, key: BoxKey): Promise<boolean> {
  if (sealer.role === 'owner' || sealer.role === 'admin') return true;
  if (key === 'space') return sealer.custom.includes('manage-users');
  const { grants, groups } = await ctx.access();
  const { holds, manage } = grantsOf(sealer.user, key.collection, grants, groups);
  return manage || (holds && (sealer.custom.includes('manage-users') || sealer.custom.includes('manage-groups')));
}

/**
 * The sealer's bundle at the key version their signature names, so a box they signed before their
 * account moved to a new key version still verifies against the keys that signed it.
 *
 * MERGE: only the bundle the server lists now is known here, so this returns it when its key
 * version is the one asked for and nothing otherwise. The branch that serves bundles by key version
 * (the bundle history) replaces the body, and checks that each bundle in the history is signed by
 * the one before it, with the newest being the listed one `verifiedRecipient` traced.
 */
async function bundleAt(
  _ctx: BoxContext,
  sealer: MemberViewDto,
  keyVersion: number,
): Promise<Uint8Array | undefined> {
  const current = decodeB64(sealer.publicBundle);
  return parseBundle(current)?.keyVersion === keyVersion ? current : undefined;
}

/** Checks a signed box's signature and the sealer behind it; throws `KeyBoxRefused`. */
async function checkSigned(
  ctx: BoxContext,
  box: BoxToOpen,
  bytes: Uint8Array,
  sealedBy: SealedByDto,
): Promise<void> {
  const ref = keyRef(box.key);
  const refuse = (reason: BoxRefusal) => new KeyBoxRefused(ref, reason);
  const members = await ctx.members();
  const sealer = members.find((m) => m.user === sealedBy.account);
  if (!sealer) throw refuse('sealer-unknown');
  // The sealer's bundle is theirs, signed by itself, at their current key version, and their
  // confirmation traces to me or to a pin; for myself, it is the bundle this browser holds.
  try {
    await verifiedRecipient(
      { crypto: ctx.deps.crypto, spaceId: ctx.spaceId, members, me: ctx.me, pins: ctx.deps.pins },
      sealer,
    );
  } catch (error) {
    if (error instanceof MemberNotVerified) {
      throw new KeyBoxRefused(ref, 'sealer-not-verified', error.compare);
    }
    throw error;
  }
  let signature: Uint8Array;
  let bundle: Uint8Array | undefined;
  try {
    signature = decodeB64(sealedBy.signature);
    bundle = await bundleAt(ctx, sealer, sealedBy.keyVersion);
  } catch {
    throw refuse('bad-signature');
  }
  if (!bundle) throw refuse('sealer-version');
  if (sealer.user !== ctx.me && !(await mayGrant(ctx, sealer, box.key))) {
    throw refuse('sealer-not-allowed');
  }
  const ok = await ctx.deps.crypto.verifyKeyBox({
    sealerBundle: bundle,
    spaceId: ctx.spaceId,
    ...(box.key === 'space' ? {} : { collectionId: box.key.collection }),
    keyVersion: box.version,
    recipientId: uuidBytes(ctx.me),
    sealed: bytes,
    signature,
  });
  if (!ok) throw refuse('bad-signature');
}

async function openIn(ctx: BoxContext, box: BoxToOpen, sealed: Uint8Array): Promise<void> {
  if (box.key === 'space') {
    await ctx.deps.crypto.openSpace({ spaceId: ctx.spaceId, keyVersion: box.version, sealed });
  } else {
    await ctx.deps.crypto.openCollection({
      spaceId: ctx.spaceId,
      collectionId: box.key.collection,
      keyVersion: box.version,
      sealed,
    });
  }
}

/**
 * Opens one key box after the checks above and keeps what it accepted. Resolves with whether the box
 * is one from before keys were signed; throws `KeyBoxRefused` for a box that fails them, and what
 * the worker throws when the box doesn't open.
 */
export async function openKeyBox(ctx: BoxContext, box: BoxToOpen): Promise<{ legacy: boolean }> {
  const ref = keyRef(box.key);
  const store = storeOf(ctx.deps);
  let bytes: Uint8Array;
  try {
    bytes = decodeB64(box.sealed);
  } catch {
    throw new KeyBoxRefused(ref, 'bad-signature');
  }
  const hash = await sha256(bytes);
  const kept = await store.load(ctx.me, ctx.spaceId, ref, box.version);

  // A box accepted before: again without asking who sealed it.
  if (kept?.hash === hash) {
    await openIn(ctx, box, bytes);
    return { legacy: !kept.signed };
  }

  if (box.sealedBy) {
    await checkSigned(ctx, box, bytes, box.sealedBy);
    await openIn(ctx, box, bytes);
    await store.save(ctx.me, ctx.spaceId, ref, box.version, { hash, signed: true });
    return { legacy: false };
  }

  // A box from before keys were signed: once per (space, key, version), never in place of a different
  // one that was accepted, and never once this browser accepted any signed box of the space: every
  // box made since signing began carries a signature, so one without that this browser hadn't
  // already accepted is a signature taken away, or a key the server made.
  if (kept) throw new KeyBoxRefused(ref, 'unsigned-changed');
  if (await store.hasSigned(ctx.me, ctx.spaceId)) throw new KeyBoxRefused(ref, 'unsigned-downgrade');
  await openIn(ctx, box, bytes);
  await store.save(ctx.me, ctx.spaceId, ref, box.version, { hash, signed: false });
  return { legacy: true };
}

/** What a space with no chain serves to this account: its own copy of the space key and the collection keys. */
export interface UnchainedKeys {
  me: Pick<MemberDto, 'sealedSpaceKey' | 'sealedBy' | 'keyVersion'>;
  /** The space key's current version, when the member's own copy names none. */
  spaceKeyVersion: number;
  collectionKeys: KeyCopyDto[];
}

/**
 * Opens the space key and every collection key served to this account, each through `openKeyBox`.
 * Resolves with the keys that are from before keys were signed (`space`, or `collection:<id>`).
 */
export async function openUnchainedKeys(ctx: BoxContext, served: UnchainedKeys): Promise<KeyRef[]> {
  const sealed = served.me.sealedSpaceKey;
  if (!sealed) throw new Error('the space key is not sealed to this account yet');
  const boxes: BoxToOpen[] = [
    {
      key: 'space',
      version: served.me.keyVersion ?? served.spaceKeyVersion,
      sealed,
      sealedBy: served.me.sealedBy,
    },
    ...served.collectionKeys.map((copy) => ({
      key: { collection: copy.collection } as BoxKey,
      version: copy.keyVersion,
      sealed: copy.sealed,
      sealedBy: copy.sealedBy,
    })),
  ];
  // The boxes from before keys were signed come first: once a signed box has been accepted, an
  // unsigned one this browser hadn't already accepted is refused, and one pass of a space that is
  // part way through being signed must not depend on the order the server lists its keys in.
  const ordered = [...boxes.filter((b) => !b.sealedBy), ...boxes.filter((b) => b.sealedBy)];
  const legacy: KeyRef[] = [];
  for (const box of ordered) {
    const opened = await openKeyBox(ctx, box);
    if (opened.legacy) legacy.push(keyRef(box.key));
  }
  return legacy;
}

/** A context whose roster and access lists are read from the server the first time they are needed. */
export function lazyContext(deps: SpaceDeps, spaceId: string, me: string): BoxContext {
  let members: Promise<MemberViewDto[]> | undefined;
  return {
    deps,
    spaceId,
    me,
    members: () => {
      members ??= deps.api.members(spaceId);
      return members;
    },
    access: async () => {
      const view = await deps.api.get(spaceId);
      return { grants: view.grants, groups: view.groups };
    },
  };
}
