// Who a key may be sealed to. The server lists a space's members and their public-key bundles, but
// it is not trusted to say whose key is whose: a collection key sealed to a key the server chose is
// a collection key the server holds. So before any key is sealed to a member, this checks the
// bundle against what a person signed (docs/crypto.md, "Public-key bundle and fingerprint" and
// "Member confirmation"):
//
//  1. the bundle parses, is for the member's account, is at the member's current key version, and
//     is signed by its own key;
//  2. the member is confirmed, and their stored confirmation covers exactly this bundle: its
//     fingerprint is the bundle's, and its key version the bundle's;
//  3. the confirmer's signature over the confirmation verifies against the confirmer's own bundle,
//     which passes the same bundle checks, and the confirmer is trusted: me (against my own
//     fingerprint, not the server's copy of it), a member whose fingerprint a person compared in
//     this browser (a **pin**), or an owner, admin or manage-users member whose own confirmation
//     verifies the same way, down to one of those two.
//
// Every field the server lists, the creator and the roles included, is the server's word, so none
// of them makes a root: the walk ends at me or at a pin, and nowhere else. A server that swaps a
// member's bundle for its own fails step 2, and one that swaps two members' bundles and signs a
// confirmation with its own key for the first can't make the first one a pin. Only a space chain
// ties the roster itself to people (docs/crypto.md, "Space chain": "First contact"); this is what
// a space without one can check, and it trusts the server for which key version is current. A
// member who doesn't pass is not sealed to, and the error names the member whose fingerprint a
// person can compare to make them pass (`compare`), or they are confirmed again.
import type { MemberViewDto } from '@/api/spaces';
import { decodeB64 } from '@/lib/b64url';
import {
  type ParsedBundle,
  fingerprintBytes,
  fingerprintText,
  parseBundle,
  uuidBytes,
} from '@/sharing/bundle';
import type { PinStore } from '@/spaces/anchors';
import type { SpaceCrypto } from '@/spaces/crypto';

export type NotVerifiedReason =
  /** The bundle can't be read. */
  | 'unreadable'
  /** The bundle is another account's. */
  | 'wrong-account'
  /** The bundle isn't at the key version the member is at. */
  | 'wrong-key-version'
  /** The bundle isn't signed by its own key. */
  | 'bad-bundle-signature'
  /** The member isn't confirmed. */
  | 'not-confirmed'
  /** Nobody confirmed this member's keys. */
  | 'no-confirmation'
  /** The confirmation is of other keys than the bundle's. */
  | 'confirmation-differs'
  /** The confirmation's signature doesn't verify. */
  | 'bad-confirmation'
  /** The confirmer isn't someone who may confirm, or isn't listed. */
  | 'unknown-confirmer'
  /** The listed bundle of this account isn't the one this browser holds. */
  | 'own-keys';

/** A member this browser won't seal to, and why. */
export class MemberNotVerified extends Error {
  readonly member: MemberViewDto;
  readonly reason: NotVerifiedReason;
  /**
   * The member whose fingerprint a person could compare so this one passes: the confirmer the walk
   * ended at, which nobody here has compared. Absent when only confirming the member again helps.
   */
  readonly compare: MemberViewDto | undefined;

  constructor(member: MemberViewDto, reason: NotVerifiedReason, compare?: MemberViewDto) {
    super(`the keys of ${member.user} can't be verified (${reason})`);
    this.name = 'MemberNotVerified';
    this.member = member;
    this.reason = reason;
    this.compare = compare;
  }
}

/** What a key is sealed to. */
export interface Recipient {
  kx1: Uint8Array;
  id: Uint8Array;
}

/** What `verifiedRecipient` knows of the space. */
export interface RosterContext {
  crypto: SpaceCrypto;
  spaceId: string;
  /** The members as the server lists them. */
  members: MemberViewDto[];
  /** This account's id. */
  me: string;
  /** The members whose fingerprint a person compared in this browser; none are when left out. */
  pins?: PinStore | undefined;
}

/** The longest run of confirmers followed, so a long or looping roster ends. */
const MAX_DEPTH = 8;

function same(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  return diff === 0;
}

/**
 * The checks that tie a bundle to an account: it reads, it is the member's, at the member's key
 * version, signed by its own key. Throws `MemberNotVerified`.
 */
export async function checkBundle(
  crypto: SpaceCrypto,
  member: MemberViewDto,
): Promise<{ bytes: Uint8Array; parsed: ParsedBundle }> {
  let bytes: Uint8Array;
  let signature: Uint8Array;
  try {
    bytes = decodeB64(member.publicBundle);
    signature = decodeB64(member.bundleSignature);
  } catch {
    throw new MemberNotVerified(member, 'unreadable');
  }
  const parsed = parseBundle(bytes);
  if (!parsed) throw new MemberNotVerified(member, 'unreadable');
  let account: Uint8Array;
  try {
    account = uuidBytes(member.user);
  } catch {
    throw new MemberNotVerified(member, 'wrong-account');
  }
  if (!same(parsed.accountId, account)) throw new MemberNotVerified(member, 'wrong-account');
  if (parsed.keyVersion !== member.userKeyVersion) {
    throw new MemberNotVerified(member, 'wrong-key-version');
  }
  if (!(await crypto.verifyBundle(bytes, signature))) {
    throw new MemberNotVerified(member, 'bad-bundle-signature');
  }
  return { bytes, parsed };
}

async function verifyConfirmed(
  ctx: RosterContext,
  member: MemberViewDto,
  depth: number,
  seen: Set<string>,
): Promise<ParsedBundle> {
  if (member.state !== 'confirmed') throw new MemberNotVerified(member, 'not-confirmed');
  const { bytes, parsed } = await checkBundle(ctx.crypto, member);
  const fingerprint = await fingerprintBytes(bytes);

  // My own entry is checked against the keys this browser holds, not against the server's word.
  if (member.user === ctx.me) {
    if (fingerprintText(fingerprint) !== (await ctx.crypto.ownFingerprint())) {
      throw new MemberNotVerified(member, 'own-keys');
    }
    return parsed;
  }

  // A member whose fingerprint a person compared here, and whose keys are still those.
  if (ctx.pins && (await ctx.pins.load(ctx.me, member.user)) === fingerprintText(fingerprint)) {
    return parsed;
  }

  const confirmation = member.confirmation;
  if (member.needsReconfirmation) throw new MemberNotVerified(member, 'confirmation-differs');
  // Nobody confirmed them: only a person comparing their fingerprint here makes them a root.
  if (!confirmation) throw new MemberNotVerified(member, 'no-confirmation', member);

  let confirmed: Uint8Array;
  try {
    confirmed = decodeB64(confirmation.fingerprint);
  } catch {
    throw new MemberNotVerified(member, 'confirmation-differs');
  }
  if (!same(confirmed, fingerprint) || confirmation.memberKeyVersion !== parsed.keyVersion) {
    throw new MemberNotVerified(member, 'confirmation-differs');
  }

  // The confirmer: listed, confirmed, allowed to confirm, and themselves verified.
  if (depth >= MAX_DEPTH || seen.has(member.user)) {
    throw new MemberNotVerified(member, 'unknown-confirmer');
  }
  const confirmer = ctx.members.find((m) => m.user === confirmation.by);
  if (
    !confirmer ||
    confirmer.user === member.user ||
    !(
      confirmer.user === ctx.me ||
      confirmer.role === 'owner' ||
      confirmer.role === 'admin' ||
      confirmer.custom.includes('manage-users')
    )
  ) {
    throw new MemberNotVerified(member, 'unknown-confirmer');
  }
  try {
    await verifyConfirmed(ctx, confirmer, depth + 1, new Set(seen).add(member.user));
  } catch (error) {
    if (error instanceof MemberNotVerified) {
      throw new MemberNotVerified(member, 'unknown-confirmer', error.compare);
    }
    throw error;
  }
  let statement: Uint8Array;
  let signature: Uint8Array;
  try {
    statement = decodeB64(confirmation.statement);
    signature = decodeB64(confirmation.signature);
  } catch {
    throw new MemberNotVerified(member, 'bad-confirmation');
  }
  const ok = await ctx.crypto.verifyConfirmation({
    space: ctx.spaceId,
    member: member.user,
    memberKeyVersion: parsed.keyVersion,
    // The fingerprint worked out here from the bundle, not the one the server sent beside it.
    fingerprint,
    confirmerBundle: decodeB64(confirmer.publicBundle),
    statement,
    signature,
  });
  if (!ok) throw new MemberNotVerified(member, 'bad-confirmation');
  return parsed;
}

/**
 * The key and account id a key may be sealed to for `member`, after the checks above. Throws
 * `MemberNotVerified`, and the caller seals nothing then.
 */
export async function verifiedRecipient(
  ctx: RosterContext,
  member: MemberViewDto,
): Promise<Recipient> {
  const parsed = await verifyConfirmed(ctx, member, 0, new Set());
  return { kx1: parsed.kx1, id: parsed.accountId };
}
