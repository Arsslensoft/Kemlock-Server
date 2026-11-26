// Who may sign a space's manifest, for `SpaceSigner` (keeper.ts).
//
// docs/crypto.md ("Using the state", Manifest) accepts a space manifest only from a signer the
// verified space chain shows as `confirmed` with `edit` on at least one collection, and checks it
// with the bundle the chain records for that signer. That is what answers here for a space with a
// chain: the state the worker verified (`deps.chain`), never the server's member list. Access is
// by grant only, so an owner or admin who holds no editing grant doesn't sign.
//
// A space with no chain has no verified state, so the server's member list is all there is, and
// what can be checked is whose keys the bundle is: the signer must be listed as `confirmed`, hold
// `edit` on a collection (as owner or admin, or by a grant, direct or through a group), and their
// keys must trace to a confirmation this browser can follow to itself or to a fingerprint a person
// compared here (`verifiedRecipient`, src/features/spaces/verify.ts). A server that invented a
// member can't pass its own manifest off that way. This account's own keys are known for certain,
// and are held to the bundle they make.
//
// A space whose chain is refused, can't be read, or waits for first contact has no signer at all.
import type {
  CollectionPermission,
  GrantDto,
  GroupDto,
  MemberViewDto,
  SpaceViewDto,
  SpacesApi,
} from '@/api/spaces';
import type { CryptoPort } from '@/crypto-port';
import type { ChainView } from '@/crypto/types';
import type { SpaceTrust } from '@/features/spaces/chain';
import { MemberNotVerified, verifiedRecipient } from '@/features/spaces/verify';
import { decodeB64 } from '@/lib/b64url';
import { parseBundle } from '@/sharing/bundle';
import type { PinStore } from '@/spaces/anchors';
import type { SpaceCrypto } from '@/spaces/crypto';
import type { SpaceSigner } from './keeper';

const EDIT: string[] = ['edit', 'edit-hide-passwords', 'manage'];

export function uuidText(bytes: Uint8Array): string {
  const hex = [...bytes].map((byte) => byte.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/** Whether `member` may edit at least one collection: as owner or admin, or by a grant. */
export function canEditSomewhere(
  member: Pick<MemberViewDto, 'user' | 'role'>,
  view: { collections: Array<{ id: string }>; grants: GrantDto[]; groups: Array<Pick<GroupDto, 'id' | 'members'>> },
): boolean {
  if (view.collections.length === 0) return false;
  if (member.role === 'owner' || member.role === 'admin') return true;
  return editsByGrant(member.user, view);
}

/** Whether a grant to the account, or to a group it is in, lets it edit a collection that exists. */
function editsByGrant(
  user: string,
  view: {
    collections: Array<{ id: string }>;
    grants: Array<{ collection: string; grantee: string; permission: string | CollectionPermission }>;
    groups: Array<{ id: string; members: string[] }>;
  },
): boolean {
  return view.grants.some((grant) => {
    if (!EDIT.includes(grant.permission)) return false;
    if (!view.collections.some((collection) => collection.id === grant.collection)) return false;
    const [kind, id] = grant.grantee.split(':');
    if (kind === 'user') return id === user;
    if (kind === 'group') return view.groups.find((group) => group.id === id)?.members.includes(user) ?? false;
    return false;
  });
}

export interface SpaceSignerDeps {
  spaces: Pick<SpacesApi, 'members' | 'get'>;
  crypto: Pick<CryptoPort, 'fingerprint' | 'ownFingerprint'>;
  /** The signed-in account's id, or null. */
  accountId: () => string | null;
  /**
   * How far a space's chain can be trusted: reads it and verifies it in the worker, as the space
   * page does (`checkSpaceChain`). `verified` carries the state the worker holds.
   */
  chain: (space: string, me: string) => Promise<SpaceTrust>;
  /** What traces a member of a space with no chain: the worker's checks and this browser's pins. */
  trace: { crypto: SpaceCrypto; pins?: PinStore | undefined };
}

/** The bundle the chain records for `signer`, null unless it shows them confirmed with `edit`. A write signed before the member was taken out is still theirs (docs/crypto.md, "Signed item writes"), so for `former` a revoked member counts too; whether they could edit then isn't known. */
function chained(view: ChainView, signer: string, former: boolean): Uint8Array | null {
  const member = view.members.find((candidate) => candidate.id === signer);
  if (!member || !member.bundle) return null;
  if (member.status === 'confirmed') {
    if (!editsByGrant(signer, view)) return null;
  } else if (!(former && member.status === 'removed')) {
    return null;
  }
  let bundle: Uint8Array;
  try {
    bundle = decodeB64(member.bundle);
  } catch {
    return null;
  }
  const parsed = parseBundle(bundle);
  if (!parsed || uuidText(parsed.accountId) !== signer) return null;
  return bundle;
}

/** The member list's view of who may sign for a space with no chain: the bundle of `signer`, or null. */
async function unchained(
  deps: SpaceSignerDeps,
  space: string,
  signer: string,
  me: string,
  former: boolean,
): Promise<Uint8Array | null> {
  const [members, view]: [MemberViewDto[], SpaceViewDto] = await Promise.all([
    deps.spaces.members(space),
    deps.spaces.get(space),
  ]);
  // A write signed before the member was taken out is still theirs, so for `former` a revoked
  // member counts too; whether they could edit then isn't known.
  const member = members.find(
    (candidate) =>
      candidate.user === signer && (candidate.state === 'confirmed' || (former && candidate.state === 'revoked')),
  );
  if (!member) return null;
  if (member.state === 'confirmed' && !canEditSomewhere(member, view)) return null;
  let bundle: Uint8Array;
  try {
    bundle = decodeB64(member.publicBundle);
  } catch {
    return null;
  }
  const parsed = parseBundle(bundle);
  if (!parsed || uuidText(parsed.accountId) !== signer) return null;
  // The keys must be the ones a person, or someone this browser can trace to itself, confirmed.
  try {
    await verifiedRecipient(
      { crypto: deps.trace.crypto, spaceId: space, members, me, pins: deps.trace.pins },
      // A member taken out is traced as the member they were when they signed.
      member.state === 'revoked' ? { ...member, state: 'confirmed' } : member,
    );
  } catch (error) {
    if (error instanceof MemberNotVerified) return null;
    throw error;
  }
  return bundle;
}

/** Who may sign for `space`: the bundle of `signer`, or null. */
async function lookup(
  deps: SpaceSignerDeps,
  space: string,
  signer: string,
  former: boolean,
): Promise<Uint8Array | null> {
  const me = deps.accountId();
  if (me === null) return null;
  const trust = await deps.chain(space, me);
  if (trust.kind === 'verified') return chained(trust.view, signer, former);
  if (trust.kind !== 'unchained') return null;
  return unchained(deps, space, signer, me, former);
}

export function createSpaceSigner(deps: SpaceSignerDeps): SpaceSigner {
  const answer: SpaceSigner = async (space, signer, options) => {
    const bundle = await lookup(deps, space, signer, options?.former === true);
    if (!bundle) return null;
    if (signer === deps.accountId()) {
      // Our own keys are known for certain: the bundle must be the one they make.
      const own = await deps.crypto.ownFingerprint().catch(() => null);
      if (own === null || own !== (await deps.crypto.fingerprint(bundle))) return null;
    }
    return bundle;
  };
  // What it answers is the verified chain's, or keys traced to a confirmation this browser can follow:
  // vouched, so the write checker may pin a bundle taken from it (`writes.ts`).
  answer.vouched = true;
  return answer;
}
