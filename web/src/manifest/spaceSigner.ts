// Who may sign a space's manifest, for `SpaceSigner` (keeper.ts).
//
// docs/crypto.md ("Using the state", Manifest) accepts a space manifest only from a signer the
// verified space chain shows as `confirmed` with `edit` on at least one collection, and checks it
// with the bundle the chain records for that signer.
//
// The web vault does not verify the space chain on this branch (another change adds it), so what
// answers here is the server's own view of the space, in `lookup` below: the signer must be listed
// as `confirmed`, hold `edit` on a collection (as owner or admin, or by a grant, direct or through
// a group), and have a bundle that is self-consistent (account, signature). For anyone but this
// account that only shows the bundle was made by someone holding its key, not that the space
// confirmed them, so a server that invented a member could pass its own manifest off here. This
// account's own keys are known for certain, and are held to the bundle they make.
//
// CHAIN HOOK: when the verified chain state is available, replace the body of `lookup` with a read
// of it: the bundle the chain records for `signer`, null unless the chain shows them `confirmed`
// with `edit` on at least one collection. Nothing else in this file needs to change.
import type {
  CollectionPermission,
  GrantDto,
  GroupDto,
  MemberViewDto,
  SpaceViewDto,
  SpacesApi,
} from '@/api/spaces';
import type { CryptoPort } from '@/crypto-port';
import { decodeB64 } from '@/lib/b64url';
import { parseBundle } from '@/sharing/bundle';
import type { SpaceSigner } from './keeper';

const EDIT: CollectionPermission[] = ['edit', 'edit-hide-passwords', 'manage'];

function uuidText(bytes: Uint8Array): string {
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
  return view.grants.some((grant) => {
    if (!EDIT.includes(grant.permission)) return false;
    if (!view.collections.some((collection) => collection.id === grant.collection)) return false;
    const [kind, id] = grant.grantee.split(':');
    if (kind === 'user') return id === member.user;
    if (kind === 'group') return view.groups.find((group) => group.id === id)?.members.includes(member.user) ?? false;
    return false;
  });
}

export interface SpaceSignerDeps {
  spaces: Pick<SpacesApi, 'members' | 'get'>;
  crypto: Pick<CryptoPort, 'verifyBundle' | 'fingerprint' | 'ownFingerprint'>;
  /** The signed-in account's id, or null. */
  accountId: () => string | null;
}

/** The server's view of who may sign for `space`: the bundle of `signer`, or null. CHAIN HOOK. */
async function lookup(deps: SpaceSignerDeps, space: string, signer: string): Promise<Uint8Array | null> {
  const [members, view]: [MemberViewDto[], SpaceViewDto] = await Promise.all([
    deps.spaces.members(space),
    deps.spaces.get(space),
  ]);
  const member = members.find((candidate) => candidate.user === signer && candidate.state === 'confirmed');
  if (!member || !canEditSomewhere(member, view)) return null;
  let bundle: Uint8Array;
  let signature: Uint8Array;
  try {
    bundle = decodeB64(member.publicBundle);
    signature = decodeB64(member.bundleSignature);
  } catch {
    return null;
  }
  const parsed = parseBundle(bundle);
  if (!parsed || uuidText(parsed.accountId) !== signer) return null;
  if (!(await deps.crypto.verifyBundle(bundle, signature))) return null;
  return bundle;
}

export function createSpaceSigner(deps: SpaceSignerDeps): SpaceSigner {
  return async (space, signer) => {
    const bundle = await lookup(deps, space, signer);
    if (!bundle) return null;
    if (signer === deps.accountId()) {
      // Our own keys are known for certain: the bundle must be the one they make.
      const own = await deps.crypto.ownFingerprint().catch(() => null);
      if (own === null || own !== (await deps.crypto.fingerprint(bundle))) return null;
    }
    return bundle;
  };
}
