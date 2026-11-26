// Who may sign a space's manifest, for `SpaceSigner` (keeper.ts).
//
// docs/crypto.md ("Using the state", Manifest) accepts a space manifest only from a signer the
// verified space chain shows as `confirmed` with `edit` on at least one collection, and checks it
// with the bundle the chain records for that signer.
//
// CHAIN HOOK: the web vault does not verify the space chain yet (another change adds it). Until it
// does, the answer here is the server's own: the signer must be listed as `confirmed`, and its
// bundle must be self-consistent (account, signature), and a signer that is this account is held
// to the bundle this browser's own keys make. For anyone else that only shows the bundle was made
// by someone with its key, not that the space confirmed them, so a server that invented a member
// could pass its own manifest off here. When the chain's verified state is available, replace
// `lookup` with a read of it: the recorded bundle of `signer`, null unless `confirmed` with edit.
import type { SpacesApi } from '@/api/spaces';
import type { CryptoPort } from '@/crypto-port';
import { decodeB64 } from '@/lib/b64url';
import { parseBundle } from '@/sharing/bundle';
import type { SpaceSigner } from './keeper';

function uuidText(bytes: Uint8Array): string {
  const hex = [...bytes].map((byte) => byte.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

export interface SpaceSignerDeps {
  spaces: Pick<SpacesApi, 'members'>;
  crypto: Pick<CryptoPort, 'verifyBundle' | 'fingerprint' | 'ownFingerprint'>;
  /** The signed-in account's id, or null. */
  accountId: () => string | null;
}

export function createSpaceSigner(deps: SpaceSignerDeps): SpaceSigner {
  return async (space, signer) => {
    const members = await deps.spaces.members(space);
    const member = members.find((candidate) => candidate.user === signer && candidate.state === 'confirmed');
    if (!member) return null;
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
    if (signer === deps.accountId()) {
      // Our own keys are known for certain: the bundle must be the one they make.
      const own = await deps.crypto.ownFingerprint().catch(() => null);
      if (own === null || own !== (await deps.crypto.fingerprint(bundle))) return null;
    }
    return bundle;
  };
}
