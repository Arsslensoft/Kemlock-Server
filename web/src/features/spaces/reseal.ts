// Re-sealing the keys of a space with no chain (docs/crypto.md, "Signed key boxes", "Boxes made
// before this change"). An owner or admin makes fresh boxes of the keys they hold and signs each, so
// the members' clients find a signed box where an unsigned one was, and a space can be moved off
// boxes nobody signed without replacing its keys.
//
// Only to members this browser can trace (`verify.ts`), as for any key sealed to someone: one it
// can't is left out, and named, so a person can compare their fingerprint and try again. Only the
// collection keys this account holds are sealed again; a collection whose key no owner or admin
// holds stays as it is until its key is replaced.
import type { ResealRequest } from '@/api/spaces';
import { encodeB64 } from '@/lib/b64url';
import { signedInAccount } from './boxes';
import { type SpaceDeps, type SpaceDetail, SpaceNotChecked, collectionsOfMember } from './model';
import { MemberNotVerified, type Recipient, verifiedRecipient } from './verify';

export interface Resealed {
  /** How many members got new boxes. */
  resealed: number;
  /** The confirmed members this browser couldn't trace, who got none. */
  skipped: string[];
}

/** Seals the current space key, and the collection keys held, again to each confirmed member. */
export async function resealKeys(deps: SpaceDeps, detail: SpaceDetail): Promise<Resealed> {
  if (detail.trust && detail.trust.kind !== 'unchained') throw new SpaceNotChecked(detail.trust.kind);
  const { view, members } = detail;
  if (view.me.role !== 'owner' && view.me.role !== 'admin') {
    throw new Error('only an owner or admin seals the keys again');
  }
  if (!detail.readable) throw new Error('the keys of this space are not open here');
  const spaceId = view.space.id;
  const me = signedInAccount(deps, view.me.user);
  const held = new Set(view.collectionKeys.map((copy) => copy.collection));
  const ctx = { crypto: deps.crypto, spaceId, members, me, pins: deps.pins };

  const body: ResealRequest = { members: [] };
  const skipped: string[] = [];
  for (const member of members) {
    if (member.state !== 'confirmed') continue;
    let recipient: Recipient;
    try {
      recipient = await verifiedRecipient(ctx, member);
    } catch (error) {
      if (!(error instanceof MemberNotVerified)) throw error;
      skipped.push(member.user);
      continue;
    }
    const spaceBox = await deps.crypto.sealSpaceKeyTo({
      spaceId,
      recipientKx1: recipient.kx1,
      recipientId: recipient.id,
    });
    const collectionKeys: ResealRequest['members'][number]['collectionKeys'] = [];
    for (const collection of collectionsOfMember(member.user, view.collections, view.grants, view.groups)) {
      if (!held.has(collection)) continue;
      const box = await deps.crypto.sealCollectionKeyTo({
        spaceId,
        collectionId: collection,
        recipientKx1: recipient.kx1,
        recipientId: recipient.id,
      });
      collectionKeys.push({
        collection,
        sealed: encodeB64(box.sealed),
        signature: encodeB64(box.signature),
      });
    }
    body.members.push({
      user: member.user,
      sealedSpaceKey: encodeB64(spaceBox.sealed),
      sealedSpaceKeySignature: encodeB64(spaceBox.signature),
      collectionKeys,
    });
  }
  if (body.members.length === 0) return { resealed: 0, skipped };
  const done = await deps.api.reseal(spaceId, body);
  return { resealed: done.resealed, skipped };
}
