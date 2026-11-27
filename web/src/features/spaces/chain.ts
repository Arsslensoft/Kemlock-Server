// A space's chain as the page uses it (docs/crypto.md, "Space chain"). The worker verifies the
// records the server serves and keeps the state; this reads them, keeps the anchor in this browser,
// asks the person to compare the fingerprint first contact needs, and says how far a space can be
// trusted:
//
//  - `unchained`: the server serves no chain, as for a space made before chains or through the
//    Bitwarden routes. Its roster is only as good as what `verify.ts` can check.
//  - `verified`: the chain verified, and first contact is done (the anchor is kept, or this
//    account's own key made the chain). Members, roles, grants, key versions and keys come from
//    the chain.
//  - `first-contact`: the chain verifies but nobody compared a fingerprint yet. No key is opened,
//    and nothing about the space is shown as checked.
//  - `unverified`: the chain didn't verify, or couldn't be read. The space is "can't be checked":
//    no key is opened, nothing is sealed, and its items aren't synced.
import type {
  CollectionPermission,
  CustomPermission,
  MemberDto,
  MemberViewDto,
  SpaceViewDto,
  SpacesApi,
} from '@/api/spaces';
import type { ChainAnchor, ChainMember, ChainView } from '@/crypto/types';
import { decodeB64 } from '@/lib/b64url';
import { type AnchorStore, type PinStore, memoryStores } from '@/spaces/anchors';
import type { SpaceCrypto } from '@/spaces/crypto';

export interface ChainDeps {
  api: SpacesApi;
  crypto: SpaceCrypto;
  /** Where this browser keeps its anchors; in memory for the page when left out. */
  anchors?: AnchorStore;
  /** Where it keeps the members whose fingerprint a person compared; in memory when left out. */
  pins?: PinStore;
  /**
   * The spaces the account's own signed manifest says have a chain: a space on the list that is
   * served no chain is a chain withheld, not a space without one. Throws when it can't be read.
   */
  chainedSpaces?: (() => Promise<ReadonlySet<string>>) | undefined;
  /** Told of a chain verified and trusted here, so that list gains the space. */
  noteChained?: ((spaceId: string) => void) | undefined;
}

export type SpaceTrust =
  | { kind: 'unchained' }
  | { kind: 'verified'; view: ChainView }
  | { kind: 'first-contact'; view: ChainView }
  | { kind: 'unverified'; reason: string; seq: number | null };

let fallback: ReturnType<typeof memoryStores> | undefined;

function storeOf(deps: ChainDeps): AnchorStore {
  if (deps.anchors) return deps.anchors;
  fallback ??= memoryStores();
  return fallback.anchors;
}

function classify(view: ChainView): SpaceTrust {
  if (!view.chained) return { kind: 'unchained' };
  return view.trusted ? { kind: 'verified', view } : { kind: 'first-contact', view };
}

/**
 * The anchor a verified chain gives: its head, epoch and links, with the owners at the head. The
 * promotions are the view's when it reports them, else those of the anchor kept before, so the
 * verifier gets back what it was told (`kept` is what this browser held when the chain was read).
 */
function anchorOf(view: ChainView, kept?: ChainAnchor): ChainAnchor | undefined {
  if (!view.head) return undefined;
  const promotions = view.promotions ?? kept?.promotions;
  return {
    seq: view.head.seq,
    epoch: view.epoch,
    links: view.links,
    ...(view.owners ? { owners: view.owners } : {}),
    ...(promotions ? { promotions } : {}),
  };
}

/**
 * Reads a space's chain and verifies it. A chain this unlock already verified is kept in the
 * worker; only when the server has records past its head is the whole chain read and verified
 * again. Anything that goes wrong (the server can't be reached, the anchor can't be read, a record
 * is refused) is `unverified`: a space whose chain can't be read is not read as one with none.
 */
export async function checkSpaceChain(
  deps: ChainDeps,
  spaceId: string,
  me: string,
): Promise<SpaceTrust> {
  try {
    const held = await deps.crypto.spaceChainView(spaceId);
    if (held?.chained && held.head) {
      const tail = await deps.api.chain(spaceId, held.head.seq + 1);
      if (tail.length === 0) return classify(held);
    }
    const store = storeOf(deps);
    const [records, anchor, listed] = await Promise.all([
      deps.api.chain(spaceId),
      store.load(me, spaceId),
      deps.chainedSpaces?.(),
    ]);
    // The account's own signed record says this space has a chain: the worker is told before it
    // reads what the server serves, so none served is a refusal there and its keys stay shut.
    if (listed?.has(spaceId)) await deps.crypto.expectChained(spaceId);
    const verdict = await deps.crypto.verifySpaceChain({
      spaceId,
      records,
      ...(anchor ? { anchor } : {}),
    });
    if (!verdict.ok) {
      // A chain that was refused is still a chain: remember it, so none served next is not "none".
      if (records.length > 0) await store.markSeen(me, spaceId);
      return { kind: 'unverified', reason: verdict.reason, seq: verdict.seq };
    }
    if (verdict.chained) {
      await store.markSeen(me, spaceId);
    } else if (await store.seen(me, spaceId)) {
      // This account has been served a chain for the space before (first contact may never have
      // been done, so there is no anchor): a server that serves none now has taken it back.
      return { kind: 'unverified', reason: 'rolled back', seq: null };
    }
    // The anchor is kept once first contact is done, and moves forward with every chain verified.
    const next = verdict.chained && verdict.trusted ? anchorOf(verdict, anchor) : undefined;
    if (next) deps.noteChained?.(spaceId);
    if (next) await store.save(me, spaceId, next, verdict.divergence !== undefined);
    return classify(verdict);
  } catch {
    return { kind: 'unverified', reason: 'unreachable', seq: null };
  }
}

/**
 * The person compared the fingerprint and it matched: the worker trusts the chain from now on, and
 * this browser keeps the anchor at the head that was compared.
 */
export async function acceptFirstContact(
  deps: ChainDeps,
  spaceId: string,
  me: string,
): Promise<SpaceTrust> {
  await deps.crypto.acceptFirstContact(spaceId);
  const view = await deps.crypto.spaceChainView(spaceId);
  if (!view?.chained) return { kind: 'unverified', reason: 'unreachable', seq: null };
  const anchor = anchorOf(view);
  if (anchor) await storeOf(deps).save(me, spaceId, anchor);
  return classify(view);
}

/** What a space is called in one of its keys' lists: the key of the space or of a collection. */
function chainKeyOf(collection: string | null): string {
  return collection === null ? 'space' : `collection:${collection}`;
}

/**
 * Opens one key through the chain (`collection` null is the space key): at the chain's current key
 * version, under the commitment's digest, the box's aad and the key check (`open_key`). Throws when
 * the chain has no seal of it for this account or any of those checks fails.
 */
export async function openChainedKey(
  deps: ChainDeps,
  spaceId: string,
  chain: ChainView,
  collection: string | null,
  servedVersion: number,
  sealed: string,
): Promise<void> {
  const key = chainKeyOf(collection);
  const held = chain.keys.find((k) => k.key === key);
  if (!held || held.sealSeq === undefined) {
    throw new Error('the chain has no seal of this key for this account');
  }
  const list = held.needsList ? await deps.api.chainSeals(spaceId, held.sealSeq) : undefined;
  await deps.crypto.openChainKey({
    spaceId,
    key,
    servedVersion,
    sealed: decodeB64(sealed),
    ...(list ? { list } : {}),
  });
}

/**
 * Opens the space key and the collection keys this account holds, through the chain. The space key
 * must open; a collection key that doesn't is left out of what is returned, as one this account
 * doesn't hold.
 */
export async function openChainedKeys(
  deps: ChainDeps,
  spaceId: string,
  chain: ChainView,
  view: Pick<SpaceViewDto, 'me' | 'space' | 'collectionKeys'>,
): Promise<Set<string>> {
  const sealedSpaceKey = view.me.sealedSpaceKey;
  if (!sealedSpaceKey) throw new Error('the space key is not sealed to this account yet');
  await openChainedKey(
    deps,
    spaceId,
    chain,
    null,
    view.me.keyVersion ?? view.space.keyVersion,
    sealedSpaceKey,
  );
  const opened = new Set<string>();
  for (const copy of view.collectionKeys) {
    try {
      await openChainedKey(deps, spaceId, chain, copy.collection, copy.keyVersion, copy.sealed);
      opened.add(copy.collection);
    } catch {
      // A collection whose key doesn't check against the chain is one this account can't open.
    }
  }
  return opened;
}

const CHAIN_STATE: Record<ChainMember['status'], MemberDto['state']> = {
  invited: 'invited',
  confirmed: 'confirmed',
  removed: 'revoked',
};

/** A member the chain has and the server's list doesn't: only what the chain says of them. */
function unlisted(member: ChainMember): MemberViewDto {
  return {
    user: member.id,
    role: member.role,
    custom: member.custom as CustomPermission[],
    state: CHAIN_STATE[member.status],
    invitedBy: member.invitedBy,
    invitedAt: 0,
    acceptedAt: null,
    sealedSpaceKey: null,
    keyVersion: null,
    confirmation: null,
    revokedAt: null,
    email: member.id,
    name: null,
    publicBundle: member.bundle ?? '',
    bundleSignature: '',
    userKeyVersion: member.bundleVersion ?? 0,
    needsReconfirmation: false,
  };
}

/**
 * The space as the verified chain says it is: who is in it and in what role, the collections and
 * their key versions, the groups and who is in them, and the grants. The server's lists give
 * names, emails and times and nothing else; a member the chain doesn't have, a collection or
 * group it doesn't have, and a grant it doesn't have are dropped. The one thing taken from the
 * server beside names and times is a newer bundle of a confirmed member than the chain's, which
 * is what asks for a new confirmation.
 */
export function overlayChain(
  view: SpaceViewDto,
  members: MemberViewDto[],
  chain: ChainView,
): { view: SpaceViewDto; members: MemberViewDto[] } {
  const serverMember = new Map(members.map((m) => [m.user, m]));
  const merged: MemberViewDto[] = [];
  for (const chained of chain.members) {
    if (chained.status === 'removed') continue;
    const server = serverMember.get(chained.id) ?? unlisted(chained);
    const state: MemberDto['state'] =
      chained.status === 'confirmed'
        ? 'confirmed'
        : server.state === 'accepted'
          ? 'accepted'
          : 'invited';
    // A confirmed member's keys are the chain's. When the server lists keys of a newer version
    // (the member replaced them since), those are shown instead, and the member is to be confirmed
    // again: a person compares the new fingerprint, and a `confirm` record makes the chain's
    // bundle the new one. Until then keys are sealed to the chain's bundle only.
    const newer =
      serverMember.has(chained.id) &&
      chained.bundleVersion !== undefined &&
      server.userKeyVersion > chained.bundleVersion;
    merged.push({
      ...server,
      role: chained.role,
      custom: chained.custom as CustomPermission[],
      state,
      invitedBy: chained.invitedBy,
      ...(chained.bundle && !newer
        ? { publicBundle: chained.bundle, userKeyVersion: chained.bundleVersion ?? server.userKeyVersion }
        : {}),
      ...(newer && chained.status === 'confirmed' ? { needsReconfirmation: true } : {}),
    });
  }
  const me = merged.find((m) => m.user === view.me.user);
  const chainedCollection = new Map(chain.collections.map((c) => [c.id, c]));
  const chainedGroup = new Map(chain.groups.map((g) => [g.id, g]));
  return {
    members: merged,
    view: {
      ...view,
      space: { ...view.space, keyVersion: chain.space.keyVersion },
      me: me
        ? { ...view.me, role: me.role, custom: me.custom, state: me.state, invitedBy: me.invitedBy }
        : view.me,
      collections: view.collections
        .filter((c) => chainedCollection.has(c.id))
        .map((c) => {
          const chained = chainedCollection.get(c.id);
          return { ...c, keyVersion: chained?.keyVersion ?? c.keyVersion, parent: chained?.parent ?? null };
        }),
      groups: view.groups
        .filter((g) => chainedGroup.has(g.id))
        .map((g) => ({ ...g, members: chainedGroup.get(g.id)?.members ?? [] })),
      grants: chain.grants.map((g) => ({
        collection: g.collection,
        grantee: g.grantee,
        permission: g.permission as CollectionPermission,
      })),
    },
  };
}

/** The name version a name of the chained space must be opened at: the one the chain recorded. */
export function nameVersionOf(
  chain: ChainView,
  kind: 'space' | 'collection' | 'group',
  id: string,
): number {
  if (kind === 'space') return chain.space.nameVersion;
  const found =
    kind === 'collection'
      ? chain.collections.find((c) => c.id === id)
      : chain.groups.find((g) => g.id === id);
  return found?.nameVersion ?? 0;
}
