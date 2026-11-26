// @vitest-environment node
import { describe, expect, it, vi } from 'vitest';
import type { ChainMember, ChainView } from '@/crypto/types';
import { type AnchorStore, memoryAnchorStore } from '@/spaces/anchors';
import { NO_CHAIN, fakeSpaceCrypto } from '@/test/fake-space-crypto';
import {
  type ChainDeps,
  acceptFirstContact,
  checkSpaceChain,
  openChainedKeys,
  overlayChain,
} from './chain';
import {
  FINANCE,
  INFRA,
  LEE,
  ME,
  OPS,
  SPACE,
  THEO,
  detail,
  fakeSpacesApi,
  members,
  spaceView,
} from './fixtures';
import { type SpaceDeps, SpaceNotChecked, confirmMember, loadSpaceDetail, loadSpaceList } from './model';

const AT = 'bGluaw';

function chainMember(id: string, role: ChainMember['role'], status: ChainMember['status'] = 'confirmed'): ChainMember {
  return { id, role, custom: [], status, invitedBy: ME, ...(status === 'confirmed' ? { bundleVersion: 1 } : {}) };
}

/** A chain as the worker would report it once it verified: Sam owns it, Lee is in group Ops. */
function view(over: Partial<ChainView> = {}): ChainView {
  return {
    ...NO_CHAIN,
    chained: true,
    head: { seq: 4, link: AT },
    epoch: 1,
    links: ['l0', 'l1', 'l2', 'l3', 'l4'],
    trusted: true,
    members: [chainMember(ME, 'owner'), chainMember(LEE, 'admin'), chainMember(THEO, 'member', 'invited')],
    space: { keyVersion: 1, marked: false, nameHash: 'h', nameVersion: 1 },
    collections: [
      { id: INFRA, keyVersion: 1, marked: false, nameHash: 'h', nameVersion: 1 },
      { id: FINANCE, keyVersion: 1, marked: false, nameHash: 'h', nameVersion: 1 },
    ],
    groups: [{ id: OPS, members: [LEE], nameHash: 'h', nameVersion: 1 }],
    grants: [{ collection: INFRA, grantee: `group:${OPS}`, permission: 'edit' }],
    keys: [
      { key: 'space', version: 1, marked: false, sealSeq: 0, needsList: false },
      { key: `collection:${INFRA}`, version: 1, marked: false, sealSeq: 1, needsList: false },
      { key: `collection:${FINANCE}`, version: 1, marked: false, sealSeq: 2, needsList: true },
    ],
    ...over,
  };
}

function setup(chain: typeof NO_CHAIN | ReturnType<typeof view> | { ok: false; reason: string; seq: number | null } = NO_CHAIN) {
  const api = fakeSpacesApi();
  const crypto = fakeSpaceCrypto();
  crypto.chain = chain;
  const anchors = memoryAnchorStore();
  // One record is served, whatever the head: what the verifier does with it is the fake's answer.
  api.chain.mockImplementation(async (_space, from) =>
    from === undefined || from === 0 ? [{ entry: 'ZQ', signature: 'cw' }] : [],
  );
  const deps: SpaceDeps = { api, crypto, anchors };
  return { api, crypto, anchors, deps };
}

describe('checking a space’s chain', () => {
  it('reads a space with no chain as one with none, and keeps no anchor', async () => {
    const { deps, anchors } = setup();
    expect(await checkSpaceChain(deps, SPACE, ME)).toEqual({ kind: 'unchained' });
    expect(await anchors.load(ME, SPACE)).toBeUndefined();
  });

  it('keeps the anchor of a chain that verifies and is trusted, and uses it next time', async () => {
    const { deps, anchors, crypto } = setup(view());
    const spy = vi.spyOn(crypto, 'verifySpaceChain');
    const first = await checkSpaceChain(deps, SPACE, ME);
    expect(first.kind).toBe('verified');
    expect(await anchors.load(ME, SPACE)).toEqual({ seq: 4, epoch: 1, links: ['l0', 'l1', 'l2', 'l3', 'l4'] });
    // The held head has nothing after it, so the chain isn't verified again.
    expect((await checkSpaceChain(deps, SPACE, ME)).kind).toBe('verified');
    expect(spy).toHaveBeenCalledTimes(1);
    expect(deps.api.chain).toHaveBeenLastCalledWith(SPACE, 5);
  });

  it('hands the kept anchor to the verifier, and verifies again when the server has more', async () => {
    const { deps, anchors, crypto, api } = setup(view());
    const spy = vi.spyOn(crypto, 'verifySpaceChain');
    const kept = { seq: 2, epoch: 1, links: ['l0', 'l1', 'l2'] };
    await anchors.save(ME, SPACE, kept);
    await checkSpaceChain(deps, SPACE, ME);
    expect(spy.mock.calls[0]?.[0]).toMatchObject({ spaceId: SPACE, anchor: kept });
    // New records after the held head: the whole chain is read and verified again.
    api.chain.mockImplementation(async () => [{ entry: 'ZQ', signature: 'cw' }]);
    await checkSpaceChain(deps, SPACE, ME);
    expect(spy).toHaveBeenCalledTimes(2);
  });

  it('keeps no anchor and opens nothing until the person compared the fingerprint', async () => {
    const waiting = view({
      trusted: false,
      firstContact: { kind: 'compare', person: ME, fingerprint: '12345 67890', owners: [] },
    });
    const { deps, anchors } = setup(waiting);
    const trust = await checkSpaceChain(deps, SPACE, ME);
    expect(trust.kind).toBe('first-contact');
    expect(await anchors.load(ME, SPACE)).toBeUndefined();

    const accepted = await acceptFirstContact(deps, SPACE, ME);
    expect(accepted.kind).toBe('verified');
    expect(crypto.calls).toContain(`acceptFirstContact:${SPACE}`);
    expect((await anchors.load(ME, SPACE))?.seq).toBe(4);
  });

  it('is unverified, with the reason and the seq, when the chain is refused', async () => {
    const { deps, anchors } = setup({ ok: false, reason: 'forked', seq: 3 });
    expect(await checkSpaceChain(deps, SPACE, ME)).toEqual({ kind: 'unverified', reason: 'forked', seq: 3 });
    expect(await anchors.load(ME, SPACE)).toBeUndefined();
  });

  it('never reads a space as unchained again once a chain was served for it', async () => {
    // First contact was never done, so there is no anchor: the chain was only seen.
    const waiting = view({
      trusted: false,
      firstContact: { kind: 'pick', owners: [] },
    });
    const { deps, anchors, crypto } = setup(waiting);
    expect((await checkSpaceChain(deps, SPACE, ME)).kind).toBe('first-contact');
    expect(await anchors.load(ME, SPACE)).toBeUndefined();
    expect(await anchors.seen(ME, SPACE)).toBe(true);
    // Another unlock, and the server serves nothing: a chain taken back, not a space with none.
    const fresh = fakeSpaceCrypto();
    fresh.chain = NO_CHAIN;
    expect(await checkSpaceChain({ ...deps, crypto: fresh }, SPACE, ME)).toEqual({
      kind: 'unverified',
      reason: 'rolled back',
      seq: null,
    });
    // A space it never saw one for is as before.
    expect(await checkSpaceChain({ ...deps, crypto: fresh }, THEO, ME)).toEqual({ kind: 'unchained' });
  });

  it('remembers a refused chain too', async () => {
    const { deps, anchors, crypto } = setup({ ok: false, reason: 'forked', seq: 3 });
    await checkSpaceChain(deps, SPACE, ME);
    expect(await anchors.seen(ME, SPACE)).toBe(true);
    crypto.chain = NO_CHAIN;
    expect(await checkSpaceChain(deps, SPACE, ME)).toMatchObject({ kind: 'unverified', reason: 'rolled back' });
  });

  it('is unverified, not unchained, when the chain can not be read', async () => {
    const { deps, api } = setup();
    api.chain.mockRejectedValue(new Error('offline'));
    expect(await checkSpaceChain(deps, SPACE, ME)).toEqual({ kind: 'unverified', reason: 'unreachable', seq: null });
  });

  it('is unverified when the kept anchor can not be read', async () => {
    const { deps } = setup();
    const broken: AnchorStore = {
      load: () => Promise.reject(new Error('indexeddb')),
      save: () => Promise.resolve(),
      seen: () => Promise.resolve(false),
      markSeen: () => Promise.resolve(),
    };
    const trust = await checkSpaceChain({ ...deps, anchors: broken } satisfies ChainDeps, SPACE, ME);
    expect(trust).toMatchObject({ kind: 'unverified', reason: 'unreachable' });
  });
});

describe('the space as its chain says', () => {
  it('takes roles, grants, group members and key versions from the chain, and drops what it lacks', () => {
    const served = spaceView({
      grants: [
        { collection: INFRA, grantee: `group:${OPS}`, permission: 'edit' },
        // The server lists a grant the chain never made.
        { collection: FINANCE, grantee: `user:${ME}`, permission: 'manage' },
      ],
      groups: [
        { id: OPS, name: 'n', members: [LEE, ME] },
        { id: 'ghost', name: 'n', members: [ME] },
      ],
    });
    const listed = [
      ...members(),
      { ...members()[0], user: 'ghost-user', email: 'x@example.co' },
    ] as ReturnType<typeof members>;
    const out = overlayChain(served, listed, view({ collections: view().collections.slice(0, 1) }));
    expect(out.view.grants).toEqual([{ collection: INFRA, grantee: `group:${OPS}`, permission: 'edit' }]);
    expect(out.view.groups.map((g) => [g.id, g.members])).toEqual([[OPS, [LEE]]]);
    expect(out.view.collections.map((c) => c.id)).toEqual([INFRA]);
    expect(out.members.map((m) => [m.user, m.role, m.state])).toEqual([
      [ME, 'owner', 'confirmed'],
      [LEE, 'admin', 'confirmed'],
      // Theo accepted at the server, which the chain doesn't record: it only says invited.
      [THEO, 'member', 'accepted'],
    ]);
    expect(out.view.me.role).toBe('owner');
  });

  it('lists a member the chain has and the server does not, by what the chain says', () => {
    const out = overlayChain(spaceView(), [], view());
    expect(out.members.map((m) => m.user)).toEqual([ME, LEE, THEO]);
    expect(out.members[0]?.email).toBe(ME);
  });

  it('uses the chain’s bundle of a member, not the server’s', () => {
    const chained = view({
      members: [{ ...chainMember(LEE, 'member'), bundle: 'Y2hhaW4', bundleVersion: 3 }, chainMember(ME, 'owner')],
    });
    const out = overlayChain(spaceView(), members(), chained);
    const lee = out.members.find((m) => m.user === LEE);
    expect(lee?.publicBundle).toBe('Y2hhaW4');
    expect(lee?.userKeyVersion).toBe(3);
  });
});

describe('opening keys through the chain', () => {
  it('opens the space key and the collection keys the chain committed, with the hash list when it needs one', async () => {
    const { deps, api, crypto } = setup(view());
    const open = vi.spyOn(crypto, 'openChainKey');
    const sealed = vi.mocked(api.chainSeals);
    sealed.mockResolvedValue([{ bundleVersion: 1, key: `collection:${FINANCE}`, member: ME, sealHash: 'aGFzaA', version: 1 }]);
    const opened = await openChainedKeys(deps, SPACE, view(), spaceView());
    expect([...opened].sort()).toEqual([FINANCE, INFRA].sort());
    expect(sealed).toHaveBeenCalledTimes(1);
    expect(sealed).toHaveBeenCalledWith(SPACE, 2);
    expect(open.mock.calls.map(([call]) => [call.key, call.list !== undefined])).toEqual([
      ['space', false],
      [`collection:${INFRA}`, false],
      [`collection:${FINANCE}`, true],
    ]);
  });

  it('leaves out a collection the chain has no seal of, and fails without the space key', async () => {
    const { deps } = setup(view());
    const lacking = view({ keys: view().keys.filter((k) => k.key !== `collection:${FINANCE}`) });
    const opened = await openChainedKeys(deps, SPACE, lacking, spaceView());
    expect([...opened]).toEqual([INFRA]);
    const noSpaceKey = view({ keys: view().keys.filter((k) => k.key !== 'space') });
    await expect(openChainedKeys(deps, SPACE, noSpaceKey, spaceView())).rejects.toThrow();
  });
});

describe('a space with a chain, loaded', () => {
  it('opens its keys through the chain only, and reads the roster from it', async () => {
    const { deps, crypto } = setup(view());
    const loaded = await loadSpaceDetail(deps, SPACE);
    expect(loaded.trust?.kind).toBe('verified');
    expect(loaded.readable).toBe(true);
    expect(loaded.name).toBe('Example Co');
    expect(crypto.calls.some((c) => c.startsWith('openChainKey:space'))).toBe(true);
    expect(crypto.calls.some((c) => c.startsWith('openSpace:') || c.startsWith('openCollection:'))).toBe(false);
    expect(loaded.members.find((m) => m.user === LEE)?.role).toBe('admin');
  });

  it('opens nothing and shows no name while it waits for first contact', async () => {
    const { deps, crypto } = setup(view({ trusted: false, firstContact: { kind: 'pick', owners: [] } }));
    const loaded = await loadSpaceDetail(deps, SPACE);
    expect(loaded.trust?.kind).toBe('first-contact');
    expect(loaded.readable).toBe(false);
    expect(loaded.name).toBeNull();
    expect(loaded.collections.every((c) => c.title === null)).toBe(true);
    expect(crypto.calls.some((c) => c.startsWith('open'))).toBe(false);
  });

  it('opens nothing when its chain is refused, and falls back on nothing', async () => {
    const { deps, crypto } = setup({ ok: false, reason: 'rolled back', seq: 29 });
    const loaded = await loadSpaceDetail(deps, SPACE);
    expect(loaded.trust).toEqual({ kind: 'unverified', reason: 'rolled back', seq: 29 });
    expect(loaded.readable).toBe(false);
    expect(loaded.name).toBeNull();
    expect(crypto.calls.some((c) => c.startsWith('open'))).toBe(false);
  });

  it('shows no name in the list, and says why, for a space that can not be checked', async () => {
    const { deps } = setup({ ok: false, reason: 'forked', seq: 3 });
    const rows = await loadSpaceList(deps);
    expect(rows[0]).toMatchObject({ id: SPACE, name: null, trust: 'unverified' });
  });

  it('seals nothing for a space it can not use the chain to change', async () => {
    const { deps, api, crypto } = setup(view());
    const loaded = { ...detail(), trust: { kind: 'verified' as const, view: view() } };
    const theo = members().find((m) => m.user === THEO);
    if (!theo) throw new Error('fixture');
    const bytes = new Uint8Array(64);
    await expect(
      confirmMember(deps, loaded, theo, { text: '0', bytes, consistent: true }),
    ).rejects.toBeInstanceOf(SpaceNotChecked);
    expect(api.confirm).not.toHaveBeenCalled();
    expect(crypto.calls.some((c) => c.startsWith('seal'))).toBe(false);
  });
});
