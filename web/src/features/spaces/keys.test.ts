import { describe, expect, it, vi } from 'vitest';
import type { CollectionDto, GrantDto, MemberDto, SpaceViewDto } from '@/api/spaces';
import { encodeB64, utf8 } from '@/lib/b64url';
import type { SpaceCrypto } from '@/spaces/crypto';
import { NO_CHAIN } from '@/test/fake-space-crypto';
import { canEditCollection, createSpaceKeyLoader, loadWritableCollections, openSpaceKeys } from './keys';
import type { SpaceDeps } from './model';

const SPACE = '00000000-0000-4000-8000-0000000000bb';
const ME = '00000000-0000-4000-8000-0000000000aa';
const C1 = '00000000-0000-4000-8000-0000000000c1';
const C2 = '00000000-0000-4000-8000-0000000000c2';
const C3 = '00000000-0000-4000-8000-0000000000c3';

function member(role: MemberDto['role'], over: Partial<MemberDto> = {}): MemberDto {
  return {
    user: ME,
    role,
    custom: [],
    state: 'confirmed',
    invitedBy: ME,
    invitedAt: 1,
    acceptedAt: 2,
    sealedSpaceKey: encodeB64(utf8('space-key')),
    keyVersion: 1,
    confirmation: null,
    revokedAt: null,
    ...over,
  };
}

const collection = (id: string): CollectionDto => ({
  id,
  parent: null,
  name: encodeB64(utf8(`name:${id}`)),
  keyVersion: 1,
  staleSince: null,
});

function view(role: MemberDto['role'], grants: GrantDto[]): SpaceViewDto {
  return {
    space: { id: SPACE, name: encodeB64(utf8('space')), keyVersion: 1, keysPendingSince: null, createdAt: 1 },
    me: member(role),
    collections: [collection(C1), collection(C2), collection(C3)],
    groups: [{ id: 'g1', name: '', members: [ME] }],
    grants,
    // This account holds keys for the first two collections only.
    collectionKeys: [C1, C2].map((c) => ({ collection: c, keyVersion: 1, sealed: encodeB64(utf8(`key:${c}`)) })),
  };
}

function deps(spaceView: SpaceViewDto) {
  const crypto = {
    // The server serves no chain for this space.
    spaceChainView: vi.fn(async () => null),
    verifySpaceChain: vi.fn(async () => NO_CHAIN),
    openSpace: vi.fn(async () => undefined),
    openCollection: vi.fn(async () => undefined),
    // Nothing waits for a person to compare it.
    provisionalKeys: vi.fn(async () => null),
    openName: vi.fn(async ({ ciphertext }: { ciphertext: Uint8Array }) =>
      new TextDecoder().decode(ciphertext).replace('name:', 'collection '),
    ),
  } as unknown as SpaceCrypto;
  const api = {
    list: vi.fn(async () => [{ space: spaceView.space, member: spaceView.me }]),
    get: vi.fn(async () => spaceView),
    chain: vi.fn(async () => []),
  } as unknown as SpaceDeps['api'];
  return { api, crypto } satisfies SpaceDeps;
}

describe('openSpaceKeys', () => {
  it('opens the space key, then every collection key sealed to me', async () => {
    const d = deps(view('member', []));
    await openSpaceKeys(d, SPACE);
    expect(d.crypto.openSpace).toHaveBeenCalledWith(expect.objectContaining({ spaceId: SPACE, keyVersion: 1 }));
    expect(d.crypto.openCollection).toHaveBeenCalledTimes(2);
    expect(d.crypto.openCollection).toHaveBeenCalledWith(expect.objectContaining({ collectionId: C2 }));
  });

  it('says so when the space key is not sealed to this account yet', async () => {
    const v = view('member', []);
    v.me = member('member', { sealedSpaceKey: null });
    await expect(openSpaceKeys(deps(v), SPACE)).rejects.toThrow('not sealed');
  });
});

describe('createSpaceKeyLoader', () => {
  it('opens a space once while the keys are held, and again after a lock', async () => {
    const d = deps(view('member', []));
    const loader = createSpaceKeyLoader(d);
    await Promise.all([loader.ensure(SPACE), loader.ensure(SPACE)]);
    await loader.ensure(SPACE);
    expect(d.api.get).toHaveBeenCalledTimes(1);
    loader.forget();
    await loader.ensure(SPACE);
    expect(d.api.get).toHaveBeenCalledTimes(2);
  });

  it('does not remember a failure', async () => {
    const d = deps(view('member', []));
    vi.mocked(d.api.get).mockRejectedValueOnce(new Error('offline'));
    const loader = createSpaceKeyLoader(d);
    await expect(loader.ensure(SPACE)).rejects.toThrow('offline');
    await loader.ensure(SPACE);
    expect(d.api.get).toHaveBeenCalledTimes(2);
  });
});

describe('canEditCollection', () => {
  it('lets an owner or admin edit, and others only by an edit grant, direct or through a group', () => {
    const grants: GrantDto[] = [
      { collection: C1, grantee: `user:${ME}`, permission: 'view' },
      { collection: C2, grantee: 'group:g1', permission: 'edit' },
      { collection: C3, grantee: 'user:someone-else', permission: 'manage' },
    ];
    const v = view('member', grants);
    expect(canEditCollection(v, v.groups, C1)).toBe(false);
    expect(canEditCollection(v, v.groups, C2)).toBe(true);
    expect(canEditCollection(v, v.groups, C3)).toBe(false);
    expect(canEditCollection(view('owner', []), [], C1)).toBe(true);
    expect(canEditCollection(view('admin', []), [], C3)).toBe(true);
  });
});

describe('loadWritableCollections', () => {
  it('lists the collections I hold a key for and may edit, with their names', async () => {
    const d = deps(
      view('member', [
        { collection: C1, grantee: `user:${ME}`, permission: 'edit' },
        { collection: C2, grantee: `user:${ME}`, permission: 'view' },
        { collection: C3, grantee: `user:${ME}`, permission: 'manage' },
      ]),
    );
    const list = await loadWritableCollections(d);
    // C2 is view only, and C3 has no key copy for this account.
    expect(list.map((c) => c.collectionId)).toEqual([C1]);
    expect(list[0]).toMatchObject({ spaceId: SPACE, collectionName: `collection ${C1}` });
  });

  it('offers nothing of a space whose keys were taken on the server’s word and nobody compared', async () => {
    const d = deps(view('owner', []));
    vi.mocked(d.crypto.provisionalKeys).mockResolvedValueOnce([
      { collection: null, version: 1, fingerprint: '11111 22222 33333 44444 55555 66666 77777 88888 99999 00000 12345 67890' },
    ]);
    expect(await loadWritableCollections(d)).toEqual([]);
    // Compared (nothing waits any more): the same space offers its collections.
    expect((await loadWritableCollections(d)).length).toBeGreaterThan(0);
  });

  it('skips a space that is not confirmed yet, and one whose keys do not open', async () => {
    const pending = view('member', []);
    pending.me = member('member', { state: 'accepted', sealedSpaceKey: null });
    expect(await loadWritableCollections(deps(pending))).toEqual([]);

    const broken = deps(view('owner', []));
    vi.mocked(broken.crypto.openSpace).mockRejectedValueOnce(new Error('invalid'));
    expect(await loadWritableCollections(broken)).toEqual([]);
  });
});
