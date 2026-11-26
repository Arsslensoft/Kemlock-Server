import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiError } from '@/api/errors';
import type { InstallRequest, RotationPlanDto } from '@/api/rotation';
import type { ItemDto } from '@/api/types';
import { encodeB64, fromUtf8, utf8 } from '@/lib/b64url';
import { makeBundleB64 } from '@/test/bundles';
import { crypto as fakeCrypto, fakeCalls, resetFakeCrypto } from '@/test/fake-crypto';
import {
  RotationBlockedError,
  RotationPasswordError,
  type RotationDeps,
  rotateKeys,
} from './rotationModel';

const USER = '00000000-0000-4000-8000-000000000001';
const DEVICE = '00000000-0000-4000-8000-0000000000d1';
const OWNER = `user:${USER}`;

function plan(overrides: Partial<RotationPlanDto> = {}): RotationPlanDto {
  return {
    keyVersion: 1,
    hasPassword: true,
    publicBundle: 'YnVuZGxl',
    kit: null,
    passkeys: [],
    deviceCopies: [],
    emergency: [],
    recovery: [],
    sends: [],
    items: { count: 2 },
    spaces: 0,
    previousKeys: null,
    ...overrides,
  };
}

function item(id: string, revision: number): ItemDto {
  return {
    id,
    owner: OWNER,
    kind: 'login',
    format: 'kem1',
    revision,
    keyVersion: 1,
    ciphertext: encodeB64(utf8(JSON.stringify([id, OWNER, 'login', revision, '{"name":"x"}']))),
    itemKey: encodeB64(utf8('item-key')),
  };
}

const A = '00000000-0000-4000-8000-00000000000a';
const B = '00000000-0000-4000-8000-00000000000b';

function incomplete(): ApiError {
  return new ApiError(409, { type: 'urn:kemlock:problem:rotation-incomplete', title: 'changed' } as never);
}

function setup(overrides: { plans?: RotationPlanDto[]; pages?: ItemDto[][]; install?: () => Promise<unknown> } = {}) {
  const plans = overrides.plans ?? [plan()];
  const pages = overrides.pages ?? [[item(A, 1), item(B, 3)]];
  const staged: Array<{ rotationId: string; toVersion: number; ids: string[] }> = [];
  const installs: InstallRequest[] = [];
  let planCalls = 0;
  let syncCalls = 0;
  const api = {
    plan: vi.fn(async () => plans[Math.min(planCalls++, plans.length - 1)] as RotationPlanDto),
    stage: vi.fn(async (request: { rotationId: string; toVersion: number; items: Array<{ id: string }> }) => {
      staged.push({ rotationId: request.rotationId, toVersion: request.toVersion, ids: request.items.map((i) => i.id) });
      return { staged: request.items.length };
    }),
    abandon: vi.fn(async () => undefined),
    install: vi.fn(async (request: InstallRequest) => {
      installs.push(request);
      if (overrides.install) return (await overrides.install()) as never;
      return { keyVersion: 2, tokens: null };
    }),
    finishSpaces: vi.fn(async () => undefined),
    prelogin: vi.fn(async () => ({ memoryKib: 65536, iterations: 3, parallelism: 4, salt: encodeB64(new Uint8Array(16)) })),
    opaqueStart: vi.fn(async () => ({ response: encodeB64(utf8('resp')), loginState: 'state' })),
    sync: vi.fn(async () => {
      const page = pages[Math.min(syncCalls++, pages.length - 1)] ?? [];
      return { notModified: false as const, page: { items: page, cursor: 'c', more: false } };
    }),
  };
  const deps: RotationDeps = {
    api: api as unknown as RotationDeps['api'],
    sends: { list: vi.fn(async () => []) },
    crypto: fakeCrypto,
    userId: USER,
    deviceId: DEVICE,
    randomBytes: (n) => new Uint8Array(n).fill(7),
  };
  return { api, deps, staged, installs };
}

describe('rotateKeys', () => {
  beforeEach(async () => {
    resetFakeCrypto();
    await fakeCrypto.unlock(USER, utf8(`wrapped:${USER}`), utf8('mk'), utf8('ek'));
  });

  it('moves every item, stages them, proves the password and installs once', async () => {
    const { api, deps, staged, installs } = setup();
    const progress: string[] = [];
    const result = await rotateKeys(deps, { email: 'sam@example.org', password: 'correct horse', makeKit: true }, (p) =>
      progress.push(`${p.phase}:${p.done}/${p.total}`),
    );

    expect(result).toMatchObject({ keyVersion: 2, kit: { kitId: 'NEWKIT22' } });
    expect(result.kit?.pieces).toHaveLength(3);
    expect(staged).toHaveLength(1);
    expect(staged[0]?.ids.sort()).toEqual([A, B]);
    expect(staged[0]?.toVersion).toBe(2);
    expect(installs).toHaveLength(1);
    const request = installs[0];
    expect(request).toMatchObject({
      fromVersion: 1,
      toVersion: 2,
      loginState: 'state',
      kit: { kitId: 'NEWKIT22' },
      dropKit: false,
      spacesHandled: false,
    });
    expect(request?.rotationId).toBe(staged[0]?.rotationId);
    expect(fromUtf8(decodeWrapped(request?.wrappedRootKey))).toContain('wrapped:v2');
    expect(result.rewritten.map((i) => [i.id, i.revision, i.keyVersion]).sort()).toEqual([
      [A, 2, 2],
      [B, 4, 2],
    ]);
    expect(progress).toContain('items:2/2');
    expect(progress.at(-1)).toBe('done:1/1');
    expect(api.abandon).not.toHaveBeenCalled();
    // The worker started, moved, and committed; it never aborted.
    expect(fakeCalls).toContain('rotationStart');
    expect(fakeCalls.filter((call) => call === 'rotationResealItem')).toHaveLength(2);
    expect(fakeCalls.indexOf('rotationCommit')).toBeGreaterThan(fakeCalls.indexOf('rotationWrapPassword'));
    expect(fakeCalls).not.toContain('rotationAbort');
  });

  it('removes what it cannot re-wrap and says how much', async () => {
    const withWraps = plan({
      kit: { kitId: 'OLDKITID' },
      passkeys: [{ id: 'p1', credentialId: 'Y3JlZA' }],
      emergency: [{ id: 'g1', state: 'confirmed', granteeId: null, granteeEmail: null, granteeBundle: null }],
      recovery: [{ space: 's1', keySeq: 4 }],
      deviceCopies: [{ deviceId: DEVICE }],
    });
    const { deps, installs } = setup({ plans: [withWraps] });
    const result = await rotateKeys(deps, { email: 'sam@example.org', password: 'pw', makeKit: false });
    expect(installs[0]).toMatchObject({
      dropKit: true,
      dropPasskeys: ['p1'],
      dropEmergency: ['g1'],
      dropRecovery: ['s1'],
      deviceCopy: { protection: 'web-crypto' },
    });
    expect(installs[0]?.kit).toBeUndefined();
    expect(result.removed).toEqual({ passkeys: [{ id: 'p1', credentialId: 'Y3JlZA' }], emergency: 1, recovery: 1 });
    expect(result.kit).toBeNull();
  });

  it('seals the new root key to a contact whose bundle the person compared, and only to that one', async () => {
    const GRANTEE = '00000000-0000-4000-8000-0000000000c1';
    const OTHER = '00000000-0000-4000-8000-0000000000c2';
    const bundle = makeBundleB64(GRANTEE);
    const swapped = makeBundleB64(GRANTEE, 1, 0x33);
    const grant = (id: string, granteeId: string, granteeBundle: string) => ({
      id,
      state: 'confirmed',
      granteeId,
      granteeEmail: `${id}@example.org`,
      granteeBundle,
    });
    const held = plan({
      emergency: [grant('kept', GRANTEE, bundle), grant('swapped', GRANTEE, swapped), grant('unseen', OTHER, bundle), grant('wrong-account', OTHER, makeBundleB64(GRANTEE))],
    });
    const { deps, installs } = setup({ plans: [held] });
    const result = await rotateKeys(deps, {
      email: 'sam@example.org',
      password: 'pw',
      makeKit: false,
      // The person compared `bundle` for the first, the old bundle for the second (the server now
      // serves another), and nothing for the third; the fourth names a bundle of another account.
      emergencyKeep: { kept: bundle, swapped: bundle, 'wrong-account': makeBundleB64(GRANTEE) },
    });
    const request = installs[0];
    expect(request?.emergency?.map((box) => box.id)).toEqual(['kept']);
    expect(request?.dropEmergency?.sort()).toEqual(['swapped', 'unseen', 'wrong-account']);
    expect(fakeCalls.filter((call) => call === 'rotationSealRootKey')).toHaveLength(1);
    expect(result.removed.emergency).toBe(3);
  });

  it('seals a recovery enrolment to the key a verified chain gives, and removes the others', async () => {
    const held = plan({
      recovery: [
        { space: '00000000-0000-4000-8000-0000000000e1', keySeq: 4 },
        { space: '00000000-0000-4000-8000-0000000000e2', keySeq: 9 },
      ],
    });
    const { deps, installs } = setup({ plans: [held] });
    const recoveryKeys = vi.fn(async (space: string) =>
      space.endsWith('e1') ? new Uint8Array(1600).fill(5) : undefined,
    );
    const result = await rotateKeys(
      { ...deps, recoveryKeys },
      { email: 'sam@example.org', password: 'pw', makeKit: false },
    );
    expect(installs[0]?.recovery).toEqual([
      { space: '00000000-0000-4000-8000-0000000000e1', keySeq: 4, box: expect.any(String) },
    ]);
    expect(installs[0]?.dropRecovery).toEqual(['00000000-0000-4000-8000-0000000000e2']);
    expect(recoveryKeys).toHaveBeenCalledWith('00000000-0000-4000-8000-0000000000e1', 4);
    expect(result.removed.recovery).toBe(1);
  });

  it('asks nothing of a password an account without one does not have', async () => {
    const { api, deps, installs } = setup({ plans: [plan({ hasPassword: false })] });
    await rotateKeys(deps, { email: 'sam@example.org', password: '', makeKit: false });
    expect(api.prelogin).not.toHaveBeenCalled();
    expect(installs[0]?.loginState).toBeUndefined();
    expect(installs[0]?.wrappedRootKey).toBeUndefined();
  });

  it('refuses an account that is in a space before the worker starts', async () => {
    const { deps, api } = setup({ plans: [plan({ spaces: 2 })] });
    await expect(rotateKeys(deps, { email: 'sam@example.org', password: 'pw', makeKit: false })).rejects.toBeInstanceOf(
      RotationBlockedError,
    );
    expect(fakeCalls).not.toContain('rotationStart');
    expect(api.stage).not.toHaveBeenCalled();
  });

  it('stages what changed and installs again when the server says the account changed', async () => {
    let attempts = 0;
    const { deps, staged, installs } = setup({
      pages: [[item(A, 1), item(B, 3)], [item(A, 2), item(B, 3)]],
      install: async () => {
        attempts += 1;
        if (attempts === 1) throw incomplete();
        return { keyVersion: 2, tokens: null };
      },
    });
    const result = await rotateKeys(deps, { email: 'sam@example.org', password: 'pw', makeKit: false });
    expect(result.keyVersion).toBe(2);
    expect(installs).toHaveLength(2);
    // The item that moved on is listed at the revision it was staged again at.
    expect(result.rewritten.find((i) => i.id === A)?.revision).toBe(3);
    // Only the item that moved on is staged again.
    expect(staged.map((s) => s.ids)).toEqual([[A, B], [A]]);
    expect(fakeCalls.filter((call) => call === 'rotationCommit')).toHaveLength(1);
  });

  it('gives up after five rounds and leaves the account as it was', async () => {
    const { deps, api } = setup({
      install: async () => {
        throw incomplete();
      },
    });
    await expect(rotateKeys(deps, { email: 'sam@example.org', password: 'pw', makeKit: false })).rejects.toBeInstanceOf(
      ApiError,
    );
    expect(api.install).toHaveBeenCalledTimes(5);
    expect(api.abandon).toHaveBeenCalled();
    expect(fakeCalls).toContain('rotationAbort');
    expect(fakeCalls).not.toContain('rotationCommit');
  });

  it('says a wrong password, and drops what it staged', async () => {
    const { deps, api } = setup();
    const failing = { ...fakeCrypto, opaqueLoginFinish: vi.fn(async () => Promise.reject(new Error('no'))) };
    await expect(
      rotateKeys({ ...deps, crypto: failing }, { email: 'sam@example.org', password: 'nope', makeKit: false }),
    ).rejects.toBeInstanceOf(RotationPasswordError);
    expect(api.install).not.toHaveBeenCalled();
    expect(api.abandon).toHaveBeenCalled();
  });

  it('turns a 401 from the server into a wrong password', async () => {
    const { deps } = setup({
      install: async () => {
        throw new ApiError(401, { type: 'urn:kemlock:problem:unauthorized', title: 'no' } as never);
      },
    });
    await expect(rotateKeys(deps, { email: 'sam@example.org', password: 'pw', makeKit: false })).rejects.toBeInstanceOf(
      RotationPasswordError,
    );
  });
});

function decodeWrapped(value: string | undefined): Uint8Array {
  const bytes = value ? atob(value.replace(/-/g, '+').replace(/_/g, '/')) : '';
  return Uint8Array.from(bytes, (c) => c.charCodeAt(0));
}
