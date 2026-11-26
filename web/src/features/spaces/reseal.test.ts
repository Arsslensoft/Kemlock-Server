// @vitest-environment node
import { describe, expect, it } from 'vitest';
import type { MemberViewDto } from '@/api/spaces';
import { decodeB64, fromUtf8 } from '@/lib/b64url';
import { fakeSpaceCrypto } from '@/test/fake-space-crypto';
import {
  INFRA,
  LEE,
  ME,
  THEO,
  confirmedMembers,
  detail,
  fakeSpacesApi,
  fingerprintTextOf,
  member,
  members,
  spaceView,
} from './fixtures';
import type { SpaceDeps } from './model';
import { resealKeys } from './reseal';

async function owner(roster: MemberViewDto[]) {
  const api = fakeSpacesApi();
  const crypto = fakeSpaceCrypto();
  crypto.ownFingerprintText = await fingerprintTextOf(roster[0] as MemberViewDto);
  const deps: SpaceDeps = { api, crypto };
  return { api, crypto, deps };
}

describe('sealing the keys of a space again', () => {
  it('seals the space key and the collection keys held to each confirmed member, signed', async () => {
    const roster = await confirmedMembers();
    const { api, crypto, deps } = await owner(roster);
    const done = await resealKeys(deps, detail({ members: roster }));
    // Me and Lee, who I confirmed; Theo only accepted, so gets nothing.
    expect(done).toEqual({ resealed: 1, skipped: [] });
    const [space, body] = api.reseal.mock.calls[0] ?? [];
    expect(space).toBeDefined();
    expect(body?.members.map((m) => m.user)).toEqual([ME, LEE]);
    for (const sealed of body?.members ?? []) {
      expect(fromUtf8(decodeB64(sealed.sealedSpaceKey))).toContain('space-key-for:');
      expect(sealed.sealedSpaceKeySignature.length).toBeGreaterThan(0);
    }
    // Lee reaches Infrastructure through the Ops group, and I hold that key; Theo isn't listed.
    const lee = body?.members.find((m) => m.user === LEE);
    expect(lee?.collectionKeys.map((k) => k.collection)).toEqual([INFRA]);
    expect(lee?.collectionKeys.every((k) => k.signature.length > 0)).toBe(true);
    expect(crypto.calls).toContain(`sealCollectionKeyTo:${INFRA}`);
    expect(body?.members.some((m) => m.user === THEO)).toBe(false);
  });

  it('leaves out, and names, a member this browser can not trace', async () => {
    // Lee has no confirmation here, so nobody a person compared vouches for him.
    const roster = members();
    const { api, deps } = await owner(roster);
    const done = await resealKeys(deps, detail({ members: roster }));
    expect(done.skipped).toEqual([LEE]);
    expect(api.reseal.mock.calls[0]?.[1].members.map((m) => m.user)).toEqual([ME]);
  });

  it('is for an owner or admin of a space with no chain whose keys are open', async () => {
    const roster = await confirmedMembers();
    const { api, deps } = await owner(roster);
    const plain = detail({ members: roster, view: spaceView({ me: member(ME, { role: 'member' }) }) });
    await expect(resealKeys(deps, plain)).rejects.toThrow();
    await expect(resealKeys(deps, detail({ members: roster, readable: false }))).rejects.toThrow();
    await expect(
      resealKeys(deps, detail({ members: roster, trust: { kind: 'unverified', reason: 'forked', seq: 3 } })),
    ).rejects.toThrow();
    expect(api.reseal).not.toHaveBeenCalled();
  });
});
