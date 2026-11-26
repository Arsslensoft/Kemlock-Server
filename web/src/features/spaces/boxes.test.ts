// @vitest-environment node
import { describe, expect, it } from 'vitest';
import type { GrantDto, MemberViewDto, SealedByDto } from '@/api/spaces';
import { decodeB64, encodeB64, utf8 } from '@/lib/b64url';
import { uuidBytes } from '@/sharing/bundle';
import { memoryPinStore } from '@/spaces/anchors';
import { type BoxStore, memoryBoxStore } from '@/spaces/boxstore';
import { fakeBoxSignature, fakeSpaceCrypto } from '@/test/fake-space-crypto';
import {
  type BoxContext,
  type BoxKey,
  type BoxRefusal,
  KeyBoxRefused,
  WrongAccount,
  openKeyBox,
  openUnchainedKeys,
  signedInAccount,
} from './boxes';
import {
  FINANCE,
  INFRA,
  LEE,
  ME,
  SPACE,
  THEO,
  confirmedBy,
  fakeSpacesApi,
  fingerprintTextOf,
  member,
  memberView,
  spaceView,
} from './fixtures';
import { openSpaceKeys } from './keys';
import type { SpaceDeps } from './model';

const BOX = utf8('collection-box');

interface Options {
  /** Lee's role, who sealed the keys. */
  role?: MemberViewDto['role'];
  custom?: MemberViewDto['custom'];
  /** Whether I confirmed Lee; a roster the server lists with nobody vouching for Lee when false. */
  confirmed?: boolean;
  grants?: GrantDto[];
}

/** I am the owner; Lee is a member I confirmed, who sealed the keys served to me. */
async function setup(options: Options = {}) {
  const crypto = fakeSpaceCrypto();
  const me = memberView(ME, 'sam@example.co', { role: 'owner' });
  crypto.ownFingerprintText = await fingerprintTextOf(me);
  crypto.ownBundle = decodeB64(me.publicBundle);
  const listed = memberView(LEE, 'lee@example.co', {
    role: options.role ?? 'admin',
    custom: options.custom ?? [],
  });
  const lee = options.confirmed === false ? listed : await confirmedBy(ME, listed);
  const roster = [me, lee];
  const boxes: BoxStore = memoryBoxStore();
  const api = fakeSpacesApi();
  api.members.mockResolvedValue(roster);
  const deps: SpaceDeps = { api, crypto, pins: memoryPinStore(), boxes };
  const ctx: BoxContext = {
    deps,
    spaceId: SPACE,
    me: ME,
    members: async () => roster,
    access: async () => ({ grants: options.grants ?? [], groups: [] }),
  };
  return { crypto, ctx, deps, api, me, lee, boxes, roster };
}

/** A box `sealer` sealed to me, with the signature they would make (the fake crypto's). */
function signedBy(
  sealer: MemberViewDto,
  key: BoxKey,
  version: number,
  over: { box?: Uint8Array; signedVersion?: number } = {},
): { sealed: string; sealedBy: SealedByDto } {
  const box = over.box ?? BOX;
  const signature = fakeBoxSignature({
    sealerBundle: decodeB64(sealer.publicBundle),
    spaceId: SPACE,
    ...(key === 'space' ? {} : { collectionId: key.collection }),
    keyVersion: version,
    recipientId: uuidBytes(ME),
    sealed: box,
  });
  return {
    sealed: encodeB64(box),
    sealedBy: {
      account: sealer.user,
      keyVersion: over.signedVersion ?? 1,
      signature: encodeB64(signature),
    },
  };
}

async function refusal(promise: Promise<unknown>): Promise<BoxRefusal> {
  const error = await promise.then(
    () => null,
    (caught: unknown) => caught,
  );
  expect(error).toBeInstanceOf(KeyBoxRefused);
  return (error as KeyBoxRefused).reason;
}

const finance: BoxKey = { collection: FINANCE };

describe('a signed key box', () => {
  it('opens when a member I confirmed signed it, and was allowed to seal it', async () => {
    const { ctx, crypto, lee } = await setup();
    const box = signedBy(lee, finance, 1);
    await expect(openKeyBox(ctx, { key: finance, version: 1, ...box })).resolves.toEqual({
      legacy: false,
    });
    expect(crypto.calls).toContain(`verifyKeyBox:${FINANCE}`);
    expect(crypto.calls).toContain(`openCollection:${FINANCE}`);
  });

  it('opens a key I sealed myself, against the keys this browser holds', async () => {
    const { ctx, crypto, me } = await setup();
    const box = signedBy(me, 'space', 2);
    await expect(openKeyBox(ctx, { key: 'space', version: 2, ...box })).resolves.toEqual({
      legacy: false,
    });
    expect(crypto.calls).toContain(`openSpace:${SPACE}`);
  });

  it('is refused when the signature is not the sealer’s over this box', async () => {
    const { ctx, crypto, lee } = await setup();
    // Signed for another box, another key version and another key: none is this one.
    const other = signedBy(lee, finance, 1, { box: utf8('another-box') });
    expect(
      await refusal(openKeyBox(ctx, { key: finance, version: 1, sealed: encodeB64(BOX), sealedBy: other.sealedBy })),
    ).toBe('bad-signature');
    const later = signedBy(lee, finance, 2);
    expect(await refusal(openKeyBox(ctx, { key: finance, version: 1, ...later }))).toBe('bad-signature');
    const infra = signedBy(lee, { collection: INFRA }, 1);
    expect(await refusal(openKeyBox(ctx, { key: finance, version: 1, ...infra }))).toBe('bad-signature');
    expect(crypto.calls.some((call) => call.startsWith('openCollection'))).toBe(false);
  });

  it('is refused when the server made the signature up', async () => {
    const { ctx, crypto, lee } = await setup();
    const forged = {
      sealed: encodeB64(BOX),
      sealedBy: { account: lee.user, keyVersion: 1, signature: encodeB64(utf8('forged')) },
    };
    expect(await refusal(openKeyBox(ctx, { key: finance, version: 1, ...forged }))).toBe('bad-signature');
    const notEncoded = { sealed: encodeB64(BOX), sealedBy: { account: lee.user, keyVersion: 1, signature: '!!' } };
    expect(await refusal(openKeyBox(ctx, { key: finance, version: 1, ...notEncoded }))).toBe('bad-signature');
    expect(crypto.calls.some((call) => call.startsWith('openCollection'))).toBe(false);
  });

  it('is refused when the sealer is nobody the roster lists', async () => {
    const { ctx, lee } = await setup();
    const box = signedBy(lee, finance, 1);
    const stranger = { ...box.sealedBy, account: THEO };
    expect(await refusal(openKeyBox(ctx, { key: finance, version: 1, sealed: box.sealed, sealedBy: stranger }))).toBe(
      'sealer-unknown',
    );
  });

  it('is refused when I can not trace the sealer to myself or to a fingerprint a person compared', async () => {
    const { ctx, lee } = await setup({ confirmed: false });
    expect(await refusal(openKeyBox(ctx, { key: finance, version: 1, ...signedBy(lee, finance, 1) }))).toBe(
      'sealer-not-verified',
    );
  });

  it('is refused when the signature names another key version of the sealer than their bundle', async () => {
    const { ctx, lee } = await setup();
    const box = signedBy(lee, finance, 1, { signedVersion: 2 });
    expect(await refusal(openKeyBox(ctx, { key: finance, version: 1, ...box }))).toBe('sealer-version');
  });

  it('is refused when the sealer could not have been allowed to seal that key', async () => {
    const plain = await setup({ role: 'member' });
    const box = signedBy(plain.lee, finance, 1);
    expect(await refusal(openKeyBox(plain.ctx, { key: finance, version: 1, ...box }))).toBe('sealer-not-allowed');
    expect(
      await refusal(openKeyBox(plain.ctx, { key: 'space', version: 1, ...signedBy(plain.lee, 'space', 1) })),
    ).toBe('sealer-not-allowed');

    // Manage on the collection is enough for it, and manage-users for the space key.
    const manager = await setup({
      role: 'member',
      grants: [{ collection: FINANCE, grantee: `user:${LEE}`, permission: 'manage' }],
    });
    await expect(
      openKeyBox(manager.ctx, { key: finance, version: 1, ...signedBy(manager.lee, finance, 1) }),
    ).resolves.toEqual({ legacy: false });
    const users = await setup({ role: 'custom', custom: ['manage-users'] });
    await expect(
      openKeyBox(users.ctx, { key: 'space', version: 1, ...signedBy(users.lee, 'space', 1) }),
    ).resolves.toEqual({ legacy: false });
    // A custom member who may manage groups seals the keys of a collection they hold.
    const groups = await setup({
      role: 'custom',
      custom: ['manage-groups'],
      grants: [{ collection: FINANCE, grantee: `user:${LEE}`, permission: 'view' }],
    });
    await expect(
      openKeyBox(groups.ctx, { key: finance, version: 1, ...signedBy(groups.lee, finance, 1) }),
    ).resolves.toEqual({ legacy: false });
  });

  it('opens again without asking who sealed it, once accepted: a sealer who left changes nothing', async () => {
    const { ctx, lee, roster, crypto } = await setup();
    const box = signedBy(lee, finance, 1);
    await openKeyBox(ctx, { key: finance, version: 1, ...box });
    // Lee is removed from the roster, and nobody can trace them any more.
    roster.splice(roster.indexOf(lee), 1);
    crypto.calls.length = 0;
    await expect(openKeyBox(ctx, { key: finance, version: 1, ...box })).resolves.toEqual({
      legacy: false,
    });
    expect(crypto.calls).not.toContain(`verifyKeyBox:${FINANCE}`);
    // A box that differs is checked afresh, and fails.
    const other = signedBy(lee, finance, 1, { box: utf8('replacement') });
    expect(await refusal(openKeyBox(ctx, { key: finance, version: 1, ...other }))).toBe('sealer-unknown');
  });
});

describe('a key box from before keys were signed', () => {
  const unsigned = { sealed: encodeB64(BOX), sealedBy: null };

  it('is accepted once, remembered and flagged', async () => {
    const { ctx, crypto, boxes } = await setup();
    await expect(openKeyBox(ctx, { key: finance, version: 1, ...unsigned })).resolves.toEqual({
      legacy: true,
    });
    expect(crypto.calls).toContain(`openCollection:${FINANCE}`);
    expect((await boxes.load(ME, SPACE, `collection:${FINANCE}`, 1))?.signed).toBe(false);
    // The same box opens again, and is still flagged; nobody is asked who sealed it.
    await expect(openKeyBox(ctx, { key: finance, version: 1, sealed: unsigned.sealed, sealedBy: undefined })).resolves
      .toEqual({ legacy: true });
  });

  it('is refused when it is another box than the one accepted for that key and version', async () => {
    const { ctx } = await setup();
    await openKeyBox(ctx, { key: finance, version: 1, ...unsigned });
    const swapped = { sealed: encodeB64(utf8('a-box-the-server-made')), sealedBy: null };
    expect(await refusal(openKeyBox(ctx, { key: finance, version: 1, ...swapped }))).toBe('unsigned-changed');
  });

  it('is refused once a signed box of that key was accepted: the signature can not be taken away', async () => {
    const { ctx, lee, crypto } = await setup();
    await openKeyBox(ctx, { key: finance, version: 1, ...signedBy(lee, finance, 1) });
    crypto.calls.length = 0;
    // The server serves a box of its own as the next version, with no signature.
    const forged = { sealed: encodeB64(utf8('server-made-key')), sealedBy: null };
    expect(await refusal(openKeyBox(ctx, { key: finance, version: 2, ...forged }))).toBe('unsigned-downgrade');
    expect(crypto.calls.some((call) => call.startsWith('openCollection'))).toBe(false);
    // Another key of the space has no signed box yet, so its old box is still taken once.
    await expect(
      openKeyBox(ctx, { key: { collection: INFRA }, version: 1, ...unsigned }),
    ).resolves.toEqual({ legacy: true });
  });

  it('is replaced by a signed box of the same key and version', async () => {
    const { ctx, lee, boxes } = await setup();
    await openKeyBox(ctx, { key: finance, version: 1, ...unsigned });
    const replacement = signedBy(lee, finance, 1, { box: utf8('re-sealed-by-lee') });
    await expect(openKeyBox(ctx, { key: finance, version: 1, ...replacement })).resolves.toEqual({
      legacy: false,
    });
    expect((await boxes.load(ME, SPACE, `collection:${FINANCE}`, 1))?.signed).toBe(true);
  });
});

describe('the keys of a space with no chain', () => {
  it('lists the keys that are from before keys were signed', async () => {
    const { ctx, lee } = await setup();
    const signed = signedBy(lee, { collection: INFRA }, 1);
    const legacy = await openUnchainedKeys(ctx, {
      me: member(ME, { role: 'owner', sealedBy: null }),
      spaceKeyVersion: 1,
      collectionKeys: [
        { collection: INFRA, keyVersion: 1, ...signed },
        { collection: FINANCE, keyVersion: 1, sealed: encodeB64(BOX), sealedBy: null },
      ],
    });
    expect(legacy).toEqual(['space', `collection:${FINANCE}`]);
  });

  it('is not opened when the server forges a collection key box and seals it to me', async () => {
    const { deps, api, crypto, lee } = await setup();
    const real = signedBy(lee, { collection: INFRA }, 1);
    // The server made this key itself; it can't sign as Lee, so it signs with whatever it has.
    const forged = {
      collection: FINANCE,
      keyVersion: 1,
      sealed: encodeB64(utf8('the-servers-own-key')),
      sealedBy: { account: lee.user, keyVersion: 1, signature: encodeB64(utf8('not-lees')) },
    };
    api.get.mockResolvedValue(
      spaceView({ collectionKeys: [{ collection: INFRA, keyVersion: 1, ...real }, forged] }),
    );
    await expect(openSpaceKeys(deps, SPACE)).rejects.toBeInstanceOf(KeyBoxRefused);
    expect(crypto.calls).toContain(`openCollection:${INFRA}`);
    expect(crypto.calls).not.toContain(`openCollection:${FINANCE}`);

    // Nor when it leaves the signature off a key it had served signed before.
    const signed = signedBy(lee, { collection: FINANCE }, 1);
    api.get.mockResolvedValue(spaceView({ collectionKeys: [{ collection: FINANCE, keyVersion: 1, ...signed }] }));
    await openSpaceKeys(deps, SPACE);
    api.get.mockResolvedValue(
      spaceView({
        collectionKeys: [
          { collection: FINANCE, keyVersion: 2, sealed: encodeB64(utf8('the-servers-own-key')), sealedBy: null },
        ],
      }),
    );
    crypto.calls.length = 0;
    await expect(openSpaceKeys(deps, SPACE)).rejects.toBeInstanceOf(KeyBoxRefused);
    expect(crypto.calls).not.toContain(`openCollection:${FINANCE}`);
  });
});

describe('the account the server names as mine', () => {
  it('is checked against the one signed in here and never used in its place', async () => {
    const { deps, crypto, api } = await setup();
    const signedIn: SpaceDeps = { ...deps, account: () => ME };
    expect(signedInAccount(signedIn, ME)).toBe(ME);
    expect(() => signedInAccount(signedIn, THEO)).toThrow(WrongAccount);
    expect(() => signedInAccount({ ...deps, account: () => null }, ME)).toThrow(WrongAccount);
    // Without a session (a test) the server's word stands.
    expect(signedInAccount(deps, THEO)).toBe(THEO);

    // The server can't reach an empty record by serving another id as mine: a box this browser
    // accepted stays the only one accepted for that key, and the space doesn't open at all.
    api.get.mockResolvedValue(spaceView());
    await openSpaceKeys(signedIn, SPACE);
    crypto.calls.length = 0;
    api.get.mockResolvedValue(
      spaceView({
        me: member(THEO, { role: 'owner', sealedSpaceKey: encodeB64(utf8('the-servers-own-key')) }),
      }),
    );
    await expect(openSpaceKeys(signedIn, SPACE)).rejects.toBeInstanceOf(WrongAccount);
    expect(crypto.calls.some((call) => call.startsWith('openSpace'))).toBe(false);
  });
});
