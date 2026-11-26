// @vitest-environment node
import { describe, expect, it } from 'vitest';
import type { MemberViewDto } from '@/api/spaces';
import { decodeB64, encodeB64, utf8 } from '@/lib/b64url';
import { parseBundle } from '@/sharing/bundle';
import { type PinStore, memoryPinStore } from '@/spaces/anchors';
import { makeBundleB64 } from '@/test/bundles';
import { fakeSpaceCrypto } from '@/test/fake-space-crypto';
import { LEE, ME, SPACE, THEO, confirmedBy, fingerprintTextOf, memberView } from './fixtures';
import { MemberNotVerified, type RosterContext, verifiedRecipient } from './verify';

const ADMIN = '20000000-0000-4000-8000-000000000009';

async function roster(extra: MemberViewDto[] = []) {
  const crypto = fakeSpaceCrypto();
  const me = memberView(ME, 'sam@example.co', { role: 'owner' });
  crypto.ownFingerprintText = await fingerprintTextOf(me);
  const lee = await confirmedBy(ME, memberView(LEE, 'lee@example.co'));
  const members = [me, lee, ...extra];
  const pins = memoryPinStore();
  const ctx: RosterContext = { crypto, spaceId: SPACE, members, me: ME, pins };
  return { crypto, ctx, me, lee, pins };
}

async function failure(ctx: RosterContext, member: MemberViewDto): Promise<MemberNotVerified> {
  const error = await verifiedRecipient(ctx, member).then(
    () => null,
    (caught: unknown) => caught,
  );
  expect(error).toBeInstanceOf(MemberNotVerified);
  return error as MemberNotVerified;
}

async function refused(ctx: RosterContext, member: MemberViewDto) {
  return (await failure(ctx, member)).reason;
}

async function pin(pins: PinStore, view: MemberViewDto) {
  await pins.save(ME, view.user, await fingerprintTextOf(view));
}

describe('who a key may be sealed to', () => {
  it('is a member whose confirmation, by me, covers exactly their listed keys', async () => {
    const { ctx, lee } = await roster();
    const recipient = await verifiedRecipient(ctx, lee);
    const parsed = parseBundle(decodeB64(lee.publicBundle));
    expect(recipient.kx1).toEqual(parsed?.kx1);
    expect(recipient.id).toEqual(parsed?.accountId);
  });

  it('follows a confirmation back through an admin whose own confirmation is mine', async () => {
    const admin = await confirmedBy(ME, memberView(ADMIN, 'ada@example.co', { role: 'admin' }));
    const theo = await confirmedBy(ADMIN, memberView(THEO, 'theo@example.co'));
    const { ctx } = await roster([admin, theo]);
    await expect(verifiedRecipient(ctx, theo)).resolves.toBeDefined();
  });

  it('does not take a listed creator, whom nobody confirmed, for a root', async () => {
    const creator = memberView(ADMIN, 'ada@example.co', { role: 'owner', invitedBy: ADMIN });
    const theo = await confirmedBy(ADMIN, memberView(THEO, 'theo@example.co'));
    const { ctx } = await roster([creator, theo]);
    // Everything about the creator is the server's word, so Theo isn't traced, and what would
    // help is a person comparing the creator's fingerprint.
    const failed = await failure(ctx, theo);
    expect(failed.reason).toBe('unknown-confirmer');
    expect(failed.compare?.user).toBe(ADMIN);
    expect((await failure(ctx, creator)).compare?.user).toBe(ADMIN);
  });

  it('takes a member whose fingerprint a person compared here for a root, and only while it is that one', async () => {
    const creator = memberView(ADMIN, 'ada@example.co', { role: 'owner', invitedBy: ADMIN });
    const theo = await confirmedBy(ADMIN, memberView(THEO, 'theo@example.co'));
    const { ctx, pins } = await roster([creator, theo]);
    await pin(pins, creator);
    await expect(verifiedRecipient(ctx, theo)).resolves.toBeDefined();
    await expect(verifiedRecipient(ctx, creator)).resolves.toBeDefined();
    // The server lists other keys under the same id: the pin is of the keys compared.
    const swapped = { ...creator, publicBundle: makeBundleB64(ADMIN, 1, 0x66) };
    expect(await refused({ ...ctx, members: [...ctx.members.filter((m) => m.user !== ADMIN), swapped] }, theo)).toBe(
      'unknown-confirmer',
    );
  });

  it('is not fooled by two members whose bundles the server swapped, and a confirmation signed for the first', async () => {
    // Alice is the real creator and Bob a member she confirmed. The server lists Alice's id with
    // its own bundle, and signs "Bob" (also its own bundle) as confirmed by that fake Alice.
    const alice = memberView(ADMIN, 'alice@example.co', { role: 'owner', invitedBy: ADMIN, publicBundle: makeBundleB64(ADMIN, 1, 0x31) });
    const bob = await confirmedBy(ADMIN, memberView(THEO, 'bob@example.co', { publicBundle: makeBundleB64(THEO, 1, 0x32) }));
    const { ctx } = await roster([alice, bob]);
    expect(await refused(ctx, bob)).toBe('unknown-confirmer');
  });

  it('refuses a bundle swapped under a confirmation of the old one', async () => {
    const { ctx, lee } = await roster();
    expect(await refused(ctx, { ...lee, publicBundle: makeBundleB64(LEE, 1, 0x77) })).toBe(
      'confirmation-differs',
    );
  });

  it('refuses a bundle that is another account’s', async () => {
    const { ctx, lee } = await roster();
    expect(await refused(ctx, { ...lee, publicBundle: makeBundleB64(THEO) })).toBe('wrong-account');
  });

  it('refuses a bundle at another key version than the member', async () => {
    const { ctx, lee } = await roster();
    expect(await refused(ctx, { ...lee, publicBundle: makeBundleB64(LEE, 2) })).toBe(
      'wrong-key-version',
    );
  });

  it('refuses a bundle that is not signed by its own key', async () => {
    const { ctx, lee } = await roster();
    expect(await refused(ctx, { ...lee, bundleSignature: encodeB64(utf8('bad-bundle-signature')) })).toBe(
      'bad-bundle-signature',
    );
  });

  it('refuses a bundle that can not be read', async () => {
    const { ctx, lee } = await roster();
    expect(await refused(ctx, { ...lee, publicBundle: encodeB64(utf8('not a bundle')) })).toBe('unreadable');
  });

  it('refuses a member who is not confirmed, or has no confirmation, or needs a new one', async () => {
    const { ctx, lee } = await roster();
    expect(await refused(ctx, { ...lee, state: 'accepted' })).toBe('not-confirmed');
    expect(await refused(ctx, { ...lee, confirmation: null })).toBe('no-confirmation');
    expect(await refused(ctx, { ...lee, needsReconfirmation: true })).toBe('confirmation-differs');
  });

  it('refuses a confirmation of another key version', async () => {
    const { ctx, lee } = await roster();
    const confirmation = lee.confirmation;
    if (!confirmation) throw new Error('fixture');
    expect(await refused(ctx, { ...lee, confirmation: { ...confirmation, memberKeyVersion: 2 } })).toBe(
      'confirmation-differs',
    );
  });

  it('refuses a signature that is not the confirmer’s over these facts', async () => {
    const { ctx, lee } = await roster();
    const confirmation = lee.confirmation;
    if (!confirmation) throw new Error('fixture');
    const forged = { ...confirmation, signature: encodeB64(utf8('sig>confirm>other')) };
    expect(await refused(ctx, { ...lee, confirmation: forged })).toBe('bad-confirmation');
    // The statement of another member's confirmation doesn't cover this one.
    const theos = await confirmedBy(ME, memberView(THEO, 'theo@example.co'));
    const swapped = { ...confirmation, statement: theos.confirmation?.statement ?? '', signature: theos.confirmation?.signature ?? '' };
    expect(await refused(ctx, { ...lee, confirmation: swapped })).toBe('bad-confirmation');
  });

  it('refuses a confirmer who is not listed, or may not confirm', async () => {
    const { ctx, lee } = await roster();
    const stranger = await confirmedBy(ADMIN, memberView(THEO, 'theo@example.co'));
    expect(await refused(ctx, stranger)).toBe('unknown-confirmer');
    const plain = await confirmedBy(LEE, memberView(THEO, 'theo@example.co'));
    expect(await refused({ ...ctx, members: [...ctx.members, plain] }, plain)).toBe('unknown-confirmer');
    expect(lee.confirmation?.by).toBe(ME);
  });

  it('refuses a confirmer whose own keys are not what they signed for', async () => {
    const admin = await confirmedBy(ME, memberView(ADMIN, 'ada@example.co', { role: 'admin' }));
    const theo = await confirmedBy(ADMIN, memberView(THEO, 'theo@example.co'));
    const { ctx } = await roster([{ ...admin, publicBundle: makeBundleB64(ADMIN, 1, 0x66) }, theo]);
    expect(await refused(ctx, theo)).toBe('unknown-confirmer');
  });

  it('refuses a listing of my own keys that is not what this browser holds', async () => {
    const { ctx, me, crypto } = await roster();
    crypto.ownFingerprintText = '00000 00000';
    expect(await refused(ctx, me)).toBe('own-keys');
  });

  it('ends a loop of confirmers', async () => {
    const a = await confirmedBy(THEO, memberView(ADMIN, 'ada@example.co', { role: 'admin' }));
    const b = await confirmedBy(ADMIN, memberView(THEO, 'theo@example.co', { role: 'admin' }));
    const { ctx } = await roster([a, b]);
    expect(await refused(ctx, a)).toBe('unknown-confirmer');
  });

  it('can tell a person which member to compare, through a confirmer that was itself confirmed', async () => {
    const root = memberView(ADMIN, 'ada@example.co', { role: 'owner', invitedBy: ADMIN });
    const admin = await confirmedBy(ADMIN, memberView('20000000-0000-4000-8000-00000000000a', 'bo@example.co', { role: 'admin' }));
    const theo = await confirmedBy(admin.user, memberView(THEO, 'theo@example.co'));
    const { ctx } = await roster([root, admin, theo]);
    expect((await failure(ctx, theo)).compare?.user).toBe(ADMIN);
  });
});
