// @vitest-environment node
import { describe, expect, it } from 'vitest';
import type { MemberViewDto } from '@/api/spaces';
import { decodeB64, encodeB64, utf8 } from '@/lib/b64url';
import { parseBundle } from '@/sharing/bundle';
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
  const ctx: RosterContext = { crypto, spaceId: SPACE, members, me: ME };
  return { crypto, ctx, me, lee };
}

async function refused(ctx: RosterContext, member: MemberViewDto) {
  const error = await verifiedRecipient(ctx, member).then(
    () => null,
    (caught: unknown) => caught,
  );
  expect(error).toBeInstanceOf(MemberNotVerified);
  return (error as MemberNotVerified).reason;
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

  it('accepts a confirmation by the creator, who nobody confirmed, as a root', async () => {
    const creator = memberView(ADMIN, 'ada@example.co', { role: 'owner', invitedBy: ADMIN });
    const theo = await confirmedBy(ADMIN, memberView(THEO, 'theo@example.co'));
    const { ctx } = await roster([creator, theo]);
    await expect(verifiedRecipient(ctx, theo)).resolves.toBeDefined();
    // But the creator's own keys are not a recipient on that word alone.
    expect(await refused(ctx, creator)).toBe('no-confirmation');
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
});
