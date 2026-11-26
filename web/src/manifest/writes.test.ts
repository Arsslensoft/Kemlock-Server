import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { ItemDto } from '@/api/types';
import { signedItem } from '@/api/signedWrites';
import { utf8 } from '@/lib/b64url';
import { crypto, resetFakeCrypto } from '@/test/fake-crypto';
import { createWriteChecker } from './writes';

const ACCOUNT = '99999999-9999-4999-8999-999999999999';
const MEMBER = '55555555-5555-4555-8555-555555555555';
const OWN = `user:${ACCOUNT}`;
const SPACE_ID = '44444444-4444-4444-8444-444444444444';
const SPACE = `space:${SPACE_ID}`;
const A = '11111111-1111-4111-8111-111111111111';

const item = (owner: string, revision = 2, extra: Partial<ItemDto> = {}): ItemDto => ({
  id: A,
  owner,
  kind: 'login',
  format: 'kem1',
  revision,
  keyVersion: 1,
  ciphertext: 'Y2lwaGVy',
  itemKey: 'a2V5',
  deleted: false,
  ...(owner === SPACE ? { collectionId: '33333333-3333-4333-8333-333333333333' } : {}),
  ...extra,
});

const spaceSigner = vi.fn(async (_space: string, signer: string) =>
  signer === MEMBER ? utf8(`bundle:${MEMBER}`) : null,
);

function checker(account: string | null = ACCOUNT) {
  return createWriteChecker({ crypto, accountId: () => account, spaceSigner });
}

beforeEach(async () => {
  resetFakeCrypto();
  spaceSigner.mockClear();
  await crypto.unlock(ACCOUNT, utf8(`wrapped:${ACCOUNT}`), new Uint8Array(), new Uint8Array());
});

describe('the verdict on a write signature', () => {
  it('has none for an item that is not kem1', async () => {
    expect(await checker().verdict({ ...item(OWN), format: 'bw' })).toBeUndefined();
  });

  it('is unsigned for an item that carries no signature', async () => {
    expect(await checker().verdict(item(OWN))).toBe('unsigned');
  });

  it('is signed for the account its own write, and invalid once anything it covers changes', async () => {
    const signed = await signedItem(crypto, item(OWN, 3));
    expect(await checker().verdict(signed)).toBe('signed');
    expect(await checker().verdict({ ...signed, revision: 4 })).toBe('invalid');
    expect(await checker().verdict({ ...signed, ciphertext: 'b3RoZXI' })).toBe('invalid');
    expect(await checker().verdict({ ...signed, deleted: true, ciphertext: null, itemKey: null })).toBe('invalid');
  });

  it('is signed for a signed deletion', async () => {
    const tombstone = await signedItem(crypto, { ...item(OWN, 5), deleted: true, ciphertext: null, itemKey: null });
    expect(tombstone.deleted).toBe(true);
    expect(await checker().verdict(tombstone)).toBe('signed');
  });

  it('is invalid for a signature that is partial, or names another account for the own vault', async () => {
    const signed = await signedItem(crypto, item(OWN));
    expect(await checker().verdict({ ...signed, writerKeyVersion: null })).toBe('invalid');
    expect(await checker().verdict({ ...signed, writer: MEMBER })).toBe('invalid');
    expect(await checker().verdict({ ...signed, writeSignature: null })).toBe('invalid');
  });

  it('is unknown when the vault is locked or the account is another', async () => {
    const signed = await signedItem(crypto, item(OWN));
    expect(await checker(MEMBER).verdict(signed)).toBe('unknown');
    resetFakeCrypto();
    expect(await checker().verdict(signed)).toBe('unknown');
  });

  it('checks a space item against the bundle of a member the space vouches for', async () => {
    // A member signs on their own device: the fake worker signs as the account it was opened for.
    resetFakeCrypto();
    await crypto.unlock(MEMBER, utf8(`wrapped:${MEMBER}`), new Uint8Array(), new Uint8Array());
    const signed = await signedItem(crypto, item(SPACE));
    // This browser is the account's, and checks with the member's bundle.
    resetFakeCrypto();
    await crypto.unlock(ACCOUNT, utf8(`wrapped:${ACCOUNT}`), new Uint8Array(), new Uint8Array());
    expect(await checker().verdict(signed)).toBe('signed');
    expect(spaceSigner).toHaveBeenCalledWith(SPACE_ID, MEMBER);
    expect(await checker().verdict({ ...signed, revision: 9 })).toBe('invalid');
  });

  it('is unknown for a space writer the space does not vouch for', async () => {
    const signed = await signedItem(crypto, item(SPACE));
    expect(signed.writer).toBe(ACCOUNT);
    expect(await checker().verdict(signed)).toBe('unknown');
  });

  it('is unknown when the member list cannot be reached', async () => {
    spaceSigner.mockRejectedValueOnce(new Error('offline'));
    const signed = await signedItem(crypto, item(SPACE, 2, { writer: MEMBER, writerKeyVersion: 1, writeSignature: 'c2ln' }));
    expect(await checker().verdict(signed)).toBe('unknown');
  });
});
