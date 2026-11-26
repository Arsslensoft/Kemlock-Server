import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { PutResult } from '@/api/client';
import type { ItemDto } from '@/api/types';
import { crypto, resetFakeCrypto, writeSignatureText } from '@/test/fake-crypto';
import { decodeB64, fromUtf8 } from '@/lib/b64url';
import { type SignedApi, signedApi, signedItem, writeFields } from './signedWrites';

const ACCOUNT = '99999999-9999-4999-8999-999999999999';
const MEMBER = '55555555-5555-4555-8555-555555555555';
const OWN = `user:${ACCOUNT}`;

const live = (id: string, revision: number): ItemDto => ({
  id,
  owner: OWN,
  kind: 'login',
  format: 'kem1',
  revision,
  keyVersion: 1,
  ciphertext: 'Y2lwaGVy',
  itemKey: 'a2V5',
  deleted: false,
});

const tombstone = (id: string, revision: number): ItemDto => ({
  id,
  owner: OWN,
  kind: 'login',
  format: 'kem1',
  revision,
  keyVersion: 1,
  deleted: true,
});

beforeEach(async () => {
  resetFakeCrypto();
  await crypto.unlock(ACCOUNT, new TextEncoder().encode(`wrapped:${ACCOUNT}`), new Uint8Array(), new Uint8Array());
});

function recorder() {
  const sent: ItemDto[] = [];
  const api: SignedApi = {
    sync: vi.fn(),
    async putItem(item): Promise<PutResult> {
      sent.push(item);
      return { item, etag: null };
    },
    async putBatch(request) {
      for (const write of request.writes) sent.push(write.item);
      return request.writes.map((w) => w.item);
    },
  };
  return { api, sent };
}

describe('writeFields', () => {
  it('holds what the signature covers, and no ciphertext for a tombstone', () => {
    expect(writeFields(live('a', 3))).toEqual({
      owner: OWN,
      id: 'a',
      kind: 'login',
      revision: 3,
      deleted: false,
      keyVersion: 1,
      ciphertext: 'Y2lwaGVy',
      itemKey: 'a2V5',
    });
    expect(writeFields(tombstone('a', 4))).toEqual({
      owner: OWN,
      id: 'a',
      kind: 'login',
      revision: 4,
      deleted: true,
      keyVersion: 1,
    });
  });

  it('names the collection of an item of a space, which the signature covers, and none for a vault', () => {
    const collectionId = '33333333-3333-4333-8333-333333333333';
    const inSpace: ItemDto = { ...live('a', 3), owner: 'space:44444444-4444-4444-8444-444444444444', collectionId };
    expect(writeFields(inSpace)).toMatchObject({ collectionId });
    // A vault's item has none to name, whatever the dto carries.
    expect(writeFields({ ...live('a', 3), collectionId })).not.toHaveProperty('collectionId');
  });
});

describe('signedItem', () => {
  it('adds the writer, its key version and the signature of a kem1 item', async () => {
    const signed = await signedItem(crypto, live('a', 2));
    expect(signed.writer).toBe(ACCOUNT);
    expect(signed.writerKeyVersion).toBe(1);
    expect(fromUtf8(decodeB64(signed.writeSignature ?? ''))).toBe(
      writeSignatureText(ACCOUNT, 1, writeFields(live('a', 2))),
    );
  });

  it('drops a signature the item came with and signs it afresh', async () => {
    // An item read from the server and sent back carries what the server served: another
    // writer's signature, or an older revision's. It is never re-sent.
    const served = { ...live('a', 2), writer: MEMBER, writerKeyVersion: 7, writeSignature: 'c2ln' };
    const signed = await signedItem(crypto, served);
    expect(signed.writer).toBe(ACCOUNT);
    expect(signed.writerKeyVersion).toBe(1);
    expect(fromUtf8(decodeB64(signed.writeSignature ?? ''))).toBe(
      writeSignatureText(ACCOUNT, 1, writeFields(live('a', 2))),
    );
  });

  it('leaves an item that is not kem1 as it is', async () => {
    const bw: ItemDto = { ...live('b', 1), format: 'bw' };
    expect(await signedItem(crypto, bw)).toBe(bw);
  });
});

describe('signedApi', () => {
  it('signs a write and a delete before they are sent', async () => {
    const { api, sent } = recorder();
    const signing = signedApi(api, crypto);
    await signing.putItem(live('a', 1), { ifNoneMatch: true });
    await signing.putItem(tombstone('a', 2), { ifMatch: 1 });
    expect(sent.map((item) => [item.revision, item.deleted, item.writer])).toEqual([
      [1, false, ACCOUNT],
      [2, true, ACCOUNT],
    ]);
    expect(sent.every((item) => item.writeSignature)).toBe(true);
  });

  it('signs every write of a batch, tombstones included', async () => {
    const { api, sent } = recorder();
    await signedApi(api, crypto).putBatch({
      writes: [
        { expectedRevision: null, item: live('a', 1) },
        { expectedRevision: 3, item: tombstone('b', 4) },
      ],
    });
    expect(sent).toHaveLength(2);
    expect(sent.every((item) => item.writer === ACCOUNT && item.writeSignature)).toBe(true);
  });

  it('sends nothing when the write cannot be signed', async () => {
    const { api, sent } = recorder();
    resetFakeCrypto();
    await expect(signedApi(api, crypto).putItem(live('a', 1), { ifNoneMatch: true })).rejects.toThrow();
    expect(sent).toEqual([]);
  });

  it('reads through unchanged', async () => {
    const { api } = recorder();
    await signedApi(api, crypto).sync('cursor', 10);
    expect(api.sync).toHaveBeenCalledWith('cursor', 10);
  });
});
