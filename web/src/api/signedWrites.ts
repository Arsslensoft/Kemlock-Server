// Signs every item write this browser makes (docs/crypto.md, "Signed item writes"): the account
// signs the write with its own sig1 key, in the worker, and the server stores the signature with
// the item, serves it back, and passes it to the vault's other servers.
//
// It wraps the calls the vault writes through (`putItem`, `putBatch`), so every write path of the
// web vault is signed in one place: a new item, an edit, a move, the Trash and its emptying, a
// delete for good, and what a merge writes. Nothing is signed for an item that isn't `kem1`.
import type { Api } from '@/api/client';
import type { BatchWrite, ItemDto } from '@/api/types';
import type { ItemWriteFields } from '@/crypto/types';
import type { CryptoPort } from '@/crypto-port';

/** The calls the vault makes, which `VaultDeps.api` is. */
export type SignedApi = Pick<Api, 'sync' | 'putItem' | 'putBatch'>;

/** The fields of an item that its write signature covers. */
export function writeFields(item: ItemDto): ItemWriteFields {
  const deleted = item.deleted === true;
  return {
    owner: item.owner,
    id: item.id,
    kind: item.kind,
    revision: item.revision,
    deleted,
    keyVersion: item.keyVersion,
    ...(!deleted && item.ciphertext ? { ciphertext: item.ciphertext } : {}),
    ...(!deleted && item.itemKey ? { itemKey: item.itemKey } : {}),
  };
}

/**
 * `item` with its write signature, made now by the unlocked account. Whatever signature the item
 * came with (an item read from the server and sent back, say) is dropped: a write is signed for the
 * revision and the envelope it is, by this account, and a served signature is never re-sent.
 */
export async function signedItem(
  crypto: Pick<CryptoPort, 'itemWriteSign'>,
  item: ItemDto,
): Promise<ItemDto> {
  if (item.format !== 'kem1') return item;
  const { writer: _writer, writerKeyVersion: _version, writeSignature: _signature, ...bare } = item;
  const signed = await crypto.itemWriteSign(writeFields(bare));
  return {
    ...bare,
    writer: signed.writer,
    writerKeyVersion: signed.writerKeyVersion,
    writeSignature: signed.writeSignature,
  };
}

/**
 * `api` with every write signed. A write that can't be signed (the vault is locked, say) fails
 * with the worker's error and nothing is sent: an unsigned write to a signed-only owner would be
 * refused anyway, and one to any other owner would leave it unprotected.
 */
export function signedApi(api: SignedApi, crypto: Pick<CryptoPort, 'itemWriteSign'>): SignedApi {
  return {
    sync: (since, limit) => api.sync(since, limit),
    async putItem(item, precondition) {
      return api.putItem(await signedItem(crypto, item), precondition);
    },
    async putBatch(request) {
      const writes: BatchWrite[] = [];
      for (const write of request.writes) {
        writes.push({ ...write, item: await signedItem(crypto, write.item) });
      }
      return api.putBatch({ ...request, writes });
    },
  };
}
