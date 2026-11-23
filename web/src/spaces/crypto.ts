// The crypto a space needs, as the page sees it. A space key and each collection key live inside
// the worker; names are encrypted under the space key; a member receives the space key and their
// collections' keys as kx1 sealed boxes (contexts `space-key` and `collection-key`) once someone
// has compared their fingerprint. The page speaks Uint8Array; the worker's contract
// (src/crypto/types.ts) speaks base64url, so `createSpaceCrypto` adapts one to the other.
import { crypto as worker } from '@/crypto';
import { type CryptoApi, CryptoError, type NameKind } from '@/crypto/types';
import { decodeB64, encodeB64 } from '@/lib/b64url';
import { createSharingCrypto, type SharingCrypto, unavailableSharingCrypto } from '@/sharing/crypto';

export type { NameKind };

export interface NewSpaceKeys {
  /** The space's name under the new space key. */
  name: Uint8Array;
  /** The space key sealed to the maker's own kx1 key. */
  sealedSpaceKey: Uint8Array;
  /** The first collection. */
  collection: { name: Uint8Array; sealedKey: Uint8Array };
}

/** What a member confirmation says (docs/crypto.md, "Member confirmation"). */
export interface ConfirmationFacts {
  space: string;
  member: string;
  memberKeyVersion: number;
  /** The 64 fingerprint bytes the confirmer compared. */
  fingerprint: Uint8Array;
}

export interface SpaceCrypto extends SharingCrypto {
  /** A fresh space key and first collection key, names sealed, both keys sealed to the maker. */
  newSpace(input: {
    spaceId: string;
    collectionId: string;
    spaceName: string;
    collectionName: string;
  }): Promise<NewSpaceKeys>;
  /** Opens the space key sealed to me and keeps it in the worker for `spaceId`. */
  openSpace(input: { spaceId: string; keyVersion: number; sealed: Uint8Array }): Promise<void>;
  /** Opens a collection key sealed to me and keeps it for sealing to others. */
  openCollection(input: {
    spaceId: string;
    collectionId: string;
    keyVersion: number;
    sealed: Uint8Array;
  }): Promise<void>;
  openName(input: {
    spaceId: string;
    keyVersion: number;
    kind: NameKind;
    id: string;
    ciphertext: Uint8Array;
  }): Promise<string>;
  sealName(input: {
    spaceId: string;
    keyVersion: number;
    kind: NameKind;
    id: string;
    name: string;
  }): Promise<Uint8Array>;
  /** A new collection: its key sealed to me, and its name under the space key. */
  newCollection(input: {
    spaceId: string;
    collectionId: string;
    name: string;
  }): Promise<{ name: Uint8Array; sealedKey: Uint8Array }>;
  /** The space key sealed to a member's kx1 key (context `space-key`, bound to the space, key version and member). */
  sealSpaceKeyTo(input: {
    spaceId: string;
    recipientKx1: Uint8Array;
    recipientId: Uint8Array;
  }): Promise<Uint8Array>;
  /** A collection key sealed to a member (context `collection-key`, bound to the space, collection, key version and member). */
  sealCollectionKeyTo(input: {
    spaceId: string;
    collectionId: string;
    recipientKx1: Uint8Array;
    recipientId: Uint8Array;
  }): Promise<Uint8Array>;
  /** The 134-byte statement the unlocked account signs to confirm a member (it is the confirmer). */
  confirmationStatement(input: ConfirmationFacts): Promise<Uint8Array>;
  /** Whether a stored confirmation is the confirmer's own signature over exactly these facts. */
  verifyConfirmation(
    input: ConfirmationFacts & {
      confirmerBundle: Uint8Array;
      statement: Uint8Array;
      signature: Uint8Array;
    },
  ): Promise<boolean>;
}

function unavailable<T>(): Promise<T> {
  return Promise.reject(new CryptoError('unavailable'));
}

export const unavailableSpaceCrypto: SpaceCrypto = {
  ...unavailableSharingCrypto,
  newSpace: () => unavailable(),
  openSpace: () => unavailable(),
  openCollection: () => unavailable(),
  openName: () => unavailable(),
  sealName: () => unavailable(),
  newCollection: () => unavailable(),
  sealSpaceKeyTo: () => unavailable(),
  sealCollectionKeyTo: () => unavailable(),
  confirmationStatement: () => unavailable(),
  verifyConfirmation: () => unavailable(),
};

type SpaceWorker = Pick<
  CryptoApi,
  | 'sealRootKey'
  | 'signStatement'
  | 'newSpace'
  | 'openSpace'
  | 'openCollection'
  | 'openName'
  | 'sealName'
  | 'newCollection'
  | 'sealSpaceKeyTo'
  | 'sealCollectionKeyTo'
  | 'confirmationStatement'
  | 'verifyConfirmation'
>;

/** Space crypto over a crypto worker client. */
export function createSpaceCrypto(api: SpaceWorker): SpaceCrypto {
  return {
    ...createSharingCrypto(api),
    async newSpace(input) {
      const made = await api.newSpace(input);
      return {
        name: decodeB64(made.name),
        sealedSpaceKey: decodeB64(made.sealedSpaceKey),
        collection: {
          name: decodeB64(made.collection.name),
          sealedKey: decodeB64(made.collection.sealedKey),
        },
      };
    },
    openSpace: ({ spaceId, keyVersion, sealed }) =>
      api.openSpace({ spaceId, keyVersion, sealed: encodeB64(sealed) }),
    openCollection: ({ spaceId, collectionId, keyVersion, sealed }) =>
      api.openCollection({ spaceId, collectionId, keyVersion, sealed: encodeB64(sealed) }),
    openName: ({ spaceId, keyVersion, kind, id, ciphertext }) =>
      api.openName({ spaceId, keyVersion, kind, id, ciphertext: encodeB64(ciphertext) }),
    async sealName(input) {
      return decodeB64(await api.sealName(input));
    },
    async newCollection(input) {
      const made = await api.newCollection(input);
      return { name: decodeB64(made.name), sealedKey: decodeB64(made.sealedKey) };
    },
    async sealSpaceKeyTo({ spaceId, recipientKx1, recipientId }) {
      return decodeB64(
        await api.sealSpaceKeyTo({
          spaceId,
          recipientKx1: encodeB64(recipientKx1),
          recipientId: encodeB64(recipientId),
        }),
      );
    },
    async sealCollectionKeyTo({ spaceId, collectionId, recipientKx1, recipientId }) {
      return decodeB64(
        await api.sealCollectionKeyTo({
          spaceId,
          collectionId,
          recipientKx1: encodeB64(recipientKx1),
          recipientId: encodeB64(recipientId),
        }),
      );
    },
    async confirmationStatement({ space, member, memberKeyVersion, fingerprint }) {
      return decodeB64(
        await api.confirmationStatement({
          space,
          member,
          memberKeyVersion,
          fingerprint: encodeB64(fingerprint),
        }),
      );
    },
    verifyConfirmation: ({
      space,
      member,
      memberKeyVersion,
      fingerprint,
      confirmerBundle,
      statement,
      signature,
    }) =>
      api.verifyConfirmation({
        space,
        member,
        memberKeyVersion,
        fingerprint: encodeB64(fingerprint),
        confirmerBundle: encodeB64(confirmerBundle),
        statement: encodeB64(statement),
        signature: encodeB64(signature),
      }),
  };
}

/** The one the app uses. */
export const spaceCrypto: SpaceCrypto = createSpaceCrypto(worker);
