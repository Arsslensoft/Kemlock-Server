// Deterministic stand-ins for the sharing and space crypto: no cryptography, the same shapes and
// the same failure points (a name opens only under the id, kind and key version it was sealed
// with; a sealed key says who it is for), so the account screens' logic is tested without
// WebAssembly.
import { fromUtf8, utf8 } from '@/lib/b64url';
import type { SharingCrypto } from '@/sharing/crypto';
import type { SpaceCrypto } from '@/spaces/crypto';

export interface FakeSharing extends SharingCrypto {
  calls: string[];
}

export function fakeSharingCrypto(): FakeSharing {
  const calls: string[] = [];
  return {
    available: true,
    calls,
    async sealRootKey(recipientKx1, context, aad) {
      calls.push(`sealRootKey:${context}`);
      return utf8(`root>${context}>${recipientKx1.length}>${aad.length}`);
    },
    async wrapForThisDevice({ keyVersion }) {
      calls.push('wrapForThisDevice');
      return utf8(`wrapped>${keyVersion}`);
    },
    async signStatement(statement, context) {
      calls.push(`sign:${context}`);
      return utf8(`sig>${context}>${fromUtf8(statement)}`);
    },
    canWrapForThisDevice: true,
  };
}

export interface FakeSpaces extends SpaceCrypto {
  calls: string[];
}

function nameBytes(spaceId: string, keyVersion: number, kind: string, id: string, name: string) {
  return utf8(JSON.stringify([spaceId, keyVersion, kind, id, name]));
}

export function fakeSpaceCrypto(): FakeSpaces {
  const base = fakeSharingCrypto();
  const calls = base.calls;
  return {
    ...base,
    async newSpace({ spaceId, collectionId, spaceName, collectionName }) {
      calls.push('newSpace');
      return {
        name: nameBytes(spaceId, 1, 'space', spaceId, spaceName),
        sealedSpaceKey: utf8(`space-key:${spaceId}`),
        collection: {
          name: nameBytes(spaceId, 1, 'collection', collectionId, collectionName),
          sealedKey: utf8(`collection-key:${collectionId}`),
        },
      };
    },
    async openSpace({ spaceId }) {
      calls.push(`openSpace:${spaceId}`);
    },
    async openCollection({ collectionId }) {
      calls.push(`openCollection:${collectionId}`);
    },
    async openName({ spaceId, keyVersion, kind, id, ciphertext }) {
      const [s, v, k, i, name] = JSON.parse(fromUtf8(ciphertext)) as [
        string,
        number,
        string,
        string,
        string,
      ];
      if (s !== spaceId || v !== keyVersion || k !== kind || i !== id) {
        throw new Error('the name does not open under these details');
      }
      return name;
    },
    async sealName({ spaceId, keyVersion, kind, id, name }) {
      return nameBytes(spaceId, keyVersion, kind, id, name);
    },
    async newCollection({ spaceId, collectionId, name }) {
      calls.push(`newCollection:${collectionId}`);
      return {
        name: nameBytes(spaceId, 1, 'collection', collectionId, name),
        sealedKey: utf8(`collection-key:${collectionId}`),
      };
    },
    async sealSpaceKeyTo({ spaceId, recipientId }) {
      calls.push(`sealSpaceKeyTo:${recipientId.length}`);
      return utf8(`space-key-for:${spaceId}`);
    },
    async sealCollectionKeyTo({ collectionId }) {
      calls.push(`sealCollectionKeyTo:${collectionId}`);
      return utf8(`collection-key-for:${collectionId}`);
    },
    async confirmationStatement({ space, member, memberKeyVersion }) {
      calls.push('confirmationStatement');
      return utf8(JSON.stringify(['confirm', space, member, memberKeyVersion]));
    },
    async verifyConfirmation({ statement, signature }) {
      return fromUtf8(signature) === `sig>confirm>${fromUtf8(statement)}`;
    },
  };
}
