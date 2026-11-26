// Deterministic stand-ins for the sharing and space crypto: no cryptography, the same shapes and
// the same failure points (a name opens only under the id, kind and key version it was sealed
// with; a sealed key says who it is for), so the account screens' logic is tested without
// WebAssembly.
import type { ChainBuilt, ChainChange, ChainReplacement, ChainView } from '@/crypto/types';
import { decodeB64, encodeB64, fromUtf8, utf8 } from '@/lib/b64url';
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

/** What the worker answers for a space the server serves no chain for. */
export const NO_CHAIN: ChainView = {
  ok: true,
  chained: false,
  epoch: 0,
  links: [],
  trusted: true,
  members: [],
  space: { keyVersion: 0, marked: false, nameHash: '', nameVersion: 0 },
  collections: [],
  groups: [],
  grants: [],
  keys: [],
};

export interface FakeSpaces extends SpaceCrypto {
  calls: string[];
  /**
   * What `verifySpaceChain` answers: a space with no chain unless a test sets it (a refusal, or a
   * verified view). A view that is chained is then what `spaceChainView` gives, until `lock`.
   */
  chain: ChainView | { ok: false; reason: string; seq: number | null };
  /** What `ownFingerprint` answers: set it to the fingerprint of the test's own bundle. */
  ownFingerprintText: string;
  /** What `buildChainRecords` answers instead of the default one record per change, when set. */
  built: ChainBuilt | null;
  /** The changes `buildChainRecords` was asked for, in order. */
  changes: ChainChange[];
  /** What `buildKeyReplacement` answers instead of a keys record and every item sealed again. */
  replaced: ChainBuilt | null;
  /** What `buildKeyReplacement` was given, in order. */
  replacements: ChainReplacement[];
}

function utf8Text(text: string): string {
  return encodeB64(utf8(text));
}

function nameBytes(spaceId: string, keyVersion: number, kind: string, id: string, name: string) {
  return utf8(JSON.stringify([spaceId, keyVersion, kind, id, name]));
}

export function fakeSpaceCrypto(): FakeSpaces {
  const base = fakeSharingCrypto();
  const calls = base.calls;
  let held: ChainView | null = null;
  const fake: FakeSpaces = {
    ...base,
    ownFingerprintText: '',
    chain: NO_CHAIN,
    built: null,
    changes: [],
    replaced: null,
    replacements: [],
    async buildKeyReplacement({ spaceId, replacement }) {
      fake.replacements.push(replacement);
      calls.push('buildKeyReplacement');
      if (fake.replaced) return fake.replaced;
      // A keys record, and every item given sealed again as the next revision, one version up.
      return {
        ok: true,
        records: [{ entry: utf8Text('keys-record'), signature: utf8Text('signature') }],
        seals: [],
        names: [],
        writes: replacement.items.map((item) => ({
          collection: item.collection,
          expectedRevision: item.revision,
          item: {
            id: item.id,
            owner: `space:${spaceId}`,
            kind: item.kind,
            format: 'kem1' as const,
            revision: item.revision + 1,
            keyVersion: item.keyVersion + 1,
            ciphertext: utf8Text(`again:${item.id}`),
            itemKey: utf8Text(`wrapped:${item.id}`),
            deleted: false as const,
            collectionId: item.collection,
          },
        })),
      };
    },
    async newChainedSpace({ spaceId, collectionId, spaceName, collectionName, at }) {
      calls.push(`newChainedSpace:${at}`);
      return {
        ok: true,
        records: [{ entry: utf8Text('create-record'), signature: utf8Text('create-signature') }],
        seals: [
          { box: utf8Text(`collection-key:${collectionId}`), key: `collection:${collectionId}`, member: 'me', seq: 0, version: 1 },
          { box: utf8Text(`space-key:${spaceId}`), key: 'space', member: 'me', seq: 0, version: 1 },
        ],
        names: [
          { name: encodeB64(nameBytes(spaceId, 1, 'collection', collectionId, collectionName)), seq: 0, target: `collection:${collectionId}` },
          { name: encodeB64(nameBytes(spaceId, 1, 'space', spaceId, spaceName)), seq: 0, target: 'space' },
        ],
      };
    },
    async buildChainRecords({ change }) {
      fake.changes.push(change);
      calls.push(`buildChainRecords:${change.action}`);
      if (fake.built) return fake.built;
      // One record for the change; a seal with nothing to share makes none.
      return {
        ok: true,
        records:
          change.action === 'seal'
            ? []
            : [{ entry: utf8Text(JSON.stringify(change)), signature: utf8Text('signature') }],
        seals: [],
        names: [],
      };
    },
    async verifySpaceChain({ spaceId }) {
      calls.push(`verifySpaceChain:${spaceId}`);
      held = fake.chain.ok && fake.chain.chained ? fake.chain : null;
      return fake.chain;
    },
    async spaceChainView() {
      return held;
    },
    async sealLocal(label, text) {
      return encodeB64(utf8(JSON.stringify([label, text])));
    },
    async openLocal(label, sealed) {
      const [kept, text] = JSON.parse(fromUtf8(decodeB64(sealed))) as [string, string];
      if (kept !== label) throw new Error('invalid');
      return text;
    },
    async acceptFirstContact(spaceId) {
      calls.push(`acceptFirstContact:${spaceId}`);
      if (held) held = { ...held, trusted: true };
    },
    async openChainKey({ key, servedVersion }) {
      calls.push(`openChainKey:${key}:${servedVersion}`);
    },
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
    async verifyBundle(_bundle, signature) {
      calls.push('verifyBundle');
      return fromUtf8(signature) !== 'bad-bundle-signature';
    },
    async ownFingerprint() {
      return fake.ownFingerprintText;
    },
    async verifyConfirmation({ space, member, memberKeyVersion, statement, signature }) {
      calls.push('verifyConfirmation');
      // Like the worker: the statement must be the one these facts give, and the signature theirs.
      return (
        fromUtf8(statement) === JSON.stringify(['confirm', space, member, memberKeyVersion]) &&
        fromUtf8(signature) === `sig>confirm>${fromUtf8(statement)}`
      );
    },
  };
  return fake;
}
