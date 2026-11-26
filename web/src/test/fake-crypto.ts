// A deterministic stand-in for the crypto worker, aliased in for `@/crypto` under Vitest. It
// does no cryptography: it keeps the same shapes and the same failure points (an item opens only
// under the id, revision, kind and owner it was sealed with, like the real AAD), so the app's
// logic is tested without WebAssembly.
import type { CryptoPort } from '@/crypto-port';
import type { ItemWriteFields } from '@/crypto/types';
import { decodeB64, encodeB64, fromUtf8, utf8 } from '@/lib/b64url';

const calls: string[] = [];

/** What the fake was asked, in order: tests read it to check the sequence of a flow. */
export const fakeCalls = calls;

let locked = true;
export const isFakeLocked = () => locked;
/** The account the fake vault was opened for, for `ownFingerprint`. */
let openedFor = '';

/** The tabs that have a reload key, as IndexedDB would keep them: a test deletes one to age it out. */
export const fakeTabKeys = new Set<string>();

export const crypto: CryptoPort = {
  async masterKey(password, kdf) {
    calls.push('masterKey');
    // A checksum, never the password itself, so a test can prove the password goes nowhere else.
    const sum = [...password].reduce((a, c) => (a * 31 + (c.codePointAt(0) ?? 0)) >>> 0, 7);
    return utf8(`mk:${sum}:${kdf.memoryKib}`);
  },
  async opaqueRegisterStart(masterKey) {
    calls.push('opaqueRegisterStart');
    return { request: utf8(`reg-req:${fromUtf8(masterKey)}`), state: { kind: 'register' } };
  },
  async opaqueRegisterFinish(_state, _masterKey, response) {
    calls.push('opaqueRegisterFinish');
    return { upload: utf8(`upload:${fromUtf8(response)}`), exportKey: utf8('export-key') };
  },
  async opaqueLoginStart(masterKey) {
    calls.push('opaqueLoginStart');
    return { request: utf8(`login-req:${fromUtf8(masterKey)}`), state: { kind: 'login' } };
  },
  async opaqueLoginFinish(_state, _masterKey, response) {
    calls.push('opaqueLoginFinish');
    return { finalization: utf8(`fin:${fromUtf8(response)}`), exportKey: utf8('export-key') };
  },
  async newAccount(accountId) {
    calls.push('newAccount');
    return {
      publicBundle: utf8(`bundle:${accountId}`),
      bundleSignature: utf8('sig'),
      sealedPrivateKeys: utf8('sealed'),
      wrappedRootKey: utf8(`wrapped:${accountId}`),
    };
  },
  async rewrapRoot(masterKey, exportKey) {
    calls.push('rewrapRoot');
    if (locked) throw new Error('the vault is locked');
    // The wrap follows both new keys, so a test sees that it was made for the new password.
    return utf8(`rewrapped:${fromUtf8(masterKey)}:${fromUtf8(exportKey)}`);
  },
  async unlock(accountId, wrappedRootKey) {
    calls.push('unlock');
    if (fromUtf8(wrappedRootKey) !== `wrapped:${accountId}`) throw new Error('wrong wrapped key');
    locked = false;
    openedFor = accountId;
  },
  async sealItem({ id, owner, kind, revision, json }) {
    calls.push('sealItem');
    if (locked) throw new Error('the vault is locked');
    return {
      ciphertext: utf8(JSON.stringify([id, owner, kind, revision, json])),
      itemKey: utf8('item-key'),
      keyVersion: 1,
    };
  },
  async openItem({ id, owner, kind, revision, ciphertext }) {
    calls.push('openItem');
    if (locked) throw new Error('the vault is locked');
    const [sid, sowner, skind, srevision, json] = JSON.parse(fromUtf8(ciphertext)) as [
      string,
      string,
      string,
      number,
      string,
    ];
    if (sid !== id || sowner !== owner || skind !== kind || srevision !== revision) {
      throw new Error('the item does not open under these details');
    }
    return json;
  },
  async dpopProof(htm, htu, nonce, accessToken) {
    calls.push('dpopProof');
    return ['proof', htm, htu, nonce ?? '', accessToken ? 'ath' : ''].join('|');
  },
  async totpUri(secret) {
    return `otpauth://totp/Kemlock?secret=${secret ?? 'NEWSECRET'}`;
  },
  // Sends. The seals keep the real ones' failure points: a part opens only for the id, kind and
  // link key it was sealed under, and the sealed key only in an unlocked vault.
  async sendNewKey() {
    calls.push('sendNewKey');
    return sendKeys.next();
  },
  async sealSend({ id, kind, linkKey, payloadJson, metaJson }) {
    calls.push('sealSend');
    // The meta's key comes from the account, as the real one's does, so sealing needs the vault
    // open and the link key plays no part in it.
    if (locked) throw new Error('the vault is locked');
    return {
      payload: utf8(JSON.stringify(['payload', id, kind, linkKey, payloadJson])),
      meta: utf8(JSON.stringify(['meta', id, kind, '', metaJson])),
    };
  },
  async openSendPayload({ id, kind, linkKey, sealed }) {
    calls.push('openSendPayload');
    return openFakeSend('payload', id, kind, linkKey, sealed);
  },
  async openSendMeta({ id, kind, sealedKey, sealed }) {
    calls.push('openSendMeta');
    if (locked) throw new Error('the vault is locked');
    // The sealed key must be this Send's own, as the real one's key version comes from it.
    const [label, sid] = JSON.parse(fromUtf8(sealedKey)) as [string, string];
    if (label !== 'send-key' || sid !== id) throw new Error('not this Send\'s key');
    return openFakeSend('meta', id, kind, '', sealed);
  },
  async wrapSendKey(id, linkKey) {
    calls.push('wrapSendKey');
    if (locked) throw new Error('the vault is locked');
    return utf8(JSON.stringify(['send-key', id, linkKey]));
  },
  async unwrapSendKey(id, sealedKey) {
    calls.push('unwrapSendKey');
    if (locked) throw new Error('the vault is locked');
    const [label, sid, linkKey] = JSON.parse(fromUtf8(sealedKey)) as [string, string, string];
    if (label !== 'send-key' || sid !== id) throw new Error('the key does not open for this Send');
    return linkKey;
  },
  async sendProof(id, linkKey, password) {
    calls.push('sendProof');
    // A checksum of the password, the Send and its key, so a test can see what the proof follows
    // and that the password itself goes nowhere.
    const text = `${password.normalize('NFC')}|${id}|${linkKey}`;
    const sum = [...text].reduce((a, c) => (a * 31 + (c.codePointAt(0) ?? 0)) >>> 0, 13);
    const out = new Uint8Array(32);
    for (let i = 0; i < out.length; i += 1) out[i] = ((sum >>> ((i % 4) * 8)) & 0xff) ^ i;
    return out;
  },
  async sealSendFile(linkKey, bytes) {
    calls.push('sealSendFile');
    return new Uint8Array([...utf8(`KMA1:${linkKey}:`), ...bytes]);
  },
  async openSendFile(linkKey, file) {
    calls.push('openSendFile');
    const head = utf8(`KMA1:${linkKey}:`);
    if (!head.every((byte, i) => file[i] === byte)) throw new Error('the file does not open');
    return file.slice(head.length);
  },
  async fingerprint(publicBundle) {
    calls.push('fingerprint');
    const text = fromUtf8(publicBundle);
    const sum = [...text].reduce((a, c) => (a * 31 + (c.codePointAt(0) ?? 0)) >>> 0, 11);
    return Array.from({ length: 12 }, (_, i) => String((sum + i * 7919) % 100000).padStart(5, '0')).join(' ');
  },
  async verifyBundle(publicBundle, bundleSignature) {
    calls.push('verifyBundle');
    return fromUtf8(bundleSignature) === 'sig' && fromUtf8(publicBundle).startsWith('bundle:');
  },
  async lock() {
    calls.push('lock');
    locked = true;
  },
  // Device approval, the new device's side. The one-time key is a counter; a box opens only for
  // the key, account and request it was sealed for, and a key opens one box at most.
  async release(handle) {
    calls.push('release');
    deviceKeys.spent.add(fromUtf8(handle));
  },
  async newDeviceKey() {
    calls.push('newDeviceKey');
    deviceKeys.count += 1;
    const n = deviceKeys.count;
    const publicKey = new Uint8Array(1600);
    publicKey.set(utf8(`kx1-public:${n}`));
    return { handle: utf8(`device-key:${n}`), publicKey };
  },
  async openApprovedKey(deviceKey, accountId, requestId, sealed) {
    calls.push('openApprovedKey');
    const handle = fromUtf8(deviceKey);
    if (deviceKeys.spent.has(handle)) throw new Error('the one-time key is spent');
    deviceKeys.spent.add(handle);
    const [label, n, account, request] = JSON.parse(fromUtf8(sealed)) as [string, string, string, string];
    if (label !== 'device-approval' || `device-key:${n}` !== handle) throw new Error('not sealed to this key');
    if (account !== accountId || request !== requestId) throw new Error('bound to another request');
    return utf8(`root:${accountId}`);
  },
  async prfWrapRoot(prfOutput, credentialId) {
    calls.push('prfWrapRoot');
    if (locked) throw new Error('the vault is locked');
    return { wrappedKey: utf8(JSON.stringify(['prf', fromUtf8(prfOutput), fromUtf8(credentialId)])), keyVersion: 1 };
  },
  async prfOpenRoot(prfOutput, credentialId, accountId, keyVersion, wrapped) {
    calls.push('prfOpenRoot');
    const [label, prf, credential] = JSON.parse(fromUtf8(wrapped)) as [string, string, string];
    if (label !== 'prf' || prf !== fromUtf8(prfOutput) || credential !== fromUtf8(credentialId) || keyVersion < 1) {
      throw new Error('the passkey does not open this wrap');
    }
    return utf8(`root:${accountId}`);
  },
  async kitMake() {
    calls.push('kitMake');
    if (locked) throw new Error('the vault is locked');
    const pieces = ['A', 'B', 'C'].map((c, i) => `BMCKIT1-FAKEKIT2-23${i + 1}-${c.repeat(52)}-ABCD`);
    return { kitId: 'FAKEKIT2', pieces, wrappedKey: utf8(JSON.stringify(['kit', 'FAKEKIT2'])), keyVersion: 1 };
  },
  async kitReadPiece(text) {
    calls.push('kitReadPiece');
    const parts = text.replace(/s+/g, '').toUpperCase().split('-');
    if (parts.length !== 5 || parts[0] !== 'BMCKIT1') return { problem: 'format' };
    if (parts[4] !== 'ABCD') return { problem: 'checksum' };
    const digits = parts[2] ?? '';
    return { kitId: parts[1] ?? '', threshold: Number(digits[0]), shares: Number(digits[1]), index: Number(digits[2]) };
  },
  async kitCheckPieces(pieces) {
    calls.push('kitCheckPieces');
    const ids = new Set<string>();
    const indexes = new Set<string>();
    for (const piece of pieces) {
      const parts = piece.replace(/s+/g, '').toUpperCase().split('-');
      ids.add(parts[1] ?? '');
      indexes.add(parts[2] ?? '');
    }
    if (ids.size > 1) return { problem: 'other-kit' };
    if (indexes.size < pieces.length) return { problem: 'duplicate' };
    return {};
  },
  async kitOpenRoot(pieces, kitId, accountId, keyVersion, wrapped) {
    calls.push('kitOpenRoot');
    const [label, id] = JSON.parse(fromUtf8(wrapped)) as [string, string];
    if (pieces.length < 2 || label !== 'kit' || id !== kitId || keyVersion < 1) {
      throw new Error('the pieces do not open this kit');
    }
    return utf8(`root:${accountId}`);
  },
  async newSsoAccount(accountId) {
    calls.push('newSsoAccount');
    locked = false;
    openedFor = accountId;
    return {
      publicBundle: utf8(`bundle:${accountId}`),
      bundleSignature: utf8('signature'),
      sealedPrivateKeys: utf8('sealed-private-keys'),
      wrappedRootKey: new Uint8Array(),
    };
  },
  // The trusted-device copy and a tab's reload copy are sealed under different keys: a copy opens
  // only under the key it was made with, and a tab's only while that tab's key still exists.
  async deviceCopySeal(accountId, deviceId, keyVersion, tabId) {
    calls.push('deviceCopySeal');
    if (locked) throw new Error('the vault is locked');
    if (tabId !== undefined) fakeTabKeys.add(tabId);
    return utf8(JSON.stringify([tabId === undefined ? 'device-copy' : `tab-copy:${tabId}`, accountId, deviceId, keyVersion]));
  },
  async deviceCopyOpen(accountId, deviceId, keyVersion, sealed, tabId) {
    calls.push('deviceCopyOpen');
    const [label, account, device, version] = JSON.parse(fromUtf8(sealed)) as [string, string, string, number];
    const expected = tabId === undefined ? 'device-copy' : `tab-copy:${tabId}`;
    if (tabId !== undefined && !fakeTabKeys.has(tabId)) throw new Error('this tab has no key');
    if (label !== expected || account !== accountId || device !== deviceId || version !== keyVersion) {
      throw new Error('this browser does not open this copy');
    }
    return utf8(`root:${accountId}`);
  },
  async deviceCopyReset(tabId) {
    calls.push('deviceCopyReset');
    if (tabId !== undefined) fakeTabKeys.delete(tabId);
  },
  async tabSeal(tabId, accountId, deviceId, data) {
    calls.push('tabSeal');
    fakeTabKeys.add(tabId);
    return utf8(JSON.stringify(['tab-session', tabId, accountId, deviceId, fromUtf8(data)]));
  },
  async tabOpen(tabId, accountId, deviceId, sealed) {
    calls.push('tabOpen');
    if (!fakeTabKeys.has(tabId)) throw new Error('this tab has no key');
    const [label, tab, account, device, data] = JSON.parse(fromUtf8(sealed)) as [string, string, string, string, string];
    if (label !== 'tab-session' || tab !== tabId || account !== accountId || device !== deviceId) {
      throw new Error('this tab does not open this');
    }
    return utf8(data);
  },
  async dpopReset() {
    calls.push('dpopReset');
  },
  async unlockWithRoot(accountId, root, options) {
    calls.push('unlockWithRoot');
    if (fromUtf8(root) !== `root:${accountId}`) throw new Error("not this account's root key");
    // Like the worker: with a bundle to check, the opened keys must be the bundle's, and the
    // fake's bundles are `bundle:<account>`.
    if (options?.publicBundle && fromUtf8(options.publicBundle) !== `bundle:${accountId}`) {
      throw new Error("the keys are not the bundle's");
    }
    locked = false;
    openedFor = accountId;
  },
  async ownFingerprint() {
    calls.push('ownFingerprint');
    if (locked) throw new Error('the vault is locked');
    return crypto.fingerprint(utf8(`bundle:${openedFor}`));
  },
  async sealSpaceItem({ spaceId, collectionId, id, kind, revision, json }) {
    calls.push('sealSpaceItem');
    if (locked) throw new Error('the vault is locked');
    return {
      ciphertext: utf8(JSON.stringify([spaceId, collectionId, id, kind, revision, json])),
      itemKey: utf8('space-item-key'),
      keyVersion: 2,
    };
  },
  async openSpaceItem({ spaceId, collectionId, id, kind, revision, keyVersion, ciphertext }) {
    calls.push('openSpaceItem');
    if (locked) throw new Error('the vault is locked');
    const [space, collection, sid, skind, srevision, json] = JSON.parse(fromUtf8(ciphertext)) as [
      string,
      string,
      string,
      string,
      number,
      string,
    ];
    if (
      space !== spaceId || collection !== collectionId || sid !== id || skind !== kind ||
      srevision !== revision || keyVersion !== 2
    ) {
      throw new Error('the item does not open under these details');
    }
    return json;
  },
  // The signed manifest. A signature names its signer and the manifest's bytes, so a test sees
  // that it checks only under the key that made it and only for those bytes; the fake's bundles
  // are `bundle:<account>`.
  async manifestSign(manifest) {
    calls.push('manifestSign');
    if (locked) throw new Error('the vault is locked');
    return utf8(`msig:${openedFor}:${encodeB64(manifest)}`);
  },
  async manifestVerifyOwn(manifest, signature) {
    calls.push('manifestVerifyOwn');
    // Like the worker: with no keys to check with there is no verdict, not a "no".
    if (locked) throw new Error('the vault is locked');
    return fromUtf8(signature) === `msig:${openedFor}:${encodeB64(manifest)}`;
  },
  async manifestVerify(signerBundle, manifest, signature) {
    calls.push('manifestVerify');
    const signer = /^bundle:(.+)$/.exec(fromUtf8(signerBundle))?.[1];
    return signer !== undefined && fromUtf8(signature) === `msig:${signer}:${encodeB64(manifest)}`;
  },
  // Signed item writes. A signature names its writer, the key version and every field of the
  // write it covers, so a test sees that it checks only for that writer and only for those fields.
  async itemWriteSign(fields) {
    calls.push('itemWriteSign');
    if (locked) throw new Error('the vault is locked');
    if (fields.owner.startsWith('user:') && fields.owner !== `user:${openedFor}`) {
      throw new Error('another account');
    }
    return {
      writer: openedFor,
      writerKeyVersion: 1,
      writeSignature: encodeB64(utf8(writeSignatureText(openedFor, 1, fields))),
    };
  },
  async itemWriteVerifyOwn(fields, signature) {
    calls.push('itemWriteVerifyOwn');
    if (locked) throw new Error('the vault is locked');
    return (
      fields.writer === openedFor &&
      fields.writerKeyVersion === 1 &&
      fromUtf8(decodeB64(signature)) === writeSignatureText(openedFor, 1, fields)
    );
  },
  async itemWriteVerify(signerBundle, fields, signature) {
    calls.push('itemWriteVerify');
    const signer = /^bundle:(.+)$/.exec(fromUtf8(signerBundle))?.[1];
    return (
      signer !== undefined &&
      fields.writer === signer &&
      fromUtf8(decodeB64(signature)) === writeSignatureText(signer, fields.writerKeyVersion ?? 0, fields)
    );
  },
};

/** What the fake's write signature says: who, at which key version, over which fields. */
export function writeSignatureText(writer: string, keyVersion: number, fields: ItemWriteFields): string {
  return `wsig:${writer}:${keyVersion}:${JSON.stringify([
    fields.owner,
    fields.id,
    fields.kind,
    fields.revision,
    fields.deleted,
    fields.keyVersion,
    fields.ciphertext ?? '',
    fields.itemKey ?? '',
  ])}`;
}

const deviceKeys = { count: 0, spent: new Set<string>() };

/** What an approving device seals to a new device's one-time key (the test plays the approver). */
export function fakeApprovalBox(publicKey: Uint8Array, accountId: string, requestId: string): Uint8Array {
  const n = /kx1-public:(\d+)/.exec(fromUtf8(publicKey.slice(0, 24)))?.[1] ?? '';
  return utf8(JSON.stringify(['device-approval', n, accountId, requestId]));
}

/** Link keys the fake hands out: 43 characters of base64url, one more each call. */
const sendKeys = {
  count: 0,
  next(): string {
    this.count += 1;
    return `fake-link-key-${String(this.count).padStart(2, '0')}`.padEnd(43, 'A');
  },
};

function openFakeSend(
  part: 'payload' | 'meta',
  id: string,
  kind: string,
  linkKey: string,
  sealed: Uint8Array,
): string {
  const [label, sid, skind, skey, json] = JSON.parse(fromUtf8(sealed)) as [
    string,
    string,
    string,
    string,
    string,
  ];
  if (label !== part || sid !== id || skind !== kind || skey !== linkKey) {
    throw new Error('the part does not open under these details');
  }
  return json;
}

export function resetFakeCrypto(): void {
  calls.length = 0;
  locked = true;
  fakeTabKeys.clear();
  openedFor = '';
  sendKeys.count = 0;
  deviceKeys.count = 0;
  deviceKeys.spent.clear();
}

/** What `@/crypto-port` resolves to under Vitest. */
export const vaultCrypto: CryptoPort = crypto;
