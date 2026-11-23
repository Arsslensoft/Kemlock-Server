// @vitest-environment node
import { beforeEach, describe, expect, it } from 'vitest';
import { decodeB64, encodeB64, utf8 } from '@/lib/b64url';
import { crypto, fakeCalls, resetFakeCrypto } from '@/test/fake-crypto';
import {
  MAX_FILE_BYTES,
  isSendKey,
  makeSend,
  newSendId,
  openOwnerView,
  parseMeta,
  parsePayload,
  sendLink,
} from './sendCrypto';

const ACCESS_ID = 'EREREhEiQzOERVVVVVVVVQ';
const NOW = new Date('2026-11-22T10:00:00Z');
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

async function unlocked() {
  await crypto.unlock('u', utf8('wrapped:u'), new Uint8Array(), new Uint8Array());
}

beforeEach(() => {
  resetFakeCrypto();
});

describe('the id', () => {
  it('is a version 4 UUID, a new one each time', () => {
    const id = newSendId();
    expect(id).toMatch(UUID_V4);
    expect(newSendId()).not.toBe(id);
  });
});

describe('makeSend', () => {
  it('makes a text Send the key of which is only in the link', async () => {
    await unlocked();
    const made = await makeSend(
      {
        kind: 'text',
        name: 'Door code',
        notes: 'for the cleaner',
        text: '4 7 1 9, then the green button',
        deleteAfterDays: 7,
        maxViews: 3,
        hideEmail: true,
      },
      { crypto },
      NOW,
    );
    expect(isSendKey(made.key)).toBe(true);
    const { request } = made;
    expect(request).toMatchObject({
      id: made.id,
      kind: 'text',
      maxAccess: 3,
      hideEmail: true,
      disabled: false,
      expiresAt: null,
      password: null,
      deletionAt: Math.floor(NOW.getTime() / 1000) + 7 * 86_400,
    });
    expect(made.id).toMatch(UUID_V4);
    expect(request.file).toBeUndefined();
    expect(made.upload).toBeNull();

    // The id and kind that bind the seals are the ones the server is sent.
    const address = { id: made.id, kind: 'text' as const, linkKey: made.key };
    const payload = await crypto.openSendPayload({ ...address, sealed: decodeB64(request.payload) });
    expect(JSON.parse(payload)).toEqual({ name: 'Door code', text: '4 7 1 9, then the green button' });
    const meta = await crypto.openSendMeta({
      id: made.id,
      kind: 'text',
      sealedKey: decodeB64(request.sealedKey),
      sealed: decodeB64(request.meta),
    });
    expect(JSON.parse(meta)).toEqual({ name: 'Door code', notes: 'for the cleaner' });
    // A recipient has the link key and the payload, and with the vault locked no way to the meta.
    await crypto.lock();
    expect(JSON.parse(await crypto.openSendPayload({ ...address, sealed: decodeB64(request.payload) }))).toEqual({
      name: 'Door code',
      text: '4 7 1 9, then the green button',
    });
    await expect(
      crypto.openSendMeta({
        id: made.id,
        kind: 'text',
        sealedKey: decodeB64(request.sealedKey),
        sealed: decodeB64(request.meta),
      }),
    ).rejects.toBeDefined();
    await unlocked();
    // The owner's copy of the key opens in this account, for this Send.
    expect(await crypto.unwrapSendKey(made.id, decodeB64(request.sealedKey))).toBe(made.key);
    await expect(crypto.unwrapSendKey(newSendId(), decodeB64(request.sealedKey))).rejects.toBeDefined();
    // Another id or kind does not open what was sealed.
    await expect(
      crypto.openSendPayload({ ...address, id: newSendId(), sealed: decodeB64(request.payload) }),
    ).rejects.toBeDefined();
    await expect(
      crypto.openSendPayload({ ...address, kind: 'file', sealed: decodeB64(request.payload) }),
    ).rejects.toBeDefined();

    // Nothing the server receives holds the key or the text, and the link puts the key after the #.
    const wire = JSON.stringify(request);
    expect(wire).not.toContain(made.key);
    expect(wire).not.toContain('green button');
    expect(sendLink('https://vault.example.org', ACCESS_ID, made.key)).toBe(
      `https://vault.example.org/#/send/${ACCESS_ID}/${made.key}`,
    );
  });

  it('adds a password proof bound to the Send and never the password', async () => {
    await unlocked();
    const input = {
      kind: 'text' as const,
      name: 'n',
      text: 't',
      deleteAfterDays: 1,
      maxViews: null,
      password: 'hunter2 é',
      hideEmail: false,
    };
    const made = await makeSend(input, { crypto }, NOW);
    expect(JSON.stringify(made.request)).not.toContain('hunter2');
    expect(decodeB64(made.request.password ?? '')).toHaveLength(32);
    // The receiver derives the same proof from the password, the key in the link and the id.
    const again = await crypto.sendProof(made.id, made.key, 'hunter2 é');
    expect(encodeB64(again)).toBe(made.request.password);
    expect(encodeB64(await crypto.sendProof(made.id, made.key, 'hunter3 é'))).not.toBe(
      made.request.password,
    );
    expect(encodeB64(await crypto.sendProof(newSendId(), made.key, 'hunter2 é'))).not.toBe(
      made.request.password,
    );
    // No password, no proof.
    const open = await makeSend({ ...input, password: '' }, { crypto }, NOW);
    expect(open.request.password).toBeNull();
  });

  it('seals a file as KMA1 and announces its length, not its bytes', async () => {
    await unlocked();
    const bytes = new Uint8Array([1, 2, 3, 250]);
    const made = await makeSend(
      {
        kind: 'file',
        name: 'lease',
        file: { name: 'lease.pdf', mime: 'application/pdf', bytes },
        deleteAfterDays: 30,
        maxViews: 1,
        hideEmail: true,
      },
      { crypto },
      NOW,
    );
    expect(made.upload).not.toBeNull();
    expect(made.request.file).toEqual({ size: made.upload?.length });
    // Opened with the key from the link, the file is the bytes; the key never went to the server.
    expect([...(await crypto.openSendFile(made.key, made.upload ?? new Uint8Array()))]).toEqual([...bytes]);
    expect(JSON.stringify(made.request)).not.toContain(made.key);

    const address = { id: made.id, kind: 'file' as const, linkKey: made.key };
    const payload = await crypto.openSendPayload({ ...address, sealed: decodeB64(made.request.payload) });
    // The payload names the file and gives its plaintext size, which is not the KMA1 length.
    expect(JSON.parse(payload)).toEqual({ name: 'lease.pdf', mime: 'application/pdf', size: 4 });
    const meta = await crypto.openSendMeta({
      id: made.id,
      kind: 'file',
      sealedKey: decodeB64(made.request.sealedKey),
      sealed: decodeB64(made.request.meta),
    });
    expect(JSON.parse(meta)).toEqual({ name: 'lease', notes: '' });
    expect(made.request.deletionAt).toBe(Math.floor(NOW.getTime() / 1000) + 30 * 86_400);
  });

  it('refuses what the server would, before sealing anything it is told about', async () => {
    await unlocked();
    const base = { kind: 'file' as const, name: 'x', deleteAfterDays: 1, maxViews: null, hideEmail: false };
    const file = { name: 'a', mime: 'a/b', bytes: new Uint8Array(4) };
    await expect(
      makeSend({ ...base, file: { ...file, bytes: new Uint8Array(MAX_FILE_BYTES + 1) } }, { crypto }, NOW),
    ).rejects.toThrow('over the limit');
    await expect(makeSend(base, { crypto }, NOW)).rejects.toThrow('needs a file');
    await expect(makeSend({ ...base, kind: 'text', deleteAfterDays: 31 }, { crypto }, NOW)).rejects.toThrow(
      '1 to 30 days',
    );
    expect(fakeCalls).not.toContain('sealSendFile');
  });
});

describe('opening a Send as its owner', () => {
  it('gets the name and the key that rebuilds the link', async () => {
    await unlocked();
    const made = await makeSend(
      { kind: 'text', name: 'Door code', text: 'x', deleteAfterDays: 1, maxViews: null, hideEmail: false },
      { crypto },
      NOW,
    );
    const send = { id: made.id, kind: 'text' as const, meta: made.request.meta, sealedKey: made.request.sealedKey };
    expect(await openOwnerView(send, crypto)).toEqual({ name: 'Door code', notes: '', key: made.key });
    // Another Send's id, a garbled part or a locked vault is no view, not a crash.
    expect(await openOwnerView({ ...send, id: newSendId() }, crypto)).toBeNull();
    expect(await openOwnerView({ ...send, kind: 'file' }, crypto)).toBeNull();
    expect(await openOwnerView({ ...send, meta: encodeB64(utf8('garbage')) }, crypto)).toBeNull();
    expect(await openOwnerView({ ...send, sealedKey: 'x' }, crypto)).toBeNull();
    await crypto.lock();
    expect(await openOwnerView(send, crypto)).toBeNull();
  });
});

describe('the JSON inside', () => {
  it('reads the owner meta exactly', () => {
    expect(parseMeta('{"name":"n","notes":""}')).toEqual({ name: 'n', notes: '' });
    for (const bad of ['nope', '[]', '{"name":"n"}', '{"name":"n","notes":1}', '{"name":"n","notes":"","x":1}']) {
      expect(parseMeta(bad)).toBeNull();
    }
  });

  it('reads a recipient payload by kind, refusing other fields', () => {
    expect(parsePayload('text', '{"name":"n","text":"t"}')).toEqual({ kind: 'text', name: 'n', text: 't' });
    expect(parsePayload('file', '{"name":"a","mime":"b/c","size":4}')).toEqual({
      kind: 'file',
      name: 'a',
      mime: 'b/c',
      size: 4,
    });
    for (const [kind, bad] of [
      ['text', '{"name":"n","text":"t","x":1}'],
      ['text', '{"name":"n","mime":"b/c","size":4}'],
      ['file', '{"name":"n","text":"t"}'],
      ['file', '{"name":"a","mime":"b/c","size":-1}'],
      ['file', '{"name":"a","mime":"b/c","size":1.5}'],
      ['file', '{"name":"a","mime":"b/c","size":"4"}'],
      ['text', 'nope'],
    ] as const) {
      expect(parsePayload(kind, bad), bad).toBeNull();
    }
  });

  it('wants 32 bytes for a key', () => {
    expect(isSendKey(encodeB64(new Uint8Array(32)))).toBe(true);
    expect(isSendKey(encodeB64(new Uint8Array(16)))).toBe(false);
    expect(isSendKey('not base64url!')).toBe(false);
  });
});
