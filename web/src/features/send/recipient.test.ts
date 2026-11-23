import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiError } from '@/api/errors';
import type { AccessDto } from '@/api/sends';
import { encodeB64, utf8 } from '@/lib/b64url';
import { crypto, resetFakeCrypto } from '@/test/fake-crypto';
import {
  type RecipientDeps,
  downloadFile,
  isSendHash,
  openSend,
  parseSendLink,
} from './recipient';
import { makeSend } from './sendCrypto';

const ACCESS_ID = encodeB64(new Uint8Array(16).fill(7));
const NOW = new Date('2026-11-22T10:00:00Z');

function problem(status: number, slug: string, extra: Record<string, unknown> = {}): ApiError {
  return new ApiError(status, { type: `urn:kemlock:problem:${slug}`, title: slug, status, ...extra });
}

/** A Send made by the owner's side of the fake worker, as the server would hold it. */
async function made(kind: 'text' | 'file', password?: string) {
  resetFakeCrypto();
  await crypto.unlock('u', utf8('wrapped:u'), new Uint8Array(), new Uint8Array());
  const send = await makeSend(
    {
      kind,
      name: kind === 'file' ? 'lease.pdf' : 'Door code',
      text: '4 7 1 9',
      ...(kind === 'file'
        ? { file: { name: 'lease.pdf', mime: 'application/pdf', bytes: utf8('PDF bytes') } }
        : {}),
      deleteAfterDays: 7,
      maxViews: null,
      hideEmail: true,
      ...(password ? { password } : {}),
    },
    { crypto },
    NOW,
  );
  // The fake binds a Send to the id it is opened under, which is the access id on the recipient side.
  const payload = await crypto.sealSend({
    id: ACCESS_ID,
    kind,
    linkKey: send.key,
    payloadJson:
      kind === 'file'
        ? JSON.stringify({ name: 'lease.pdf', mime: 'application/pdf', size: 9 })
        : JSON.stringify({ name: 'Door code', text: '4 7 1 9' }),
    metaJson: '{}',
  });
  await crypto.lock();
  const proofB64 = password ? encodeB64(await crypto.sendProof(ACCESS_ID, send.key, password)) : undefined;
  return { send, payload: encodeB64(payload.payload), proofB64 };
}

function deps(over: {
  open?: RecipientDeps['access']['open'];
  file?: RecipientDeps['access']['file'];
}): RecipientDeps {
  return {
    access: {
      open: over.open ?? (() => Promise.reject(problem(404, 'not-found'))),
      file: over.file ?? (() => Promise.reject(problem(404, 'not-found'))),
    },
    crypto,
  };
}

function dto(kind: 'text' | 'file', payload: string): AccessDto {
  return {
    id: ACCESS_ID,
    kind,
    payload,
    fileSize: kind === 'file' ? 41 : null,
    expiresAt: null,
    deletionAt: 1_795_000_000,
    senderEmail: null,
  };
}

describe('parseSendLink', () => {
  const key = 'A'.repeat(43);
  it('reads the access id and the key from the fragment', () => {
    expect(parseSendLink(`#/send/${ACCESS_ID}/${key}`)).toEqual({ accessId: ACCESS_ID, key });
    expect(parseSendLink(`#/send/${ACCESS_ID}/${key}/`)).toEqual({ accessId: ACCESS_ID, key });
  });
  it('refuses a link cut short, padded or with the wrong lengths', () => {
    expect(parseSendLink(`#/send/${ACCESS_ID}`)).toBeNull();
    expect(parseSendLink(`#/send/${ACCESS_ID}/${key.slice(1)}`)).toBeNull();
    expect(parseSendLink(`#/send/${ACCESS_ID}/${key}=`)).toBeNull();
    expect(parseSendLink(`#/send/short/${key}`)).toBeNull();
    expect(parseSendLink('')).toBeNull();
  });
  it('tells a Send hash from the rest', () => {
    expect(isSendHash('#/send/x')).toBe(true);
    expect(isSendHash('#/other')).toBe(false);
    expect(isSendHash('')).toBe(false);
  });
});

describe('openSend', () => {
  beforeEach(() => resetFakeCrypto());

  it('opens a note with the key from the link and sends the server no key', async () => {
    const { send, payload } = await made('text');
    const open = vi.fn(async (_id: string, _password?: string) => dto('text', payload));
    const result = await openSend(deps({ open }), { accessId: ACCESS_ID, key: send.key });
    expect(result).toMatchObject({
      state: 'opened',
      send: { payload: { kind: 'text', name: 'Door code', text: '4 7 1 9' }, proof: null },
    });
    // The only things that go to the server are the access id and, with a password, a proof.
    expect(open).toHaveBeenCalledTimes(1);
    expect(open).toHaveBeenCalledWith(ACCESS_ID, undefined);
    expect(JSON.stringify(open.mock.calls)).not.toContain(send.key);
  });

  it('asks for the password when the Send has one, then sends a proof, never the password', async () => {
    const { send, payload, proofB64 } = await made('text', 'swordfish');
    const open = vi.fn(async (_id: string, password?: string) => {
      if (password === undefined) throw problem(401, 'send-password-required');
      if (password !== proofB64) throw problem(401, 'send-wrong-password');
      return dto('text', payload);
    });
    const link = { accessId: ACCESS_ID, key: send.key };
    expect(await openSend(deps({ open }), link)).toEqual({ state: 'password', wrong: false });
    expect(await openSend(deps({ open }), link, 'guess')).toEqual({ state: 'password', wrong: true });
    const result = await openSend(deps({ open }), link, 'swordfish');
    expect(result.state).toBe('opened');
    expect(JSON.stringify(open.mock.calls)).not.toContain('swordfish');
    expect(open).toHaveBeenLastCalledWith(ACCESS_ID, proofB64);
  });

  it('says a Send is unavailable for a missing one and for a key that does not open it', async () => {
    const { payload } = await made('text');
    const link = { accessId: ACCESS_ID, key: 'B'.repeat(43) };
    expect(await openSend(deps({}), link)).toEqual({ state: 'unavailable' });
    const wrongKey = await openSend(deps({ open: async () => dto('text', payload) }), link);
    expect(wrongKey).toEqual({ state: 'unavailable' });
  });

  it('reports a rate limit and a server that cannot be reached', async () => {
    const link = { accessId: ACCESS_ID, key: 'A'.repeat(43) };
    const limited = deps({ open: () => Promise.reject(problem(429, 'rate-limited', { retryAfter: 9 })) });
    expect(await openSend(limited, link, 'x')).toEqual({ state: 'rate-limited', seconds: 9 });
    const broken = deps({ open: () => Promise.reject(new Error('offline')) });
    expect(await openSend(broken, link)).toEqual({ state: 'failed' });
  });
});

describe('downloadFile', () => {
  it('downloads the KMA1 bytes and opens them with the link key', async () => {
    const { send, payload } = await made('file');
    const sealed = await crypto.sealSendFile(send.key, utf8('PDF bytes'));
    const file = vi.fn(async (_id: string, _password?: string) => sealed);
    const d = deps({ open: async () => dto('file', payload), file });
    const link = { accessId: ACCESS_ID, key: send.key };
    const opened = await openSend(d, link);
    if (opened.state !== 'opened') throw new Error('did not open');
    const result = await downloadFile(d, link, opened.send);
    expect(result).toMatchObject({ state: 'file', name: 'lease.pdf', mime: 'application/pdf' });
    expect(result.state === 'file' && new TextDecoder().decode(result.bytes)).toBe('PDF bytes');
    expect(file).toHaveBeenCalledWith(ACCESS_ID, undefined);
  });

  it('does not take a file that opens to another length than the payload names', async () => {
    const { send, payload } = await made('file');
    const sealed = await crypto.sealSendFile(send.key, utf8('short'));
    const d = deps({ open: async () => dto('file', payload), file: async () => sealed });
    const link = { accessId: ACCESS_ID, key: send.key };
    const opened = await openSend(d, link);
    if (opened.state !== 'opened') throw new Error('did not open');
    expect(await downloadFile(d, link, opened.send)).toEqual({ state: 'unavailable' });
  });

  it('is unavailable when the bytes do not open under the key', async () => {
    const { send, payload } = await made('file');
    const d = deps({
      open: async () => dto('file', payload),
      file: async () => utf8('KMA1:other-key:xxxxxxxxx'),
    });
    const link = { accessId: ACCESS_ID, key: send.key };
    const opened = await openSend(d, link);
    if (opened.state !== 'opened') throw new Error('did not open');
    expect(await downloadFile(d, link, opened.send)).toEqual({ state: 'unavailable' });
  });
});
