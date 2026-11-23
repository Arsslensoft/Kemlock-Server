// What a Send is made of, in the browser: docs/crypto.md, "Sends". The link carries the key after the
// `#`, which a browser never sends to a server: https://host/#/send/<accessId>/<key>. The crypto
// worker makes every seal, so this file only decides what goes into them and what the server is sent.
//
//   key       K, 32 random bytes (the worker makes it), base64url in the link
//   id        a UUID v4 the client chooses; accessId is its 16 bytes in base64url (the server says it)
//   payload   {"name","text"} or {"name","mime","size"}, sealed under the payload key from K, with
//             the id and kind bound
//   meta      {"name","notes"}, the owner's list entry, sealed under a key from the account's item-wrap
//             key, never from K, so a link holder cannot read it
//   sealedKey K under the account's item-wrap key: u32be(key version) and its seal, 64 bytes
//   password  the 32-byte Argon2id proof bound to K and the id, never the password
//   file      the KMA1 file of the bytes under the payload key, uploaded with PUT …/file
import type { CreateSendRequest, SendKind } from '@/api/sends';
import type { CryptoPort } from '@/crypto-port';
import { decodeB64, encodeB64 } from '@/lib/b64url';

/**
 * The largest file this build takes: it is read into memory and sealed in one piece. The
 * server's own limit (`max_file_size_mib`, 100 by default) is higher.
 */
export const MAX_FILE_BYTES = 1024 * 1024;
/** The server holds a note's or a file descriptor's ciphertext up to 256 KiB. */
export const MAX_PAYLOAD_BYTES = 256 * 1024;
/** A Send deletes itself at most this many days ahead. */
export const MAX_DELETE_DAYS = 30;

export interface SendInput {
  kind: SendKind;
  name: string;
  /** The owner's private notes, which a recipient never sees. */
  notes?: string;
  text?: string;
  file?: { name: string; mime: string; bytes: Uint8Array };
  deleteAfterDays: number;
  maxViews: number | null;
  password?: string;
  hideEmail: boolean;
}

/** The worker operations a Send needs. */
export type SendCrypto = Pick<
  CryptoPort,
  'sendNewKey' | 'sealSend' | 'wrapSendKey' | 'sendProof' | 'sealSendFile'
>;

export interface MadeSend {
  /** The Send's id, chosen here; the request carries it. */
  id: string;
  request: CreateSendRequest;
  /** The link key, base64url: it goes only into the link. */
  key: string;
  /** The `KMA1` bytes to `PUT` once the server has made a file Send. */
  upload: Uint8Array | null;
}

export function sendLink(origin: string, accessId: string, key: string): string {
  return `${origin}/#/send/${accessId}/${key}`;
}

/** A version 4 UUID, which is what the server accepts as a Send's id. */
export function newSendId(): string {
  return globalThis.crypto.randomUUID();
}

/**
 * Everything a create request holds, sealed by the worker. Throws on a file over the limit, on a
 * text too long for the server's payload and on a file Send without a file.
 */
export async function makeSend(
  input: SendInput,
  deps: { crypto: SendCrypto },
  now: Date = new Date(),
): Promise<MadeSend> {
  if (
    !Number.isInteger(input.deleteAfterDays) ||
    input.deleteAfterDays < 1 ||
    input.deleteAfterDays > MAX_DELETE_DAYS
  ) {
    throw new Error(`a Send deletes itself in 1 to ${MAX_DELETE_DAYS} days`);
  }
  const worker = deps.crypto;
  const id = newSendId();
  const key = await worker.sendNewKey();

  let payloadJson: string;
  let upload: Uint8Array | null = null;
  if (input.kind === 'file') {
    const file = input.file;
    if (!file) throw new Error('a file Send needs a file');
    if (file.bytes.length > MAX_FILE_BYTES) throw new Error('the file is over the limit');
    upload = await worker.sealSendFile(key, file.bytes);
    payloadJson = JSON.stringify({ name: file.name, mime: file.mime, size: file.bytes.length });
  } else {
    payloadJson = JSON.stringify({ name: input.name, text: input.text ?? '' });
  }
  const metaJson = JSON.stringify({ name: input.name, notes: input.notes ?? '' });
  const sealed = await worker.sealSend({ id, kind: input.kind, linkKey: key, payloadJson, metaJson });
  if (sealed.payload.length > MAX_PAYLOAD_BYTES) throw new Error('the text is over the limit');
  const sealedKey = await worker.wrapSendKey(id, key);
  const password =
    input.password && input.password !== ''
      ? encodeB64(await worker.sendProof(id, key, input.password))
      : null;
  return {
    id,
    key,
    upload,
    request: {
      id,
      kind: input.kind,
      meta: encodeB64(sealed.meta),
      sealedKey: encodeB64(sealedKey),
      payload: encodeB64(sealed.payload),
      file: upload ? { size: upload.length } : undefined,
      maxAccess: input.maxViews,
      hideEmail: input.hideEmail,
      disabled: false,
      expiresAt: null,
      deletionAt: Math.floor(now.getTime() / 1000) + input.deleteAfterDays * 86_400,
      password,
    },
  };
}

/** What the owner's list needs of a Send: its name and the key that rebuilds its link. */
export interface OwnerView {
  name: string;
  notes: string;
  /** The link key, base64url. */
  key: string;
}

/**
 * Opens a Send's owner copy: the link key from `sealedKey` under the account's key, and `meta`
 * under the account's key too (never the link key, which a recipient has). Null when either does
 * not open, or the JSON is not `{name, notes}` exactly.
 */
export async function openOwnerView(
  send: { id: string; kind: SendKind; meta: string; sealedKey: string },
  worker: Pick<CryptoPort, 'unwrapSendKey' | 'openSendMeta'>,
): Promise<OwnerView | null> {
  try {
    const sealedKey = decodeB64(send.sealedKey);
    const key = await worker.unwrapSendKey(send.id, sealedKey);
    const meta = parseMeta(
      await worker.openSendMeta({
        id: send.id,
        kind: send.kind,
        sealedKey,
        sealed: decodeB64(send.meta),
      }),
    );
    return meta ? { ...meta, key } : null;
  } catch {
    return null;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function hasExactly(record: Record<string, unknown>, fields: string[]): boolean {
  const keys = Object.keys(record);
  return keys.length === fields.length && fields.every((field) => keys.includes(field));
}

/** The owner's `{name, notes}`; null for anything else, unknown fields included. */
export function parseMeta(json: string): { name: string; notes: string } | null {
  try {
    const parsed: unknown = JSON.parse(json);
    if (!isRecord(parsed) || !hasExactly(parsed, ['name', 'notes'])) return null;
    const { name, notes } = parsed;
    if (typeof name !== 'string' || typeof notes !== 'string') return null;
    return { name, notes };
  } catch {
    return null;
  }
}

export type SendPayload =
  | { kind: 'text'; name: string; text: string }
  | { kind: 'file'; name: string; mime: string; size: number };

/** What a recipient reads: the payload JSON of a Send of this kind, or null when it isn't exactly that. */
export function parsePayload(kind: SendKind, json: string): SendPayload | null {
  try {
    const parsed: unknown = JSON.parse(json);
    if (!isRecord(parsed)) return null;
    if (kind === 'text') {
      const { name, text } = parsed;
      if (!hasExactly(parsed, ['name', 'text']) || typeof name !== 'string' || typeof text !== 'string') {
        return null;
      }
      return { kind, name, text };
    }
    const { name, mime, size } = parsed;
    if (
      !hasExactly(parsed, ['name', 'mime', 'size']) ||
      typeof name !== 'string' ||
      typeof mime !== 'string' ||
      typeof size !== 'number' ||
      !Number.isSafeInteger(size) ||
      size < 0
    ) {
      return null;
    }
    return { kind, name, mime, size };
  } catch {
    return null;
  }
}

/** A key from a link must decode to 32 bytes. */
export function isSendKey(text: string): boolean {
  try {
    return decodeB64(text).length === 32;
  } catch {
    return false;
  }
}
