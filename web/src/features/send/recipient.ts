// The recipient's side of a Send (docs/crypto.md, "Sends"): a link is
// `https://<host>/#/send/<accessId>/<key>`. The key is read from the fragment, which a browser never
// sends, and goes only to the crypto worker: nothing here puts it in a request, a log line or a
// query. No React in here, so the whole flow is tested with fakes.
//
//   open    POST /kem/v1/send-access/{accessId}  (a password proof in the body, when there is a password)
//   payload the sealed payload, opened by the worker under the payload key from the key
//   file    POST /kem/v1/send-access/{accessId}/file, the KMA1 bytes, opened by the worker
import type { AccessDto } from '@/api/sends';
import { isApiError } from '@/api/errors';
import type { CryptoPort } from '@/crypto-port';
import { decodeB64, encodeB64 } from '@/lib/b64url';
import { type SendPayload, isSendKey, parsePayload } from './sendCrypto';

/** The link a recipient opened, read from `location.hash`; null when the hash is not a Send link. */
export interface SendLink {
  /** base64url of the Send's 16-byte id: 22 characters. */
  accessId: string;
  /** The link key, base64url: 43 characters. It stays on this side. */
  key: string;
}

const LINK = /^#\/send\/([A-Za-z0-9_-]+)\/([A-Za-z0-9_-]+)\/?$/;

/** `#/send/<accessId>/<key>`, or null. A hash that has the shape but not the lengths is null too. */
export function parseSendLink(hash: string): SendLink | null {
  const match = LINK.exec(hash);
  if (!match) return null;
  const [, accessId, key] = match;
  if (!accessId || !key) return null;
  try {
    if (decodeB64(accessId).length !== 16 || !isSendKey(key)) return null;
  } catch {
    return null;
  }
  return { accessId, key };
}

/** Whether the hash starts a Send link, whether or not it is a good one. */
export function isSendHash(hash: string): boolean {
  return hash.startsWith('#/send/');
}

export interface RecipientDeps {
  access: {
    open(accessId: string, password?: string): Promise<AccessDto>;
    file(accessId: string, password?: string): Promise<Uint8Array>;
  };
  crypto: Pick<CryptoPort, 'openSendPayload' | 'sendProof' | 'openSendFile'>;
}

export type RecipientResult =
  | { state: 'opened'; send: OpenedSend }
  | { state: 'password'; wrong: boolean }
  /** No such Send, one that is closed, expired or used up, or a link whose key does not open it. */
  | { state: 'unavailable' }
  | { state: 'rate-limited'; seconds: number | undefined }
  | { state: 'failed' };

export interface OpenedSend {
  payload: SendPayload;
  /** The sender's email, unless they hid it. */
  senderEmail: string | null;
  /** Unix seconds. */
  deletionAt: number;
  expiresAt: number | null;
  /** The proof to send again with the file request; null when the Send has no password. */
  proof: string | null;
}

async function proofOf(
  deps: RecipientDeps,
  link: SendLink,
  password: string | undefined,
): Promise<string | undefined> {
  if (password === undefined || password === '') return undefined;
  // The worker works the Argon2id proof out from the password, the access id and the key.
  return encodeB64(await deps.crypto.sendProof(link.accessId, link.key, password.normalize('NFC')));
}

/**
 * Opens a Send: asks the server for its sealed payload and opens it with the link key. A Send with a
 * password answers `password` until a proof is given; a wrong one answers `password` with `wrong`.
 */
export async function openSend(
  deps: RecipientDeps,
  link: SendLink,
  password?: string,
): Promise<RecipientResult> {
  let proof: string | undefined;
  let access: AccessDto;
  try {
    proof = await proofOf(deps, link, password);
    access = await deps.access.open(link.accessId, proof);
  } catch (error) {
    if (isApiError(error)) {
      if (error.slug === 'send-password-required') return { state: 'password', wrong: false };
      if (error.slug === 'send-wrong-password') return { state: 'password', wrong: true };
      if (error.status === 404) return { state: 'unavailable' };
      if (error.status === 429) return { state: 'rate-limited', seconds: error.retryAfter };
    }
    return { state: 'failed' };
  }
  let payload: SendPayload | null;
  try {
    payload = parsePayload(
      access.kind,
      await deps.crypto.openSendPayload({
        id: link.accessId,
        kind: access.kind,
        linkKey: link.key,
        sealed: decodeB64(access.payload),
      }),
    );
  } catch {
    // A key that is not the link's, or a payload altered on the way: both read as unopenable.
    return { state: 'unavailable' };
  }
  if (!payload) return { state: 'unavailable' };
  return {
    state: 'opened',
    send: {
      payload,
      senderEmail: access.senderEmail,
      deletionAt: access.deletionAt,
      expiresAt: access.expiresAt,
      proof: proof ?? null,
    },
  };
}

export type FileResult =
  | { state: 'file'; name: string; mime: string; bytes: Uint8Array }
  | { state: 'unavailable' }
  | { state: 'password'; wrong: boolean }
  | { state: 'failed' };

/** Downloads a file Send's `KMA1` bytes and opens them with the link key. */
export async function downloadFile(
  deps: RecipientDeps,
  link: SendLink,
  send: OpenedSend,
): Promise<FileResult> {
  if (send.payload.kind !== 'file') return { state: 'failed' };
  const { name, mime, size } = send.payload;
  let sealed: Uint8Array;
  try {
    sealed = await deps.access.file(link.accessId, send.proof ?? undefined);
  } catch (error) {
    if (isApiError(error)) {
      if (error.slug === 'send-password-required') return { state: 'password', wrong: false };
      if (error.slug === 'send-wrong-password') return { state: 'password', wrong: true };
      if (error.status === 404) return { state: 'unavailable' };
    }
    return { state: 'failed' };
  }
  try {
    const bytes = await deps.crypto.openSendFile(link.key, sealed);
    // The payload says how long the file is: a file that opens to another length is not this one.
    if (bytes.length !== size) return { state: 'unavailable' };
    return { state: 'file', name, mime, bytes };
  } catch {
    return { state: 'unavailable' };
  }
}
