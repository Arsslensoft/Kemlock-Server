// Send: a text or a file shared by a link (crates/kemlock-api-kem/src/routes/sends.rs). Binary
// values are base64url without padding, ids are UUIDs and times are Unix seconds. The server holds
// only sealed parts it can't open: the owner's `meta` and `sealedKey`, and the `payload` that
// whoever has the link opens with the key after the `#`. Their bytes are docs/crypto.md's
// "Sends"; the client chooses the Send's id because the seals bind it.
//
//   POST   /kem/v1/sends                       CreateSendRequest -> SendDto (201)
//   GET    /kem/v1/sends                       -> SendDto[]
//   GET    /kem/v1/sends/{id}                  -> SendDto
//   PUT    /kem/v1/sends/{id}                  UpdateSendRequest -> SendDto
//   DELETE /kem/v1/sends/{id}                  -> 204
//   PUT    /kem/v1/sends/{id}/file             a file Send's KMA1 bytes, Content-Length required
//   POST   /kem/v1/send-access/{accessId}      (public) AccessRequest -> AccessDto
//   POST   /kem/v1/send-access/{accessId}/file (public) AccessRequest -> the KMA1 bytes
import type { Api, FeatureCall } from './client';

export type SendKind = 'text' | 'file';

/** The bytes of a file Send, announced when the Send is made. */
export interface NewFileDto {
  /** The exact length of the `KMA1` file that will be uploaded, header and tags included. */
  size: number;
}

export interface CreateSendRequest {
  /** A UUID version 4 the client chooses; a taken one is a 409. */
  id: string;
  kind: SendKind;
  /** The owner's name and notes, sealed under the meta key (from the owner's item-wrap key, the Send id and key version; never the link key), 28 bytes to 16 KiB. */
  meta: string;
  /** The link key under the owner's item-wrap key: `u32be(key version)` and its seal, 64 bytes. */
  sealedKey: string;
  /**
   * What a recipient opens with the key from the link: the note, or the file's name and size,
   * sealed under the payload key (28 bytes to 256 KiB).
   */
  payload: string;
  /** For a file Send. */
  file?: NewFileDto | undefined;
  /**
   * The account's key version `meta` and `payload` were sealed for (`ownKeyVersion()` of the key
   * worker). A change for a version that is no longer the account's is a `409 key-version-stale`;
   * absent is accepted, as an old client sends it.
   */
  keyVersion?: number | undefined;
  /** How many times it may be opened; absent for no limit. */
  maxAccess?: number | null | undefined;
  hideEmail: boolean;
  disabled: boolean;
  /** When the link stops working (Unix seconds); absent for never before deletion. */
  expiresAt?: number | null | undefined;
  /** When the Send is deleted (Unix seconds): at most 30 days ahead. */
  deletionAt: number;
  /** The password proof, 32 bytes of the client's Argon2id (base64url); absent for no password. */
  password?: string | null | undefined;
}

/** `PUT /kem/v1/sends/{id}`: the settings an owner may change. The key and the file never do. */
export interface UpdateSendRequest {
  meta: string;
  /** New content, for a note. */
  payload?: string | null | undefined;
  maxAccess?: number | null | undefined;
  hideEmail: boolean;
  disabled: boolean;
  expiresAt?: number | null | undefined;
  deletionAt: number;
  /** A new password proof (32 bytes); absent keeps the password. */
  password?: string | null | undefined;
  /** Takes the password away. Not together with `password`. */
  removePassword?: boolean | undefined;
}

export interface SendFileDto {
  size: number;
  /** Whether the bytes have arrived. A file Send that is not ready can't be opened. */
  ready: boolean;
}

/** A Send as its owner sees it. */
export interface SendDto {
  id: string;
  /** The id the link carries. */
  accessId: string;
  kind: SendKind;
  meta: string;
  sealedKey: string;
  payload: string;
  file: SendFileDto | null;
  hasPassword: boolean;
  maxAccess: number | null;
  accessCount: number;
  hideEmail: boolean;
  disabled: boolean;
  expiresAt: number | null;
  deletionAt: number;
  createdAt: number;
  revisedAt: number;
  /** Where to `PUT` a file Send's bytes; only in the answer that makes it. */
  uploadUrl?: string;
}

/** The optional body of an access: the password proof, base64url. */
export interface AccessRequest {
  password?: string | undefined;
}

/** What a recipient gets: ciphertext and dates. */
export interface AccessDto {
  /** The access id. */
  id: string;
  kind: SendKind;
  /** The note, or the file's name and size, sealed under the Send's key. */
  payload: string;
  /** A file Send's size in bytes. */
  fileSize: number | null;
  expiresAt: number | null;
  deletionAt: number;
  /** The sender's email, unless they hid it. */
  senderEmail: string | null;
}

export interface SendsApi {
  list(): Promise<SendDto[]>;
  create(request: CreateSendRequest): Promise<SendDto>;
  update(id: string, request: UpdateSendRequest): Promise<SendDto>;
  remove(id: string): Promise<void>;
  /** Streams a file Send's `KMA1` bytes. The Send's own `Content-Length` must match its `file.size`. */
  upload(id: string, bytes: Uint8Array): Promise<SendDto>;
}

type Http = Pick<Api, 'request' | 'send'>;

export function createSendsApi(api: Http): SendsApi {
  const path = (id: string) => `/kem/v1/sends/${encodeURIComponent(id)}`;
  return {
    list: () => api.request<SendDto[]>({ method: 'GET', path: '/kem/v1/sends' }),
    create: (request) =>
      api.request<SendDto>({ method: 'POST', path: '/kem/v1/sends', body: request }),
    update: (id, request) => api.request<SendDto>({ method: 'PUT', path: path(id), body: request }),
    remove: (id) => api.send({ method: 'DELETE', path: path(id) }),
    upload: (id, bytes) => {
      const call: FeatureCall = {
        method: 'PUT',
        path: `${path(id)}/file`,
        body: bytes,
        headers: { 'Content-Type': 'application/octet-stream' },
      };
      return api.request<SendDto>(call);
    },
  };
}

/**
 * The public routes: no account and no token, so no DPoP proof either. They take the password
 * proof in the body. A 401 `send-password-required` or `send-wrong-password` asks for one.
 */
export function createSendAccessApi(api: Pick<Api, 'request' | 'raw'>) {
  const call = (accessId: string, suffix: string, password: string | undefined): FeatureCall => ({
    method: 'POST',
    path: `/kem/v1/send-access/${encodeURIComponent(accessId)}${suffix}`,
    mode: 'public',
    body: password === undefined ? {} : ({ password } satisfies AccessRequest),
  });
  return {
    /** Opens a Send and counts one access. */
    open: (accessId: string, password?: string) =>
      api.request<AccessDto>(call(accessId, '', password)),
    /** A file Send's `KMA1` bytes. */
    file: async (accessId: string, password?: string): Promise<Uint8Array> =>
      new Uint8Array(await (await api.raw(call(accessId, '/file', password))).arrayBuffer()),
  };
}
