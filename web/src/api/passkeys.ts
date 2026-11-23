// The account's passkeys (crates/kemlock-api-kem/src/routes/passkeys.rs): list them, register one
// from a `navigator.credentials.create` answer, delete one. A passkey with PRF also keeps a wrap
// of the root key (`prf` at registration, or `PUT .../{id}/prf` later), which opens the vault at
// sign-in. Signing in with one is `createPasskeySignInApi`.
import type { Api } from './client';
import type { DeviceDto, TokenResponse } from './types';

/** The root key wrapped under a passkey's PRF output, as the server stores it. */
export interface PrfWrapDto {
  /** base64url, 92 bytes. */
  wrappedKey: string;
  keyVersion: number;
}

export interface PasskeyDto {
  id: string;
  name: string;
  /** Whether the passkey holds a PRF copy of the root key. */
  prf: boolean;
  prfKeyVersion: number | null;
  createdAt: string;
  lastUsedAt: string | null;
}

type Http = Pick<Api, 'request' | 'send'>;

const base = '/kem/v1/account/passkeys';

export function createPasskeysApi(http: Http) {
  return {
    list: () => http.request<{ passkeys: PasskeyDto[] }>({ method: 'GET', path: base }).then((r) => r.passkeys),
    /** `PublicKeyCredentialCreationOptions` as JSON (maybe wrapped as `{ publicKey }`). */
    creationOptions: () =>
      http
        .request<{ options: Record<string, unknown> }>({ method: 'POST', path: `${base}/options` })
        .then((r) => r.options),
    register: (name: string, credential: Record<string, unknown>, prf?: PrfWrapDto) =>
      http.request<PasskeyDto>({
        method: 'POST',
        path: base,
        body: { name, credential, ...(prf ? { prf } : {}) },
      }),
    /** Stores the PRF wrap for a passkey made without one. */
    putPrf: (id: string, prf: PrfWrapDto) =>
      http.send({ method: 'PUT', path: `${base}/${id}/prf`, body: prf }),
    remove: (id: string) => http.send({ method: 'DELETE', path: `${base}/${id}` }),
  };
}

export type PasskeysApi = ReturnType<typeof createPasskeysApi>;

/** `POST /kem/v1/auth/passkey/verify`: tokens, and the PRF wrap when the passkey has one. */
export interface PasskeySignInResponse {
  tokens: TokenResponse;
  passkeyId: string;
  prf: PrfWrapDto | null;
  keyVersion: number;
}

/** Sign-in with a passkey: both calls carry a DPoP proof and no token (the challenge is bound to the key). */
export function createPasskeySignInApi(http: Http) {
  return {
    options: () =>
      http.request<{ options: Record<string, unknown>; challenge: string }>({
        method: 'POST',
        path: '/kem/v1/auth/passkey/options',
        mode: 'proof',
      }),
    verify: (body: { challenge: string; credential: Record<string, unknown>; device: DeviceDto }) =>
      http.request<PasskeySignInResponse>({
        method: 'POST',
        path: '/kem/v1/auth/passkey/verify',
        mode: 'proof',
        body,
      }),
  };
}

export type PasskeySignInApi = ReturnType<typeof createPasskeySignInApi>;
