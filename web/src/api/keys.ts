// The first keys of an account single sign-on made with none
// (`POST /kem/v1/account/keys/enrol`, crates/kemlock-api-kem/src/routes/contract.rs). The device
// makes them; the server stores the public bundle, its signature, the sealed private keys and this
// device's copy of the root key, and refuses (409) once the account has keys.
import type { Api } from './client';
import type { KeyProtection } from './devices';

export interface EnrolKeysRequest {
  /** base64url, for key version 1. */
  publicBundle: string;
  bundleSignature: string;
  sealedPrivateKeys: string;
  deviceCopy: { wrappedKey: string; protection: KeyProtection };
}

export interface EnrolKeysResponse {
  keyVersion: number;
}

type Http = Pick<Api, 'request'>;

export function createKeysApi(http: Http) {
  return {
    enrol: (body: EnrolKeysRequest) =>
      http.request<EnrolKeysResponse>({ method: 'POST', path: '/kem/v1/account/keys/enrol', body }),
  };
}

export type KeysApi = ReturnType<typeof createKeysApi>;
