// The personal API key for the Bitwarden CLI and scripts (crates/kemlock-api-kem/src/routes/
// api_key.rs). Showing the secret and replacing it take the same fresh proof turning a second step
// off does (`POST .../two-factor/proof`).
import type { Api } from './client';
import { ApiError } from './errors';

/** `GET /kem/v1/account/api-key`: what the key looks like without its secret. */
export interface ApiKeyInfoDto {
  /** `user.<id>`, the CLI's `client_id`. */
  clientId: string;
  /** Whether the key was made yet. */
  set: boolean;
}

/** The key with its secret. */
export interface ApiKeyDto {
  clientId: string;
  clientSecret: string;
  revisionDate: string;
}

type Http = Pick<Api, 'request' | 'send'>;

const path = '/kem/v1/account/api-key';

export function createApiKeyApi(http: Http) {
  return {
    /** The key's client id, or null when the account has none to have (no Bitwarden sign-in). */
    show: async (): Promise<ApiKeyInfoDto | null> => {
      try {
        return await http.request<ApiKeyInfoDto>({ method: 'GET', path });
      } catch (error) {
        if (error instanceof ApiError && error.status === 404) return null;
        throw error;
      }
    },
    /** The secret; the server makes the key when there is none. */
    reveal: (proof: string) => http.request<ApiKeyDto>({ method: 'POST', path, body: { proof } }),
    /** A new secret: the old one stops signing in. */
    rotate: (proof: string) => http.request<ApiKeyDto>({ method: 'POST', path: `${path}/rotate`, body: { proof } }),
    /** Mails the one-time code that proves the owner. */
    proofRequest: () => http.send({ method: 'POST', path: '/kem/v1/account/two-factor/proof' }),
  };
}

export type ApiKeyApi = ReturnType<typeof createApiKeyApi>;
