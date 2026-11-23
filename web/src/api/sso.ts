// Single sign-on (crates/kemlock-api-kem/src/routes/sso.rs). The web vault is the "device": it sends
// a PKCE challenge, its own `state` and a DPoP proof to `start`, goes to the provider's address, and
// comes back to a path of this server with a one-time code, which `finish` trades for tokens with the
// PKCE verifier and a proof of the same DPoP key. SSO never hands out a vault key.
import type { Api } from './client';
import type { DeviceDto, TokenResponse } from './types';

type Http = Pick<Api, 'request'>;

export interface SsoStartResponse {
  /** Where to send the browser. */
  authorizationUrl: string;
  providerName: string;
}

export interface SsoFinishResponse {
  status: 'signed_in' | 'two_factor_required';
  tokens: TokenResponse | null;
  /** With `two_factor_required`: send it to `/auth/two-factor` with the code. */
  challenge: string | null;
  methods: string[] | null;
  /** The sign-in made the account, which has no keys yet. */
  newAccount: boolean;
  /** The provider did multi-factor authentication, so Kemlock's own second step was skipped. */
  mfaViaSso: boolean;
}

export function createSsoApi(http: Http) {
  return {
    start: (body: { challenge: string; state: string; redirect: string }) =>
      http.request<SsoStartResponse>({
        method: 'POST',
        path: '/kem/v1/auth/sso/start',
        mode: 'proof',
        body,
      }),
    finish: (body: { code: string; verifier: string; device: DeviceDto }) =>
      http.request<SsoFinishResponse>({
        method: 'POST',
        path: '/kem/v1/auth/sso/finish',
        mode: 'proof',
        body,
      }),
  };
}

export type SsoApi = ReturnType<typeof createSsoApi>;
