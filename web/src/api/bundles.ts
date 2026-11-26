// `GET /kem/v1/accounts/{id}/bundles/{version}` (crates/kemlock-api-kem/src/routes/write_sig.rs):
// the public-key bundle an account had at a key version, for checking a write it signed before a
// key replacement (docs/crypto.md, "Signed item writes", "Key versions"). The account itself and a
// member of a space it is in may ask.
import type { Api } from './client';
import { isApiError } from './errors';

export interface BundleAtDto {
  keyVersion: number;
  /** base64url */
  publicBundle: string;
  /** base64url: the account's own sig1 signature of the bundle */
  bundleSignature: string;
}

type Http = Pick<Api, 'request'>;

export function createBundlesApi(http: Http) {
  return {
    /** The bundle at `version`, or null when there is none to give this caller (404). */
    at: async (account: string, version: number): Promise<BundleAtDto | null> => {
      try {
        return await http.request<BundleAtDto>({
          method: 'GET',
          path: `/kem/v1/accounts/${encodeURIComponent(account)}/bundles/${version}`,
        });
      } catch (error) {
        if (isApiError(error) && error.status === 404) return null;
        throw error;
      }
    },
  };
}

export type BundlesApi = ReturnType<typeof createBundlesApi>;
