// `GET` and `PUT /kem/v1/manifests/{owner}` (crates/kemlock-api-kem/src/routes/manifests.rs): the
// signed manifest of an owner's items, where the owner is `user:<uuid>` (the account's own) or
// `space:<uuid>`. Bytes are base64url; docs/crypto.md, "Signed manifest", says what they hold.
import type { Api } from './client';
import { isApiError } from './errors';

export interface ManifestDto {
  owner: string;
  counter: number;
  /** The signed bytes, as stored. */
  manifest: string;
  signature: string;
  /** The account whose bundle's sig1 key signed it. */
  signer: string;
  storedAt: string;
}

export interface PutManifestBody {
  manifest: string;
  signature: string;
}

type Http = Pick<Api, 'request'>;

export function createManifestsApi(http: Http) {
  return {
    /** The latest manifest of an owner, or null when none was ever stored (404). */
    get: async (owner: string): Promise<ManifestDto | null> => {
      try {
        return await http.request<ManifestDto>({ method: 'GET', path: `/kem/v1/manifests/${owner}` });
      } catch (error) {
        if (isApiError(error) && error.status === 404) return null;
        throw error;
      }
    },
    /** Stores a manifest; 409 when its counter is not above the stored one (`currentCounter`). */
    put: (owner: string, body: PutManifestBody) =>
      http.request<ManifestDto>({ method: 'PUT', path: `/kem/v1/manifests/${owner}`, body }),
  };
}

export type ManifestsApi = ReturnType<typeof createManifestsApi>;

/** The counter a 409 says the server holds, when it says. */
export function currentCounter(error: unknown): number | undefined {
  if (!isApiError(error)) return undefined;
  const value = error.problem?.['currentCounter'];
  return typeof value === 'number' ? value : undefined;
}
