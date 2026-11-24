// The account's Recovery Kit (crates/kemlock-api-kem/src/routes/recovery_kit.rs): the non-secret
// record the server keeps of a kit made in the key worker, never a piece. Replacing or removing it
// takes the same fresh proof turning a second step off does (`POST .../two-factor/proof`).
import type { Api } from './client';
import { ApiError } from './errors';

/** `GET /kem/v1/account/recovery-kit`. */
export interface RecoveryKitDto {
  kitId: string;
  /** Pieces needed to unlock: 2. */
  threshold: number;
  /** Pieces made: 3. */
  shares: number;
  keyVersion: number;
  createdAt: string;
  /** Whether the kit is for the account's current key version; if not, its pieces open nothing. */
  current: boolean;
  /** base64url: the root key under the kit key. Useless without the pieces. */
  wrappedKey: string;
}

/** What a new kit takes: the key worker's `kitMake`, wrap as base64url. */
export interface NewKitInput {
  kitId: string;
  keyVersion: number;
  wrappedKey: string;
}

type Http = Pick<Api, 'request' | 'send'>;

const path = '/kem/v1/account/recovery-kit';

export function createRecoveryKitApi(http: Http) {
  return {
    /** The account's kit, or null when it has none. */
    show: async (): Promise<RecoveryKitDto | null> => {
      try {
        return await http.request<RecoveryKitDto>({ method: 'GET', path });
      } catch (error) {
        if (error instanceof ApiError && error.status === 404) return null;
        throw error;
      }
    },
    create: (kit: NewKitInput) => http.request<RecoveryKitDto>({ method: 'POST', path, body: kit }),
    /** A new kit in place of the old one; the old pieces stop working. */
    replace: (kit: NewKitInput, proof: string) =>
      http.request<RecoveryKitDto>({ method: 'PUT', path, body: { ...kit, proof } }),
    remove: (proof: string) => http.send({ method: 'DELETE', path, body: { proof } }),
    /** Mails the one-time code that proves the owner, which replacing and removing take. */
    proofRequest: () => http.send({ method: 'POST', path: '/kem/v1/account/two-factor/proof' }),
  };
}

export type RecoveryKitApi = ReturnType<typeof createRecoveryKitApi>;
