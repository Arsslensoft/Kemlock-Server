// Rotating the account's root key (crates/kemlock-api-kem/src/routes/rotation.rs, docs/crypto.md
// "Rotating the root key"). The key worker makes everything secret; these calls carry only what the
// server stores. The install asks the password again, as changing it does.
import type { Api } from './client';
import type { PasswordProof } from './eraseAccount';
import type { Proof } from './twoStep';
import type { TokenResponse } from './types';

/** What the account holds that a rotation must cover (`GET /kem/v1/account/rotation`). */
export interface RotationPlanDto {
  keyVersion: number;
  hasPassword: boolean;
  /** base64url */
  publicBundle: string;
  kit: { kitId: string } | null;
  /** Passkeys that have a PRF wrap. */
  passkeys: Array<{ id: string; credentialId: string }>;
  deviceCopies: Array<{ deviceId: string }>;
  /** Grants that hold a box. */
  emergency: Array<{ id: string; state: string; granteeId: string | null }>;
  recovery: Array<{ space: string; keySeq: number }>;
  sends: Array<{ id: string; kind: 'text' | 'file' }>;
  items: { count: number };
  /** How many spaces the account is a member of. */
  spaces: number;
  previousKeys: { keyVersion: number; sealed: string } | null;
}

/** An item sealed again under the new keys, staged until the install. */
export interface StagedItemDto {
  id: string;
  baseRevision: number;
  ciphertext: string;
  itemKey: string;
}

export interface StageRequest {
  /** 16 random bytes, base64url: one attempt. */
  rotationId: string;
  toVersion: number;
  items: StagedItemDto[];
}

export interface InstallRequest extends Partial<PasswordProof> {
  rotationId: string;
  fromVersion: number;
  toVersion: number;
  proof?: Proof;
  publicBundle: string;
  bundleSignature: string;
  sealedPrivateKeys: string;
  sealedPreviousPrivateKeys: string;
  wrappedRootKey?: string;
  kit?: { kitId: string; wrappedKey: string };
  dropKit?: boolean;
  deviceCopy?: { wrappedKey: string; protection: string };
  passkeys?: Array<{ id: string; wrappedKey: string }>;
  dropPasskeys?: string[];
  emergency?: Array<{ id: string; sealedKey: string }>;
  dropEmergency?: string[];
  recovery?: Array<{ space: string; keySeq: number; box: string }>;
  dropRecovery?: string[];
  sends?: Array<{ id: string; sealedKey: string; meta: string }>;
  spacesHandled?: boolean;
}

export interface Rotated {
  keyVersion: number;
  /** New tokens for this device: the new security stamp ended the ones it held. */
  tokens: TokenResponse | null;
}

type Http = Pick<Api, 'request' | 'send'>;

const path = '/kem/v1/account/rotation';

export function createRotationApi(http: Http) {
  return {
    plan: () => http.request<RotationPlanDto>({ method: 'GET', path }),
    /** Stages re-encrypted items, out of sight of every reader; the same item again replaces it. */
    stage: (request: StageRequest) =>
      http.request<{ staged: number }>({ method: 'PUT', path: `${path}/items`, body: request }),
    abandon: () => http.send({ method: 'DELETE', path }),
    install: (request: InstallRequest) => http.request<Rotated>({ method: 'POST', path, body: request }),
    /** The account's spaces have moved to the new keys: the previous private keys are deleted. */
    finishSpaces: () => http.send({ method: 'DELETE', path: `${path}/previous-keys` }),
  };
}

export type RotationApi = ReturnType<typeof createRotationApi>;
