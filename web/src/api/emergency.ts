// Emergency access (crates/kemlock-api-kem/src/routes/emergency.rs): a contact the account's owner
// names, the wait before they can ask, and the root key sealed to their kx1 key.
import type { Api } from './client';

export type EmergencyKind = 'view' | 'takeover';
export type EmergencyState =
  | 'invited'
  | 'accepted'
  | 'confirmed'
  | 'recovery-initiated'
  | 'approved'
  | 'rejected';

export interface EmergencyGrantDto {
  id: string;
  grantorId: string;
  granteeEmail: string;
  granteeId: string | null;
  kind: EmergencyKind;
  waitDays: number;
  state: EmergencyState;
  recoveryInitiatedAt: string | null;
  /** While a request runs: when the wait ends and the timer approves. */
  dueAt: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface ContactKeysDto {
  publicBundle: string;
  bundleSignature: string;
  keyVersion: number;
}

export interface GrantViewDto {
  grant: EmergencyGrantDto;
  /** On the contact's side: who named them. */
  grantorEmail: string | null;
  /** On the grantor's side, while the contact waits for confirmation. */
  contactKeys: ContactKeysDto | null;
}

export interface EmergencyOverviewDto {
  /** Grants where the signed-in account is the grantor. */
  trustedContacts: GrantViewDto[];
  /** Grants that name the signed-in account as the contact. */
  grantors: GrantViewDto[];
}

export interface KeyReleaseDto {
  grantId: string;
  grantorId: string;
  kind: EmergencyKind;
  sealedKey: string;
}

type Http = Pick<Api, 'request' | 'send'>;

const grants = '/kem/v1/emergency/grants';

export function createEmergencyApi(http: Http) {
  const post = (id: string, action: string) =>
    http.request<EmergencyGrantDto>({ method: 'POST', path: `${grants}/${id}/${action}` });
  return {
    overview: () => http.request<EmergencyOverviewDto>({ method: 'GET', path: '/kem/v1/emergency' }),
    invite: (body: { email: string; kind: EmergencyKind; waitDays: number }) =>
      http.request<EmergencyGrantDto>({ method: 'POST', path: grants, body }),
    revoke: (id: string) => http.send({ method: 'DELETE', path: `${grants}/${id}` }),
    accept: (id: string) => post(id, 'accept'),
    /** `keyVersion`: the key version of the root key in the box; a box for another is a `409 key-version-stale`. Absent is accepted. */
    confirm: (id: string, sealedKey: string, keyVersion?: number) =>
      http.request<EmergencyGrantDto>({
        method: 'POST',
        path: `${grants}/${id}/confirm`,
        body: keyVersion === undefined ? { sealedKey } : { sealedKey, keyVersion },
      }),
    initiate: (id: string) => post(id, 'initiate'),
    approve: (id: string) => post(id, 'approve'),
    reject: (id: string) => post(id, 'reject'),
    key: (id: string) => http.request<KeyReleaseDto>({ method: 'GET', path: `${grants}/${id}/key` }),
  };
}

export type EmergencyApi = ReturnType<typeof createEmergencyApi>;
