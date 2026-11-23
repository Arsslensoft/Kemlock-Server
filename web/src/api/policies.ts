// Space policies (crates/kemlock-api-kem/src/routes/policies.rs). Booleans are plain JSON
// booleans and times are Unix seconds.
//
//   GET /kem/v1/spaces/{id}/policies  any confirmed member: the space's policies
//   PUT /kem/v1/spaces/{id}/policies  owners and admins: replaces them
//   GET /kem/v1/policies              what binds the caller across every space they are in
//
// The server never sees a password or opens an item, so it can't enforce the master password
// rules, the session timeout, "no PIN unlock" or "no export of space items": clients do, from
// these answers.
import type { Api } from './client';

/** The master password rules. Clients enforce them. */
export interface MasterPasswordPolicyDto {
  /** The fewest characters (1 to 128). */
  minLength?: number | null;
  /** Bitwarden's complexity score, 0 to 4. */
  minComplexity?: number | null;
  requireUpper: boolean;
  requireLower: boolean;
  requireNumbers: boolean;
  requireSpecial: boolean;
  /** Whether a client also checks the password at each sign-in. */
  enforceOnLogin: boolean;
}

export type TimeoutAction = 'lock' | 'logOut';

/**
 * A space's policies. Every setting defaults to off, so a `PUT` that leaves one out turns it
 * off: send the whole object.
 */
export interface PoliciesDto {
  /** Members sign in through SSO only. Owners and admins are exempt. */
  requireSso: boolean;
  /** A member needs a confirmed two-step method to join. Owners and admins are exempt. */
  twoStep: boolean;
  /** The master password rules; absent for none. */
  masterPassword?: MasterPasswordPolicyDto | null;
  /** A member may belong to no other space. Owners and admins are exempt. */
  singleSpace: boolean;
  /**
   * Clients refuse to export the space's items. Advice only: whoever can view an item can copy
   * it, so the server can't make this true.
   */
  disableExport: boolean;
  /** Members can't make Sends. Owners and admins are exempt. */
  disableSend: boolean;
  /** A member's Send can't hide the sender's email. Owners and admins are exempt. */
  alwaysShowEmail: boolean;
  /** The longest session timeout clients allow, in minutes; absent for none. */
  sessionTimeoutMinutes?: number | null;
  sessionTimeoutAction?: TimeoutAction | null;
  noPinUnlock: boolean;
  /** Clients make new items in the space, not in the member's own vault. */
  centralOwnership: boolean;
  noCardItems: boolean;
}

/** A space's policies as stored. */
export interface SpacePoliciesDto {
  policies: PoliciesDto;
  /** When they were last set; absent for a space nobody has set policies for. */
  updatedAt?: number | null;
  updatedBy?: string | null;
}

/** Every policy off: where a space starts, and what a `PUT` that says nothing means. */
export const NO_POLICIES: PoliciesDto = {
  requireSso: false,
  twoStep: false,
  masterPassword: null,
  singleSpace: false,
  disableExport: false,
  disableSend: false,
  alwaysShowEmail: false,
  sessionTimeoutMinutes: null,
  sessionTimeoutAction: null,
  noPinUnlock: false,
  centralOwnership: false,
  noCardItems: false,
};

export function createPoliciesApi(api: Pick<Api, 'request'>) {
  const space = (id: string) => `/kem/v1/spaces/${encodeURIComponent(id)}/policies`;
  return {
    /** `GET /kem/v1/spaces/{id}/policies` */
    forSpace: (id: string) => api.request<SpacePoliciesDto>({ method: 'GET', path: space(id) }),
    /** `PUT /kem/v1/spaces/{id}/policies`: replaces them all. */
    setForSpace: (id: string, policies: PoliciesDto) =>
      api.request<SpacePoliciesDto>({ method: 'PUT', path: space(id), body: policies }),
    /**
     * `GET /kem/v1/policies`: what binds the caller across every space they are in, the strictest
     * rules and the shortest timeout among them.
     */
    mine: () => api.request<PoliciesDto>({ method: 'GET', path: '/kem/v1/policies' }),
  };
}

export type PoliciesApi = ReturnType<typeof createPoliciesApi>;
