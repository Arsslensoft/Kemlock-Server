// The profile routes (crates/kemlock-api-kem/src/routes/profile.rs): the name, the master password
// and the address the account signs in with. The password and the address change by making the
// OPAQUE record again under the new password (or the new address), so each call carries a fresh
// proof of the current password (`PasswordProof`, as deleting the account does) and the new
// record, the new KDF settings and the root key wrapped for them.
import type { Api } from './client';
import type { PasswordProof } from './eraseAccount';
import type { KdfDto, TokenResponse } from './types';

export interface ProfileDto {
  userId: string;
  email: string;
  name: string | null;
  /** An identity provider owns the name and the address: they are read-only here. */
  sso: boolean;
  /** The account has a master password. One that signs in through SSO only may not. */
  hasPassword: boolean;
  /** The account is shared with Bitwarden apps, which hold its password and its address. */
  compatible: boolean;
  /** An address change waits for its link to be opened. */
  pendingEmail: string | null;
}

/** What replaces the account's password record: made in the browser, in the worker. */
export interface NewCredential {
  /**
   * The server's sealed ticket from the registration's first message. It binds that registration
   * to this account, this device key and (for an address change) this address, and the change
   * is refused without it.
   */
  ticket: string;
  /** OPAQUE's `RegistrationUpload`, base64url. */
  upload: string;
  kdf: KdfDto;
  /** The root key under the new master key and export key, base64url, 92 bytes. */
  wrappedRootKey: string;
}

export interface PasswordChange extends PasswordProof, NewCredential {
  signOutOthers: boolean;
}

export interface EmailChange extends PasswordProof, NewCredential {
  email: string;
}

/**
 * What a changed password answers. `tokens` is present when the other devices were signed out: the
 * account's security stamp changed with them, so this device's old tokens stopped working and these
 * are the ones to carry on with.
 */
export interface PasswordChanged {
  tokens: TokenResponse | null;
}

export interface EmailChangeRequested {
  pendingEmail: string;
  /** RFC 3339. */
  expiresAt: string;
}

type Http = Pick<Api, 'request' | 'send'>;

export function createProfileApi(http: Http) {
  return {
    get: () => http.request<ProfileDto>({ method: 'GET', path: '/kem/v1/account/profile' }),
    /** A blank name clears it. Refused (403 `sso-managed`) when an identity provider owns it. */
    rename: (name: string) =>
      http.request<ProfileDto>({ method: 'PATCH', path: '/kem/v1/account/profile', body: { name } }),
    /**
     * OPAQUE registration, first answer: bound to the account's address, or, with `email`, to the
     * address it is about to have, and a ticket that the last call must carry back.
     */
    credentialsStart: (request: string, email?: string) =>
      http.request<{ response: string; ticket: string }>({
        method: 'POST',
        path: '/kem/v1/account/credentials/start',
        body: email === undefined ? { request } : { request, email },
      }),
    changePassword: (change: PasswordChange) =>
      http.request<PasswordChanged>({ method: 'PUT', path: '/kem/v1/account/password', body: change }),
    /** Mails a link to the new address; nothing changes until it is opened. */
    requestEmailChange: (change: EmailChange) =>
      http.request<EmailChangeRequested>({ method: 'POST', path: '/kem/v1/account/email', body: change }),
    cancelEmailChange: () => http.send({ method: 'DELETE', path: '/kem/v1/account/email' }),
    /** The link's token is the proof: no session needed. */
    confirmEmailChange: (token: string) =>
      http.request<{ email: string }>({
        method: 'POST',
        path: '/kem/v1/account/email/confirm',
        mode: 'public',
        body: { token },
      }),
  };
}

export type ProfileApi = ReturnType<typeof createProfileApi>;
