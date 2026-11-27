// The Bitwarden API's accept routes, called with the signed token of a mailed link and the
// invitee's master password hash, with no sign-in: an account made in a Bitwarden app has no way into
// this web vault, and the server checks the hash as it checks a password sign-in. The answers are
// Vaultwarden-shaped (`{ message }`), not problem documents, so this reads them itself rather than
// through the Kemlock client. The raw password never reaches this file: only the hash does.
import type { BitwardenKdf } from '@/crypto/types';

/** Why an accept did not go through, as far as the person can act on it. */
export type Accepted =
  | { ok: true }
  /** The server said 400 with the Bitwarden bad-login text: a wrong password and an unknown account look the same. */
  | { ok: false; reason: 'password'; message: string }
  /** `429`: too many tries; `retryAfter` is the wait in seconds when the server says it. */
  | { ok: false; reason: 'limited'; message: string; retryAfter?: number }
  | { ok: false; reason: 'other'; message: string };

/** What the server says to a wrong master password hash (crates/kemlock-api-bw/src/identity.rs, `BAD_LOGIN`). */
export const BAD_LOGIN = 'Username or password is incorrect. Try again';

async function messageOf(response: Response): Promise<string> {
  try {
    const body = (await response.json()) as { message?: unknown; Message?: unknown; error_description?: unknown };
    const text = body.message ?? body.Message ?? body.error_description;
    if (typeof text === 'string') return text;
  } catch {
    // An answer with no body: the status says enough.
  }
  return '';
}

/** The seconds a `Retry-After` header asks for, or undefined. */
function waitOf(response: Response): number | undefined {
  const value = Number(response.headers.get('Retry-After'));
  return Number.isFinite(value) && value > 0 ? Math.ceil(value) : undefined;
}

async function post(path: string, token: string, masterPasswordHash: string): Promise<Accepted> {
  let response: Response;
  try {
    response = await fetch(path, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ token, masterPasswordHash }),
      credentials: 'omit',
      cache: 'no-store',
      referrerPolicy: 'no-referrer',
    });
  } catch {
    return { ok: false, reason: 'other', message: '' };
  }
  if (response.ok) return { ok: true };
  const message = await messageOf(response);
  if (response.status === 429) {
    const retryAfter = waitOf(response);
    return { ok: false, reason: 'limited', message, ...(retryAfter === undefined ? {} : { retryAfter }) };
  }
  // Only the bad-login text is a wrong password. Any other 400 (an expired or bad token, an invitation
  // already accepted, a user not valid, a disabled account) is a refusal, shown with its message.
  if (response.status === 400 && message === BAD_LOGIN) return { ok: false, reason: 'password', message };
  return { ok: false, reason: 'other', message };
}

const part = encodeURIComponent;

/** What `/identity/accounts/prelogin` says of an account, in either of the spellings a server uses. */
interface Prelogin {
  kdf?: unknown;
  Kdf?: unknown;
  kdfIterations?: unknown;
  KdfIterations?: unknown;
  kdfMemory?: unknown;
  KdfMemory?: unknown;
  kdfParallelism?: unknown;
  KdfParallelism?: unknown;
}

/** The KDF a prelogin names, or `undefined` for an answer that is not one. */
export function kdfOf(body: Prelogin): BitwardenKdf | undefined {
  const type = body.kdf ?? body.Kdf;
  const iterations = body.kdfIterations ?? body.KdfIterations;
  const memory = body.kdfMemory ?? body.KdfMemory;
  const parallelism = body.kdfParallelism ?? body.KdfParallelism;
  if ((type !== 0 && type !== 1) || typeof iterations !== 'number') return undefined;
  if (type === 0) return { type, iterations };
  if (typeof memory !== 'number' || typeof parallelism !== 'number') return undefined;
  return { type, iterations, memory, parallelism };
}

export const bwInvitations = {
  /**
   * `POST /identity/accounts/prelogin { email }`: the KDF the account's master password is run
   * through. A server answers the same for an account it has not, so this says nothing about
   * whether the account exists. `undefined` when the answer cannot be used or the server is out of reach.
   */
  prelogin: async (email: string): Promise<BitwardenKdf | undefined> => {
    try {
      const response = await fetch('/identity/accounts/prelogin', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ email }),
        credentials: 'omit',
        cache: 'no-store',
        referrerPolicy: 'no-referrer',
      });
      if (!response.ok) return undefined;
      return kdfOf((await response.json()) as Prelogin);
    } catch {
      return undefined;
    }
  },
  /** `POST /api/organizations/{org}/users/{member}/accept` */
  acceptOrganization: (organization: string, member: string, token: string, masterPasswordHash: string) =>
    post(`/api/organizations/${part(organization)}/users/${part(member)}/accept`, token, masterPasswordHash),
  /** `POST /api/emergency-access/{id}/accept` */
  acceptEmergency: (id: string, token: string, masterPasswordHash: string) =>
    post(`/api/emergency-access/${part(id)}/accept`, token, masterPasswordHash),
};
