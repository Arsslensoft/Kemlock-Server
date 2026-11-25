// The words for a sign-in that did not go through, for the screens that ask an authenticator.
import { isApiError } from '@/api/errors';
import { type Described, describeError } from '@/lib/errors';
import { PasskeyError, SecurityKeyRejectedError } from '@/lib/passkey';
import { NoSignInWaiting } from './signIn';

/**
 * Whether a failed second step cannot be tried again and the person has to start from the password:
 * the challenge expired or was used (the server refuses it as credentials), or it is gone here.
 */
export function secondStepIsOver(error: unknown, described: Described): boolean {
  return error instanceof NoSignInWaiting || described.id === 'error.credentials';
}

/** The words for a passkey or key that did not answer; anything else is described as everywhere else. */
export function describeSignInError(error: unknown): Described {
  // Not "wrong password": the password was right, and the key can be tried again from here.
  if (error instanceof SecurityKeyRejectedError) return { id: 'password.keyRejected' };
  if (error instanceof PasskeyError) {
    return { id: error.reason === 'cancelled' ? 'signIn.passkeyCancelled' : 'signIn.passkeyUnavailable' };
  }
  return describeError(error);
}

/**
 * Like `describeSignInError`, for signing in with a passkey. A 401 there is not a wrong password:
 * the browser offered a credential that is not a sign-in passkey of any account, typically a
 * security key added as a second step.
 */
export function describePasskeySignInError(error: unknown): Described {
  if (isApiError(error) && error.status === 401) return { id: 'signIn.passkeyRejected' };
  return describeSignInError(error);
}
