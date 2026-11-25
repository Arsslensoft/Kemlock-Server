// The words for a sign-in that did not go through, for the screens that ask an authenticator.
import { type Described, describeError } from '@/lib/errors';
import { PasskeyError } from '@/lib/passkey';

/** The words for a passkey or key that did not answer; anything else is described as everywhere else. */
export function describeSignInError(error: unknown): Described {
  if (error instanceof PasskeyError) {
    return { id: error.reason === 'cancelled' ? 'signIn.passkeyCancelled' : 'signIn.passkeyUnavailable' };
  }
  return describeError(error);
}
