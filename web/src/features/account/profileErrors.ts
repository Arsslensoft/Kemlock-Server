// The Profile page's own words for failures: the account screens' (errors.ts), and what only the
// profile routes answer. `invalid-request` is the server's word for any malformed body, so it
// reads as "that could not be saved" here and nowhere else.
import { isApiError } from '@/api/errors';
import { type Described, describeAccountError } from './errors';

export function describeProfileError(error: unknown): Described {
  if (isApiError(error)) {
    if (error.slug === 'invalid-request') {
      // The second step's code was wrong, spent or out of time: the server says so in words.
      if (error.detail?.includes('the code is wrong')) return { id: 'profile.error.proof' };
      return { id: 'profile.error.badRequest' };
    }
    // The account was written by someone else between the read and the write: nothing was changed.
    if (error.slug === 'account-changed') return { id: 'profile.error.changed' };
  }
  return describeAccountError(error);
}
