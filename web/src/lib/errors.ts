// Turns what went wrong into a message id, so every screen words its failures the same way.
import { ApiError, NetworkError } from '@/api/errors';
import type { MessageId, Values } from '@/i18n';

/** The OPAQUE exchange failed on this side: the password is wrong (or the account is not there). */
export class CredentialsError extends Error {
  constructor() {
    super('The email or password is wrong');
    this.name = 'CredentialsError';
  }
}

export interface Described {
  id: MessageId;
  values?: Values;
}

export function describeError(error: unknown): Described {
  if (error instanceof NetworkError) return { id: 'error.network' };
  if (error instanceof CredentialsError) return { id: 'error.credentials' };
  if (error instanceof ApiError) {
    switch (error.slug) {
      case 'setup-code-wrong':
        return { id: 'error.setupCodeWrong' };
      case 'setup-complete':
        return { id: 'error.setupComplete' };
      case 'insecure-context':
        return { id: 'error.insecureContext' };
      case 'two-step-required':
        return { id: 'error.twoStepRequired' };
      case 'rate-limited':
        return { id: 'error.rateLimited', values: { seconds: error.retryAfter ?? 1 } };
      case 'unauthorized':
      case 'session-ended':
        return { id: error.status === 401 ? 'error.credentials' : 'error.generic' };
      case 'step-up-failed':
        return { id: 'admin.reauth.wrong' };
      case 'already-exists':
        return { id: 'error.exists' };
      case 'stale-revision':
        return { id: 'error.stale' };
      case 'forbidden':
        return { id: 'error.forbidden' };
      // "Verify the email of a new account" is on and the link in the mail hasn't been opened.
      case 'email-not-confirmed':
        return { id: 'error.emailNotConfirmed' };
      // The attachment quota (crates/kemlock-api-kem/src/routes/files.rs).
      case 'storage-disabled':
        return { id: 'error.storageDisabled' };
      case 'storage-limit-reached':
        return { id: 'error.storageFull' };
      case 'storage-limit-exceeded':
        return { id: 'error.storageTooBig' };
      case 'file-too-large':
        return { id: 'itemForm.error.fileTooLarge' };
      default:
        return { id: error.status >= 500 ? 'error.server' : 'error.generic' };
    }
  }
  // Not one the app knows: say so in the console, which is the only place its cause shows.
  console.error('unexpected error', error);
  return { id: 'error.generic' };
}
