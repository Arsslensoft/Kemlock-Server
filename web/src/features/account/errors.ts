// Errors the account screens can meet beyond the shared ones: a space waiting for its keys, a
// fingerprint that didn't match, and a worker that can't seal or sign yet.
import { isApiError } from '@/api/errors';
import type { MessageId } from '@/i18n';
import { describeError } from '@/lib/errors';
import { PasskeyError } from '@/lib/passkey';
import { isUnavailable } from '@/sharing/crypto';

export interface Described {
  id: MessageId;
  values?: Record<string, string | number>;
}

export function describeAccountError(error: unknown): Described {
  if (isUnavailable(error)) return { id: 'sharing.unavailable' };
  if (error instanceof PasskeyError) {
    return { id: error.reason === 'cancelled' ? 'security.passkeys.cancelled' : 'security.passkeys.unavailable' };
  }
  if (isApiError(error)) {
    switch (error.slug) {
      case 'space-keys-pending':
        return { id: 'space.error.keysPending' };
      case 'fingerprint-mismatch':
        return { id: 'space.error.fingerprint' };
      case 'last-owner':
        return { id: 'space.error.lastOwner' };
      case 'wrong-state':
        return { id: 'space.error.wrongState' };
      case 'stale-key-version':
        return { id: 'space.error.staleKey' };
      default:
        break;
    }
  }
  return describeError(error);
}
