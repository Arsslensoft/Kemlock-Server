// Emergency access from the grantor's side: confirming a contact seals the account's root key to
// their kx1 key, and only after the person has compared the contact's fingerprint.
import type { EmergencyApi, EmergencyGrantDto, GrantViewDto } from '@/api/emergency';
import { decodeB64, encodeB64 } from '@/lib/b64url';
import { type Fingerprint, parseBundle, uuidBytes } from '@/sharing/bundle';
import type { SharingCrypto } from '@/sharing/crypto';

export function confirmEmergencyContact(
  deps: { api: Pick<EmergencyApi, 'confirm'>; crypto: SharingCrypto },
  view: GrantViewDto,
  fingerprint: Fingerprint,
): Promise<EmergencyGrantDto> {
  return (async () => {
    if (!fingerprint.consistent) {
      throw new Error('the fingerprint worked out here differs from the worker’s');
    }
    if (!view.contactKeys) throw new Error('the contact has not shared their keys yet');
    const parsed = parseBundle(decodeB64(view.contactKeys.publicBundle));
    if (!parsed) throw new Error("the contact's key bundle can't be read");
    const recipient = view.grant.granteeId ? uuidBytes(view.grant.granteeId) : parsed.accountId;
    const sealed = await deps.crypto.sealRootKey(parsed.kx1, 'emergency-access', recipient);
    return deps.api.confirm(view.grant.id, encodeB64(sealed));
  })();
}

/** `KQ7M4XZP...` -> `KQ7M 4XZP ...`, which is easier to type from a screen. */
export function groupSecret(secret: string): string {
  return secret.replace(/\s+/g, '').replace(/(.{4})/g, '$1 ').trim();
}

/** Days left of the wait, from the grant's due time; 0 when it has passed. */
export function daysLeft(dueAt: string | null, now: Date): number | null {
  if (!dueAt) return null;
  const due = new Date(dueAt).getTime();
  if (Number.isNaN(due)) return null;
  return Math.max(0, Math.ceil((due - now.getTime()) / 86_400_000));
}
