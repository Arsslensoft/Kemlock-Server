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
    // The grant says who the contact is; without that there is nobody to hold the bundle against.
    const granteeId = view.grant.granteeId;
    if (!granteeId) throw new Error('the contact has no account yet');
    const bundle = decodeB64(view.contactKeys.publicBundle);
    const parsed = parseBundle(bundle);
    if (!parsed) throw new Error("the contact's key bundle can't be read");
    const grantee = uuidBytes(granteeId);
    if (!parsed.accountId.every((byte, i) => byte === grantee[i])) {
      throw new Error("the contact's key bundle is another account's");
    }
    // The worker checks the bundle's own signature and the account again before it seals: it seals
    // to no key the page chose.
    const sealed = await deps.crypto.sealEmergencyKey(bundle, decodeB64(view.contactKeys.bundleSignature), granteeId);
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

/** Whether the bundle the server holds for a contact is the grantee's: the account id in it is the grant's. */
export function bundleIsGranteesOwn(view: GrantViewDto): boolean {
  if (!view.contactKeys || !view.grant.granteeId) return false;
  try {
    const parsed = parseBundle(decodeB64(view.contactKeys.publicBundle));
    const grantee = uuidBytes(view.grant.granteeId);
    return parsed !== null && parsed.accountId.every((byte, i) => byte === grantee[i]);
  } catch {
    return false;
  }
}
