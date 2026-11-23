// Devices and approval requests as the page works with them. The five words of a request are
// worked out here from its one-time public key; the server's `phrase` is never shown.
import type { DeviceEntryDto, DevicesApi, PendingApprovalDto } from '@/api/devices';
import type { DeviceKind } from '@/api/types';
import { approvalPhrase } from '@/lib/approvalPhrase';
import { decodeB64, encodeB64 } from '@/lib/b64url';
import { uuidBytes } from '@/sharing/bundle';
import type { SharingCrypto } from '@/sharing/crypto';

/** A request's key is a kx1 public key. */
export const KX1_PUBLIC_LEN = 1600;

export interface ApprovalRow {
  id: string;
  deviceName: string;
  deviceKind: DeviceKind;
  ip: string;
  ageSeconds: number;
  /** The five words, from the key. null when the server sent no usable key. */
  phrase: string | null;
  publicKey: Uint8Array | null;
}

function keyOf(approval: PendingApprovalDto): Uint8Array | null {
  if (!approval.publicKey) return null;
  try {
    const key = decodeB64(approval.publicKey);
    return key.length === KX1_PUBLIC_LEN ? key : null;
  } catch {
    return null;
  }
}

export async function loadApprovals(
  api: Pick<DevicesApi, 'approvals'>,
  phraseOf: (key: Uint8Array) => Promise<string> = approvalPhrase,
): Promise<ApprovalRow[]> {
  const approvals = await api.approvals();
  return Promise.all(
    approvals.map(async (approval) => {
      const publicKey = keyOf(approval);
      return {
        id: approval.id,
        deviceName: approval.deviceName,
        deviceKind: approval.deviceKind,
        ip: approval.ip,
        ageSeconds: approval.ageSeconds,
        phrase: publicKey ? await phraseOf(publicKey) : null,
        publicKey,
      };
    }),
  );
}

/** Seals the root key to the request's key and sends it. Needs the key: no key, no approval. */
export async function approveRequest(
  deps: { api: Pick<DevicesApi, 'approve'>; crypto: SharingCrypto },
  row: ApprovalRow,
  accountId: string,
): Promise<void> {
  if (!row.publicKey) throw new Error('the request carries no public key to seal to');
  // The box is bound to my account and to this request (docs/crypto.md: aad = account id ‖
  // approval request id), so an answer can't be replayed onto another request.
  const aad = new Uint8Array(32);
  aad.set(uuidBytes(accountId), 0);
  aad.set(uuidBytes(row.id), 16);
  const sealed = await deps.crypto.sealRootKey(row.publicKey, 'device-approval', aad);
  await deps.api.approve(row.id, encodeB64(sealed));
}

/** Whether a device speaks the Kemlock API (the others use the Bitwarden one). */
export function isKemlockApp(kind: DeviceKind): boolean {
  return kind === 'kemlock-android' || kind === 'kemlock-ios' || kind === 'kemlock-web' || kind === 'kemlock-cli';
}

/** The devices other than this one, newest sync first. */
export function otherDevices(devices: DeviceEntryDto[], currentId: string | null): DeviceEntryDto[] {
  return devices
    .filter((device) => !device.current && device.id !== currentId)
    .sort((a, b) => b.lastSeenAt.localeCompare(a.lastSeenAt));
}
