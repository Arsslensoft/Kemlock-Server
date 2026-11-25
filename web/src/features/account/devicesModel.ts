// Devices and approval requests as the page works with them. The five words of a request are
// worked out here from its one-time public key; the server's `phrase` is never shown.
import type { DeviceEntryDto, DevicesApi, PendingApprovalDto } from '@/api/devices';
import type { DeviceKind } from '@/api/types';
import type { MessageId } from '@/i18n';
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
  return (
    kind === 'kemlock-android' ||
    kind === 'kemlock-ios' ||
    kind === 'kemlock-web' ||
    kind === 'kemlock-browser' ||
    kind === 'kemlock-cli'
  );
}

/** What a row's menu can do. */
export type DeviceMenuAction = 'trust' | 'untrust' | 'sign-out';

/**
 * The items of a device row's menu, in order. Trust is for Kemlock apps only: the Bitwarden-API
 * apps (Bitwarden, Amethystora Vault) get Sign out alone. A trusted copy of the key is wrapped by a
 * key only its device holds, so this browser can start trusting itself but no other device: another
 * Kemlock app that is trusted can be taken off, and one that is not still lists Trust this device,
 * which the screen shows off with the reason, because only that app can turn it on.
 */
export function deviceMenu(device: { kind: DeviceKind; trusted: boolean; current: boolean }): DeviceMenuAction[] {
  if (!isKemlockApp(device.kind)) return ['sign-out'];
  return device.trusted ? ['untrust', 'sign-out'] : ['trust', 'sign-out'];
}

/** The message that names what kind of app a device is, for the devices list. */
export function deviceKindLabelId(kind: DeviceKind): MessageId {
  switch (kind) {
    case 'kemlock-android':
      return 'devices.kind.kemlockAndroid';
    case 'kemlock-ios':
      return 'devices.kind.kemlockIos';
    case 'kemlock-web':
      return 'devices.kind.kemlockWeb';
    case 'kemlock-browser':
      return 'devices.kind.kemlockBrowser';
    case 'kemlock-cli':
      return 'devices.kind.kemlockCli';
    case 'amethystora':
      return 'devices.kind.amethystora';
    case 'bitwarden':
      return 'devices.kind.bitwarden';
    default:
      return 'devices.kind.other';
  }
}

/**
 * Signs this browser out: the server forgets this device and its key copy, then the session ends
 * here, then the page goes to the sign-in. When the server can't be reached the browser still lets
 * go of its own session, so a person is never stuck signed in.
 */
export async function leaveThisBrowser(
  steps: {
    signOutDevice: (deviceId: string) => Promise<unknown>;
    endSession: () => Promise<unknown>;
    goToSignIn: () => Promise<unknown>;
  },
  deviceId: string | null,
): Promise<void> {
  if (deviceId) await steps.signOutDevice(deviceId).catch(() => undefined);
  await steps.endSession();
  await steps.goToSignIn();
}

/** The devices other than this one, newest sync first. */
export function otherDevices(devices: DeviceEntryDto[], currentId: string | null): DeviceEntryDto[] {
  return devices
    .filter((device) => !device.current && device.id !== currentId)
    .sort((a, b) => b.lastSeenAt.localeCompare(a.lastSeenAt));
}
