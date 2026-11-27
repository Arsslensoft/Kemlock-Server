// Approving a new device, this device's key copy and signing devices out
// (crates/kemlock-api-kem/src/routes/devices.rs), and the device list
// (crates/kemlock-api-kem/src/routes/contract.rs). Every shape here is what the server writes.
import { ApiError } from './errors';
import type { Api } from './client';
import type { DeviceKind, TokenResponse } from './types';

/** An open request from a new device. */
export interface PendingApprovalDto {
  id: string;
  deviceName: string;
  deviceKind: DeviceKind;
  /** The requester's address, cut to its /24 or /48. */
  ip: string;
  /** The server's cross-check only. It is never shown: the phrase is worked out here. */
  phrase: string;
  createdAt: string;
  expiresAt: string;
  ageSeconds: number;
  /**
   * The request's one-time kx1 public key: 1,600 bytes, base64url, always present. The phrase is
   * worked out from it here, and the root key is sealed to it.
   */
  publicKey: string;
}

/** `POST /kem/v1/auth/device/request` answers this to the new device. */
export interface ApprovalRequestResponse {
  requestId: string;
  /** The server's cross-check only; the new device works the phrase out from its own key. */
  phrase: string;
  expiresAt: string;
  /**
   * True when the account was getting so many requests that this one was held back among them:
   * it still shows on the account's open devices, but the owner may be slow to find it.
   */
  heldBack?: boolean;
}

export type ApprovalStatus = 'pending' | 'approved' | 'denied' | 'expired' | 'used';

/** `GET /kem/v1/auth/device/request/{id}`: what the new device polls for. */
export interface ApprovalPollResponse {
  status: ApprovalStatus;
  expiresAt: string | null;
  /** With `approved`: the root key sealed to the device's one-time key, base64url. */
  sealedKey: string | null;
  /** With `approved` only: the account the key opens, which the sealed box's aad binds. */
  accountId?: string;
}

export interface ApprovalListResponse {
  approvals: PendingApprovalDto[];
}

export type KeyProtection = 'secure-enclave' | 'keystore' | 'web-crypto' | 'browser' | 'software';

export interface KeyCopyRequest {
  wrappedKey: string;
  protection: KeyProtection;
  /** The key version the copy was made for; a copy for another is a `409 key-version-stale`. Absent is accepted. */
  keyVersion?: number | undefined;
}

export interface KeyCopyResponse {
  deviceId: string;
  wrappedKey: string;
  protection: KeyProtection;
  createdAt: string;
  updatedAt: string;
}

/** A signed-in device or app (`GET /kem/v1/devices`), most recently seen first. */
export interface DeviceEntryDto {
  id: string;
  name: string;
  kind: DeviceKind;
  createdAt: string;
  /** The latest sign-in, refresh or use of either API. */
  lastSeenAt: string;
  /** The last authenticated request on the Kemlock API; absent when there was none. */
  lastKemlockUseAt?: string | null;
  /** The last authenticated request on the Bitwarden API; absent when there was none. */
  lastBitwardenUseAt?: string | null;
  /** Whether this is the device that asked. */
  current: boolean;
  /** Whether the device keeps a trusted-device copy of the root key on the server. */
  trusted: boolean;
  /** When the device made that copy; null or absent when it holds none (an older server sends none). */
  trustedSince?: string | null;
}

export interface DeviceListResponse {
  devices: DeviceEntryDto[];
}

type Http = Pick<Api, 'request' | 'send'>;

export function createDevicesApi(http: Http) {
  return {
    approvals: async (): Promise<PendingApprovalDto[]> =>
      (await http.request<ApprovalListResponse>({ method: 'GET', path: '/kem/v1/devices/approvals' }))
        .approvals,
    approve: (id: string, sealedKey: string) =>
      http.send({
        method: 'POST',
        path: `/kem/v1/devices/approvals/${id}`,
        body: { decision: 'approve', sealedKey },
      }),
    deny: (id: string) =>
      http.send({
        method: 'POST',
        path: `/kem/v1/devices/approvals/${id}`,
        body: { decision: 'deny' },
      }),
    /** This device's key copy, or null when it has none (a 404). */
    keyCopy: async (): Promise<KeyCopyResponse | null> => {
      try {
        return await http.request<KeyCopyResponse>({ method: 'GET', path: '/kem/v1/devices/key-copy' });
      } catch (error) {
        if (error instanceof ApiError && error.status === 404) return null;
        throw error;
      }
    },
    putKeyCopy: (body: KeyCopyRequest) =>
      http.request<KeyCopyResponse>({ method: 'PUT', path: '/kem/v1/devices/key-copy', body }),
    deleteKeyCopy: () => http.send({ method: 'DELETE', path: '/kem/v1/devices/key-copy' }),
    /**
     * Stops trusting another device of the account: its copy of the root key goes and its session
     * carries on. Only the device itself can make a copy, so there is no call to start trusting one.
     */
    untrustDevice: (deviceId: string) =>
      http.send({ method: 'DELETE', path: `/kem/v1/devices/${encodeURIComponent(deviceId)}/key-copy` }),
    /**
     * Ends this device's session on the server and nothing else: its refresh tokens are revoked,
     * and its device row and key copy stay, so an account that can only open its vault with this
     * browser's copy is not locked out of it by signing out.
     */
    endSession: () => http.send({ method: 'POST', path: '/kem/v1/auth/sign-out' }),
    /**
     * Ends this device's other sessions and keeps this one, the device row and its key copy: the
     * refresh tokens an earlier sign-in left behind (in a closed tab's storage) stop working.
     */
    endOtherSessions: () =>
      http.send({ method: 'POST', path: '/kem/v1/auth/sign-out', body: { others: true } }),
    /** Removes a device: its session, its row and its key copy. The "remove this device" action. */
    signOut: (deviceId: string) =>
      http.send({ method: 'POST', path: '/kem/v1/devices/sign-out', body: { deviceId } }),
    /** The account's devices, or null when an older server has no such list (a 404 or 405). */
    devices: async (): Promise<DeviceEntryDto[] | null> => {
      try {
        return (await http.request<DeviceListResponse>({ method: 'GET', path: '/kem/v1/devices' }))
          .devices;
      } catch (error) {
        if (error instanceof ApiError && (error.status === 404 || error.status === 405)) return null;
        throw error;
      }
    },
  };
}

export type DevicesApi = ReturnType<typeof createDevicesApi>;

/** `POST /kem/v1/auth/device/request`: what a new device sends to ask for approval. */
export interface ApprovalRequestBody {
  email: string;
  /** The device's one-time kx1 public key, 1,600 bytes, base64url. */
  publicKey: string;
  device: { id?: string | null; name: string; kind?: DeviceKind | null };
}

export interface DeviceChallengeResponse {
  challenge: string;
}

/**
 * The new device's side of an approval: no account yet, so each call carries a DPoP proof (mode
 * `proof`) and no token. The server ties the request to the key that signed it, so the poll, the
 * challenge and the verify must all come from the browser that made the request.
 */
export function createNewDeviceApi(http: Pick<Api, 'request'>) {
  return {
    request: (body: ApprovalRequestBody) =>
      http.request<ApprovalRequestResponse>({
        method: 'POST',
        path: '/kem/v1/auth/device/request',
        mode: 'proof',
        body,
      }),
    poll: (requestId: string) =>
      http.request<ApprovalPollResponse>({
        method: 'GET',
        path: `/kem/v1/auth/device/request/${encodeURIComponent(requestId)}`,
        mode: 'proof',
      }),
    challenge: (requestId: string) =>
      http.request<DeviceChallengeResponse>({
        method: 'POST',
        path: '/kem/v1/auth/device/challenge',
        mode: 'proof',
        body: { requestId },
      }),
    verify: (challenge: string) =>
      http.request<TokenResponse>({
        method: 'POST',
        path: '/kem/v1/auth/device/verify',
        mode: 'proof',
        body: { challenge },
      }),
  };
}

export type NewDeviceApi = ReturnType<typeof createNewDeviceApi>;
