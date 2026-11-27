// What the account screens need from the crypto worker beyond src/crypto/types.ts: sealing the
// root key to someone's kx1 key and signing a confirmation with sig1. The page speaks Uint8Array;
// the worker's contract speaks base64url, so `createSharingCrypto` adapts one to the other. Keys
// stay in the worker: only boxes and signatures come back.
import { crypto as worker } from '@/crypto';
import { type CryptoApi, CryptoError, type RootKeyContext } from '@/crypto/types';
import { decodeB64, encodeB64 } from '@/lib/b64url';

export type { RootKeyContext };

export interface SharingCrypto {
  /** Whether the worker can do these at all; screens that need them say so when it can't. */
  readonly available: boolean;
  /**
   * Whether `wrapForThisDevice` works: the worker has a key for this browser (WebCrypto,
   * non-extractable, in IndexedDB). An implementation that leaves this out is taken to support it.
   */
  readonly canWrapForThisDevice?: boolean;
  /**
   * Seals the unlocked account's root key to a kx1 public key (1,600 bytes) as a sealed box
   * (docs/crypto.md): context `device-approval`, with `aad` the account id then the approval
   * request id (32 bytes). Nothing else is sealed here: an emergency contact's box is
   * `sealEmergencyKey`.
   */
  sealRootKey(
    recipientKx1: Uint8Array,
    context: RootKeyContext,
    aad: Uint8Array,
  ): Promise<Uint8Array>;
  /**
   * Wraps the root key under a non-extractable key only this browser holds (WebCrypto,
   * docs/crypto.md: u8(1) || u8(3) || AES-256-GCM, aad bound to the account, device and key
   * version), for the trusted-device key copy.
   */
  wrapForThisDevice(input: {
    accountId: Uint8Array;
    deviceId: Uint8Array;
    keyVersion: number;
  }): Promise<Uint8Array>;
  /**
   * Seals the unlocked account's root key to an emergency contact, from the contact's public bundle
   * and its own signature. The worker checks the signature and that the bundle is `granteeId`'s (a
   * UUID, as text) before it seals, so the page can't have the key sealed to one it made up.
   */
  sealEmergencyKey(bundle: Uint8Array, bundleSignature: Uint8Array, granteeId: string): Promise<Uint8Array>;
  /**
   * A sig1 signature (3,373 bytes) over a member-confirmation statement (docs/crypto.md), under
   * context `confirm`, with the account's key. The worker signs nothing else.
   */
  signStatement(statement: Uint8Array, context: string): Promise<Uint8Array>;
}

/** What the browser has when the worker can't be reached: nothing that seals or signs. */
export const unavailableSharingCrypto: SharingCrypto = {
  available: false,
  canWrapForThisDevice: false,
  sealRootKey: () => Promise.reject(new CryptoError('unavailable')),
  sealEmergencyKey: () => Promise.reject(new CryptoError('unavailable')),
  signStatement: () => Promise.reject(new CryptoError('unavailable')),
  wrapForThisDevice: () => Promise.reject(new CryptoError('unavailable')),
};

/** Sharing over a crypto worker client. */
/** The canonical text of 16 UUID bytes. */
function uuidText(bytes: Uint8Array): string {
  if (bytes.length !== 16) throw new CryptoError('invalid');
  const hex = [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

export function createSharingCrypto(
  api: Pick<CryptoApi, 'sealRootKey' | 'sealEmergencyKey' | 'signStatement'> & Partial<Pick<CryptoApi, 'deviceCopySeal'>>,
): SharingCrypto {
  const deviceCopySeal = api.deviceCopySeal?.bind(api);
  return {
    available: true,
    canWrapForThisDevice: deviceCopySeal !== undefined,
    async sealRootKey(recipientKx1, context, aad) {
      return decodeB64(await api.sealRootKey(encodeB64(recipientKx1), context, encodeB64(aad)));
    },
    async sealEmergencyKey(bundle, bundleSignature, granteeId) {
      return decodeB64(await api.sealEmergencyKey(encodeB64(bundle), encodeB64(bundleSignature), granteeId));
    },
    async wrapForThisDevice({ accountId, deviceId, keyVersion }) {
      if (!deviceCopySeal) throw new CryptoError('unavailable');
      return decodeB64(await deviceCopySeal(uuidText(accountId), uuidText(deviceId), keyVersion));
    },
    async signStatement(statement, context) {
      return decodeB64(await api.signStatement(encodeB64(statement), context));
    },
  };
}

/** The one the app uses. */
export const sharingCrypto: SharingCrypto = createSharingCrypto(worker);

export function isUnavailable(error: unknown): boolean {
  return error instanceof CryptoError && error.code === 'unavailable';
}
