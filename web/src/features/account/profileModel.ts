// What the Profile page does besides drawing: the checks on what was typed, and the two changes that
// replace the account's password record, a new master password and a new sign-in address. No React
// in here, so it is tested with fakes.
//
// Both changes make the OPAQUE record again (docs/crypto.md, "Changing the master password and the
// sign-in address"): the new master key comes from the typed password and a fresh salt, OPAQUE is
// registered again (under the new address for an address change), and the worker wraps the open
// root key under the new master key and export key. The root key does not change, so nothing else
// in the vault is touched. The server is told only the new record, the new KDF settings and the
// wrap, together with the ticket the registration's first message got (it binds the registration to
// this device and this use) and a fresh proof of the current password.
import { z } from 'zod';
import { ApiError } from '@/api/errors';
import type { Api } from '@/api/client';
import type { Proof } from '@/api/twoStep';
import type { EmailChangeRequested, NewCredential, PasswordChanged, ProfileApi } from '@/api/profile';
import type { CryptoPort } from '@/crypto-port';
import { NEW_ACCOUNT_KDF } from '@/features/setup/registerAccount';
import { decodeB64, encodeB64 } from '@/lib/b64url';
import { CredentialsError } from '@/lib/errors';
import { MASTER_PASSWORD_MIN } from '@/lib/schemas';
import { reauthenticate } from './deleteAccountModel';

/** The current password was not it: the OPAQUE exchange failed here, or the server refused the proof. */
export class WrongPasswordError extends Error {
  constructor() {
    super('The current master password is wrong');
    this.name = 'WrongPasswordError';
  }
}

export interface ProfileDeps {
  api: Pick<ProfileApi, 'credentialsStart' | 'changePassword' | 'requestEmailChange'> &
    Pick<Api, 'prelogin' | 'opaqueStart'>;
  crypto: Pick<
    CryptoPort,
    | 'masterKey'
    | 'opaqueRegisterStart'
    | 'opaqueRegisterFinish'
    | 'opaqueLoginStart'
    | 'opaqueLoginFinish'
    | 'rewrapRoot'
    | 'release'
  >;
  /** Random bytes for the new salt; the browser's by default. */
  randomBytes?: (length: number) => Uint8Array;
}

/** Why a new master password is refused before anything is sent. */
export type PasswordProblem = 'short' | 'mismatch' | 'same';

export function passwordProblem(current: string, next: string, again: string): PasswordProblem | undefined {
  if (next.length < MASTER_PASSWORD_MIN) return 'short';
  if (next !== again) return 'mismatch';
  if (next === current) return 'same';
  return undefined;
}

const emailShape = z.email();

/** An address the server will take: a full one, however it was cased and spaced. */
export function isEmail(value: string): boolean {
  return emailShape.safeParse(value.trim()).success;
}

/** Whether two addresses are one: the server keys accounts on the trimmed, lower-cased address. */
export function sameEmail(a: string, b: string): boolean {
  return a.trim().toLowerCase() === b.trim().toLowerCase();
}

/** The proof of the current password: a wrong one is the person's to fix, not a server fault. */
async function proveCurrent(deps: ProfileDeps, email: string, password: string) {
  try {
    return await reauthenticate(deps, email, password);
  } catch (error) {
    if (error instanceof CredentialsError || (error instanceof ApiError && error.status === 401)) {
      throw new WrongPasswordError();
    }
    throw error;
  }
}

/**
 * The record that replaces the account's password record: a master key from `password` and a fresh
 * salt, OPAQUE registered again (under `email` when the address is changing), the ticket of that
 * registration, and the open root key wrapped under both keys. Both handles are given back to the worker if anything fails before the
 * wrap spends them.
 */
export async function makeCredential(deps: ProfileDeps, password: string, email?: string): Promise<NewCredential> {
  const randomBytes = deps.randomBytes ?? ((n: number) => globalThis.crypto.getRandomValues(new Uint8Array(n)));
  const salt = randomBytes(16);
  const masterKey = await deps.crypto.masterKey(password.normalize('NFC'), { ...NEW_ACCOUNT_KDF, salt });
  let exportKey: Uint8Array | undefined;
  let wrapped = false;
  try {
    const first = await deps.crypto.opaqueRegisterStart(masterKey);
    const started = await deps.api.credentialsStart(encodeB64(first.request), email);
    const second = await deps.crypto.opaqueRegisterFinish(first.state, masterKey, decodeB64(started.response));
    exportKey = second.exportKey;
    const wrap = await deps.crypto.rewrapRoot(masterKey, exportKey);
    wrapped = true;
    return {
      ticket: started.ticket,
      upload: encodeB64(second.upload),
      kdf: { ...NEW_ACCOUNT_KDF, salt: encodeB64(salt) },
      wrappedRootKey: encodeB64(wrap),
    };
  } finally {
    if (!wrapped) {
      // Not spent by the wrap: hand them back so the worker does not keep them.
      await deps.crypto.release(masterKey).catch(() => undefined);
      if (exportKey) await deps.crypto.release(exportKey).catch(() => undefined);
    }
  }
}

export interface PasswordChangeInput {
  /** The address the account signs in with now. */
  email: string;
  current: string;
  next: string;
  signOutOthers: boolean;
  /** The second step's fresh proof, when the account has one on. */
  proof?: Proof;
}

/**
 * Changes the master password. The server swaps the record, the KDF settings and the wrap in one
 * write. When the other devices are signed out the answer carries this device's new tokens, which
 * the caller must take up: the old ones stopped working with the others.
 */
export async function changePassword(deps: ProfileDeps, input: PasswordChangeInput): Promise<PasswordChanged> {
  const proof = await proveCurrent(deps, input.email, input.current);
  const credential = await makeCredential(deps, input.next);
  try {
    return await deps.api.changePassword({
      ...proof,
      ...credential,
      signOutOthers: input.signOutOthers,
      ...(input.proof !== undefined ? { proof: input.proof } : {}),
    });
  } catch (error) {
    if (error instanceof ApiError && error.status === 401) throw new WrongPasswordError();
    throw error;
  }
}

export interface EmailChangeInput {
  /** The address the account signs in with now. */
  email: string;
  newEmail: string;
  /** The current master password: the new record is made from it, under the new address. */
  current: string;
  /** The second step's fresh proof, when the account has one on. */
  proof?: Proof;
}

/**
 * Asks to change the address. The server mails a link to the new one and changes nothing until it
 * is opened. The password stays the same; its record is made again because OPAQUE binds the record
 * to the address.
 */
export async function requestEmailChange(deps: ProfileDeps, input: EmailChangeInput): Promise<EmailChangeRequested> {
  const newEmail = input.newEmail.trim().toLowerCase();
  const proof = await proveCurrent(deps, input.email, input.current);
  const credential = await makeCredential(deps, input.current, newEmail);
  try {
    return await deps.api.requestEmailChange({
      ...proof,
      ...credential,
      email: newEmail,
      ...(input.proof !== undefined ? { proof: input.proof } : {}),
    });
  } catch (error) {
    if (error instanceof ApiError && error.status === 401) throw new WrongPasswordError();
    throw error;
  }
}
