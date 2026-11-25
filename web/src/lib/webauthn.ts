// The one place the web vault makes a passkey or a security key and hands it to the server
// (`POST /kem/v1/account/passkeys/options` and `POST /kem/v1/account/passkeys`). The browser calls
// and the base64url wire shape are in `passkey.ts`; this is the flow on top, shared by first-run
// setup and Account security, so neither repeats the PRF wrap step.
//
// The PRF output and the root key never leave the browser: only the wrap of the root key under the
// PRF output goes to the server (docs/crypto.md, "The passkey PRF wrap of the root key").
import type { PasskeyDto, PasskeysApi, SecurityKeyApi } from '@/api/passkeys';
import type { WebauthnProof } from '@/api/twoStep';
import type { CryptoPort } from '@/crypto-port';
import { encodeB64, wipe } from './b64url';
import {
  PasskeyError,
  assertWithPasskey,
  createPasskey,
  decodeCreationOptions,
  encodeNewCredential,
  passkeysAvailable,
} from './passkey';

export { decodeB64 as fromBase64Url, encodeB64 as toBase64Url } from './b64url';
export {
  PasskeyError,
  assertWithPasskey,
  assertWithPasskeyAndPrf,
  createPasskey,
  passkeysAvailable,
} from './passkey';

export interface RegisterPasskeyDeps {
  passkeys: Pick<PasskeysApi, 'creationOptions' | 'register'>;
  crypto: Pick<CryptoPort, 'prfWrapRoot'>;
  /** Defaults to `createPasskey`; tests pass a fake authenticator. */
  create?: typeof createPasskey;
}

/**
 * Asks the server for creation options, makes the credential, and stores it. An authenticator that
 * gives a PRF output also stores a wrap of the open account's root key, which opens the vault at
 * sign-in; one that does not stores a passkey that only proves who is asking.
 */
export async function registerPasskey(deps: RegisterPasskeyDeps, name: string): Promise<PasskeyDto> {
  const options = await deps.passkeys.creationOptions();
  const made = await (deps.create ?? createPasskey)(options);
  try {
    let prf: { wrappedKey: string; keyVersion: number } | undefined;
    if (made.prfOutput) {
      const wrap = await deps.crypto.prfWrapRoot(made.prfOutput, made.credentialId);
      prf = { wrappedKey: encodeB64(wrap.wrappedKey), keyVersion: wrap.keyVersion };
    }
    return await deps.passkeys.register(name, made.credential, prf);
  } finally {
    wipe(made.prfOutput);
  }
}

/** Asks the person to touch a security key; no PRF, since a second step does not open the vault. */
export async function createSecurityKey(options: Record<string, unknown>): Promise<Record<string, unknown>> {
  if (!passkeysAvailable() || typeof navigator.credentials.create !== 'function') {
    throw new PasskeyError('unavailable');
  }
  let credential: Credential | null;
  try {
    credential = await navigator.credentials.create({ publicKey: decodeCreationOptions(options) });
  } catch (error) {
    if (error instanceof DOMException && (error.name === 'NotAllowedError' || error.name === 'AbortError')) {
      throw new PasskeyError('cancelled');
    }
    throw error;
  }
  if (!credential) throw new PasskeyError('cancelled');
  return encodeNewCredential(credential as PublicKeyCredential);
}

export interface RegisterSecurityKeyDeps {
  keys: Pick<SecurityKeyApi, 'creationOptions' | 'confirm'>;
  /** Defaults to `createSecurityKey`; tests pass a fake authenticator. */
  create?: typeof createSecurityKey;
}

/** Makes a security key and turns it on as a second step. */
export async function registerSecurityKey(deps: RegisterSecurityKeyDeps, name: string): Promise<void> {
  const options = await deps.keys.creationOptions();
  const credential = await (deps.create ?? createSecurityKey)(options);
  await deps.keys.confirm(name, credential);
}

export interface ProveWithKeyDeps {
  /** `createSecondStepsApi(...).proofKeyOptions`: the options for the account's keys and passkeys. */
  options: () => Promise<Record<string, unknown>>;
  /** Defaults to `assertWithPasskey`; tests pass a fake authenticator. */
  assert?: typeof assertWithPasskey;
}

/**
 * Proves it is the account's owner with a security key or passkey: asks the server for options,
 * has the person touch the key, and returns the answer in the `{ webauthn }` shape every request
 * that takes a fresh proof accepts. The challenge is good once, for two minutes.
 */
export async function proveWithKey(deps: ProveWithKeyDeps): Promise<WebauthnProof> {
  if (!passkeysAvailable()) throw new PasskeyError('unavailable');
  const options = await deps.options();
  return { webauthn: await (deps.assert ?? assertWithPasskey)(options) };
}
