// The OPAQUE sign-in, start to unlocked vault. Pure of React so it can be tested with fakes.
//
// Secrets (the master key and OPAQUE's export key) live in the closure only until the vault is
// open, then are overwritten. They are handles for the crypto worker, not the keys themselves.
import { type Api, tokensFromResponse } from '@/api/client';
import { NetworkError, isApiError } from '@/api/errors';
import type { SecurityKeyStepApi } from '@/api/passkeys';
import type { DeviceDto, TokenResponse } from '@/api/types';
import type { Session } from '@/app/session';
import type { CryptoPort } from '@/crypto-port';
import { decodeB64, encodeB64, wipe } from '@/lib/b64url';
import { rememberDeviceId } from '@/lib/device';
import { CredentialsError } from '@/lib/errors';
import { PasskeyError, SecurityKeyRejectedError, assertWithPasskey } from '@/lib/passkey';

export interface SignInDeps {
  api: Pick<Api, 'prelogin' | 'opaqueStart' | 'opaqueFinish' | 'twoFactor' | 'accountKeys'>;
  crypto: Pick<CryptoPort, 'masterKey' | 'opaqueLoginStart' | 'opaqueLoginFinish' | 'unlock'>;
  /** The security key as a second step. */
  securityKey: SecurityKeyStepApi;
  /** Asks the person's authenticator: the browser's own by default, a fake in tests. */
  assert?: (options: Record<string, unknown>) => Promise<Record<string, unknown>>;
  session: Session;
  device: () => DeviceDto;
  now?: () => number;
}

export type SignInStatus =
  | { status: 'signed-in'; admin: boolean }
  | { status: 'second-step'; methods: string[] };

export function createSignIn(deps: SignInDeps) {
  const now = deps.now ?? (() => Date.now());
  let email = '';
  let masterKey: Uint8Array | undefined;
  let exportKey: Uint8Array | undefined;
  let wrappedRootKey: Uint8Array | undefined;
  let sealedPrivateKeys: Uint8Array | undefined;
  let challenge: string | undefined;

  function forget(): void {
    wipe(masterKey, exportKey);
    masterKey = exportKey = wrappedRootKey = sealedPrivateKeys = undefined;
    challenge = undefined;
  }

  async function unlock(tokens: TokenResponse): Promise<SignInStatus> {
    deps.session.tokenStore.set(tokensFromResponse(tokens, now()));
    rememberDeviceId(tokens.deviceId);
    deps.session.signedIn({
      email,
      userId: tokens.userId,
      deviceId: tokens.deviceId,
      admin: tokens.admin,
    });
    try {
      if (!masterKey || !exportKey) throw new Error('the sign-in lost its keys');
      // The account's keys come from the server unless the caller made them a moment ago. With the
      // sealed private keys the worker also opens the exchange and signing keys, which spaces,
      // device approval and member confirmations need.
      let wrapped = wrappedRootKey;
      let sealed = sealedPrivateKeys;
      let keyVersion: number | undefined;
      if (!wrapped) {
        const keys = await deps.api.accountKeys();
        wrapped = decodeB64(keys.wrappedRootKey);
        keyVersion = keys.keyVersion;
        if (keys.sealedPrivateKeys) sealed = decodeB64(keys.sealedPrivateKeys);
      }
      await deps.crypto.unlock(tokens.userId, wrapped, masterKey, exportKey, {
        ...(keyVersion !== undefined ? { keyVersion } : {}),
        ...(sealed ? { sealedPrivateKeys: sealed } : {}),
      });
    } catch (error) {
      deps.session.end();
      throw error;
    } finally {
      forget();
    }
    deps.session.unlocked();
    return { status: 'signed-in', admin: tokens.admin };
  }

  /**
   * Runs OPAQUE with a master key already derived. `wrapped` (with `sealed`, the sealed private
   * keys) skips asking the server for the account's keys.
   */
  async function start(
    address: string,
    key: Uint8Array,
    wrapped?: Uint8Array,
    sealed?: Uint8Array,
  ): Promise<SignInStatus> {
    email = address;
    masterKey = key;
    wrappedRootKey = wrapped;
    sealedPrivateKeys = sealed;
    try {
      const first = await deps.crypto.opaqueLoginStart(key);
      const started = await deps.api.opaqueStart({
        email: address,
        request: encodeB64(first.request),
      });
      // A wrong password fails here, in the client, before anything more is sent: OPAQUE's
      // server proof doesn't check out. An unknown email fails the same way.
      const last = await deps.crypto
        .opaqueLoginFinish(first.state, key, decodeB64(started.response))
        .catch(() => {
          throw new CredentialsError();
        });
      exportKey = last.exportKey;
      const result = await deps.api.opaqueFinish({
        email: address,
        loginState: started.loginState,
        finalization: encodeB64(last.finalization),
        device: deps.device(),
      });
      if (result.status === 'signed_in' && result.tokens) return await unlock(result.tokens);
      if (result.status === 'two_factor_required' && result.challenge) {
        challenge = result.challenge;
        return { status: 'second-step', methods: result.methods ?? ['totp'] };
      }
      throw new Error('the server answered the sign-in with something unexpected');
    } catch (error) {
      if (!challenge) forget();
      throw error;
    }
  }

  return {
    /** Password sign-in: the server's KDF settings, the master key, then OPAQUE. */
    async password(address: string, password: string): Promise<SignInStatus> {
      const dto = await deps.api.prelogin(address);
      const key = await deps.crypto.masterKey(password.normalize('NFC'), {
        memoryKib: dto.memoryKib,
        iterations: dto.iterations,
        parallelism: dto.parallelism,
        salt: decodeB64(dto.salt),
      });
      return start(address, key);
    },
    start,
    /** The second step, with the challenge the first one returned. */
    async secondStep(code: string): Promise<SignInStatus> {
      if (!challenge) throw new Error('there is no sign-in waiting for a code');
      try {
        const tokens = await deps.api.twoFactor({ challenge, method: 'totp', code });
        return await unlock(tokens);
      } catch (error) {
        if (!isApiError(error)) forget();
        throw error;
      }
    },
    /**
     * The second step with a security key, when the first step listed `webauthn` among its
     * methods: the browser asks for the key and its answer is traded for tokens. A key that was
     * not touched (`PasskeyError`) or a refusal leaves the challenge, so it can be tried again.
     */
    async securityKey(): Promise<SignInStatus> {
      if (!challenge) throw new Error('there is no sign-in waiting for a key');
      const assert = deps.assert ?? assertWithPasskey;
      try {
        const options = await deps.securityKey.options(challenge);
        const credential = await assert(options);
        const tokens = await deps.securityKey.verify({ challenge, credential });
        return await unlock(tokens);
      } catch (error) {
        // The challenge survives a refusal, a closed prompt or a dropped connection: the key can be
        // tried again. Anything else ends the sign-in.
        if (!isApiError(error) && !(error instanceof PasskeyError) && !(error instanceof NetworkError)) forget();
        if (isApiError(error) && error.status === 401) throw new SecurityKeyRejectedError();
        throw error;
      }
    },
    /** Gives up on a sign-in that stopped at its second step. */
    abandon: forget,
  };
}

export type SignIn = ReturnType<typeof createSignIn>;
