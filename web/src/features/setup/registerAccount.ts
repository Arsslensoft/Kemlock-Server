// Makes an account in the browser: OPAQUE registration, then the key bundle, then one request that
// stores it all. The master password never leaves this function except through the worker.
import type { Api } from '@/api/client';
import type { CryptoPort } from '@/crypto-port';
import { decodeB64, encodeB64, wipe } from '@/lib/b64url';

/** New accounts' Argon2id settings (docs/crypto.md, "Master key"). */
export const NEW_ACCOUNT_KDF = { memoryKib: 65536, iterations: 3, parallelism: 4 } as const;

export interface RegisterDeps {
  api: Pick<Api, 'registerStart' | 'registerFinish'>;
  crypto: Pick<
    CryptoPort,
    'masterKey' | 'opaqueRegisterStart' | 'opaqueRegisterFinish' | 'newAccount'
  >;
  randomBytes?: (length: number) => Uint8Array;
  newId?: () => string;
}

export interface RegisterInput {
  email: string;
  name: string;
  password: string;
  /** The setup grant: present for the first admin, absent for an open sign-up. */
  setupGrant?: string;
}

export interface Registered {
  userId: string;
  admin: boolean;
  /** Handles for the sign-in that follows; the caller overwrites them when done. */
  masterKey: Uint8Array;
  wrappedRootKey: Uint8Array;
  /** The account's private keys under the user key, for the sign-in to open them. */
  sealedPrivateKeys: Uint8Array;
}

export async function registerAccount(
  deps: RegisterDeps,
  input: RegisterInput,
): Promise<Registered> {
  const randomBytes =
    deps.randomBytes ?? ((n: number) => globalThis.crypto.getRandomValues(new Uint8Array(n)));
  const userId = (deps.newId ?? (() => globalThis.crypto.randomUUID()))();
  const salt = randomBytes(16);
  const masterKey = await deps.crypto.masterKey(input.password.normalize('NFC'), {
    ...NEW_ACCOUNT_KDF,
    salt,
  });
  let exportKey: Uint8Array | undefined;
  try {
    const first = await deps.crypto.opaqueRegisterStart(masterKey);
    const started = await deps.api.registerStart({
      email: input.email,
      request: encodeB64(first.request),
      setupGrant: input.setupGrant ?? null,
    });
    const second = await deps.crypto.opaqueRegisterFinish(
      first.state,
      masterKey,
      decodeB64(started.response),
    );
    exportKey = second.exportKey;
    const keys = await deps.crypto.newAccount(userId, masterKey, exportKey);
    const done = await deps.api.registerFinish({
      userId,
      email: input.email,
      name: input.name,
      upload: encodeB64(second.upload),
      kdf: { ...NEW_ACCOUNT_KDF, salt: encodeB64(salt) },
      publicBundle: encodeB64(keys.publicBundle),
      bundleSignature: encodeB64(keys.bundleSignature),
      sealedPrivateKeys: encodeB64(keys.sealedPrivateKeys),
      wrappedRootKey: encodeB64(keys.wrappedRootKey),
      setupGrant: input.setupGrant ?? null,
    });
    return {
      userId: done.userId,
      admin: done.admin,
      masterKey,
      wrappedRootKey: keys.wrappedRootKey,
      sealedPrivateKeys: keys.sealedPrivateKeys,
    };
  } catch (error) {
    wipe(masterKey);
    throw error;
  } finally {
    wipe(exportKey);
  }
}
