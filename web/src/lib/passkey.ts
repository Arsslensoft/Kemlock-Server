// A WebAuthn assertion for the admin step-up (`POST /admin/v1/step-up/passkey/*`): the server sends
// `PublicKeyCredentialRequestOptions` as JSON, with every binary value base64url, and takes the
// browser's answer back as JSON in the same form. The browser's `navigator.credentials.get` wants
// ArrayBuffers, so the options are decoded on the way in and the credential encoded on the way out.
import { decodeB64, encodeB64 } from './b64url';

export class PasskeyError extends Error {
  readonly reason: 'unavailable' | 'cancelled';

  constructor(reason: 'unavailable' | 'cancelled') {
    super(`passkey: ${reason}`);
    this.name = 'PasskeyError';
    this.reason = reason;
  }
}

/** Whether this browser can ask for a passkey at all. */
export function passkeysAvailable(): boolean {
  return (
    typeof navigator !== 'undefined' &&
    typeof navigator.credentials?.get === 'function' &&
    typeof PublicKeyCredential !== 'undefined'
  );
}

function bytes(text: unknown): Uint8Array<ArrayBuffer> {
  if (typeof text !== 'string') throw new PasskeyError('unavailable');
  return Uint8Array.from(decodeB64(text));
}

/** The options as `credentials.get` takes them: `challenge` and each credential id as bytes. */
export function decodeRequestOptions(options: Record<string, unknown>): PublicKeyCredentialRequestOptions {
  // The server may wrap the options as `{ publicKey: {...} }`, as webauthn-rs does.
  const inner = (
    typeof options['publicKey'] === 'object' && options['publicKey'] !== null ? options['publicKey'] : options
  ) as Record<string, unknown>;
  const allowed = Array.isArray(inner['allowCredentials']) ? inner['allowCredentials'] : [];
  return {
    ...(inner as unknown as PublicKeyCredentialRequestOptions),
    challenge: bytes(inner['challenge']),
    allowCredentials: allowed.map((entry: Record<string, unknown>) => ({
      ...(entry as unknown as PublicKeyCredentialDescriptor),
      id: bytes(entry['id']),
    })),
  };
}

/** The credential as JSON, every buffer base64url (what `PublicKeyCredential.toJSON()` gives). */
export function encodeCredential(credential: PublicKeyCredential): Record<string, unknown> {
  const response = credential.response as AuthenticatorAssertionResponse;
  const userHandle = response.userHandle;
  return {
    id: credential.id,
    rawId: encodeB64(new Uint8Array(credential.rawId)),
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment ?? undefined,
    response: {
      authenticatorData: encodeB64(new Uint8Array(response.authenticatorData)),
      clientDataJSON: encodeB64(new Uint8Array(response.clientDataJSON)),
      signature: encodeB64(new Uint8Array(response.signature)),
      ...(userHandle ? { userHandle: encodeB64(new Uint8Array(userHandle)) } : {}),
    },
    clientExtensionResults: credential.getClientExtensionResults(),
  };
}

/** `first` of the PRF extension: `SHA-256("kemlock/v1/prf-salt")` (docs/crypto.md). */
export async function prfSalt(): Promise<Uint8Array<ArrayBuffer>> {
  const text = new TextEncoder().encode('kemlock/v1/prf-salt');
  return new Uint8Array(await crypto.subtle.digest('SHA-256', text));
}

/** The request options with the PRF extension asked for. */
async function withPrf(options: PublicKeyCredentialRequestOptions): Promise<PublicKeyCredentialRequestOptions> {
  const first = await prfSalt();
  return {
    ...options,
    extensions: { ...options.extensions, prf: { eval: { first } } } as AuthenticationExtensionsClientInputs,
  };
}

/** The PRF output of an answer, when the authenticator evaluated it. */
function prfOutputOf(credential: PublicKeyCredential): Uint8Array<ArrayBuffer> | undefined {
  const results = credential.getClientExtensionResults() as { prf?: { results?: { first?: ArrayBuffer } } };
  const first = results.prf?.results?.first;
  return first ? new Uint8Array(first) : undefined;
}

async function getCredential(
  options: Record<string, unknown>,
  prf: boolean,
): Promise<PublicKeyCredential> {
  if (!passkeysAvailable()) throw new PasskeyError('unavailable');
  let credential: Credential | null;
  try {
    const decoded = decodeRequestOptions(options);
    credential = await navigator.credentials.get({ publicKey: prf ? await withPrf(decoded) : decoded });
  } catch (error) {
    // The person closed the prompt, or no authenticator answered in time.
    if (error instanceof DOMException && (error.name === 'NotAllowedError' || error.name === 'AbortError')) {
      throw new PasskeyError('cancelled');
    }
    throw error;
  }
  if (!credential) throw new PasskeyError('cancelled');
  return credential as PublicKeyCredential;
}

/** Asks the person's authenticator to sign the server's challenge. */
export async function assertWithPasskey(options: Record<string, unknown>): Promise<Record<string, unknown>> {
  return encodeCredential(await getCredential(options, false));
}

/** A sign-in answer: the credential as JSON, its raw id, and the PRF output when there is one. */
export interface PasskeyAnswer {
  credential: Record<string, unknown>;
  credentialId: Uint8Array;
  prfOutput?: Uint8Array;
}

/** Like `assertWithPasskey`, asking for the PRF output too, which opens the vault. */
export async function assertWithPasskeyAndPrf(options: Record<string, unknown>): Promise<PasskeyAnswer> {
  const credential = await getCredential(options, true);
  const prfOutput = prfOutputOf(credential);
  return {
    credential: encodeCredential(credential),
    credentialId: new Uint8Array(credential.rawId),
    ...(prfOutput ? { prfOutput } : {}),
  };
}

/** The options as `credentials.create` takes them: `challenge`, `user.id` and each excluded id as bytes. */
export function decodeCreationOptions(options: Record<string, unknown>): PublicKeyCredentialCreationOptions {
  const inner = (
    typeof options['publicKey'] === 'object' && options['publicKey'] !== null ? options['publicKey'] : options
  ) as Record<string, unknown>;
  const user = inner['user'] as Record<string, unknown> | undefined;
  if (!user) throw new PasskeyError('unavailable');
  const excluded = Array.isArray(inner['excludeCredentials']) ? inner['excludeCredentials'] : [];
  return {
    ...(inner as unknown as PublicKeyCredentialCreationOptions),
    challenge: bytes(inner['challenge']),
    user: { ...(user as unknown as PublicKeyCredentialUserEntity), id: bytes(user['id']) },
    excludeCredentials: excluded.map((entry: Record<string, unknown>) => ({
      ...(entry as unknown as PublicKeyCredentialDescriptor),
      id: bytes(entry['id']),
    })),
  };
}

/** The new credential as JSON, every buffer base64url (`PublicKeyCredential.toJSON()`). */
export function encodeNewCredential(credential: PublicKeyCredential): Record<string, unknown> {
  if (typeof credential.toJSON === 'function') return credential.toJSON() as unknown as Record<string, unknown>;
  const response = credential.response as AuthenticatorAttestationResponse;
  return {
    id: credential.id,
    rawId: encodeB64(new Uint8Array(credential.rawId)),
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment ?? undefined,
    response: {
      attestationObject: encodeB64(new Uint8Array(response.attestationObject)),
      clientDataJSON: encodeB64(new Uint8Array(response.clientDataJSON)),
      transports: typeof response.getTransports === 'function' ? response.getTransports() : [],
    },
    clientExtensionResults: credential.getClientExtensionResults(),
  };
}

/** A passkey just made: the credential as JSON, its raw id, and the PRF output when it has one. */
export interface NewPasskey {
  credential: Record<string, unknown>;
  credentialId: Uint8Array;
  /** Present when the authenticator supports PRF: wrap the root key under it. */
  prfOutput?: Uint8Array;
}

/**
 * Asks the person's authenticator to make a passkey from the server's creation options, asking
 * for the PRF extension. An authenticator that does not evaluate it at creation but supports it
 * is asked once more for the output, with a challenge of our own that goes nowhere.
 */
export async function createPasskey(options: Record<string, unknown>): Promise<NewPasskey> {
  if (!passkeysAvailable() || typeof navigator.credentials.create !== 'function') {
    throw new PasskeyError('unavailable');
  }
  let credential: Credential | null;
  try {
    const decoded = decodeCreationOptions(options);
    const first = await prfSalt();
    credential = await navigator.credentials.create({
      publicKey: {
        ...decoded,
        extensions: { ...decoded.extensions, prf: { eval: { first } } } as AuthenticationExtensionsClientInputs,
      },
    });
  } catch (error) {
    if (error instanceof DOMException && (error.name === 'NotAllowedError' || error.name === 'AbortError')) {
      throw new PasskeyError('cancelled');
    }
    throw error;
  }
  if (!credential) throw new PasskeyError('cancelled');
  const made = credential as PublicKeyCredential;
  const credentialId = new Uint8Array(made.rawId);
  let prfOutput = prfOutputOf(made);
  const enabled = (made.getClientExtensionResults() as { prf?: { enabled?: boolean } }).prf?.enabled;
  if (!prfOutput && enabled) {
    try {
      const answer = await getCredential(
        {
          challenge: encodeB64(crypto.getRandomValues(new Uint8Array(32))),
          rpId: location.hostname,
          userVerification: 'required',
          allowCredentials: [{ type: 'public-key', id: encodeB64(credentialId) }],
        },
        true,
      );
      prfOutput = prfOutputOf(answer);
    } catch {
      // The passkey is still made; it just won't open the vault.
    }
  }
  return {
    credential: encodeNewCredential(made),
    credentialId,
    ...(prfOutput ? { prfOutput } : {}),
  };
}
