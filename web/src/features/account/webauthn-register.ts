// A security key as a second step: the server's creation options go to `credentials.create` and
// the attestation goes back as JSON. Unlike a passkey it asks for no PRF output (a key that
// signs a second step does not open the vault), and it accepts a roaming authenticator.
import { PasskeyError, decodeCreationOptions, encodeNewCredential, passkeysAvailable } from '@/lib/passkey';

/** Asks the person to touch a security key, and returns the credential as JSON. */
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
