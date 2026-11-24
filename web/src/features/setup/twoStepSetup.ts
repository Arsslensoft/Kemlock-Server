// What the two-step setup screen does when a button is pressed. No React in here, so it is tested
// with fakes.
import type { RegisterPasskeyDeps, RegisterSecurityKeyDeps } from '@/lib/webauthn';
import { registerPasskey, registerSecurityKey } from '@/lib/webauthn';
import { setupMemory } from './memory';

export interface TwoStepSetupDeps {
  passkeys: RegisterPasskeyDeps;
  keys: RegisterSecurityKeyDeps;
  totpConfirm: (code: string) => Promise<unknown>;
  /** The name a new passkey or key is saved under. */
  name: string;
}

/** The security key is the admin's second step: it is on as a two-factor method. */
export async function confirmSecurityKey(deps: TwoStepSetupDeps): Promise<void> {
  await registerSecurityKey(deps.keys, deps.name);
  setupMemory.set({ twoStep: 'key' });
}

/**
 * The authenticator app's code is the second step. A passkey ticked on the first screen is made
 * first, once; if it fails (cancelled, no support) the code is still confirmed, because the admin
 * must not be stuck without a second step, and the failure comes back as `passkeyFailed`.
 */
export async function confirmAuthenticatorApp(
  deps: TwoStepSetupDeps,
  code: string,
): Promise<{ passkeyFailed: boolean }> {
  let passkeyFailed = false;
  const memory = setupMemory.get();
  if (memory.wantPasskey && !memory.passkeyMade) {
    try {
      await registerPasskey(deps.passkeys, deps.name);
      setupMemory.set({ passkeyMade: true });
    } catch {
      // A prompt closed, no support or a server refusal: a warning, not a stop. The app code below
      // is what setup needs.
      passkeyFailed = true;
    }
  }
  await deps.totpConfirm(code);
  setupMemory.set({ twoStep: 'totp' });
  return { passkeyFailed };
}
