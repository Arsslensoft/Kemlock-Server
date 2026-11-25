// What the two-step setup screen does when a button is pressed. No React in here, so it is tested
// with fakes.
import type { RegisterPasskeyDeps, RegisterSecurityKeyDeps } from '@/lib/webauthn';
import { registerPasskey, registerSecurityKey } from '@/lib/webauthn';
import { setupMemory } from './memory';

export interface TwoStepSetupDeps {
  passkeys: RegisterPasskeyDeps;
  keys: RegisterSecurityKeyDeps;
  totpConfirm: (code: string) => Promise<unknown>;
  /** The name a new passkey is saved under. */
  name: string;
  /** The name a new security key is saved under; `name` when absent. */
  keyName?: string;
}

/**
 * The passkey ticked on the first screen, made once. A failure (cancelled, no support, a server
 * refusal) is a warning, not a stop: the second step is what setup needs.
 */
async function makeTickedPasskey(deps: TwoStepSetupDeps): Promise<{ passkeyFailed: boolean }> {
  const memory = setupMemory.get();
  if (!memory.wantPasskey || memory.passkeyMade) return { passkeyFailed: false };
  try {
    await registerPasskey(deps.passkeys, deps.name);
    setupMemory.set({ passkeyMade: true });
    return { passkeyFailed: false };
  } catch {
    return { passkeyFailed: true };
  }
}

/**
 * The security key is the admin's second step: it is on as a two-factor method. A passkey ticked
 * on the first screen is made after it, so the key, which setup needs, is asked for first.
 */
export async function confirmSecurityKey(deps: TwoStepSetupDeps): Promise<{ passkeyFailed: boolean }> {
  if (setupMemory.get().twoStep !== 'key') {
    await registerSecurityKey(deps.keys, deps.keyName ?? deps.name);
    setupMemory.set({ twoStep: 'key' });
  }
  return makeTickedPasskey(deps);
}

/**
 * The authenticator app's code is the second step. A passkey ticked on the first screen is made
 * first, once; if it fails the code is still confirmed, because the admin must not be stuck
 * without a second step, and the failure comes back as `passkeyFailed`.
 */
export async function confirmAuthenticatorApp(
  deps: TwoStepSetupDeps,
  code: string,
): Promise<{ passkeyFailed: boolean }> {
  const { passkeyFailed } = await makeTickedPasskey(deps);
  await deps.totpConfirm(code);
  setupMemory.set({ twoStep: 'totp' });
  return { passkeyFailed };
}
