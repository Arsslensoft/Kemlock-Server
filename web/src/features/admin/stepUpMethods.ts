// Which step-up ways the signed-in admin has: an authenticator app that is on, passkeys and security
// keys. The step-up dialog (reauth.tsx) offers only these, so nobody is asked for a code they never set up.
import { createPasskeysApi } from '@/api/passkeys';
import { createTwoStepApi, enabledMethods } from '@/api/twoStep';
import { api } from '@/app/services';

export interface StepUpMethods {
  /** The authenticator app is set up and on: `POST /admin/v1/step-up/totp` can work. */
  totp: boolean;
  /** At least one passkey: `step-up/passkey/*` can work. */
  passkey: boolean;
  /** Security keys are on as a second step: `step-up/passkey/*` takes them too. */
  securityKey?: boolean;
}

const twoStepApi = createTwoStepApi(api);
const passkeysApi = createPasskeysApi(api);

export async function loadStepUpMethods(): Promise<StepUpMethods> {
  const [list, passkeys] = await Promise.all([twoStepApi.list(), passkeysApi.list()]);
  const on = enabledMethods(list);
  return { totp: on.includes('totp'), passkey: passkeys.length > 0, securityKey: on.includes('webauthn') };
}
