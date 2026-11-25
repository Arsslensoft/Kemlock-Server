// Which step-up ways the signed-in admin has: an authenticator app that is on, and passkeys. The
// step-up dialog (reauth.tsx) offers only these, so nobody is asked for a code they never set up.
import { createPasskeysApi } from '@/api/passkeys';
import { createTwoStepApi, enabledMethods } from '@/api/twoStep';
import { api } from '@/app/services';

export interface StepUpMethods {
  /** The authenticator app is set up and on: `POST /admin/v1/step-up/totp` can work. */
  totp: boolean;
  /** At least one passkey: `step-up/passkey/*` can work (security keys are not taken there). */
  passkey: boolean;
}

const twoStepApi = createTwoStepApi(api);
const passkeysApi = createPasskeysApi(api);

export async function loadStepUpMethods(): Promise<StepUpMethods> {
  const [list, passkeys] = await Promise.all([twoStepApi.list(), passkeysApi.list()]);
  return { totp: enabledMethods(list).includes('totp'), passkey: passkeys.length > 0 };
}
