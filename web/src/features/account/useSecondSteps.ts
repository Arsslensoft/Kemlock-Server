import { useQuery, useQueryClient } from '@tanstack/react-query';
import { createSecondStepsApi } from '@/api/twoStep';
import { api } from '@/app/services';
import { useT } from '@/i18n';
import { passkeysAvailable } from '@/lib/passkey';
import type { SecondStepsProps } from './SecondStepsCard';
import { useRun } from './useRun';
import { createSecurityKey } from './webauthn-register';

const stepsApi = createSecondStepsApi(api);

/** The second steps beyond an authenticator app and passkeys: what they read and how they change. */
export function useSecondSteps(hasRecoveryCode: boolean | undefined) {
  const t = useT();
  const queryClient = useQueryClient();
  const setup = useQuery({ queryKey: ['security', 'setup'], queryFn: () => stepsApi.setup() });
  const keys = useQuery({
    queryKey: ['security', 'security-keys'],
    queryFn: () => stepsApi.securityKeys().then((r) => r.keys),
    enabled: passkeysAvailable(),
  });
  const { run, pending, error } = useRun();

  // A change refreshes everything a method touches: the list of methods, what was set up, the keys.
  async function change(action: () => Promise<unknown>): Promise<boolean> {
    const done = await run(() => action().then(() => true));
    await Promise.all([
      queryClient.invalidateQueries({ queryKey: ['security', 'setup'] }),
      queryClient.invalidateQueries({ queryKey: ['security', 'security-keys'] }),
      queryClient.invalidateQueries({ queryKey: ['security', 'methods'] }),
    ]);
    return done === true;
  }

  const props: SecondStepsProps = {
    setup: setup.data,
    securityKeys: passkeysAvailable() ? keys.data : undefined,
    securityKeysAvailable: passkeysAvailable(),
    hasRecoveryCode,
    busy: pending,
    actions: {
      addSecurityKey: (name) =>
        change(async () => {
          const options = await stepsApi.securityKeyOptions();
          const credential = await createSecurityKey(options);
          return stepsApi.securityKeyConfirm(name || t('security.webauthn.defaultName'), credential);
        }),
      askProof: () => change(() => stepsApi.proofRequest()),
      removeSecurityKey: (slot, proof) => change(() => stepsApi.securityKeyRemove(slot, proof)),
      emailBegin: (address) => change(() => stepsApi.emailBegin(address)),
      emailConfirm: (address, code) => change(() => stepsApi.emailConfirm(address, code)),
      emailOff: (proof) => change(() => stepsApi.emailOff(proof)),
      yubikeySet: (otps, nfc) => change(() => stepsApi.yubikeySet(otps, nfc)),
      yubikeyOff: (proof) => change(() => stepsApi.yubikeyOff(proof)),
      duoSet: (input) => change(() => stepsApi.duoSet(input)),
      duoOff: (proof) => change(() => stepsApi.duoOff(proof)),
      showRecoveryCode: () => run(() => stepsApi.recoveryCode()),
    },
  };
  return { props, error };
}
