import { createEraseAccountApi } from '@/api/eraseAccount';
import { signOut } from '@/app/actions';
import { api } from '@/app/services';
import { vaultCrypto } from '@/crypto-port';
import type { DeleteAccountProps } from './DeleteAccountCard';
import { deleteAccount } from './deleteAccountModel';
import { useRun } from './useRun';

const eraseApi = createEraseAccountApi(api);

/**
 * The delete-account card of Account security. `secondStep` is whether a second step is on, which
 * asks a fresh proof beside the password. `onGone` runs once the server has erased the account and
 * the session is over: the page sends the person to the sign-in screen.
 */
export function useDeleteAccount(email: string, secondStep: boolean, onGone: () => void) {
  const { run, pending, error } = useRun();

  const props: DeleteAccountProps = {
    email,
    secondStep,
    busy: pending,
    actions: {
      askProof: () =>
        eraseApi
          .proofRequest()
          .then(() => true)
          .catch(() => false),
      erase: async (typed, password, proof) => {
        const done = await run(() =>
          deleteAccount(
            { api: { erase: eraseApi.erase, prelogin: api.prelogin, opaqueStart: api.opaqueStart }, crypto: vaultCrypto, signOut: () => signOut({ server: false }) },
            { email, typed, password, proof, secondStep },
          ),
        );
        if (done) onGone();
        return done === true;
      },
    },
  };
  return { props, error };
}
