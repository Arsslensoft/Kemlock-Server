import { createEraseAccountApi } from '@/api/eraseAccount';
import { signOut } from '@/app/actions';
import { api } from '@/app/services';
import type { DeleteAccountProps } from './DeleteAccountCard';
import { deleteAccount } from './deleteAccountModel';
import { useRun } from './useRun';

const eraseApi = createEraseAccountApi(api);

/**
 * The delete-account card of Account security. `onGone` runs once the server has erased the account
 * and the session is over: the page sends the person to the sign-in screen.
 */
export function useDeleteAccount(email: string, onGone: () => void) {
  const { run, pending, error } = useRun();

  const props: DeleteAccountProps = {
    email,
    busy: pending,
    actions: {
      askProof: () =>
        eraseApi
          .proofRequest()
          .then(() => true)
          .catch(() => false),
      erase: async (typed, proof) => {
        const done = await run(() => deleteAccount({ api: eraseApi, signOut }, { email, typed, proof }));
        if (done) onGone();
        return done === true;
      },
    },
  };
  return { props, error };
}
