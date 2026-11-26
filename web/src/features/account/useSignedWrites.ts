import { useQuery, useQueryClient } from '@tanstack/react-query';
import { createEraseAccountApi } from '@/api/eraseAccount';
import { createOwnerSigningApi } from '@/api/ownerSigning';
import { api, session } from '@/app/services';
import { useSessionState } from '@/app/session';
import { vaultCrypto } from '@/crypto-port';
import type { SignedWritesProps } from './SignedWritesCard';
import { clearSignedWrites, ownVault, requireSignedWrites } from './signedWritesModel';
import { useRun } from './useRun';

const owners = createOwnerSigningApi(api);
const eraseApi = createEraseAccountApi(api);

/** The signed-writes card of Account security. `secondStep` is whether a second step is on. */
export function useSignedWrites(email: string, secondStep: boolean) {
  const queryClient = useQueryClient();
  const userId = useSessionState(session).userId;
  const state = useQuery({
    queryKey: ['security', 'signed-writes', userId],
    queryFn: () => owners.required(ownVault(userId ?? '')),
    enabled: userId != null,
  });
  const { run, pending, error } = useRun();
  const refresh = () => queryClient.invalidateQueries({ queryKey: ['security', 'signed-writes'] });
  const wiring = {
    api: { require: owners.require, clear: owners.clear, prelogin: api.prelogin, opaqueStart: api.opaqueStart },
    crypto: vaultCrypto,
  };

  const props: SignedWritesProps = {
    required: state.isPending ? undefined : (state.data ?? false),
    secondStep,
    busy: pending,
    actions: {
      turnOn: async () => {
        if (userId == null) return false;
        const done = await run(() => requireSignedWrites(wiring, userId).then(() => true));
        await refresh();
        return done === true;
      },
      askProof: () =>
        eraseApi
          .proofRequest()
          .then(() => true)
          .catch(() => false),
      turnOff: async (password, proof) => {
        if (userId == null) return false;
        const done = await run(() => clearSignedWrites(wiring, { userId, email, password, proof, secondStep }));
        await refresh();
        return done === true;
      },
    },
  };
  return { props, error };
}
