import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { createRecoveryKitApi } from '@/api/recoveryKit';
import { api } from '@/app/services';
import { vaultCrypto } from '@/crypto-port';
import type { RecoveryKitProps } from './RecoveryKitCard';
import { type PendingKit, confirmsPiece, keepKit, makeKit } from './recoveryKitModel';
import { useRun } from './useRun';

const kitApi = createRecoveryKitApi(api);

/** The Recovery Kit row of Account security: what the server holds, and the steps that change it. */
export function useRecoveryKit() {
  const queryClient = useQueryClient();
  const kit = useQuery({ queryKey: ['security', 'recovery-kit'], queryFn: () => kitApi.show() });
  const { run, pending, error, clearError } = useRun();
  const [making, setMaking] = useState<PendingKit | null>(null);
  const [mismatch, setMismatch] = useState(false);

  const refresh = () => queryClient.invalidateQueries({ queryKey: ['security', 'recovery-kit'] });

  const props: RecoveryKitProps = {
    kit: kit.isPending ? undefined : (kit.data ?? null),
    making: making ? { pieces: making.pieces, mismatch } : null,
    busy: pending,
    actions: {
      start: async () => {
        setMismatch(false);
        const made = await run(() => makeKit(vaultCrypto));
        if (made) setMaking(made);
      },
      cancel: () => {
        setMaking(null);
        setMismatch(false);
        clearError();
      },
      askProof: async () => (await run(() => kitApi.proofRequest().then(() => true))) === true,
      // The confirmation is the person typing a piece back; only then does the server get the kit.
      confirm: async (typed, proof) => {
        if (!making) return false;
        if (!confirmsPiece(making, typed)) {
          setMismatch(true);
          return false;
        }
        setMismatch(false);
        const kept = await run(() => keepKit(kitApi, making, proof));
        await refresh();
        if (kept) setMaking(null);
        return kept !== undefined;
      },
      remove: async (proof) => {
        const done = await run(() => kitApi.remove(proof).then(() => true));
        await refresh();
        return done === true;
      },
    },
  };
  return { props, error };
}
