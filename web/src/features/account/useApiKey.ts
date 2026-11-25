import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { createApiKeyApi } from '@/api/apiKey';
import { api } from '@/app/services';
import type { ApiKeyProps } from './ApiKeyCard';
import { useRun } from './useRun';

const keyApi = createApiKeyApi(api);

/** The API key card of Account security: what the server says of the key, and the proved steps that show or replace it. */
export function useApiKey() {
  const queryClient = useQueryClient();
  const info = useQuery({ queryKey: ['security', 'api-key'], queryFn: () => keyApi.show() });
  const { run, pending, error } = useRun();
  const [secret, setSecret] = useState<string | null>(null);
  const [changed, setChanged] = useState<'created' | 'rotated' | null>(null);

  const refresh = () => queryClient.invalidateQueries({ queryKey: ['security', 'api-key'] });

  const props: ApiKeyProps = {
    info: info.isPending ? undefined : (info.data ?? null),
    secret,
    changed,
    busy: pending,
    actions: {
      // Mail may be off or out of reach: then an authenticator code or the recovery code is the
      // proof, so a failed request is not an error on the screen.
      askProof: () =>
        keyApi
          .proofRequest()
          .then(() => true)
          .catch(() => false),
      reveal: async (proof) => {
        const wasSet = info.data?.set ?? false;
        const key = await run(() => keyApi.reveal(proof));
        if (!key) return false;
        setSecret(key.clientSecret);
        setChanged(wasSet ? null : 'created');
        await refresh();
        return true;
      },
      rotate: async (proof) => {
        const key = await run(() => keyApi.rotate(proof));
        if (!key) return false;
        setSecret(key.clientSecret);
        setChanged('rotated');
        await refresh();
        return true;
      },
      hide: () => {
        setSecret(null);
        setChanged(null);
      },
    },
  };
  return { props, error };
}
