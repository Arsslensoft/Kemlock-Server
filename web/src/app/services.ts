// The app's singletons: the API client, the session, and the query cache.
import { QueryClient, queryOptions } from '@tanstack/react-query';
import { createApi } from '@/api/client';
import { ApiError, NetworkError } from '@/api/errors';
import { vaultCrypto } from '@/crypto-port';
import { createSession } from './session';

export const session = createSession();

export const api = createApi({
  origin: window.location.origin,
  tokens: session.tokenStore,
  dpop: (htm, htu, nonce, accessToken) => vaultCrypto.dpopProof(htm, htu, nonce, accessToken),
  onSessionEnded: () => {
    session.end();
    void vaultCrypto.lock();
  },
});

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      // Ciphertext and settings change rarely; refetching on focus is enough.
      staleTime: 10_000,
      retry: (count, error) =>
        // A 4xx is an answer. Only the network and a 5xx are worth another try.
        (error instanceof NetworkError || (error instanceof ApiError && error.status >= 500)) &&
        count < 2,
    },
  },
});

export const configQuery = queryOptions({
  queryKey: ['config'],
  queryFn: () => api.config(),
  staleTime: 5_000,
});

/** `https://vault.example.org/` -> `vault.example.org`. */
export function hostOf(domain: string | undefined): string {
  if (!domain) return window.location.host;
  try {
    return new URL(domain).host;
  } catch {
    return domain;
  }
}
