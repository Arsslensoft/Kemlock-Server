import { useQuery } from '@tanstack/react-query';
import { createPasskeysApi } from '@/api/passkeys';
import { createSecondStepsApi } from '@/api/twoStep';
import { api } from '@/app/services';
import { passkeysAvailable } from '@/lib/passkey';
import { proveWithKey } from '@/lib/webauthn';
import type { KeyProof } from './ProofInput';
import type { useRun } from './useRun';

const stepsApi = createSecondStepsApi(api);
const passkeysApi = createPasskeysApi(api);

/**
 * The way to answer a fresh proof with a security key or passkey, or undefined when this browser
 * can not or the account has none: the screens then offer the code only. A failure (a cancelled
 * touch, a refused answer) lands in `run`'s error, and the person may try again or type a code.
 */
export function useKeyProof(run: ReturnType<typeof useRun>['run']): KeyProof | undefined {
  const keys = useQuery({
    queryKey: ['security', 'security-keys'],
    queryFn: () => stepsApi.securityKeys().then((r) => r.keys),
    enabled: passkeysAvailable(),
  });
  const passkeys = useQuery({
    queryKey: ['security', 'passkeys'],
    queryFn: () => passkeysApi.list(),
    enabled: passkeysAvailable(),
  });
  const has = (keys.data?.length ?? 0) > 0 || (passkeys.data?.length ?? 0) > 0;
  if (!passkeysAvailable() || !has) return undefined;
  return () => run(() => proveWithKey({ options: stepsApi.proofKeyOptions }));
}
