import type { useRouter } from '@tanstack/react-router';
import { configQuery, queryClient } from '@/app/services';
import { safeNext } from '@/lib/safe-next';
import type { SignInStatus } from './signIn';

/** Where a finished sign-in goes: the setup's unfinished step, the page asked for, or the vault. */
export async function afterSignIn(
  router: ReturnType<typeof useRouter>,
  status: Extract<SignInStatus, { status: 'signed-in' }>,
  next: string | undefined,
): Promise<void> {
  const config = await queryClient.fetchQuery({ ...configQuery, staleTime: 0 });
  if (status.admin && config.setup === 'pending') {
    await router.navigate({ to: '/setup/two-step' });
    return;
  }
  const target = safeNext(next);
  if (target) router.history.push(target);
  else await router.navigate({ to: '/vault' });
}
