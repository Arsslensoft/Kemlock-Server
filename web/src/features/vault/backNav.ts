import { useCanGoBack, useNavigate, useRouter } from '@tanstack/react-router';

/**
 * Where "back to the list" goes: one step back in the history when there is one, so the list keeps its
 * search, page and kind, and an item opened from Trash returns to Trash. Otherwise the plain vault.
 */
export function useBackToList(): () => void {
  const canGoBack = useCanGoBack();
  const router = useRouter();
  const navigate = useNavigate();
  return () => {
    if (canGoBack) router.history.back();
    else void navigate({ to: '/vault' });
  };
}
