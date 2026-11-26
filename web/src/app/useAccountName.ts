// The avatar names the person. Sign-in answers with the address only, so once the vault is open the
// shell reads the profile (the query the Profile page shares) and hands the session its name.
import { useQuery } from '@tanstack/react-query';
import { useEffect } from 'react';
import { api, session } from './services';
import type { SessionState } from './session';

export const PROFILE_KEY = ['profile'] as const;

export function useAccountName(state: SessionState): void {
  // Only while the session has no name: a rename on Profile tells the session itself.
  const missing = state.status === 'unlocked' && !state.name;
  const query = useQuery({
    queryKey: PROFILE_KEY,
    // Loaded on demand: the profile API stays out of the sign-in screen's scripts.
    queryFn: async () => (await import('@/api/profile')).createProfileApi(api).get(),
    enabled: missing,
  });
  const name = query.data?.name?.trim() || null;
  useEffect(() => {
    if (missing && name) session.renamed(name);
  }, [missing, name]);
}
