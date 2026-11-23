// Where the federation screens send you. The views take an `onNavigate` callback and never touch
// the router, so tests need no router; the default exports pass `useAdminNav()`.
import { useNavigate } from '@tanstack/react-router';
import { useCallback } from 'react';

export type AdminNav =
  | { to: 'federation' }
  | { to: 'pair' }
  | { to: 'events' }
  | { to: 'peer'; peerId?: string }
  | { to: 'mismatch'; peerId: string };

export function useAdminNav(): (nav: AdminNav) => void {
  const navigate = useNavigate();
  return useCallback(
    (nav) => {
      switch (nav.to) {
        case 'federation':
          void navigate({ to: '/admin/federation' });
          break;
        case 'pair':
          void navigate({ to: '/admin/federation/pair' });
          break;
        case 'events':
          void navigate({ to: '/admin/events' });
          break;
        case 'peer':
          // The security page names its peer in the address; the route declares no search of its own.
          void navigate({
            to: '/admin/federation/security',
            search: (nav.peerId ? { peer: nav.peerId } : {}) as never,
          });
          break;
        case 'mismatch':
          void navigate({ to: '/admin/federation/mismatch/$peerId', params: { peerId: nav.peerId } });
          break;
      }
    },
    [navigate],
  );
}
