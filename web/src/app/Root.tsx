// What `main.tsx` renders: the router, except for a Send link. A Send link is
// `/#/send/<accessId>/<key>` (docs/crypto.md, "Sends"), with its key in the fragment; the router
// works on the path and would send `/` to the sign-in, so the recipient's page is chosen here,
// from the fragment, before any route runs. It needs no account.
import { RouterProvider } from '@tanstack/react-router';
import { Suspense, lazy, useSyncExternalStore } from 'react';
import { isSendHash, parseSendLink } from '@/features/send/recipient';
import type { createAppRouter } from './router';

const SendAccess = lazy(() => import('@/features/send/SendAccess'));

function subscribe(onChange: () => void): () => void {
  window.addEventListener('hashchange', onChange);
  return () => window.removeEventListener('hashchange', onChange);
}

const currentHash = () => window.location.hash;

export function Root({ router }: { router: ReturnType<typeof createAppRouter> }) {
  const hash = useSyncExternalStore(subscribe, currentHash, () => '');
  if (isSendHash(hash)) {
    return (
      <Suspense fallback={null}>
        <SendAccess link={parseSendLink(hash)} />
      </Suspense>
    );
  }
  return <RouterProvider router={router} />;
}
