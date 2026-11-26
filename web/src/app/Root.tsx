// What `main.tsx` renders: the router, except for a Send link. A Send link is
// `/#/send/<accessId>/<key>` (docs/crypto.md, "Sends"), with its key in the fragment; the router
// works on the path and would send `/` to the sign-in, so the recipient's page is chosen here,
// from the fragment, before any route runs. It needs no account. The fragment is taken out of the
// address as soon as it is read and the link is held in memory (sendLink.ts), so the key does not
// stay in the address bar or the history.
import { RouterProvider } from '@tanstack/react-router';
import { Suspense, lazy, use, useSyncExternalStore } from 'react';
import type { createAppRouter } from './router';
import { absorbSendLinkFromAddress, heldSendLink, subscribeSendLink } from './sendLink';
import { PendingScreen } from './states';

const SendAccess = lazy(() => import('@/features/send/SendAccess'));

// Before anything renders: the key is out of the address bar from the first moment.
absorbSendLinkFromAddress();

/** Mounts the router once the tab's session is back, which the route guards read synchronously. */
function Routed({ router, restored }: { router: AppRouter; restored: Promise<unknown> }) {
  use(restored);
  return <RouterProvider router={router} />;
}

type AppRouter = ReturnType<typeof createAppRouter>;

/**
 * `restored` settles when the session of a reloaded tab is back (or has failed to come back, which
 * is a shut vault). A Send link does not wait for it: that page needs no account.
 */
export function Root({ router, restored }: { router: AppRouter; restored: Promise<unknown> }) {
  const held = useSyncExternalStore(subscribeSendLink, heldSendLink, () => undefined);
  if (held) {
    return (
      <Suspense fallback={null}>
        <SendAccess link={held.link} />
      </Suspense>
    );
  }
  return (
    <Suspense fallback={<PendingScreen />}>
      <Routed router={router} restored={restored} />
    </Suspense>
  );
}
