import { QueryClientProvider } from '@tanstack/react-query';
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { Root } from '@/app/Root';
import { keepRootSealed, restoreSession } from '@/app/persistence';
import { hashLinkToPath } from '@/app/hashLinks';
import { createAppRouter } from '@/app/router';
import { forgetEndedSession, lockVault, signOut } from '@/app/actions';
import { startAutoLock } from '@/app/autoLock';
import { startOtherSessionsCleanup } from '@/app/otherSessionsCleanup';
import { createDevicesApi } from '@/api/devices';
import { getDeviceId } from '@/lib/device';
import { createPoliciesApi } from '@/api/policies';
import { hasUnsavedItemForm } from '@/features/vault/forms/unsaved';
import { sessionEndedTarget } from '@/app/sessionEnded';
import { api, onSessionEndedPage, queryClient, session } from '@/app/services';
import { claimTabKey, keepTabKeyAlive, purgeClosedTabKeys } from '@/app/tabKey';
import { vaultCrypto } from '@/crypto-port';
import { I18nProvider } from '@/i18n';
import { installImportWorker } from '@/import/install';
import './styles/index.css';

// First of all: a closed tab's reload key must not outlive it, so every load of the origin deletes
// the keys of tabs that have gone quiet before anything can use one (see src/app/tabKey.ts).
const purged = purgeClosedTabKeys();

// A person's own choice of theme wins over the system's. Nothing here is a secret.
try {
  const theme = localStorage.getItem('kemlock.theme');
  if (theme === 'light' || theme === 'dark') document.documentElement.dataset['theme'] = theme;
} catch {
  // Storage is blocked: follow the system.
}

// Reading and writing import and export files happens in a worker of its own.
installImportWorker();

// The links Bitwarden's mails carry keep their route in the hash; the router reads paths.
const fromHash = hashLinkToPath(window.location);
if (fromHash) window.history.replaceState(null, '', fromHash);

const router = createAppRouter({ queryClient, session });
const root = document.getElementById('root');
if (!root) throw new Error('index.html has no #root');

const persistence = { session, api, crypto: vaultCrypto, claimTab: claimTabKey };
keepRootSealed(persistence);
// A reload keeps the person signed in and the vault open. The route guards read the session
// synchronously, so the router waits for this (a spinner shows meanwhile, and a server that does not
// answer is given up on after a few seconds); on any failure the vault is just shut.
// A purge that did not finish (IndexedDB hung) leaves a closed tab's key possibly in place, so nothing is
// restored: the person signs in. The page does not wait on it for ever.
const restored = purged
  .then((finished) => (finished ? restoreSession(persistence) : session.end()))
  .catch(() => undefined);

// Only once the restore has settled does this page say its tab is open: before that the tab id in
// the storage may be a closed tab's, which must not look alive.
void restored.then(() => keepTabKeyAlive(session));

// A browser that used an earlier version has its device's other sessions ended once, so tokens an old
// closed tab still holds stop working. This session, the device and its key copy stay.
void restored.then(() =>
  startOtherSessionsCleanup({
    session,
    devices: createDevicesApi(api),
    usedBefore: getDeviceId() !== null,
  }),
);

// An open vault shuts itself after a while idle or out of sight, sooner if a space's policy says so.
void restored.then(() =>
  startAutoLock({
    session,
    policies: createPoliciesApi(api),
    // A form with unsaved changes is not thrown away because the tab was in the background.
    holdHidden: hasUnsavedItemForm,
    expire: (action) => {
      if (action === 'logOut') {
        void signOut().then(() => router.navigate({ to: '/sign-in' }));
        return;
      }
      // The unlock screen brings the person back to the page they were on.
      const next = router.state.location.href;
      void lockVault().then(() => router.navigate({ to: '/unlock', search: { next } }));
    },
  }),
);

// The server refusing the refresh token ends the session while a page is open: forget what that
// page decrypted and go to the sign-in, keeping the page as `next`. Not before the router is up.
void restored.then(() =>
  onSessionEndedPage(() => {
    forgetEndedSession();
    const { location } = router.state;
    const target = sessionEndedTarget(location);
    if (target) void router.navigate({ ...target, replace: true });
  }),
);

createRoot(root).render(
  <StrictMode>
    <I18nProvider>
      <QueryClientProvider client={queryClient}>
        <Root router={router} restored={restored} />
      </QueryClientProvider>
    </I18nProvider>
  </StrictMode>,
);
