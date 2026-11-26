import { QueryClientProvider } from '@tanstack/react-query';
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { Root } from '@/app/Root';
import { keepRootSealed, restoreSession } from '@/app/persistence';
import { hashLinkToPath } from '@/app/hashLinks';
import { createAppRouter } from '@/app/router';
import { forgetEndedSession } from '@/app/actions';
import { sessionEndedTarget } from '@/app/sessionEnded';
import { api, onSessionEndedPage, queryClient, session } from '@/app/services';
import { vaultCrypto } from '@/crypto-port';
import { I18nProvider } from '@/i18n';
import { installImportWorker } from '@/import/install';
import './styles/index.css';

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

const persistence = { session, api, crypto: vaultCrypto };
keepRootSealed(persistence);
// A reload keeps the person signed in and the vault open. The route guards read the session
// synchronously, so the router waits for this (a spinner shows meanwhile, and a server that does not
// answer is given up on after a few seconds); on any failure the vault is just shut.
const restored = restoreSession(persistence).catch(() => undefined);

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
