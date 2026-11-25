import { QueryClientProvider } from '@tanstack/react-query';
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { Root } from '@/app/Root';
import { keepRootSealed, restoreSession } from '@/app/persistence';
import { createAppRouter } from '@/app/router';
import { api, queryClient, session } from '@/app/services';
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

const router = createAppRouter({ queryClient, session });
const root = document.getElementById('root');
if (!root) throw new Error('index.html has no #root');

async function start(mount: HTMLElement): Promise<void> {
  const persistence = { session, api, crypto: vaultCrypto };
  keepRootSealed(persistence);
  // A reload keeps the person signed in and the vault open. The route guards read the session
  // synchronously, so it is back before the first page is chosen; on any failure it is just shut.
  await restoreSession(persistence).catch(() => undefined);
  createRoot(mount).render(
    <StrictMode>
      <I18nProvider>
        <QueryClientProvider client={queryClient}>
          <Root router={router} />
        </QueryClientProvider>
      </I18nProvider>
    </StrictMode>,
  );
}

void start(root);
