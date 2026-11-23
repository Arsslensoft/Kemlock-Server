import { QueryClientProvider } from '@tanstack/react-query';
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { Root } from '@/app/Root';
import { createAppRouter } from '@/app/router';
import { queryClient, session } from '@/app/services';
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

createRoot(root).render(
  <StrictMode>
    <I18nProvider>
      <QueryClientProvider client={queryClient}>
        <Root router={router} />
      </QueryClientProvider>
    </I18nProvider>
  </StrictMode>,
);
