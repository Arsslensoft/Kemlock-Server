import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, waitFor } from '@testing-library/react';
import type { ReactNode } from 'react';
import { describe, expect, it, vi } from 'vitest';
import { I18nProvider } from '@/i18n';
import { AuthPage } from './AuthPage';
import { SourceLink } from './SourceLink';

const server = vi.hoisted(() => ({ sourceUrl: 'https://github.com/Arsslensoft/Kemlock-Server/tree/abc1234' }));

// The config the server would send, through the same query the app uses.
vi.mock('@/app/services', () => ({
  configQuery: {
    queryKey: ['config'],
    queryFn: () => Promise.resolve({ version: '1.0.0', license: 'AGPL-3.0-only', sourceUrl: server.sourceUrl }),
  },
}));
vi.mock('@tanstack/react-router', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@tanstack/react-router')>()),
  Link: ({ children, to }: { children: ReactNode; to: string }) => <a href={to}>{children}</a>,
}));

function renderPage(ui: ReactNode) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <I18nProvider>{ui}</I18nProvider>
    </QueryClientProvider>,
  );
  return client;
}

describe('the source link', () => {
  it('points at the address the server gave, in a new tab, once the config has loaded', async () => {
    server.sourceUrl = 'https://github.com/Arsslensoft/Kemlock-Server/tree/abc1234';
    renderPage(<SourceLink />);
    const link = await screen.findByRole('link', { name: 'Source code' });
    expect(link).toHaveAttribute('href', server.sourceUrl);
    expect(link).toHaveAttribute('target', '_blank');
    expect(link).toHaveAttribute('rel', 'noopener noreferrer');
  });

  it('is not shown for an address that is not http or https', async () => {
    server.sourceUrl = 'javascript:alert(1)';
    const client = renderPage(<SourceLink />);
    await waitFor(() => expect(client.getQueryData(['config'])).toBeDefined());
    expect(screen.queryByRole('link', { name: 'Source code' })).not.toBeInTheDocument();
  });
});

describe('the sign-in and setup page frame', () => {
  it('offers the source and the about page to someone who has not signed in', async () => {
    server.sourceUrl = 'https://git.example.org/me/kemlock';
    renderPage(
      <AuthPage>
        <h1>Sign in</h1>
      </AuthPage>,
    );
    expect(await screen.findByRole('link', { name: 'Source code' })).toHaveAttribute('href', server.sourceUrl);
    expect(screen.getByRole('link', { name: 'About' })).toHaveAttribute('href', '/about');
  });

  it('leaves them out when the page says all of it already', () => {
    renderPage(
      <AuthPage legal={false}>
        <h1>About</h1>
      </AuthPage>,
    );
    expect(screen.queryByRole('link', { name: 'About' })).not.toBeInTheDocument();
    expect(screen.queryByRole('navigation')).not.toBeInTheDocument();
  });
});
