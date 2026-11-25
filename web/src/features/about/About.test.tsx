import { fireEvent, screen } from '@testing-library/react';
import type { ReactNode } from 'react';
import { describe, expect, it, vi } from 'vitest';
import { renderWithIntl } from '@/test/render';
import { type AboutConfig, AboutView } from './About';

// The page frame needs the server's config and the router; only what the page says is under test.
vi.mock('@/app/services', () => ({ configQuery: { queryKey: ['config'], queryFn: () => ({}) } }));
vi.mock('@/ui/AuthPage', () => ({
  AuthPage: ({ children }: { children: ReactNode }) => <main>{children}</main>,
}));
const router = vi.hoisted(() => ({ canGoBack: false, back: vi.fn() }));
vi.mock('@tanstack/react-router', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@tanstack/react-router')>()),
  Link: ({
    children,
    to,
    onClick,
  }: {
    children: ReactNode;
    to: string;
    onClick?: (event: { preventDefault: () => void }) => void;
  }) => (
    <a href={to} onClick={onClick}>
      {children}
    </a>
  ),
  useCanGoBack: () => router.canGoBack,
  useRouter: () => ({ history: { back: router.back } }),
}));

const config: AboutConfig = {
  version: '1.4.2',
  commit: '0123456789abcdef0123456789abcdef01234567',
  license: 'AGPL-3.0-only',
  sourceUrl: 'https://github.com/Arsslensoft/Kemlock-Server/tree/0123456789abcdef0123456789abcdef01234567',
};

describe('the about page', () => {
  it('names the product, its version and the start of its commit', () => {
    renderWithIntl(<AboutView config={config} />);
    expect(screen.getByRole('heading', { name: 'About Kemlock Server', level: 1 })).toBeInTheDocument();
    expect(screen.getByText('1.4.2')).toBeInTheDocument();
    expect(screen.getByText('0123456789ab')).toBeInTheDocument();
  });

  it('leaves the commit out when the build did not know it', () => {
    renderWithIntl(<AboutView config={{ ...config, commit: null }} />);
    expect(screen.queryByText('Commit')).not.toBeInTheDocument();
    expect(screen.getByText('1.4.2')).toBeInTheDocument();
  });

  it('links the licence, the source, the third-party notices and the notices', () => {
    renderWithIntl(<AboutView config={config} />);
    expect(screen.getByRole('link', { name: 'Licensed under AGPL-3.0-only' })).toHaveAttribute('href', '/LICENSE.txt');
    expect(screen.getByRole('link', { name: 'Source code' })).toHaveAttribute('href', config.sourceUrl);
    expect(screen.getByRole('link', { name: 'Third-party notices' })).toHaveAttribute(
      'href',
      '/THIRD-PARTY-NOTICES.txt',
    );
    expect(screen.getByRole('link', { name: 'Notices' })).toHaveAttribute('href', '/NOTICE.txt');
  });

  it('names the author and links the contributors', () => {
    renderWithIntl(<AboutView config={config} />);
    expect(screen.getByText('Arsslen Idadi')).toBeInTheDocument();
    const link = screen.getByRole('link', { name: 'Everyone who has contributed' });
    expect(link).toHaveAttribute('href', 'https://github.com/Arsslensoft/Kemlock-Server/graphs/contributors');
    expect(link).toHaveAttribute('rel', 'noopener noreferrer');
    expect(link).toHaveAttribute('target', '_blank');
  });

  it('does not link a source address that is not a web address', () => {
    renderWithIntl(<AboutView config={{ ...config, sourceUrl: 'javascript:alert(1)' }} />);
    expect(screen.queryByRole('link', { name: 'Source code' })).not.toBeInTheDocument();
  });

  it('says it is not affiliated with Bitwarden or Vaultwarden, before the config has loaded too', () => {
    renderWithIntl(<AboutView config={undefined} />);
    expect(
      screen.getByText(
        'Not affiliated with Bitwarden Inc. or Vaultwarden. Bitwarden is a trademark of Bitwarden Inc.',
      ),
    ).toBeInTheDocument();
    expect(screen.getByRole('status')).toBeInTheDocument();
  });

  it('goes back to the page the person came from', () => {
    router.canGoBack = true;
    router.back.mockClear();
    renderWithIntl(<AboutView config={config} />);
    // fireEvent returns false when a handler cancelled the link's own navigation to the vault.
    expect(fireEvent.click(screen.getByRole('link', { name: 'Back' }))).toBe(false);
    expect(router.back).toHaveBeenCalledOnce();
  });

  it('leaves a modified or middle click alone, so the link opens where the person asked', () => {
    router.canGoBack = true;
    router.back.mockClear();
    renderWithIntl(<AboutView config={config} />);
    const link = screen.getByRole('link', { name: 'Back' });
    const seen: boolean[] = [];
    const stop = (event: Event) => {
      seen.push(event.defaultPrevented);
      event.preventDefault();
    };
    document.addEventListener('click', stop);
    for (const init of [{ ctrlKey: true }, { metaKey: true }, { shiftKey: true }, { altKey: true }, { button: 1 }]) {
      fireEvent.click(link, init);
    }
    document.removeEventListener('click', stop);
    expect(seen).toEqual([false, false, false, false, false]);
    expect(router.back).not.toHaveBeenCalled();
  });

  it('leads home when About was opened on its own', () => {
    router.canGoBack = false;
    router.back.mockClear();
    renderWithIntl(<AboutView config={config} />);
    const link = screen.getByRole('link', { name: 'Back' });
    expect(link).toHaveAttribute('href', '/');
    // Seen after the link's handler: it left the navigation alone. Then stop jsdom following it.
    let cancelled: boolean | undefined;
    const stop = (event: Event) => {
      cancelled = event.defaultPrevented;
      event.preventDefault();
    };
    document.addEventListener('click', stop);
    fireEvent.click(link);
    document.removeEventListener('click', stop);
    expect(cancelled).toBe(false);
    expect(router.back).not.toHaveBeenCalled();
  });
});
