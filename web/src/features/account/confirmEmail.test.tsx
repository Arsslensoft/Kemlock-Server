import { render, screen, waitFor } from '@testing-library/react';
import { StrictMode, type ReactNode } from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiError } from '@/api/errors';
import { I18nProvider } from '@/i18n';

const state = vi.hoisted(() => ({ token: 'tok_1-A' as string | undefined, status: 'signed-out' }));
const confirm = vi.hoisted(() => vi.fn());
const signOut = vi.hoisted(() => vi.fn(async () => undefined));

vi.mock('@tanstack/react-router', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@tanstack/react-router')>()),
  getRouteApi: () => ({ useSearch: () => ({ token: state.token }) }),
  Link: ({ children, to, className }: { children: ReactNode; to: string; className?: string }) => (
    <a href={to} className={className}>
      {children}
    </a>
  ),
}));
vi.mock('@/api/profile', () => ({ createProfileApi: () => ({ confirmEmailChange: confirm }) }));
vi.mock('@/app/services', () => ({ api: {}, session: { getState: () => ({ status: state.status }) } }));
vi.mock('@/app/actions', () => ({ signOut }));
vi.mock('@/ui/AuthPage', () => ({ AuthPage: ({ children }: { children: ReactNode }) => <main>{children}</main> }));

import ConfirmEmail from './ConfirmEmail';

function open() {
  render(
    <StrictMode>
      <I18nProvider>
        <ConfirmEmail />
      </I18nProvider>
    </StrictMode>,
  );
}

const problem = (slug: string, status: number) =>
  new ApiError(status, { type: `urn:kemlock:problem:${slug}`, title: slug, status } as never);

beforeEach(() => {
  confirm.mockReset();
  signOut.mockClear();
  state.token = 'tok_1-A';
  state.status = 'signed-out';
});

describe('the link mailed to a new address', () => {
  it('spends the token once, says the address changed and leads to the sign-in', async () => {
    confirm.mockResolvedValue({ email: 'new@example.org' });
    open();
    expect(screen.getByRole('status')).toHaveTextContent('Confirming your new address');
    expect(await screen.findByText(/Your address is now new@example.org/)).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Sign in' })).toHaveAttribute('href', '/sign-in');
    // StrictMode ran the effect twice; the server saw one try.
    expect(confirm).toHaveBeenCalledOnce();
    expect(confirm).toHaveBeenCalledWith('tok_1-A');
  });

  it('forgets this browser\'s session when it had one, since the server ended them all', async () => {
    state.status = 'unlocked';
    confirm.mockResolvedValue({ email: 'new@example.org' });
    open();
    await screen.findByText(/Your address is now/);
    expect(signOut).toHaveBeenCalledOnce();
  });

  it('leaves a browser with no session alone', async () => {
    confirm.mockResolvedValue({ email: 'new@example.org' });
    open();
    await screen.findByText(/Your address is now/);
    expect(signOut).not.toHaveBeenCalled();
  });

  it('says a used or expired link is no good, without saying which', async () => {
    confirm.mockRejectedValue(problem('email-change-invalid', 400));
    open();
    expect(await screen.findByText(/expired or was already used/)).toBeInTheDocument();
    expect(screen.queryByRole('link', { name: 'Sign in' })).toBeNull();
  });

  it('says when the address was taken meanwhile', async () => {
    confirm.mockRejectedValue(problem('email-taken', 409));
    open();
    expect(await screen.findByText(/Another account uses that address now/)).toBeInTheDocument();
  });

  it('says what went wrong when the server could not be reached', async () => {
    confirm.mockRejectedValue(problem('whatever', 500));
    open();
    expect(await screen.findByText('The server had a problem. Try again in a moment.')).toBeInTheDocument();
  });

  it('says the link is incomplete when it has no token, and asks the server nothing', async () => {
    state.token = undefined;
    open();
    expect(await screen.findByText(/This link is incomplete/)).toBeInTheDocument();
    await waitFor(() => expect(confirm).not.toHaveBeenCalled());
  });
});
