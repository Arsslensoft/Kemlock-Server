import { screen } from '@testing-library/react';
import type { ReactNode } from 'react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { renderWithIntl } from '@/test/render';
import { ApprovalRefused } from './approvalFlow';
import { DeviceApprovalView } from './DeviceApproval';

// AuthPage reads the server's config through React Query and `Link` needs a router, so the view is
// rendered with both stubbed out: only what the screen says is under test here.
vi.mock('@/ui/AuthPage', () => ({
  AuthPage: ({ children }: { children: ReactNode }) => <main>{children}</main>,
}));
vi.mock('@tanstack/react-router', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@tanstack/react-router')>()),
  Link: ({ children }: { children: ReactNode }) => <a href="/sign-in">{children}</a>,
  getRouteApi: () => ({ useSearch: () => ({ email: 'sam@example.co' }) }),
}));

const noop = () => undefined;

describe('DeviceApprovalView', () => {
  it('shows the five words and what to do with them, and can be cancelled', async () => {
    const onCancel = vi.fn();
    renderWithIntl(
      <DeviceApprovalView
        email="sam@example.co"
        progress={{ step: 'waiting', phrase: 'abacus lemon river stone paper', expiresAt: '2026-11-25T10:05:00Z' }}
        onCancel={onCancel}
        onRetry={noop}
      />,
    );
    expect(screen.getByRole('heading', { name: 'Sign in with another device', level: 1 })).toBeInTheDocument();
    expect(screen.getByText('abacus lemon river stone paper')).toBeInTheDocument();
    expect(screen.getByText(/Approve only if the other device shows exactly these five words/)).toBeInTheDocument();
    await userEvent.setup().click(screen.getByRole('button', { name: 'Cancel' }));
    expect(onCancel).toHaveBeenCalledOnce();
  });

  it.each([
    ['requesting' as const, 'Asking for approval'],
    ['signing-in' as const, 'Approved. Opening your vault'],
  ])('says what it is doing at the %s step', (step, words) => {
    renderWithIntl(
      <DeviceApprovalView email="a@b.c" progress={{ step }} onCancel={noop} onRetry={noop} />,
    );
    expect(screen.getByRole('status')).toHaveTextContent(words);
  });

  it.each([
    [{ status: 'denied' as const }, /The other device refused this request/],
    [{ status: 'expired' as const }, /lapsed or was already used/],
    [{ status: 'failed' as const, error: new ApprovalRefused('phrase') }, /did not match this browser's key/],
    [{ status: 'failed' as const, error: new Error('x') }, /could not be completed/],
  ])('ends with a reason and a way to start again: %#', async (ended, reason) => {
    const onRetry = vi.fn();
    renderWithIntl(
      <DeviceApprovalView
        email="a@b.c"
        progress={{ step: 'requesting' }}
        ended={ended}
        onCancel={noop}
        onRetry={onRetry}
      />,
    );
    expect(screen.getByRole('alert')).toHaveTextContent(reason);
    await userEvent.setup().click(screen.getByRole('button', { name: 'Start again' }));
    expect(onRetry).toHaveBeenCalledOnce();
  });
});
