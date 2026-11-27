import { screen } from '@testing-library/react';
import type { ReactNode } from 'react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { renderWithIntl } from '@/test/render';
import { ApprovalRefused } from './approvalFlow';
import { DeviceApprovalView, lastGroup } from './DeviceApproval';

// AuthPage reads the server's config through React Query and `Link` needs a router, so the view is
// rendered with both stubbed out: only what the screen says is under test here.
vi.mock('@/ui/AuthPage', () => ({
  AuthPage: ({ children }: { children: ReactNode }) => <main>{children}</main>,
}));
vi.mock('@tanstack/react-router', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@tanstack/react-router')>()),
  Link: ({ children, search }: { children: ReactNode; search?: unknown }) => (
    <a href="/sign-in" data-search={JSON.stringify(search ?? null)}>
      {children}
    </a>
  ),
  getRouteApi: () => ({ useSearch: () => ({ email: 'sam@example.co' }) }),
}));

const noop = () => undefined;

describe('lastGroup', () => {
  it('is the last group of digits of a fingerprint', () => {
    expect(lastGroup('11111 22222 67890')).toBe('67890');
    expect(lastGroup('  67890 ')).toBe('67890');
    expect(lastGroup('')).toBe('');
  });
});

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

  it('says so when the request was held back among many', () => {
    renderWithIntl(
      <DeviceApprovalView
        email="sam@example.co"
        progress={{
          step: 'waiting',
          phrase: 'abacus lemon river stone paper',
          expiresAt: '2026-11-25T10:05:00Z',
          heldBack: true,
        }}
        onCancel={noop}
        onRetry={noop}
      />,
    );
    expect(screen.getByText(/getting a lot of approval requests/)).toBeInTheDocument();
  });

  it("asks the person to compare the account's fingerprint before the vault counts as open", async () => {
    const onCompare = vi.fn();
    renderWithIntl(
      <DeviceApprovalView
        email="sam@example.co"
        progress={{ step: 'compare', fingerprint: '11111 22222 33333 44444 55555 66666 77777 88888 99999 00000 12345 67890' }}
        onCancel={noop}
        onRetry={noop}
        onCompare={onCompare}
      />,
    );
    expect(screen.getByText('11111 22222 33333 44444 55555 66666 77777 88888 99999 00000 12345 67890')).toBeInTheDocument();
    const user = userEvent.setup();
    // "Same" is deliberate: it opens only once the last group of digits has been typed as shown elsewhere.
    const same = screen.getByRole('button', { name: 'They are the same' });
    expect(same).toBeDisabled();
    await user.type(screen.getByLabelText('Type the last group of digits as the other device shows it'), '67891');
    expect(same).toBeDisabled();
    await user.clear(screen.getByLabelText('Type the last group of digits as the other device shows it'));
    await user.type(screen.getByLabelText('Type the last group of digits as the other device shows it'), '67890');
    expect(same).toBeEnabled();
    await user.click(same);
    expect(onCompare).toHaveBeenLastCalledWith(true);
    // Saying they differ needs nothing typed.
    await user.click(screen.getByRole('button', { name: 'They are not the same' }));
    expect(onCompare).toHaveBeenLastCalledWith(false);
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
    [{ status: 'failed' as const, error: new ApprovalRefused('fingerprint') }, /fingerprints were not the same/],
    [{ status: 'failed' as const, error: new ApprovalRefused('keys') }, /not the account.s own/],
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

  it('goes back to the sign-in with the page the person was headed for', () => {
    renderWithIntl(
      <DeviceApprovalView
        email="a@b.c"
        progress={{ step: 'requesting' }}
        ended={{ status: 'expired' }}
        onCancel={noop}
        onRetry={noop}
        next="/trash"
      />,
    );
    expect(screen.getByRole('link')).toHaveAttribute('data-search', '{"next":"/trash"}');
  });
});
