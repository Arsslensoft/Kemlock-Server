import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { useState } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ApiError } from '@/api/errors';
import { PasskeyError } from '@/lib/passkey';
import { I18nProvider } from '@/i18n';
import { renderWithIntl } from '@/test/render';
import { ReauthDialogView, currentGrant, forgetGrant, rememberGrant, useReauth } from './reauth';

afterEach(() => forgetGrant());

describe('the grant', () => {
  it('is held until a minute before it ends', () => {
    expect(currentGrant(0)).toBeUndefined();
    rememberGrant('G', 300);
    expect(currentGrant(100_000)).toBe('G');
    expect(currentGrant(250_000)).toBeUndefined();
  });
});

describe('ReauthDialogView', () => {
  it('takes only six digits and hands them over without spaces', async () => {
    const onSubmit = vi.fn();
    renderWithIntl(<ReauthDialogView isOpen onSubmit={onSubmit} onCancel={vi.fn()} />);
    const user = userEvent.setup();
    const confirm = screen.getByRole('button', { name: 'Confirm' });
    expect(confirm).toBeDisabled();
    await user.type(screen.getByLabelText('Code from your authenticator app'), '123 45');
    expect(confirm).toBeDisabled();
    await user.type(screen.getByLabelText('Code from your authenticator app'), '6');
    await user.click(confirm);
    expect(onSubmit).toHaveBeenCalledWith('123456');
  });

  it('shows what went wrong', () => {
    renderWithIntl(
      <ReauthDialogView isOpen error={{ id: 'error.credentials' }} onSubmit={vi.fn()} onCancel={vi.fn()} />,
    );
    expect(screen.getByRole('alert')).toHaveTextContent(/email or password is wrong/);
  });
});

describe('forgetGrant', () => {
  it('drops the held grant', () => {
    rememberGrant('G', 300);
    forgetGrant();
    expect(currentGrant(100_000)).toBeUndefined();
  });
});

describe('ReauthDialogView reopened', () => {
  it('opens empty, not with the code typed the last time', async () => {
    const ui = (isOpen: boolean) => (
      <I18nProvider>
        <ReauthDialogView isOpen={isOpen} onSubmit={vi.fn()} onCancel={vi.fn()} />
      </I18nProvider>
    );
    const { rerender } = render(ui(true));
    await userEvent.setup().type(screen.getByLabelText('Code from your authenticator app'), '123456');
    rerender(ui(false));
    rerender(ui(true));
    expect(screen.getByLabelText('Code from your authenticator app')).toHaveValue('');
  });
});

describe('useReauth', () => {
  function Harness({
    action,
    reauth,
  }: {
    action: (grant: string | undefined) => Promise<string>;
    reauth: (code: string) => Promise<{ token: string; expiresAt: number }>;
  }) {
    const { guard, dialog } = useReauth({ stepUpTotp: reauth }, undefined, async () => ({ totp: true, passkey: false }));
    const [result, setResult] = useState('');
    return (
      <>
        <button type="button" onClick={() => void guard(action).then(setResult, (error: unknown) => setResult(error instanceof Error ? error.name : 'failed'))}>
          run
        </button>
        <p role="status">{result}</p>
        {dialog}
      </>
    );
  }

  const problem = new ApiError(403, {
    type: 'urn:kemlock:problem:step-up-required',
    title: 'Confirm it is you',
    status: 403,
  });

  it('runs the action once when the server asks for nothing', async () => {
    const action = vi.fn(async () => 'done');
    renderWithIntl(<Harness action={action} reauth={vi.fn()} />);
    await userEvent.setup().click(screen.getByRole('button', { name: 'run' }));
    await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent('done'));
    expect(action).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });

  it('asks for a code on step-up-required, then runs the action again with the grant', async () => {
    const action = vi.fn(async (grant: string | undefined) => {
      if (!grant) throw problem;
      return `done with ${grant}`;
    });
    const reauth = vi.fn(async () => ({ token: 'G1', expiresAt: Math.floor(Date.now() / 1000) + 300 }));
    renderWithIntl(<Harness action={action} reauth={reauth} />);
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'run' }));
    await user.type(await screen.findByLabelText('Code from your authenticator app'), '123456');
    await user.click(screen.getByRole('button', { name: 'Confirm' }));
    await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent('done with G1'));
    expect(reauth).toHaveBeenCalledWith('123456');
    expect(action).toHaveBeenCalledTimes(2);
  });

  it('does not run the action again when the person backs out', async () => {
    const action = vi.fn(async () => {
      throw problem;
    });
    renderWithIntl(<Harness action={action} reauth={vi.fn()} />);
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'run' }));
    await user.click(await screen.findByRole('button', { name: 'Cancel' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent('ReauthCancelled'));
    expect(action).toHaveBeenCalledTimes(1);
  });
});

describe('the passkey step-up', () => {
  const problem = new ApiError(403, {
    type: 'urn:kemlock:problem:step-up-required',
    title: 'Confirm it is you',
    status: 403,
  });
  const granted = { token: 'P1', expiresAt: Math.floor(Date.now() / 1000) + 300 };

  function Harness({
    api,
    passkey,
    ways = { totp: true, passkey: true },
  }: {
    api: Parameters<typeof useReauth>[0];
    passkey: NonNullable<Parameters<typeof useReauth>[1]>;
    ways?: { totp: boolean; passkey: boolean };
  }) {
    const { guard, dialog } = useReauth(api, passkey, async () => ways);
    const [result, setResult] = useState('');
    const action = async (grant: string | undefined) => {
      if (!grant) throw problem;
      return `done with ${grant}`;
    };
    return (
      <>
        <button type="button" onClick={() => void guard(action).then(setResult)}>
          run
        </button>
        <p role="status">{result}</p>
        {dialog}
      </>
    );
  }

  it('offers a passkey beside the code when the dialog is given one to use', () => {
    renderWithIntl(<ReauthDialogView isOpen onSubmit={vi.fn()} onPasskey={vi.fn()} onCancel={vi.fn()} />);
    expect(screen.getByRole('button', { name: 'Use a passkey' })).toBeInTheDocument();
  });

  it('offers only the code when it is not', () => {
    renderWithIntl(<ReauthDialogView isOpen onSubmit={vi.fn()} onCancel={vi.fn()} />);
    expect(screen.queryByRole('button', { name: 'Use a passkey' })).not.toBeInTheDocument();
  });

  it('asks for the options, has the authenticator sign the challenge, and runs the action with the token', async () => {
    const stepUpPasskeyOptions = vi.fn(async () => ({ options: { challenge: 'Y2g' }, challenge: 'sealed-challenge' }));
    const stepUpPasskeyFinish = vi.fn(async () => granted);
    const assert = vi.fn(async () => ({ id: 'cred' }));
    renderWithIntl(
      <Harness
        api={{ stepUpTotp: vi.fn(), stepUpPasskeyOptions, stepUpPasskeyFinish }}
        passkey={{ available: () => true, assert }}
      />,
    );
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'run' }));
    await user.click(await screen.findByRole('button', { name: 'Use a passkey' }));
    await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent('done with P1'));
    expect(assert).toHaveBeenCalledWith({ challenge: 'Y2g' });
    // The sealed challenge goes back unread, with the answer.
    expect(stepUpPasskeyFinish).toHaveBeenCalledWith('sealed-challenge', { id: 'cred' });
  });

  it('says a passkey was not used, and leaves the code to type', async () => {
    renderWithIntl(
      <Harness
        api={{
          stepUpTotp: vi.fn(),
          stepUpPasskeyOptions: vi.fn(async () => ({ options: {}, challenge: 'c' })),
          stepUpPasskeyFinish: vi.fn(),
        }}
        passkey={{
          available: () => true,
          assert: vi.fn(async () => {
            throw new PasskeyError('cancelled');
          }),
        }}
      />,
    );
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'run' }));
    await user.click(await screen.findByRole('button', { name: 'Use a passkey' }));
    expect(await screen.findByRole('alert')).toHaveTextContent(/The passkey was not used/);
    expect(screen.getByLabelText('Code from your authenticator app')).toBeInTheDocument();
  });

  it('hides the passkey button where the browser has none', async () => {
    renderWithIntl(
      <Harness
        api={{
          stepUpTotp: vi.fn(),
          stepUpPasskeyOptions: vi.fn(),
          stepUpPasskeyFinish: vi.fn(),
        }}
        passkey={{ available: () => false, assert: vi.fn() }}
      />,
    );
    await userEvent.setup().click(screen.getByRole('button', { name: 'run' }));
    await screen.findByLabelText('Code from your authenticator app');
    expect(screen.queryByRole('button', { name: 'Use a passkey' })).not.toBeInTheDocument();
  });
});

describe('the step-up asks only for what the account has', () => {
  const problem = new ApiError(403, {
    type: 'urn:kemlock:problem:step-up-required',
    title: 'Confirm it is you',
    status: 403,
  });
  const granted = { token: 'P1', expiresAt: Math.floor(Date.now() / 1000) + 300 };

  function Harness({
    ways,
    assert = vi.fn(async () => ({ id: 'cred' })),
    finish = vi.fn(async () => granted),
  }: {
    ways: { totp: boolean; passkey: boolean };
    assert?: (options: Record<string, unknown>) => Promise<Record<string, unknown>>;
    finish?: () => Promise<{ token: string; expiresAt: number }>;
  }) {
    const { guard, dialog } = useReauth(
      {
        stepUpTotp: vi.fn(),
        stepUpPasskeyOptions: vi.fn(async () => ({ options: { challenge: 'Y2g' }, challenge: 'c' })),
        stepUpPasskeyFinish: finish,
      },
      { available: () => true, assert },
      async () => ways,
    );
    const [result, setResult] = useState('');
    const action = async (grant: string | undefined) => {
      if (!grant) throw problem;
      return `done with ${grant}`;
    };
    return (
      <>
        <button type="button" onClick={() => void guard(action).then(setResult)}>
          run
        </button>
        <p data-testid="result">{result}</p>
        {dialog}
      </>
    );
  }

  it('opens the passkey prompt at once when a passkey is the only way, with no code field', async () => {
    const assert = vi.fn(async () => ({ id: 'cred' }));
    renderWithIntl(<Harness ways={{ totp: false, passkey: true }} assert={assert} />);
    await userEvent.setup().click(screen.getByRole('button', { name: 'run' }));
    await waitFor(() => expect(screen.getByTestId('result')).toHaveTextContent('done with P1'));
    expect(assert).toHaveBeenCalledTimes(1);
    expect(screen.queryByLabelText('Code from your authenticator app')).not.toBeInTheDocument();
  });

  it('keeps a passkey-only dialog open to try again, without pointing at a code', async () => {
    const assert = vi.fn(async () => {
      throw new PasskeyError('cancelled');
    });
    renderWithIntl(<Harness ways={{ totp: false, passkey: true }} assert={assert} />);
    await userEvent.setup().click(screen.getByRole('button', { name: 'run' }));
    expect(await screen.findByRole('alert')).toHaveTextContent(/Press Use a passkey to try again/);
    expect(screen.getByRole('button', { name: 'Use a passkey' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Confirm' })).not.toBeInTheDocument();
  });

  it('shows only the code when there is no passkey', async () => {
    const assert = vi.fn();
    renderWithIntl(<Harness ways={{ totp: true, passkey: false }} assert={assert} />);
    await userEvent.setup().click(screen.getByRole('button', { name: 'run' }));
    await screen.findByLabelText('Code from your authenticator app');
    expect(screen.queryByRole('button', { name: 'Use a passkey' })).not.toBeInTheDocument();
    expect(assert).not.toHaveBeenCalled();
  });

  it('says what to set up when the account has neither', async () => {
    renderWithIntl(<Harness ways={{ totp: false, passkey: false }} />);
    await userEvent.setup().click(screen.getByRole('button', { name: 'run' }));
    expect(await screen.findByText(/no authenticator app or passkey/)).toBeInTheDocument();
    expect(screen.queryByLabelText('Code from your authenticator app')).not.toBeInTheDocument();
  });
});
