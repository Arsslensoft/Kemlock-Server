import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { renderWithIntl } from '@/test/render';
import { CodeForm } from '@/ui/CodeForm';
import { PasswordForm } from './auth/PasswordForm';
import { SetupAdminForm } from './setup/SetupAdmin';
import { TwoStepChoice } from './setup/SetupTwoStep';
import { SetupCodeForm } from './setup/SetupCode';
import { SetupServerForm, defaultBasics } from './setup/SetupServer';

describe('SetupCodeForm', () => {
  it('refuses a code that is not 12 characters and says why', async () => {
    const onSubmit = vi.fn();
    renderWithIntl(<SetupCodeForm onSubmit={onSubmit} secureContext />);
    const user = userEvent.setup({ delay: null });
    await user.type(screen.getByLabelText('Setup code'), 'abc');
    await user.click(screen.getByRole('button', { name: 'Continue' }));
    expect(await screen.findByText(/12 letters and digits/, {}, { timeout: 4000 })).toBeInTheDocument();
    expect(onSubmit).not.toHaveBeenCalled();
  });

  it('hands over the normalised code', async () => {
    const onSubmit = vi.fn();
    renderWithIntl(<SetupCodeForm onSubmit={onSubmit} secureContext />);
    const user = userEvent.setup({ delay: null });
    await user.type(screen.getByLabelText('Setup code'), 'abcd-efgh-jkmn');
    await user.click(screen.getByRole('button', { name: 'Continue' }));
    await waitFor(() => expect(onSubmit).toHaveBeenCalledWith('ABCDEFGHJKMN'));
  });

  it('cannot be submitted away from HTTPS or localhost', () => {
    renderWithIntl(<SetupCodeForm onSubmit={vi.fn()} secureContext={false} />);
    expect(screen.getByRole('button', { name: 'Continue' })).toBeDisabled();
  });

  it('shows the server error', () => {
    renderWithIntl(
      <SetupCodeForm onSubmit={vi.fn()} secureContext error={{ id: 'error.setupCodeWrong' }} />,
    );
    expect(screen.getByRole('alert')).toHaveTextContent(/setup code is wrong/);
  });
});

describe('SetupAdminForm', () => {
  async function fill(user: ReturnType<typeof userEvent.setup>, password: string, confirm: string) {
    await user.type(screen.getByLabelText('Name'), 'Sam Rivera');
    await user.type(screen.getByLabelText('Email'), 'sam@example.co');
    await user.type(screen.getByLabelText('Master password'), password);
    await user.type(screen.getByLabelText('Type it again'), confirm);
    await user.click(screen.getByRole('button', { name: 'Make my account' }));
  }

  it('wants matching passwords of at least 12 characters', async () => {
    const onSubmit = vi.fn();
    renderWithIntl(<SetupAdminForm onSubmit={onSubmit} />);
    const user = userEvent.setup({ delay: null });
    await fill(user, 'tooshort', 'tooshort');
    expect(await screen.findByText(/at least 12 characters/)).toBeInTheDocument();
    expect(onSubmit).not.toHaveBeenCalled();
  });

  it('says when the two passwords differ', async () => {
    const onSubmit = vi.fn();
    renderWithIntl(<SetupAdminForm onSubmit={onSubmit} />);
    const user = userEvent.setup({ delay: null });
    await fill(user, 'a long enough password', 'a long enough passwor');
    expect(await screen.findByText(/passwords don't match/)).toBeInTheDocument();
    expect(onSubmit).not.toHaveBeenCalled();
  });

  it('submits a complete form', async () => {
    const onSubmit = vi.fn();
    renderWithIntl(<SetupAdminForm onSubmit={onSubmit} />);
    const user = userEvent.setup({ delay: null });
    await fill(user, 'a long enough password', 'a long enough password');
    await waitFor(() => expect(onSubmit).toHaveBeenCalledOnce());
    expect(onSubmit.mock.calls[0]?.[0]).toMatchObject({
      name: 'Sam Rivera',
      email: 'sam@example.co',
      password: 'a long enough password',
    });
  });

  it('lets the passkey option be ticked, and says so on submit', async () => {
    const onSubmit = vi.fn();
    renderWithIntl(<SetupAdminForm onSubmit={onSubmit} />);
    const user = userEvent.setup({ delay: null });
    const box = screen.getByRole('checkbox', { name: /Add a passkey too/ });
    expect(box).toBeEnabled();
    expect(box).not.toBeChecked();
    await user.click(box);
    expect(box).toBeChecked();
    await fill(user, 'a long enough password', 'a long enough password');
    await waitFor(() => expect(onSubmit).toHaveBeenCalledOnce());
    expect(onSubmit.mock.calls[0]?.[1]).toEqual({ passkey: true });
  });
});

describe('TwoStepChoice', () => {
  it('lets the security key be picked, and the app again', async () => {
    const onChange = vi.fn();
    renderWithIntl(<TwoStepChoice value="totp" onChange={onChange} />);
    const key = screen.getByRole('radio', { name: /Security key/ });
    expect(key).toBeEnabled();
    expect(screen.getByRole('radio', { name: /Authenticator app/ })).toBeChecked();
    await userEvent.setup({ delay: null }).click(key);
    expect(onChange).toHaveBeenCalledWith('key');
  });
});

describe('SetupServerForm', () => {
  it('submits the defaults', async () => {
    const onSubmit = vi.fn();
    renderWithIntl(<SetupServerForm initial={defaultBasics('https://vault.example.org')} onSubmit={onSubmit} />);
    await userEvent.setup({ delay: null }).click(screen.getByRole('button', { name: 'Save and finish' }));
    await waitFor(() => expect(onSubmit).toHaveBeenCalledOnce());
    expect(onSubmit.mock.calls[0]?.[0]).toMatchObject({ address: 'https://vault.example.org', join: 'invite' });
  });

  it('asks for the server.key confirmation once backups are on', async () => {
    const onSubmit = vi.fn();
    renderWithIntl(<SetupServerForm initial={defaultBasics('https://vault.example.org')} onSubmit={onSubmit} />);
    const user = userEvent.setup({ delay: null });
    await user.click(screen.getByRole('switch', { name: /Encrypted backups/ }));
    await user.click(screen.getByRole('button', { name: 'Save and finish' }));
    expect(await screen.findByText(/age recipient/i, { selector: '.error' })).toBeInTheDocument();
    expect(onSubmit).not.toHaveBeenCalled();
  });
});

describe('PasswordForm and CodeForm', () => {
  it('needs a password, then hands it over', async () => {
    const onSubmit = vi.fn();
    renderWithIntl(<PasswordForm onSubmit={onSubmit} submitLabel="Open the vault" />);
    const user = userEvent.setup({ delay: null });
    await user.click(screen.getByRole('button', { name: 'Open the vault' }));
    expect(await screen.findByText('This is required.')).toBeInTheDocument();
    await user.type(screen.getByLabelText('Master password'), 'secret words');
    await user.click(screen.getByRole('button', { name: 'Open the vault' }));
    await waitFor(() => expect(onSubmit).toHaveBeenCalledWith('secret words'));
  });

  it('takes a six-digit code with spaces', async () => {
    const onSubmit = vi.fn();
    renderWithIntl(<CodeForm label="Code" submitLabel="Go" onSubmit={onSubmit} />);
    const user = userEvent.setup({ delay: null });
    await user.type(screen.getByLabelText('Code'), '482 913');
    await user.click(screen.getByRole('button', { name: 'Go' }));
    await waitFor(() => expect(onSubmit).toHaveBeenCalledWith('482913'));
  });

  it('rejects a short code', async () => {
    const onSubmit = vi.fn();
    renderWithIntl(<CodeForm label="Code" submitLabel="Go" onSubmit={onSubmit} />);
    const user = userEvent.setup({ delay: null });
    await user.type(screen.getByLabelText('Code'), '4829');
    await user.click(screen.getByRole('button', { name: 'Go' }));
    expect(await screen.findByText(/6 digits/)).toBeInTheDocument();
    expect(onSubmit).not.toHaveBeenCalled();
  });
});
