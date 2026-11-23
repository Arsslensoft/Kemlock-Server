import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { renderWithIntl } from '@/test/render';
import { CodeForm } from '@/ui/CodeForm';
import { PasswordForm } from './auth/PasswordForm';
import { SetupAdminForm } from './setup/SetupAdmin';
import { SetupCodeForm } from './setup/SetupCode';
import { SetupServerForm, defaultBasics } from './setup/SetupServer';
import { LoginForm, NoteForm } from './vault/ItemForm';
import { loginDefaults, loginFields, noteDefaults, noteFields } from './vault/NewItem';
import type { VaultItem } from './vault/vault';

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

  it('offers the passkey option but keeps it off', () => {
    renderWithIntl(<SetupAdminForm onSubmit={vi.fn()} />);
    expect(screen.getByRole('checkbox', { name: /Add a passkey too/ })).toBeDisabled();
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

describe('the item forms', () => {
  it('saves a login, and can generate its password', async () => {
    const onSubmit = vi.fn();
    renderWithIntl(
      <LoginForm
        initial={loginDefaults()}
        onSubmit={onSubmit}
        onCancel={vi.fn()}
        submitLabel="Save"
      />,
    );
    const user = userEvent.setup({ delay: null });
    await user.type(screen.getByLabelText('Name'), 'GitHub');
    await user.type(screen.getByLabelText('Username'), 'sam@example.org');
    await user.click(screen.getByRole('button', { name: 'Generate' }));
    await user.type(screen.getByLabelText('Website'), 'https://github.com');
    await user.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(onSubmit).toHaveBeenCalledOnce());
    const values = onSubmit.mock.calls[0]?.[0] as { password: string; name: string; url: string };
    expect(values.name).toBe('GitHub');
    expect(values.url).toBe('https://github.com');
    expect(values.password).toHaveLength(20);
  });

  it('refuses a login with no name or a javascript: website', async () => {
    const onSubmit = vi.fn();
    renderWithIntl(
      <LoginForm initial={loginDefaults()} onSubmit={onSubmit} onCancel={vi.fn()} submitLabel="Save" />,
    );
    const user = userEvent.setup({ delay: null });
    await user.type(screen.getByLabelText('Website'), 'javascript:alert(1)');
    await user.click(screen.getByRole('button', { name: 'Save' }));
    expect(await screen.findByText('This is required.')).toBeInTheDocument();
    expect(screen.getByText(/starts with https/)).toBeInTheDocument();
    expect(onSubmit).not.toHaveBeenCalled();
  });

  it('saves a note', async () => {
    const onSubmit = vi.fn();
    renderWithIntl(
      <NoteForm initial={noteDefaults()} onSubmit={onSubmit} onCancel={vi.fn()} submitLabel="Save" />,
    );
    const user = userEvent.setup({ delay: null });
    await user.type(screen.getByLabelText('Name'), 'Recovery plan');
    await user.type(screen.getByLabelText('Text'), 'line one');
    await user.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(onSubmit).toHaveBeenCalledOnce());
    expect(onSubmit.mock.calls[0]?.[0]).toEqual({ name: 'Recovery plan', text: 'line one', favorite: false });
  });

  it('keeps what other apps wrote when a login is edited', () => {
    const existing: VaultItem = {
      id: 'i',
      owner: 'user:u',
      kind: 'login',
      revision: 3,
      keyVersion: 1,
      sizes: { ciphertext: 1, itemKey: 1 },
      data: {
        name: 'Old',
        username: 'u',
        password: 'p',
        urls: ['https://a.example', 'https://b.example'],
        favorite: true,
      },
    };
    const defaults = loginDefaults(existing);
    expect(defaults).toMatchObject({ name: 'Old', url: 'https://a.example', favorite: true });
    const fields = loginFields({ ...defaults, url: 'https://c.example', notes: '' }, existing);
    expect(fields['urls']).toEqual(['https://c.example', 'https://b.example']);
    expect(fields['notes']).toBeUndefined();
    expect(noteFields({ name: 'N', text: 't', favorite: false })).toEqual({
      name: 'N',
      text: 't',
      favorite: undefined,
    });
  });
});
