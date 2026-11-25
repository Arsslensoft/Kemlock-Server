import { fireEvent, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { renderWithIntl } from '@/test/render';
import type { VaultItem } from '../vault';
import type { MatchRule } from '../websites';
import { LoginForm, type LoginFormValues, loginDefaults, loginFields } from './login';
import { newSiteRow, siteProblem, siteRowsOf, sitesFields } from './siteRows';

function login(data: Record<string, unknown>): VaultItem {
  return { id: 'i', owner: 'user:u', kind: 'login', revision: 3, keyVersion: 1, sizes: { ciphertext: 1, itemKey: 1 }, data };
}

function setup(initial = loginDefaults()) {
  const onSubmit = vi.fn();
  renderWithIntl(<LoginForm initial={initial} onSubmit={onSubmit} onCancel={vi.fn()} submitLabel="Save" />);
  return { onSubmit, user: userEvent.setup({ delay: null }) };
}

function submitted(onSubmit: ReturnType<typeof vi.fn>): LoginFormValues {
  return onSubmit.mock.calls[0]?.[0] as LoginFormValues;
}

describe('LoginForm', () => {
  it('saves a login with a generated password and a website on the base domain', async () => {
    const { onSubmit, user } = setup();
    await user.type(screen.getByLabelText('Name'), 'GitHub');
    await user.type(screen.getByLabelText('Username'), 'sam@example.org');
    await user.click(screen.getByRole('button', { name: 'Generate' }));
    expect(screen.getByText(/20 characters/)).toBeInTheDocument();
    await user.type(screen.getByLabelText('Website 1'), 'https://github.com');
    await user.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(onSubmit).toHaveBeenCalledOnce());
    const values = submitted(onSubmit);
    expect(values.name).toBe('GitHub');
    expect(values.password).toHaveLength(20);
    expect(values.websites).toMatchObject([{ uri: 'https://github.com', match: 'domain' }]);
  });

  it('refuses a login with no name and a javascript: website', async () => {
    const { onSubmit, user } = setup();
    await user.type(screen.getByLabelText('Website 1'), 'javascript:alert(1)');
    await user.click(screen.getByRole('button', { name: 'Save' }));
    expect(await screen.findByText('This is required.')).toBeInTheDocument();
    expect(await screen.findByText(/Type a website, like github.com/)).toBeInTheDocument();
    expect(onSubmit).not.toHaveBeenCalled();
  });

  it('adds and removes websites, each with its own rule', async () => {
    const { onSubmit, user } = setup();
    await user.type(screen.getByLabelText('Name'), 'GitHub');
    await user.type(screen.getByLabelText('Website 1'), 'github.com');
    await user.click(screen.getByRole('button', { name: 'Add a website' }));
    await user.type(screen.getByLabelText('Website 2'), 'gist.github.com');
    await user.selectOptions(screen.getByLabelText('Match rule for website 2'), 'Host');
    await user.click(screen.getByRole('button', { name: 'Add a website' }));
    await user.type(screen.getByLabelText('Website 3'), 'https://old.example');
    await user.click(screen.getByRole('button', { name: 'Remove website 3' }));
    expect(screen.queryByLabelText('Website 3')).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(onSubmit).toHaveBeenCalledOnce());
    expect(submitted(onSubmit).websites).toMatchObject([
      { uri: 'github.com', match: 'domain' },
      { uri: 'gist.github.com', match: 'host' },
    ]);
  });

  it('offers the six rules, and Default only for a website that has it', () => {
    setup(loginDefaults(login({ name: 'Old', urls: ['https://a.example'] })));
    const rule = screen.getByLabelText('Match rule for website 1');
    expect([...rule.querySelectorAll('option')].map((option) => option.textContent)).toEqual([
      'Default',
      'Base domain',
      'Host',
      'Starts with',
      'Exact',
      'Regular expression',
      'Never',
    ]);
  });

  it('refuses a regular expression that does not compile', async () => {
    const { onSubmit, user } = setup();
    await user.type(screen.getByLabelText('Name'), 'Odd');
    await user.selectOptions(screen.getByLabelText('Match rule for website 1'), 'Regular expression');
    await user.type(screen.getByLabelText('Website 1'), '(unclosed');
    await user.click(screen.getByRole('button', { name: 'Save' }));
    expect(await screen.findByText('That is not a valid regular expression.')).toBeInTheDocument();
    expect(onSubmit).not.toHaveBeenCalled();
  });

  it('puts the show and hide eye inside the password field', async () => {
    const { user } = setup();
    const password = screen.getByLabelText('Password');
    const eye = screen.getByRole('button', { name: 'Show the password' });
    expect(password.parentElement).toBe(eye.parentElement);
    expect(password).toHaveAttribute('type', 'password');
    await user.click(eye);
    expect(password).toHaveAttribute('type', 'text');
  });

  it('sets the length and the characters of the generated password under "Strength"', async () => {
    const { user } = setup();
    expect(screen.getByText('Strength')).toBeInTheDocument();
    expect(screen.getByText('Length 20')).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('Length 20'), { target: { value: '32' } });
    expect(screen.getByText('Length 32')).toBeInTheDocument();
    for (const option of ['A to Z', 'a to z', '!@#$%^&*']) await user.click(screen.getByLabelText(option));
    await user.click(screen.getByRole('button', { name: 'Generate' }));
    const made = (screen.getByLabelText('Password') as HTMLInputElement).value;
    expect(made).toMatch(/^[2-9]{32}$/);
  });
});

describe('the websites of a login', () => {
  it('open as rows: a login with none has one empty row, the others one row each', () => {
    expect(siteRowsOf(null)).toHaveLength(1);
    const rows = siteRowsOf({ uris: [{ uri: 'https://a.example', match: 1 }, { uri: 'b.example' }] });
    expect(rows.map(({ uri, match }) => ({ uri, match }))).toEqual([
      { uri: 'https://a.example', match: 'host' },
      { uri: 'b.example', match: 'default' },
    ]);
  });

  it('are written as uris, urls and websites in step, a regular expression only in uris', () => {
    const fields = sitesFields([
      newSiteRow('https://github.com'),
      newSiteRow('gist.github.com', 'host'),
      newSiteRow('^https://x\\.example/', 'regex'),
      newSiteRow('  '),
    ]);
    expect(fields['uris']).toEqual([
      { uri: 'https://github.com', match: 0 },
      { uri: 'gist.github.com', match: 1 },
      { uri: '^https://x\\.example/', match: 4 },
    ]);
    expect(fields['urls']).toEqual(['https://github.com', 'gist.github.com']);
    expect(fields['websites']).toEqual(['github.com', 'gist.github.com']);
  });

  it('write an empty list of urls and no uris for a login with no website', () => {
    const fields = sitesFields([newSiteRow()]);
    expect(fields['urls']).toEqual([]);
    expect(fields['uris']).toBeUndefined();
    expect(fields['websites']).toBeUndefined();
  });

  it('are checked: a host, a web address and a package name are fine, javascript: and spaces are not', () => {
    const problem = (uri: string, match: MatchRule = 'domain') => siteProblem(newSiteRow(uri, match));
    expect(problem('')).toBeUndefined();
    expect(problem('github.com')).toBeUndefined();
    expect(problem('localhost:8080')).toBeUndefined();
    expect(problem('https://github.com/login')).toBeUndefined();
    expect(problem('androidapp://com.github.android')).toBeUndefined();
    expect(problem('javascript:alert(1)')).toBe('itemForm.websites.bad');
    expect(problem('data:text/html,x')).toBe('itemForm.websites.bad');
    expect(problem('two words')).toBe('itemForm.websites.bad');
    expect(problem('^a+$', 'regex')).toBeUndefined();
    expect(problem('(', 'regex')).toBe('itemForm.websites.badRegex');
  });
});

describe('loginFields', () => {
  it('keeps what other apps wrote, and writes the websites as the form shows them', () => {
    const existing = login({
      name: 'Old',
      username: 'u',
      password: 'p',
      urls: ['https://a.example', 'https://b.example'],
      favorite: true,
      passwordHistory: [{ password: 'x', replacedAt: '2026-01-01T00:00:00Z' }],
    });
    const defaults = loginDefaults(existing);
    expect(defaults).toMatchObject({ name: 'Old', favorite: true });
    expect(defaults.websites.map((row) => row.uri)).toEqual(['https://a.example', 'https://b.example']);
    const websites = [{ ...defaults.websites[0]!, uri: 'https://c.example' }, defaults.websites[1]!];
    const fields = loginFields({ ...defaults, websites, notes: '' }, existing);
    expect(fields['urls']).toEqual(['https://c.example', 'https://b.example']);
    expect(fields['notes']).toBeUndefined();
    expect('passwordHistory' in fields).toBe(false);
  });

  it('writes no fields and no links member for an item that has none, so it stays as it was', () => {
    const existing = login({ name: 'Plain', username: 'u', password: 'p', urls: ['https://a.example'] });
    const fields = loginFields(loginDefaults(existing), existing);
    expect(fields['fields']).toBeUndefined();
    expect(fields['links']).toBeUndefined();
  });
});
