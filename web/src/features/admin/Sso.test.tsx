import { screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { renderWithIntl } from '@/test/render';
import { DOMAINS, SPACES, SSO } from './fixtures';
import { SsoView, checkSso, formFrom, updateFrom } from './Sso';

describe('the SSO form', () => {
  it('starts from the saved config, with the scopes on one line and no secret', () => {
    const form = formFrom(SSO);
    expect(form.clientSecret).toBe('');
    expect(form.scopes).toBe('openid email profile groups');
    expect(form).not.toHaveProperty('callbackUrl');
    expect(form).not.toHaveProperty('clientSecretSet');
  });

  it('sends a secret only when one was typed, or when it is to be removed', () => {
    const base = updateFrom(formFrom(SSO));
    expect(base).not.toHaveProperty('clientSecret');
    expect(base).not.toHaveProperty('clearClientSecret');
    expect(base.scopes).toEqual(['openid', 'email', 'profile', 'groups']);
    expect(updateFrom({ ...formFrom(SSO), clientSecret: 's3cret' }).clientSecret).toBe('s3cret');
    expect(updateFrom({ ...formFrom(SSO), clearClientSecret: true }).clearClientSecret).toBe(true);
    // A typed secret wins over removing it, as it does on the server.
    const both = updateFrom({ ...formFrom(SSO), clientSecret: 'x', clearClientSecret: true });
    expect(both).not.toHaveProperty('clearClientSecret');
  });

  it('checks what an enabled provider needs, and nothing when it is off', () => {
    const bad = { ...formFrom(SSO), issuer: 'id.example.co', clientId: ' ', scopes: 'email' };
    expect(checkSso(bad)).toEqual({
      issuer: 'error.url',
      clientId: 'error.required',
      scopes: 'admin.sso.error.scopes',
    });
    expect(checkSso({ ...bad, enabled: false })).toEqual({});
    expect(checkSso(formFrom(SSO))).toEqual({});
  });
});

describe('SsoView', () => {
  function view(props: Partial<Parameters<typeof SsoView>[0]> = {}) {
    const handlers = {
      onSave: vi.fn(),
      onAddDomain: vi.fn(),
      onVerifyDomain: vi.fn(),
      onRemoveDomain: vi.fn(),
    };
    renderWithIntl(<SsoView config={SSO} spaces={SPACES} domains={DOMAINS} {...handlers} {...props} />);
    return handlers;
  }

  it('shows the redirect address to register, and keeps the secret out of the page', () => {
    view();
    expect(screen.getByText(SSO.callbackUrl)).toBeInTheDocument();
    const secret = screen.getByLabelText('Client secret');
    expect(secret).toHaveValue('');
    expect(secret).toHaveAttribute('placeholder', 'Kept. Type to replace it.');
  });

  it('refuses to save a bad issuer and says why', async () => {
    const { onSave } = view();
    const user = userEvent.setup();
    const issuer = screen.getByLabelText('Issuer URL');
    await user.clear(issuer);
    await user.type(issuer, 'not a url');
    await user.click(screen.getByRole('button', { name: 'Save' }));
    expect(await screen.findByText(/Type a web address that starts with/)).toBeInTheDocument();
    expect(onSave).not.toHaveBeenCalled();
  });

  it('saves the changes, and the secret only if typed', async () => {
    const { onSave } = view();
    const user = userEvent.setup();
    await user.clear(screen.getByLabelText('Name people see'));
    await user.type(screen.getByLabelText('Name people see'), 'Staff');
    await user.click(screen.getByRole('button', { name: 'Save' }));
    expect(onSave).toHaveBeenCalledTimes(1);
    const first = onSave.mock.calls[0]?.[0] as Record<string, unknown>;
    expect(first['displayName']).toBe('Staff');
    expect(first).not.toHaveProperty('clientSecret');
    await user.type(screen.getByLabelText('Client secret'), 'new-secret');
    await user.click(screen.getByRole('button', { name: 'Save' }));
    expect((onSave.mock.calls[1]?.[0] as Record<string, unknown>)['clientSecret']).toBe('new-secret');
  });

  it('adds and removes a group rule', async () => {
    const { onSave } = view();
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Add a rule' }));
    expect(screen.getAllByLabelText('Provider group')).toHaveLength(2);
    await user.click(screen.getByRole('button', { name: 'Remove the rule for engineering' }));
    expect(screen.getAllByLabelText('Provider group')).toHaveLength(1);
    await user.click(screen.getByRole('button', { name: 'Save' }));
    const saved = onSave.mock.calls[0]?.[0] as { groupRules: Array<{ group: string; space: string; role: string; collections: string[] }> };
    expect(saved.groupRules).toEqual([{ group: '', space: 's1aaaaaaaa', role: 'member', collections: [] }]);
  });

  it('flips a sign-in option', async () => {
    const { onSave } = view();
    const user = userEvent.setup();
    await user.click(screen.getByRole('checkbox', { name: /Only accept people whose email domain is verified here/ }));
    await user.click(screen.getByRole('button', { name: 'Save' }));
    const saved = onSave.mock.calls[0]?.[0] as { requireVerifiedDomain: boolean };
    expect(saved.requireVerifiedDomain).toBe(false);
  });

  it('discards edits', async () => {
    view();
    const user = userEvent.setup();
    const name = screen.getByLabelText('Name people see');
    await user.type(name, ' edited');
    await user.click(screen.getByRole('button', { name: 'Discard' }));
    expect(screen.getByLabelText('Name people see')).toHaveValue('Example Co');
  });

  it('lists the email domains, and claims, checks and removes them at once', async () => {
    const { onAddDomain, onVerifyDomain, onRemoveDomain } = view();
    expect(screen.getByText('Verified by DNS')).toBeInTheDocument();
    expect(screen.getByText('Add the TXT record kemlock-verify=def456')).toBeInTheDocument();
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Check the DNS record of example.dev' }));
    expect(onVerifyDomain).toHaveBeenCalledWith('example.dev');
    expect(screen.queryByRole('button', { name: 'Check the DNS record of example.co' })).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Remove example.co' }));
    expect(onRemoveDomain).toHaveBeenCalledWith('example.co');
    await user.type(screen.getByLabelText('Add a domain'), 'Example.org');
    await user.click(screen.getByRole('button', { name: 'Add' }));
    expect(onAddDomain).toHaveBeenCalledWith('example.org');
  });

  it('keeps Save disabled and Discard away until the form changes', async () => {
    view();
    const user = userEvent.setup();
    expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled();
    expect(screen.queryByRole('button', { name: 'Discard' })).not.toBeInTheDocument();
    await user.type(screen.getByLabelText('Name people see'), 'x');
    expect(screen.getByRole('button', { name: 'Save' })).toBeEnabled();
    expect(screen.getByRole('button', { name: 'Discard' })).toBeInTheDocument();
  });

  it('marks a bad issuer invalid and describes it by its error', async () => {
    view();
    const user = userEvent.setup();
    const issuer = screen.getByLabelText('Issuer URL');
    await user.clear(issuer);
    await user.type(issuer, 'nope');
    await user.click(screen.getByRole('button', { name: 'Save' }));
    expect(issuer).toHaveAttribute('aria-invalid', 'true');
    expect(issuer).toHaveAccessibleDescription(/Type a web address/);
    expect(issuer).toBeRequired();
  });
});
