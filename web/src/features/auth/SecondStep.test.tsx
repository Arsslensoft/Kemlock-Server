import { screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { renderWithIntl } from '@/test/render';
import { SecondStep } from './SecondStep';

function show(methods: string[], source: 'password' | 'sso' = 'password') {
  const onCode = vi.fn();
  const onSecurityKey = vi.fn();
  renderWithIntl(<SecondStep methods={methods} source={source} onCode={onCode} onSecurityKey={onSecurityKey} />);
  return { onCode, onSecurityKey };
}

describe('SecondStep', () => {
  it('asks only for the security key when that is the only method', async () => {
    const { onSecurityKey } = show(['webauthn']);
    expect(screen.queryByLabelText('Code from your authenticator app')).toBeNull();
    await userEvent.setup({ delay: null }).click(screen.getByRole('button', { name: 'Use your security key' }));
    expect(onSecurityKey).toHaveBeenCalled();
  });

  it('asks only for the code when the account has an authenticator app', () => {
    show(['totp']);
    expect(screen.getByLabelText('Code from your authenticator app')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Use your security key' })).toBeNull();
  });

  it('offers both when the account has both', () => {
    show(['totp', 'webauthn'], 'sso');
    expect(screen.getByLabelText('Code from your authenticator app')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Use your security key' })).toBeInTheDocument();
  });

  it('falls back to the code box for a method this page cannot do', () => {
    show(['email']);
    expect(screen.getByLabelText('Code from your authenticator app')).toBeInTheDocument();
  });
});
