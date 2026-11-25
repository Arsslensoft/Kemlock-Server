import { screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { renderWithIntl } from '@/test/render';
import { Alternatives } from './SignInScreen';

const handlers = { onSso: vi.fn(), onPasskey: vi.fn(), onDevice: vi.fn(), onPassword: vi.fn() };

describe('Alternatives', () => {
  it('stacks two methods as full-width buttons', () => {
    const { container } = renderWithIntl(
      <Alternatives methods={['password']} passkey={false} {...handlers} />,
    );
    expect(container.querySelector('.tiles')).toBeNull();
    expect(screen.getByRole('button', { name: 'Sign in with another device' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Use my master password' })).toBeInTheDocument();
  });

  it('keeps SSO full width and tiles the rest', async () => {
    const { container } = renderWithIntl(
      <Alternatives methods={['sso', 'passkey', 'password']} provider="Okta" passkey {...handlers} />,
    );
    expect(screen.getByRole('button', { name: /Okta/ }).closest('.tiles')).toBeNull();
    const tiles = container.querySelector('.tiles');
    expect(tiles).toHaveAttribute('data-count', '3');
    expect(tiles?.querySelectorAll('button')).toHaveLength(3);
    expect(screen.getByText('Master password')).toBeInTheDocument();
    await userEvent.setup({ delay: null }).click(screen.getByRole('button', { name: 'Sign in with a passkey' }));
    expect(handlers.onPasskey).toHaveBeenCalled();
  });
});
