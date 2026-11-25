import { act, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import { I18nProvider } from '@/i18n';
import { LockBadge } from './LockBadge';

function show(body?: 'lists.enc.body') {
  const view = render(
    <I18nProvider>
      <LockBadge {...(body ? { body } : {})} />
    </I18nProvider>,
  );
  return view.container.querySelector('.enc') as HTMLElement;
}

describe('LockBadge', () => {
  it('is a button named "End-to-end encrypted" that the tooltip describes', () => {
    show();
    const lock = screen.getByRole('button', { name: 'End-to-end encrypted' });
    expect(lock).toHaveAccessibleDescription(/Encrypted on the device that saved it/);
  });

  it('says what the list pages say when they ask for their own text', () => {
    show('lists.enc.body');
    expect(screen.getByRole('button', { name: 'End-to-end encrypted' })).toHaveAccessibleDescription(
      /Every item is encrypted on your devices first, with ML-KEM-1024 and X25519, then AES-256-GCM\. The server keeps ciphertext only and can't open any of it\./,
    );
  });

  it('shows its tooltip on hover and hides it when the pointer leaves', async () => {
    const badge = show();
    const user = userEvent.setup();
    expect(badge).not.toHaveAttribute('data-open');
    await user.hover(screen.getByRole('button', { name: 'End-to-end encrypted' }));
    expect(badge).toHaveAttribute('data-open');
    await user.unhover(screen.getByRole('button', { name: 'End-to-end encrypted' }));
    expect(badge).not.toHaveAttribute('data-open');
  });

  it('shows its tooltip on keyboard focus too, and hides it when focus leaves', async () => {
    const badge = show();
    const user = userEvent.setup();
    await user.tab();
    const lock = screen.getByRole('button', { name: 'End-to-end encrypted' });
    expect(lock).toHaveFocus();
    expect(badge).toHaveAttribute('data-open');
    act(() => lock.blur());
    expect(badge).not.toHaveAttribute('data-open');
  });

  it('closes with Escape while it keeps the focus, and opens again on the next focus', async () => {
    const badge = show();
    const user = userEvent.setup();
    await user.tab();
    const lock = screen.getByRole('button', { name: 'End-to-end encrypted' });
    await user.keyboard('{Escape}');
    expect(badge).not.toHaveAttribute('data-open');
    expect(lock).toHaveFocus();
    act(() => lock.blur());
    act(() => lock.focus());
    expect(badge).toHaveAttribute('data-open');
  });
});
