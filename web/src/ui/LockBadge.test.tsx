import { screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import { renderWithIntl } from '@/test/render';
import { LockBadge } from './LockBadge';

const TEXT = /Encrypted on the device that saved it/;

function tooltip() {
  return screen.getByRole('tooltip');
}
const shown = () => tooltip().parentElement?.hasAttribute('data-open');

describe('LockBadge', () => {
  it('is a button named "End-to-end encrypted" that the tooltip describes', () => {
    renderWithIntl(<LockBadge />);
    const button = screen.getByRole('button', { name: 'End-to-end encrypted' });
    expect(button).toHaveAccessibleDescription(/Encrypted on the device that saved it/);
    expect(tooltip()).toHaveTextContent('End-to-end encrypted');
    expect(tooltip()).toHaveTextContent(TEXT);
    expect(shown()).toBe(false);
  });

  it('shows the tooltip while the pointer is over it, and hides it when the pointer leaves', async () => {
    renderWithIntl(<LockBadge />);
    const user = userEvent.setup();
    await user.hover(screen.getByRole('button', { name: 'End-to-end encrypted' }));
    expect(shown()).toBe(true);
    await user.unhover(screen.getByRole('button', { name: 'End-to-end encrypted' }));
    expect(shown()).toBe(false);
  });

  it('keeps the tooltip while the pointer is on the tooltip itself', async () => {
    renderWithIntl(<LockBadge />);
    const user = userEvent.setup();
    await user.hover(screen.getByRole('button', { name: 'End-to-end encrypted' }));
    await user.hover(tooltip());
    expect(shown()).toBe(true);
  });

  it('shows the tooltip on keyboard focus and hides it on blur', async () => {
    renderWithIntl(<LockBadge />);
    const user = userEvent.setup();
    await user.tab();
    expect(screen.getByRole('button', { name: 'End-to-end encrypted' })).toHaveFocus();
    expect(shown()).toBe(true);
    await user.tab();
    expect(shown()).toBe(false);
  });

  it('closes on Escape without taking focus away, and comes back on the next focus', async () => {
    renderWithIntl(<LockBadge />);
    const user = userEvent.setup();
    await user.tab();
    await user.keyboard('{Escape}');
    expect(shown()).toBe(false);
    expect(screen.getByRole('button', { name: 'End-to-end encrypted' })).toHaveFocus();
    await user.tab();
    await user.tab({ shift: true });
    expect(shown()).toBe(true);
  });
});
