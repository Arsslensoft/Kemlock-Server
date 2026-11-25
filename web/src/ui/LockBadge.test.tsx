import { fireEvent, screen } from '@testing-library/react';
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

  it('says what the list pages say when they ask for their own text', () => {
    renderWithIntl(<LockBadge body="lists.enc.body" />);
    expect(screen.getByRole('button', { name: 'End-to-end encrypted' })).toHaveAccessibleDescription(
      /Every item is encrypted on your devices first, with ML-KEM-1024 and X25519, then AES-256-GCM. The server keeps ciphertext only and can't open any of it./,
    );
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

  // What a finger does: no hover, then a press that also focuses the button, then the click.
  function tap(button: HTMLElement) {
    fireEvent.pointerOver(button, { pointerType: 'touch' });
    fireEvent.pointerDown(button, { pointerType: 'touch' });
    button.focus();
    fireEvent.pointerUp(button, { pointerType: 'touch' });
    fireEvent.click(button);
  }

  it('opens on a tap and closes on the next, though a finger has no hover and the press focuses it', () => {
    renderWithIntl(<LockBadge />);
    const button = screen.getByRole('button', { name: 'End-to-end encrypted' });
    tap(button);
    expect(shown()).toBe(true);
    tap(button);
    expect(shown()).toBe(false);
  });

  it('closes when the person taps elsewhere', () => {
    renderWithIntl(<LockBadge />);
    const button = screen.getByRole('button', { name: 'End-to-end encrypted' });
    tap(button);
    button.blur();
    expect(shown()).toBe(false);
  });

  it('closes a tooltip that hovering opened when the lock is clicked, and Escape closes a tapped one', async () => {
    renderWithIntl(<LockBadge />);
    const user = userEvent.setup();
    const button = screen.getByRole('button', { name: 'End-to-end encrypted' });
    await user.click(button);
    expect(shown()).toBe(false);
    button.blur();
    tap(button);
    expect(shown()).toBe(true);
    await user.keyboard('{Escape}');
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
