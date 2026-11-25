import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { renderWithIntl } from '@/test/render';
import { ItemMenu } from './ItemMenu';

function setup(props: Partial<Parameters<typeof ItemMenu>[0]> = {}) {
  const onAction = vi.fn();
  renderWithIntl(<ItemMenu name="GitHub" trashed={false} websites copy onAction={onAction} {...props} />);
  const trigger = screen.getByRole('button', { name: 'More actions for GitHub' });
  return { onAction, trigger, user: userEvent.setup() };
}

const names = () => screen.getAllByRole('menuitem').map((entry) => entry.textContent);

describe('the ⋯ menu', () => {
  it('is one button that names the item and says it opens a menu', () => {
    const { trigger } = setup();
    expect(trigger).toHaveAttribute('aria-haspopup');
    expect(trigger).toHaveAttribute('aria-expanded', 'false');
    expect(screen.queryByRole('menu')).not.toBeInTheDocument();
  });

  it('lists, in order, websites and rules, move, copy, what the server holds, and Move to Trash after a divider', async () => {
    const { trigger, user } = setup();
    await user.click(trigger);
    const menu = await screen.findByRole('menu', { name: 'More actions for GitHub' });
    expect(names()).toEqual([
      'Websites and rules',
      'Move to a space',
      'Make a copy',
      'What the server holds',
      'Move to TrashKept there for 30 days. You can restore it.',
    ]);
    const divider = screen.getByRole('separator');
    const entries = screen.getAllByRole('menuitem');
    expect(divider.compareDocumentPosition(entries[4] as HTMLElement) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(divider.compareDocumentPosition(entries[3] as HTMLElement) & Node.DOCUMENT_POSITION_PRECEDING).toBeTruthy();
    expect(menu).toContainElement(divider);
  });

  it('says in words how long the Trash keeps it', async () => {
    const { trigger, user } = setup();
    await user.click(trigger);
    const trash = await screen.findByRole('menuitem', { name: 'Move to Trash' });
    expect(trash).toHaveAccessibleDescription('Kept there for 30 days. You can restore it.');
    expect(trash).toHaveClass('im-danger');
  });

  it('leaves out websites and rules for anything but a login, and the copy for what cannot be copied', async () => {
    const { trigger, user } = setup({ websites: false, copy: false });
    await user.click(trigger);
    await screen.findByRole('menu');
    expect(names()).toEqual([
      'Move to a space',
      'What the server holds',
      'Move to TrashKept there for 30 days. You can restore it.',
    ]);
  });

  it('holds only what the server holds for an item in the Trash', async () => {
    const { trigger, user } = setup({ trashed: true });
    await user.click(trigger);
    await screen.findByRole('menu');
    expect(names()).toEqual(['What the server holds']);
    expect(screen.queryByRole('separator')).not.toBeInTheDocument();
  });

  it('acts on the choice after the menu has closed and focus is back on the button', async () => {
    const { onAction, trigger, user } = setup();
    await user.click(trigger);
    await user.click(await screen.findByRole('menuitem', { name: 'Make a copy' }));
    await waitFor(() => expect(onAction).toHaveBeenCalledWith('copy'));
    expect(onAction).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole('menu')).not.toBeInTheDocument();
    expect(trigger).toHaveFocus();
  });

  it.each([
    ['Websites and rules', 'websites'],
    ['Move to a space', 'move'],
    ['What the server holds', 'server'],
    ['Move to Trash', 'trash'],
  ])('reports %s as %s', async (label, action) => {
    const { onAction, trigger, user } = setup();
    await user.click(trigger);
    await user.click(await screen.findByRole('menuitem', { name: label }));
    await waitFor(() => expect(onAction).toHaveBeenCalledWith(action));
  });

  it('opens from the keyboard, moves with the arrows and chooses with Enter', async () => {
    const { onAction, trigger, user } = setup();
    trigger.focus();
    await user.keyboard('{Enter}');
    await screen.findByRole('menu');
    expect(screen.getByRole('menuitem', { name: 'Websites and rules' })).toHaveFocus();
    await user.keyboard('{ArrowDown}{ArrowDown}{ArrowDown}');
    expect(screen.getByRole('menuitem', { name: 'What the server holds' })).toHaveFocus();
    await user.keyboard('{Enter}');
    await waitFor(() => expect(onAction).toHaveBeenCalledWith('server'));
    expect(trigger).toHaveFocus();
  });

  it('closes on Escape and gives focus back to the button, choosing nothing', async () => {
    const { onAction, trigger, user } = setup();
    trigger.focus();
    await user.keyboard('{Enter}');
    await screen.findByRole('menu');
    await user.keyboard('{Escape}');
    await waitFor(() => expect(screen.queryByRole('menu')).not.toBeInTheDocument());
    // React Aria gives focus back on the next frame.
    await waitFor(() => expect(trigger).toHaveFocus());
    expect(trigger).toHaveAttribute('aria-expanded', 'false');
    // Give a stray action time to show up, if there were one.
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(onAction).not.toHaveBeenCalled();
  });

  it('closes on Escape after being opened with the pointer too', async () => {
    const { trigger, user } = setup();
    await user.click(trigger);
    await screen.findByRole('menu');
    await user.keyboard('{Escape}');
    await waitFor(() => expect(screen.queryByRole('menu')).not.toBeInTheDocument());
    await waitFor(() => expect(trigger).toHaveFocus());
  });
});
