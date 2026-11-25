import { screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { renderWithIntl } from '@/test/render';
import { ConfirmDialog } from './ConfirmDialog';

function open(props: Partial<Parameters<typeof ConfirmDialog>[0]> = {}) {
  const onConfirm = vi.fn();
  const onOpenChange = vi.fn();
  renderWithIntl(
    <ConfirmDialog
      isOpen
      onOpenChange={onOpenChange}
      title="Delete it?"
      confirmLabel="Delete"
      onConfirm={onConfirm}
      {...props}
    >
      <p>It can't be undone.</p>
    </ConfirmDialog>,
  );
  return { onConfirm, onOpenChange };
}

describe('ConfirmDialog', () => {
  it('confirms from the danger button', async () => {
    const { onConfirm } = open();
    await userEvent.setup().click(screen.getByRole('button', { name: 'Delete' }));
    expect(onConfirm).toHaveBeenCalledOnce();
  });

  it('shows why it failed inside the dialog, which stays open', () => {
    open({ error: 'Something went wrong' });
    expect(screen.getByRole('dialog')).toHaveTextContent('Delete it?');
    expect(screen.getByRole('alert')).toHaveTextContent('Something went wrong');
  });

  it('shows no alert without an error', () => {
    open();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });

  it('disables Cancel and Delete while it is working', () => {
    open({ pending: true });
    expect(screen.getByRole('button', { name: 'Cancel' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Delete' })).toBeDisabled();
  });
});
