import { screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { renderWithIntl } from '@/test/render';
import { Way } from './Unlock';

describe('Way', () => {
  it('is pressable once it has something to do', async () => {
    const onPress = vi.fn();
    renderWithIntl(<Way icon="device" title="Approve" hint="from a device" onPress={onPress} />);
    const button = screen.getByRole('button', { name: /Approve/ });
    expect(button).toBeEnabled();
    await userEvent.setup({ delay: null }).click(button);
    expect(onPress).toHaveBeenCalledOnce();
  });

  it('stays off with no action', () => {
    renderWithIntl(<Way icon="key" title="Kit" hint="soon" />);
    expect(screen.getByRole('button', { name: /Kit/ })).toBeDisabled();
  });
});
