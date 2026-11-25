import { screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { renderWithIntl } from '@/test/render';
import { SetupServerForm, defaultBasics } from './SetupServer';

describe('SetupServerForm', () => {
  it('shows placeholders and an inline error for a bad port', async () => {
    const onSubmit = vi.fn();
    renderWithIntl(<SetupServerForm initial={defaultBasics('https://vault.example.co')} onSubmit={onSubmit} />);
    const user = userEvent.setup({ delay: null });
    expect(screen.getByPlaceholderText('smtp.example.com')).toBeInTheDocument();
    expect(screen.getByLabelText('Port')).toHaveAttribute('maxlength', '5');
    await user.type(screen.getByLabelText('SMTP server'), 'smtp.example.co');
    await user.clear(screen.getByLabelText('Port'));
    await user.type(screen.getByLabelText('Port'), '99999');
    await user.click(document.querySelector<HTMLButtonElement>('button[type=submit]')!);
    expect(await screen.findByText(/A port is a number/, {}, { timeout: 4000 })).toBeInTheDocument();
    expect(onSubmit).not.toHaveBeenCalled();
  });
});
