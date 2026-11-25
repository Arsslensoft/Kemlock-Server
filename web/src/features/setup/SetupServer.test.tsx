import { screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { renderWithIntl } from '@/test/render';
import { SetupServerForm, basicsBody, defaultBasics } from './SetupServer';

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

describe('basicsBody', () => {
  it('sends push, backups and the address along with who may join and the mail', () => {
    const values = {
      ...defaultBasics('https://vault.example.co'),
      join: 'domains' as const,
      joinDomains: 'example.co',
      push: true,
      backups: true,
      backupEvery: 'six-hours' as const,
      backupKeep: '14' as const,
      backupRecipient: 'age1abc',
      folder: '/data/files',
    };
    expect(basicsBody(values)).toEqual({
      join: 'domains',
      joinDomains: 'example.co',
      mailHost: '',
      mailPort: '587',
      mailSecurity: 'starttls',
      mailFrom: '',
      mailUser: '',
      address: 'https://vault.example.co',
      push: true,
      backups: true,
      backupEvery: 'six-hours',
      backupKeep: '14',
      backupRecipient: 'age1abc',
    });
  });

  it('never sends the files folder, which stays configuration', () => {
    expect(Object.keys(basicsBody(defaultBasics('https://vault.example.co')))).not.toContain('folder');
  });
});
