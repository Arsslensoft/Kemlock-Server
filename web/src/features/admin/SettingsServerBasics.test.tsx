import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import type { ServerAddress } from '@/api/admin';
import { renderWithIntl } from '@/test/render';
import { setting } from './fixtures';
import { SettingsView } from './Settings';
import { groupsOf } from './settingsForm';

const BASICS = [
  setting({ key: 'push_enabled', group: 'push', kind: 'bool', default: 'false', value: 'false' }),
  setting({ key: 'push_installation_id', group: 'push', kind: 'secret' }),
  setting({
    key: 'push_installation_key',
    group: 'push',
    kind: 'secret',
    secretSet: true,
    source: 'env',
    readOnly: true,
  }),
  setting({ key: 'kemlock_push_relay', group: 'push', kind: 'bool', default: 'false', value: 'false' }),
  setting({
    key: 'backup_schedule',
    group: 'backups',
    kind: 'choice',
    choices: ['off', 'nightly', '6h'],
    default: 'off',
    value: 'off',
  }),
  setting({ key: 'backup_destination', group: 'backups', kind: 'text', maxLength: 200, default: '', value: '' }),
];

const ADDRESS: ServerAddress = {
  domain: 'https://vault.example.org',
  recordedDomain: 'https://vault.example.org',
  differs: false,
  dataFolder: '/data',
};

function view(address?: ServerAddress) {
  const onSave = vi.fn();
  renderWithIntl(<SettingsView settings={BASICS} onSave={onSave} address={address} />);
  return { onSave };
}

describe('push and backups in Settings', () => {
  it('puts Push and Backups right after Email in the console\'s order', () => {
    const later = setting({ key: 'smtp_host', group: 'smtp', kind: 'text' });
    expect(groupsOf([...BASICS, later]).map((g) => g.group)).toEqual(['smtp', 'push', 'backups']);
  });

  it('shows a card for each, and says what the environment sets without letting it be edited', () => {
    view();
    expect(screen.getByRole('heading', { name: 'Push' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Backups' })).toBeInTheDocument();
    const key = screen.getByLabelText('Bitwarden installation key');
    expect(key).toBeDisabled();
    expect(key).toHaveValue('');
    expect(screen.getByText(/Set by PUSH_INSTALLATION_KEY/)).toBeInTheDocument();
  });

  it('saves a secret only when one is typed, with its own card', async () => {
    const { onSave } = view();
    const user = userEvent.setup();
    const push = screen.getByRole('region', { name: 'Push' });
    await user.type(within(push).getByLabelText('Bitwarden installation id'), 'abc-123');
    await user.click(within(push).getByRole('button', { name: /^Save/ }));
    expect(onSave).toHaveBeenCalledWith({ push_installation_id: 'abc-123' }, 'push');
  });

  it('saves the backup schedule with its own card', async () => {
    const { onSave } = view();
    const user = userEvent.setup();
    const backups = screen.getByRole('region', { name: 'Backups' });
    await user.selectOptions(within(backups).getByRole('combobox'), 'nightly');
    await user.click(within(backups).getByRole('button', { name: /^Save/ }));
    expect(onSave).toHaveBeenCalledWith({ backup_schedule: 'nightly' }, 'backups');
  });
});

describe('the address card', () => {
  it('shows the address in use, the one recorded and the data folder, and says they are configuration', () => {
    view(ADDRESS);
    const card = screen.getByRole('region', { name: 'Address and data folder' });
    expect(within(card).getByText('Address in use (DOMAIN)').nextElementSibling).toHaveTextContent('https://vault.example.org');
    expect(within(card).getByText('Address chosen at setup').nextElementSibling).toHaveTextContent('https://vault.example.org');
    expect(within(card).getByText('/data')).toBeInTheDocument();
    expect(within(card).getByText(/can't be changed here/)).toBeInTheDocument();
    expect(within(card).queryByRole('button', { name: /^Save/ })).not.toBeInTheDocument();
    expect(within(card).queryByRole('alert')).not.toBeInTheDocument();
  });

  it('warns when the address chosen at setup is not the one in use', () => {
    view({ ...ADDRESS, recordedDomain: 'https://old.example.org', differs: true });
    const card = screen.getByRole('region', { name: 'Address and data folder' });
    expect(within(card).getByText(/not the one in use/)).toBeInTheDocument();
    expect(within(card).getByText('https://old.example.org')).toBeInTheDocument();
  });

  it('is left out when the server does not say', () => {
    view();
    expect(screen.queryByRole('region', { name: 'Address and data folder' })).not.toBeInTheDocument();
  });
});
