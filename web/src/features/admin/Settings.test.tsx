import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { renderWithIntl } from '@/test/render';
import { SETTINGS, setting } from './fixtures';
import { SettingsView } from './Settings';
import { changesOf, draftOf, errorOf, groupsOf } from './settingsForm';

function view(props: Partial<Parameters<typeof SettingsView>[0]> = {}) {
  const onSave = vi.fn();
  renderWithIntl(<SettingsView settings={SETTINGS} onSave={onSave} {...props} />);
  return { onSave };
}

/** The Save button of the card with this title. */
function saveOf(title: string) {
  return within(screen.getByRole('region', { name: title })).getByRole('button', { name: 'Save' });
}

describe('the settings form', () => {
  it('groups the catalogue in the console\'s order and puts a group it does not know last', () => {
    const extra = setting({ key: 'new_thing', group: 'later', kind: 'bool' });
    expect(groupsOf([extra, ...SETTINGS]).map((g) => g.group)).toEqual([
      'smtp',
      'signups',
      'files',
      'trash',
      'retention',
      'rate-limits',
      'security',
      'later',
    ]);
  });

  it('starts from the values in effect, with a secret empty', () => {
    const draft = draftOf(SETTINGS);
    expect(draft['smtp_host']).toBe('smtp.example.org');
    expect(draft['smtp_password']).toBe('');
    expect(draft['signups_allowed']).toBe('false');
  });

  it('checks a typed value against the kind and bounds the server states', () => {
    const port = SETTINGS.find((s) => s.key === 'smtp_port');
    const security = SETTINGS.find((s) => s.key === 'smtp_security');
    if (!port || !security) throw new Error('fixture');
    expect(errorOf(port, '70000')).toBe('admin.settings.error.number');
    expect(errorOf(port, '25.5')).toBe('admin.settings.error.number');
    expect(errorOf(port, '465')).toBeUndefined();
    expect(errorOf(security, 'plain')).toBe('admin.settings.error.choice');
    expect(errorOf(security, 'force_tls')).toBeUndefined();
  });

  it('sends only what changed, never an environment setting, and a secret only when typed', () => {
    const smtp = groupsOf(SETTINGS)[0]?.settings ?? [];
    expect(changesOf(smtp, draftOf(smtp))).toEqual({ ok: true, changes: {} });
    const edited = { ...draftOf(smtp), smtp_host: ' mail.example.org ', smtp_password: 'hunter2' };
    expect(changesOf(smtp, edited)).toEqual({
      ok: true,
      changes: { smtp_host: 'mail.example.org', smtp_password: 'hunter2' },
    });
    const files = groupsOf(SETTINGS).find((g) => g.group === 'files')?.settings ?? [];
    expect(changesOf(files, { max_file_size_mib: '5' })).toEqual({ ok: true, changes: {} });
    expect(changesOf(smtp, { ...draftOf(smtp), smtp_port: '0' })).toEqual({
      ok: false,
      errors: { smtp_port: 'admin.settings.error.number' },
    });
  });
});

describe('SettingsView', () => {
  it('shows a card for every group', () => {
    view();
    for (const name of ['Email', 'Who can make an account', 'Files', 'Trash', 'Log retention', 'Rate limits', 'Security contact']) {
      expect(screen.getByRole('heading', { name })).toBeInTheDocument();
    }
  });

  it('keeps secrets out of the page', () => {
    view();
    const password = screen.getByLabelText('SMTP password');
    expect(password).toHaveValue('');
    expect(password).toHaveAttribute('placeholder', 'Kept. Type to replace it.');
  });

  it('shows what the environment sets, and does not let it be edited', () => {
    view();
    const largest = screen.getByLabelText('Largest file, in MiB');
    expect(largest).toHaveValue(250);
    expect(largest).toBeDisabled();
    expect(screen.getByText(/Set by KEMLOCK_MAX_FILE_SIZE_MIB/)).toBeInTheDocument();
    const files = screen.getByRole('region', { name: 'Files' });
    expect(within(files).queryByRole('button', { name: 'Save' })).not.toBeInTheDocument();
  });

  it('refuses a bad port without sending anything', async () => {
    const { onSave } = view();
    const user = userEvent.setup();
    const port = screen.getByLabelText('SMTP port');
    await user.clear(port);
    await user.type(port, '70000');
    await user.click(saveOf('Email'));
    expect(await screen.findByText(/Type a whole number from 1 to 65535/)).toBeInTheDocument();
    expect(onSave).not.toHaveBeenCalled();
  });

  it('saves one group on its own, with only what changed', async () => {
    const { onSave } = view();
    const user = userEvent.setup();
    const host = screen.getByLabelText('SMTP server');
    await user.clear(host);
    await user.type(host, 'mail.example.org');
    await user.click(saveOf('Email'));
    expect(onSave).toHaveBeenCalledTimes(1);
    expect(onSave).toHaveBeenLastCalledWith({ smtp_host: 'mail.example.org' }, 'smtp');
    await user.type(screen.getByLabelText('SMTP password'), 'hunter2');
    await user.click(saveOf('Email'));
    expect(onSave).toHaveBeenLastCalledWith({ smtp_host: 'mail.example.org', smtp_password: 'hunter2' }, 'smtp');
  });

  it('flips a switch and saves it with its group', async () => {
    const { onSave } = view();
    const user = userEvent.setup();
    await user.click(screen.getByRole('switch', { name: 'Anyone may make an account' }));
    await user.click(saveOf('Who can make an account'));
    expect(onSave).toHaveBeenCalledWith({ signups_allowed: 'true' }, 'signups');
  });

  it('says which group was saved', () => {
    view({ savedGroup: 'trash' });
    expect(screen.getAllByText('Saved.')).toHaveLength(1);
  });

  it('blocks Save and marks the field while a value is wrong, then lets go when it is right', async () => {
    const { onSave } = view();
    const user = userEvent.setup();
    const port = screen.getByLabelText('SMTP port');
    await user.clear(port);
    await user.type(port, '0');
    expect(port).toHaveAttribute('aria-invalid', 'true');
    expect(port).toHaveAccessibleDescription(/Type a whole number from 1 to 65535/);
    await user.click(saveOf('Email'));
    expect(onSave).not.toHaveBeenCalled();
    await user.clear(port);
    await user.type(port, '465');
    expect(port).not.toHaveAttribute('aria-invalid');
    await user.click(saveOf('Email'));
    expect(onSave).toHaveBeenCalledWith({ smtp_port: '465' }, 'smtp');
  });

  it('refuses a host with a slash', async () => {
    const { onSave } = view();
    const user = userEvent.setup();
    const host = screen.getByLabelText('SMTP server');
    await user.clear(host);
    await user.type(host, 'https://mail.example.org');
    expect(await screen.findByText(/without https:[/][/] or a slash/)).toBeInTheDocument();
    await user.click(saveOf('Email'));
    expect(onSave).not.toHaveBeenCalled();
  });

  it('keeps Save disabled and Discard away while the section is clean', async () => {
    view();
    const user = userEvent.setup();
    const email = screen.getByRole('region', { name: 'Email' });
    expect(saveOf('Email')).toBeDisabled();
    expect(within(email).queryByRole('button', { name: 'Discard' })).not.toBeInTheDocument();
    await user.type(screen.getByLabelText('SMTP server'), 'x');
    expect(saveOf('Email')).toBeEnabled();
    await user.click(within(email).getByRole('button', { name: 'Discard' }));
    expect(screen.getByLabelText('SMTP server')).toHaveValue('smtp.example.org');
    expect(saveOf('Email')).toBeDisabled();
    expect(within(email).queryByRole('button', { name: 'Discard' })).not.toBeInTheDocument();
  });

  it('shows the unit beside a size limit and says 0 means no limit in its description', () => {
    const kib = setting({ key: 'user_attachment_limit_kib', group: 'files', kind: 'int', min: 0, max: 1048576, value: '0' });
    view({ settings: [kib] });
    expect(screen.getByText('KiB')).toBeInTheDocument();
    expect(screen.getByLabelText('Attachments per person')).toHaveAccessibleDescription(/0 means no limit/);
  });

  it('puts the range in the placeholder, and Saved. under the title of the saved section', () => {
    view({ savedGroup: 'smtp' });
    expect(screen.getByLabelText('SMTP port')).toHaveAttribute('placeholder', '1–65535');
    expect(screen.getByLabelText('SMTP port')).toHaveAttribute('min', '1');
    expect(screen.getByLabelText('SMTP port')).toBeRequired();
    const email = screen.getByRole('region', { name: 'Email' });
    expect(within(email).getByText('Saved.')).toBeInTheDocument();
  });
});
