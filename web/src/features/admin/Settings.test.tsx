import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { I18nProvider } from '@/i18n';
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
  return within(screen.getByRole('region', { name: title })).getByRole('button', { name: `Save ${title}` });
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

  it('asks for a whole number, without a range, when the server states no bounds', () => {
    const open = setting({ key: 'extra_count', group: 'later', kind: 'int' });
    expect(errorOf(open, '2.5')).toBe('admin.settings.error.whole');
    expect(errorOf(open, '12')).toBeUndefined();
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
    expect(within(files).queryByRole('button', { name: /^Save/ })).not.toBeInTheDocument();
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

  it('gives the host input a pattern that is valid with the v flag', () => {
    view();
    expect(screen.getByLabelText('SMTP server')).toHaveAttribute('pattern', '[^\\s\\/]+');
    expect(() => new RegExp('^(?:[^\\s\\/]+)$', 'v')).not.toThrow();
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

describe('saving one group', () => {
  it('leaves the unsaved edits of the other groups alone', async () => {
    const { rerender } = renderWithIntl(<SettingsView settings={SETTINGS} onSave={vi.fn()} />);
    const user = userEvent.setup();
    const host = screen.getByDisplayValue('smtp.example.org');
    await user.clear(host);
    await user.type(host, 'mail.example.org');
    // The server answers with the trash group saved: its data changes, the smtp group's does not.
    const after = SETTINGS.map((s) => (s.key === 'trash_days' ? { ...s, value: '45' } : s));
    rerender(
      <I18nProvider>
        <SettingsView settings={after} onSave={vi.fn()} />
      </I18nProvider>,
    );
    expect(screen.getByDisplayValue('mail.example.org')).toBeInTheDocument();
    expect(screen.getByDisplayValue('45')).toBeInTheDocument();
  });

  it('starts the group over when the server sends it back unchanged, as after a secret is replaced', async () => {
    const { rerender } = renderWithIntl(<SettingsView settings={SETTINGS} onSave={vi.fn()} />);
    const password = screen.getByLabelText('SMTP password', { exact: false });
    await userEvent.setup().type(password, 'a-new-password');
    // The password was already set, so the answer to the save is the same as before.
    rerender(
      <I18nProvider>
        <SettingsView settings={SETTINGS} onSave={vi.fn()} savedGroup="smtp" saves={{ smtp: 1 }} />
      </I18nProvider>,
    );
    expect(screen.getByLabelText('SMTP password', { exact: false })).toHaveValue('');
    expect(within(screen.getByRole('region', { name: 'Email' })).getByText('Saved.')).toBeInTheDocument();
  });
});

describe('the hint under each switch', () => {
  const SWITCHES = [
    setting({ key: 'signups_allowed', group: 'signups', kind: 'bool', value: 'false' }),
    setting({ key: 'signups_verify', group: 'signups', kind: 'bool', value: 'true' }),
    setting({ key: 'invitations_allowed', group: 'signups', kind: 'bool', value: 'true' }),
    setting({ key: 'push_enabled', group: 'push', kind: 'bool', value: 'false' }),
    setting({ key: 'kemlock_push_relay', group: 'push', kind: 'bool', value: 'false' }),
  ];

  it('says what the switch does, in the words of the design', () => {
    view({ settings: SWITCHES });
    const signups = within(screen.getByRole('region', { name: 'Who can make an account' }));
    expect(signups.getByText('When off, people join only by an invitation or through SSO.')).toBeInTheDocument();
    expect(
      signups.getByText("Sends a link to the new address. The account can't sign in until the link is opened."),
    ).toBeInTheDocument();
    expect(
      signups.getByText('Admins can invite people from Users & spaces, even while sign-up is off.'),
    ).toBeInTheDocument();
  });

  it('is the description of its switch, not part of its name', () => {
    view({ settings: SWITCHES });
    const named = (name: string) => screen.getByRole('switch', { name });
    expect(named('Anyone may make an account')).toHaveAccessibleDescription(
      'When off, people join only by an invitation or through SSO.',
    );
    expect(named('Verify the email of a new account')).toHaveAccessibleDescription(
      "Sends a link to the new address. The account can't sign in until the link is opened.",
    );
    expect(named('Admins may invite people')).toHaveAccessibleDescription(
      'Admins can invite people from Users & spaces, even while sign-up is off.',
    );
  });

  it('has one for every switch the server has, push included', () => {
    view({ settings: SWITCHES });
    for (const switchElement of screen.getAllByRole('switch')) {
      expect(switchElement, switchElement.getAttribute('aria-label') ?? '').toHaveAccessibleDescription(/\S/);
    }
    expect(screen.getAllByRole('switch')).toHaveLength(SWITCHES.length);
  });

  it("says the server pushes itself and the relay is only a fallback, for Kemlock's relay", () => {
    view({ settings: SWITCHES });
    const relay = screen.getByRole('switch', { name: "Register with Kemlock's push relay" });
    expect(relay).toHaveAccessibleDescription(
      /pushes to Kemlock's iPhones \(Apple push\) and Android phones \(UnifiedPush\) itself/,
    );
    expect(relay).toHaveAccessibleDescription(/only an optional fallback for iPhones on a server with no Apple key/);
    expect(relay).toHaveAccessibleDescription(/never an item or an email/);
  });

  it("says what Bitwarden's relay is sent: ids and the kind of change, never contents", () => {
    view({ settings: SWITCHES });
    const relay = screen.getByRole('switch', { name: "Use Bitwarden's push relay" });
    expect(relay).toHaveAccessibleDescription(
      /user, device and item ids and the kind of change, never an item's contents/,
    );
    expect(relay).toHaveAccessibleDescription(/Kemlock's apps are woken by this server itself/);
  });

  it('keeps the environment note after it when the environment sets the switch', () => {
    view({
      settings: [
        setting({
          key: 'signups_allowed',
          group: 'signups',
          kind: 'bool',
          value: 'true',
          source: 'env',
          readOnly: true,
          env: 'SIGNUPS_ALLOWED',
        }),
      ],
    });
    const description = screen.getByRole('switch', { name: 'Anyone may make an account' });
    expect(description).toBeDisabled();
    expect(description).toHaveAccessibleDescription(
      /^When off, people join only by an invitation or through SSO\. Set by SIGNUPS_ALLOWED/,
    );
  });
});
