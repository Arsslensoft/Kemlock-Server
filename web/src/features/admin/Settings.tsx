import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import type { AdminSetting, SettingChanges } from '@/api/admin';
import { type MessageId, useT } from '@/i18n';
import { Button } from '@/ui/Button';
import { Notice } from '@/ui/Notice';
import { admin } from './client';
import { useReauth } from './reauth';
import {
  type Draft,
  type SettingErrors,
  changesOf,
  draftOf,
  groupsOf,
  HOST_PATTERN,
  isDirty,
} from './settingsForm';
import { ErrorNotice, Loading, PageHead, SelectBox, TextBox, Toggle } from './ui';

const GROUP_TITLES: Record<string, MessageId> = {
  smtp: 'admin.settings.group.smtp',
  signups: 'admin.settings.group.signups',
  files: 'admin.settings.group.files',
  trash: 'admin.settings.group.trash',
  retention: 'admin.settings.group.retention',
  'rate-limits': 'admin.settings.group.rateLimits',
  security: 'admin.settings.group.security',
};

/** The words for each setting the server has today; one it adds later shows under its own key. */
const LABELS: Record<string, MessageId> = {
  smtp_host: 'admin.settings.key.smtp_host',
  smtp_port: 'admin.settings.key.smtp_port',
  smtp_security: 'admin.settings.key.smtp_security',
  smtp_username: 'admin.settings.key.smtp_username',
  smtp_password: 'admin.settings.key.smtp_password',
  smtp_from: 'admin.settings.key.smtp_from',
  smtp_from_name: 'admin.settings.key.smtp_from_name',
  signups_allowed: 'admin.settings.key.signups_allowed',
  signups_verify: 'admin.settings.key.signups_verify',
  signups_domains_whitelist: 'admin.settings.key.signups_domains_whitelist',
  invitations_allowed: 'admin.settings.key.invitations_allowed',
  user_attachment_limit_kib: 'admin.settings.key.user_attachment_limit_kib',
  space_attachment_limit_kib: 'admin.settings.key.space_attachment_limit_kib',
  send_file_limit_kib: 'admin.settings.key.send_file_limit_kib',
  max_file_size_mib: 'admin.settings.key.max_file_size_mib',
  trash_days: 'admin.settings.key.trash_days',
  event_log_days: 'admin.settings.key.event_log_days',
  sign_in_log_days: 'admin.settings.key.sign_in_log_days',
  email_log_days: 'admin.settings.key.email_log_days',
  backup_days: 'admin.settings.key.backup_days',
  deleted_account_grace_days: 'admin.settings.key.deleted_account_grace_days',
  rate_sign_in_per_minute: 'admin.settings.key.rate_sign_in_per_minute',
  rate_password_failures_per_15_minutes: 'admin.settings.key.rate_password_failures_per_15_minutes',
  rate_second_step_failures_per_15_minutes: 'admin.settings.key.rate_second_step_failures_per_15_minutes',
  rate_register_per_hour: 'admin.settings.key.rate_register_per_hour',
  security_contact: 'admin.settings.key.security_contact',
  security_encryption: 'admin.settings.key.security_encryption',
};

/** A switch, a list of domains or a long text keeps the full width of the grid. */
function isWide(setting: AdminSetting): boolean {
  return setting.kind === 'bool' || setting.kind === 'domains' || setting.key === 'security_encryption';
}

/** One setting as a control: by its kind, with what the server says about it. */
function Field({
  setting,
  value,
  error,
  onChange,
}: {
  setting: AdminSetting;
  value: string;
  error?: MessageId | undefined;
  onChange: (value: string) => void;
}) {
  const t = useT();
  const labelId = LABELS[setting.key];
  const label = labelId ? t(labelId) : setting.key;
  const range = { min: setting.min ?? 0, max: setting.max ?? 0 };
  const bounded = setting.kind === 'int' && setting.min != null && setting.max != null;
  const placeholder = !bounded
    ? undefined
    : setting.key.endsWith('_days')
      ? t('admin.settings.placeholder.days', range)
      : t('admin.settings.placeholder.range', range);
  const suffix = setting.key.endsWith('_kib') ? 'KiB' : setting.key.endsWith('_mib') ? 'MiB' : undefined;
  const hints = [
    setting.readOnly ? t('admin.settings.env', { name: setting.env }) : '',
    setting.kind === 'secret' ? t('admin.secretHint') : '',
    setting.kind === 'int' && setting.min === 0 && setting.key.endsWith('_kib') ? t('admin.settings.noLimitHint') : '',
  ].filter((hint) => hint !== '');
  const hint = hints.length > 0 ? hints.join(' ') : undefined;
  switch (setting.kind) {
    case 'bool':
      return (
        <Toggle
          label={label}
          hint={hint}
          checked={value === 'true'}
          disabled={setting.readOnly}
          onChange={(on) => onChange(on ? 'true' : 'false')}
        />
      );
    case 'choice':
      return (
        <SelectBox
          label={label}
          value={value}
          onChange={onChange}
          hint={hint}
          options={(setting.choices ?? []).map((choice) => ({ value: choice, label: choice }))}
        />
      );
    case 'secret':
      return (
        <TextBox
          label={label}
          type="password"
          value={value}
          onChange={onChange}
          placeholder={setting.secretSet ? t('admin.secretKept') : ''}
          hint={hint}
          disabled={setting.readOnly}
          autoComplete="new-password"
        />
      );
    case 'int':
      return (
        <TextBox
          label={label}
          type="number"
          inputMode="numeric"
          value={value}
          onChange={onChange}
          hint={hint}
          placeholder={placeholder}
          suffix={suffix}
          error={error}
          errorValues={range}
          min={setting.min ?? undefined}
          max={setting.max ?? undefined}
          step={1}
          required
          disabled={setting.readOnly}
        />
      );
    case 'email':
      return (
        <TextBox
          label={label}
          type="email"
          inputMode="email"
          value={value}
          onChange={onChange}
          hint={hint}
          placeholder="name@example.co"
          error={error}
          disabled={setting.readOnly}
        />
      );
    default:
      return (
        <TextBox
          label={label}
          mono={setting.kind === 'domains'}
          value={value}
          onChange={onChange}
          hint={setting.kind === 'domains' ? [hint, t('admin.settings.domainsHint')].filter(Boolean).join(' ') : hint}
          error={error}
          pattern={setting.key === 'smtp_host' ? HOST_PATTERN : undefined}
          maxLength={setting.maxLength ?? undefined}
          disabled={setting.readOnly}
        />
      );
  }
}

/** A card with its own Save: groups are saved one at a time, and only what changed is sent. */
function Group({
  group,
  settings,
  saved,
  onSave,
}: {
  group: string;
  settings: AdminSetting[];
  saved: boolean;
  onSave: (changes: SettingChanges, group: string) => void;
}) {
  const t = useT();
  const titleId = GROUP_TITLES[group];
  const title = titleId ? t(titleId) : group;
  const [draft, setDraft] = useState<Draft>(() => draftOf(settings));
  const editable = settings.some((setting) => !setting.readOnly);
  const dirty = isDirty(settings, draft);
  // A changed field is checked as it is typed; a clean one has nothing to check.
  const checked = changesOf(settings, draft);
  const errors: SettingErrors = checked.ok ? {} : checked.errors;
  return (
    <section className="card" aria-labelledby={`h-${group}`}>
      <div className="adm-head">
        <h2 id={`h-${group}`}>{title}</h2>
      </div>
      {saved && !dirty ? (
        <div className="adm-saved">
          <Notice tone="info" live>
            <p>{t('admin.saved')}</p>
          </Notice>
        </div>
      ) : null}
      <form
        className="adm-pad"
        noValidate
        onSubmit={(event) => {
          event.preventDefault();
          if (checked.ok && Object.keys(checked.changes).length > 0) onSave(checked.changes, group);
        }}
      >
        <div className="adm-g2">
          {settings.map((setting) => (
            <div key={setting.key} className={isWide(setting) ? 'wide' : undefined}>
              <Field
                setting={setting}
                value={draft[setting.key] ?? ''}
                error={errors[setting.key]}
                onChange={(value) => setDraft((d) => ({ ...d, [setting.key]: value }))}
              />
            </div>
          ))}
        </div>
        {editable ? (
          <div className="actions">
            {dirty ? <Button onPress={() => setDraft(draftOf(settings))}>{t('admin.discard')}</Button> : null}
            <Button type="submit" variant="primary" isDisabled={!dirty}>
              {t('action.save')}
            </Button>
          </div>
        ) : null}
      </form>
    </section>
  );
}

export interface SettingsViewProps {
  settings: AdminSetting[];
  onSave: (changes: SettingChanges, group: string) => void;
  /** The group that was just saved. */
  savedGroup?: string | undefined;
  error?: unknown;
}

export function SettingsView({ settings, onSave, savedGroup, error }: SettingsViewProps) {
  const t = useT();
  return (
    <>
      <PageHead title={t('admin.settings')} lede={t('admin.settings.lede')} />
      {error ? <ErrorNotice error={error} /> : null}
      {groupsOf(settings).map((view) => (
        <Group
          key={view.group}
          group={view.group}
          settings={view.settings}
          saved={savedGroup === view.group}
          onSave={onSave}
        />
      ))}
    </>
  );
}

export default function Settings() {
  const queryClient = useQueryClient();
  const { guard, dialog } = useReauth(admin);
  const settings = useQuery({ queryKey: ['admin', 'settings'], queryFn: () => admin.settings() });
  const [saved, setSaved] = useState<string | undefined>();
  const save = useMutation({
    mutationFn: async (input: { changes: SettingChanges; group: string }) => {
      const result = await guard((token) => admin.saveSettings(input.changes, token));
      return { group: input.group, result };
    },
    onSuccess: ({ group, result }) => {
      setSaved(group);
      // The server answers every setting as it is now: secrets cleared, numbers normalised.
      queryClient.setQueryData(['admin', 'settings'], result);
    },
  });
  if (settings.isPending) return <Loading />;
  if (!settings.data) return <ErrorNotice error={settings.error} />;
  return (
    <>
      <SettingsView
        // A saved group remounts with what the server kept.
        key={JSON.stringify(settings.data)}
        settings={settings.data}
        onSave={(changes, group) => {
          setSaved(undefined);
          save.mutate({ changes, group });
        }}
        savedGroup={saved}
        error={save.error}
      />
      {dialog}
    </>
  );
}
