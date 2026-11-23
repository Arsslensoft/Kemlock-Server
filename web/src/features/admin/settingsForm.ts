// The settings screen works from the server's own catalogue (`GET /admin/v1/settings`): each
// setting says its kind and bounds, so the form is built from it and checked the way the server
// will check it. Values are text on the wire (`"true"`, `"587"`).
import type { AdminSetting, SettingChanges } from '@/api/admin';
import type { MessageId } from '@/i18n';

/** The console's sections, in the order they are shown; a group the server adds goes after them. */
export const GROUP_ORDER = ['smtp', 'signups', 'files', 'trash', 'retention', 'rate-limits', 'security'] as const;

export interface SettingGroupView {
  group: string;
  settings: AdminSetting[];
}

export function groupsOf(settings: AdminSetting[]): SettingGroupView[] {
  const known: string[] = [...GROUP_ORDER];
  const extra = [...new Set(settings.map((s) => s.group))].filter((g) => !known.includes(g));
  return [...known, ...extra]
    .map((group) => ({ group, settings: settings.filter((s) => s.group === group) }))
    .filter((view) => view.settings.length > 0);
}

/** What the person is typing: a setting's key to its text. A secret starts empty, and stays so. */
export type Draft = Record<string, string>;

export function draftOf(settings: AdminSetting[]): Draft {
  const draft: Draft = {};
  for (const setting of settings) {
    draft[setting.key] = setting.kind === 'secret' ? '' : (setting.value ?? '');
  }
  return draft;
}

export type SettingErrors = Record<string, MessageId>;
export type Checked =
  | { ok: true; changes: SettingChanges }
  | { ok: false; errors: SettingErrors };

const WHOLE_NUMBER = /^-?\d+$/;

/** The error a typed value earns, or undefined. The server checks again, so this only spares a trip. */
export function errorOf(setting: AdminSetting, text: string): MessageId | undefined {
  const value = text.trim();
  switch (setting.kind) {
    case 'int': {
      if (!WHOLE_NUMBER.test(value)) return 'admin.settings.error.number';
      const n = Number(value);
      if (setting.min != null && n < setting.min) return 'admin.settings.error.number';
      if (setting.max != null && n > setting.max) return 'admin.settings.error.number';
      return undefined;
    }
    case 'choice':
      return setting.choices?.includes(value) ? undefined : 'admin.settings.error.choice';
    case 'email':
      return value === '' || /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value) ? undefined : 'error.email';
    case 'text':
      return setting.maxLength != null && value.length > setting.maxLength
        ? 'admin.settings.error.tooLong'
        : undefined;
    default:
      return undefined;
  }
}

/**
 * The changes a draft makes to the settings of one group: only what differs from what is saved,
 * never a setting the environment sets, and a secret only when one was typed.
 */
export function changesOf(settings: AdminSetting[], draft: Draft): Checked {
  const changes: SettingChanges = {};
  const errors: SettingErrors = {};
  for (const setting of settings) {
    if (setting.readOnly) continue;
    const typed = draft[setting.key] ?? '';
    if (setting.kind === 'secret') {
      if (typed !== '') changes[setting.key] = typed;
      continue;
    }
    if (typed === (setting.value ?? '')) continue;
    const error = errorOf(setting, typed);
    if (error) errors[setting.key] = error;
    else changes[setting.key] = typed.trim();
  }
  return Object.keys(errors).length > 0 ? { ok: false, errors } : { ok: true, changes };
}
