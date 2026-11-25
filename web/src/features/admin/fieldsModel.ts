// The Custom fields page's rules, with no screen in them: the item types a field can apply to, the
// words for them, and what an admin's form says about its draft. The server checks the same
// things again (crates/kemlock-domain/src/custom_field.rs).
import type { CustomField, CustomFieldInput, CustomFieldType } from '@/api/admin';
import type { MessageId } from '@/i18n';

/**
 * The item types that take custom fields, in the order the apps list their types. A file and a
 * passkey take none. `otp` is the MFA code.
 */
export const FIELD_KINDS = [
  'login',
  'note',
  'otp',
  'backup-codes',
  'card',
  'identity',
  'contact',
  'certificate',
  'ssh-key',
  'pgp-key',
] as const;

export type FieldKind = (typeof FIELD_KINDS)[number];

/** The plural names the table and the form use for the types. */
export const KIND_LABELS: Record<FieldKind, MessageId> = {
  login: 'admin.fields.kind.login',
  note: 'admin.fields.kind.note',
  otp: 'admin.fields.kind.otp',
  'backup-codes': 'admin.fields.kind.backupCodes',
  card: 'admin.fields.kind.card',
  identity: 'admin.fields.kind.identity',
  contact: 'admin.fields.kind.contact',
  certificate: 'admin.fields.kind.certificate',
  'ssh-key': 'admin.fields.kind.sshKey',
  'pgp-key': 'admin.fields.kind.pgpKey',
};

export const FIELD_TYPES: CustomFieldType[] = ['text', 'hidden', 'checkbox'];

export const TYPE_LABELS: Record<CustomFieldType, MessageId> = {
  text: 'admin.fields.type.text',
  hidden: 'admin.fields.type.hidden',
  checkbox: 'admin.fields.type.checkbox',
};

/** The longest a name may be, in characters. */
export const MAX_NAME_CHARS = 64;

/** Whether `kind` is one a field can apply to. */
export function isFieldKind(kind: string): kind is FieldKind {
  return (FIELD_KINDS as readonly string[]).includes(kind);
}

/** What the form holds while it is open. */
export interface FieldDraft {
  name: string;
  type: CustomFieldType;
  /** `all` applies to every type that takes fields; `only` to the ticked ones. */
  scope: 'all' | 'only';
  kinds: FieldKind[];
}

/** A blank draft, or the draft of a field being changed. */
export function draftOf(field?: CustomField): FieldDraft {
  if (!field) return { name: '', type: 'text', scope: 'all', kinds: [] };
  if (field.kinds === 'all') return { name: field.name, type: field.type, scope: 'all', kinds: [] };
  return { name: field.name, type: field.type, scope: 'only', kinds: field.kinds.filter(isFieldKind) };
}

/** The name as the server keeps it: trimmed, each run of white space one space. */
export function cleanName(raw: string): string {
  return raw.split(/\s+/).filter(Boolean).join(' ');
}

export interface DraftErrors {
  name?: MessageId;
  kinds?: MessageId;
}

export type Checked = { ok: true; input: CustomFieldInput } | { ok: false; errors: DraftErrors };

/** What the form sends, or what is wrong with it. */
export function checkDraft(draft: FieldDraft): Checked {
  const errors: DraftErrors = {};
  const name = cleanName(draft.name);
  if (name === '' || [...name].length > MAX_NAME_CHARS || /\p{Cc}/u.test(name)) {
    errors.name = 'admin.fields.error.name';
  }
  if (draft.scope === 'only' && draft.kinds.length === 0) errors.kinds = 'admin.fields.error.kinds';
  if (errors.name || errors.kinds) return { ok: false, errors };
  return {
    ok: true,
    input: {
      name,
      type: draft.type,
      // In the apps' order, whichever order they were ticked in.
      kinds: draft.scope === 'all' ? 'all' : FIELD_KINDS.filter((kind) => draft.kinds.includes(kind)),
    },
  };
}

/** The "On" column: the words of `admin.fields.on.all`, or the plural names of the types. */
export function appliesTo(field: Pick<CustomField, 'kinds'>): 'all' | MessageId[] {
  if (field.kinds === 'all') return 'all';
  return field.kinds.filter(isFieldKind).map((kind) => KIND_LABELS[kind]);
}
