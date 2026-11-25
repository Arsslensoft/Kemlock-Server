import type { MessageId } from '@/i18n';
import type { IconName } from '@/ui/Icon';

/**
 * Every kind of item, in the order the sidebar, the filters and the New menu list them. `otp` is
 * the MFA code: the id stays `otp` because that is what the Kemlock app and every stored item call it.
 */
export const KIND_ORDER = [
  'login',
  'note',
  'file',
  'otp',
  'backup-codes',
  'passkey',
  'card',
  'identity',
  'contact',
  'certificate',
  'ssh-key',
  'pgp-key',
] as const;
export type KnownKind = (typeof KIND_ORDER)[number];

/** A kind this web vault has a form for. A passkey is made by a website, so it has none to edit. */
export type EditableKind = Exclude<KnownKind, 'passkey'>;

export const EDITABLE_KINDS: EditableKind[] = KIND_ORDER.filter((kind): kind is EditableKind => kind !== 'passkey');

/** A kind whose fields can go in an item Send: a file's bytes live in a file, not in its fields. */
export type SendableKind = Exclude<EditableKind, 'file'>;

export const SENDABLE_KIND_ORDER: SendableKind[] = EDITABLE_KINDS.filter(
  (kind): kind is SendableKind => kind !== 'file',
);

const KIND_LABELS: Record<KnownKind, MessageId> = {
  login: 'kind.login',
  note: 'kind.note',
  file: 'kind.file',
  otp: 'kind.code',
  'backup-codes': 'kind.backupCodes',
  passkey: 'kind.passkey',
  card: 'kind.card',
  identity: 'kind.identity',
  contact: 'kind.contact',
  certificate: 'kind.certificate',
  'ssh-key': 'kind.sshKey',
  'pgp-key': 'kind.pgpKey',
};

const KIND_PLURALS: Record<KnownKind, MessageId> = {
  login: 'kind.plural.login',
  note: 'kind.plural.note',
  file: 'kind.plural.file',
  otp: 'kind.plural.otp',
  'backup-codes': 'kind.plural.backup-codes',
  passkey: 'kind.plural.passkey',
  card: 'kind.plural.card',
  identity: 'kind.plural.identity',
  contact: 'kind.plural.contact',
  certificate: 'kind.plural.certificate',
  'ssh-key': 'kind.plural.ssh-key',
  'pgp-key': 'kind.plural.pgp-key',
};

const KIND_ICONS: Record<KnownKind, IconName> = {
  login: 'login',
  note: 'note',
  file: 'file',
  otp: 'mfa',
  'backup-codes': 'backupCodes',
  passkey: 'passkey',
  card: 'card',
  identity: 'identity',
  contact: 'contact',
  certificate: 'certificate',
  'ssh-key': 'key',
  'pgp-key': 'pgpKey',
};

export function isKnownKind(kind: string): kind is KnownKind {
  return (KIND_ORDER as readonly string[]).includes(kind);
}

/** "Login", "MFA code": the singular name of a kind. A kind from a newer app is "Item". */
export function kindLabel(kind: string): MessageId {
  return isKnownKind(kind) ? KIND_LABELS[kind] : 'kind.other';
}

/** "Logins", "MFA codes": the plural name, for the sidebar and the list titles. */
export function kindPluralLabel(kind: string): MessageId {
  return isKnownKind(kind) ? KIND_PLURALS[kind] : 'kind.other';
}

export function kindIcon(kind: string): IconName {
  return isKnownKind(kind) ? KIND_ICONS[kind] : 'items';
}

export function isEditable(kind: string): kind is EditableKind {
  return (EDITABLE_KINDS as string[]).includes(kind);
}

/** The letter on an item's tile. */
export function tileLetter(name: string): string {
  const first = [...name.trim()][0];
  return first ? first.toUpperCase() : '?';
}

/** `https://www.github.com/x` -> `github.com`; anything that isn't a URL is returned as is. */
export function hostOfUrl(url: string): string {
  try {
    return new URL(url).host.replace(/^www\./, '');
  } catch {
    return url;
  }
}

/** Only http and https links are made clickable. */
export function isWebUrl(url: string): boolean {
  try {
    const { protocol } = new URL(url);
    return protocol === 'https:' || protocol === 'http:';
  } catch {
    return false;
  }
}

const UNITS: Array<[Intl.RelativeTimeFormatUnit, number]> = [
  ['year', 365 * 24 * 3600],
  ['month', 30 * 24 * 3600],
  ['day', 24 * 3600],
  ['hour', 3600],
  ['minute', 60],
];

/** "2 hours ago", from an ISO date. Empty when the date is missing or unreadable. */
export function timeAgo(iso: unknown, now: Date = new Date()): string {
  if (typeof iso !== 'string' && typeof iso !== 'number') return '';
  const then = new Date(iso);
  if (Number.isNaN(then.getTime())) return '';
  const seconds = Math.round((then.getTime() - now.getTime()) / 1000);
  const formatter = new Intl.RelativeTimeFormat('en', { numeric: 'auto' });
  for (const [unit, size] of UNITS) {
    if (Math.abs(seconds) >= size) return formatter.format(Math.round(seconds / size), unit);
  }
  return formatter.format(0, 'second');
}

export function shortDate(date: Date): string {
  return new Intl.DateTimeFormat('en', { day: 'numeric', month: 'short' }).format(date);
}
