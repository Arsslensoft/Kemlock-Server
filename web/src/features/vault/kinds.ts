import type { MessageId } from '@/i18n';
import type { IconName } from '@/ui/Icon';

export type EditableKind = 'login' | 'note' | 'otp' | 'backup-codes' | 'card' | 'identity';

export const EDITABLE_KINDS: EditableKind[] = ['login', 'note', 'otp', 'backup-codes', 'card', 'identity'];

const KIND_LABELS: Record<string, MessageId> = {
  login: 'kind.login',
  note: 'kind.note',
  otp: 'kind.code',
  'backup-codes': 'kind.backupCodes',
  passkey: 'kind.passkey',
  card: 'kind.card',
  identity: 'kind.identity',
  'ssh-key': 'kind.sshKey',
  'pgp-key': 'kind.pgpKey',
  certificate: 'kind.certificate',
  contact: 'kind.contact',
};

export function kindLabel(kind: string): MessageId {
  return KIND_LABELS[kind] ?? 'kind.other';
}

export function kindIcon(kind: string): IconName {
  switch (kind) {
    case 'login':
      return 'login';
    case 'note':
      return 'note';
    case 'ssh-key':
    case 'pgp-key':
    case 'passkey':
      return 'key';
    default:
      return 'items';
  }
}

export function isEditable(kind: string): kind is EditableKind {
  return EDITABLE_KINDS.includes(kind as EditableKind);
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
