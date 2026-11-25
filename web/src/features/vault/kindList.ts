// The item types as the lists show them: in the order the design fixes (sidebar, type chips, menus),
// each with its plural label and the gray line under the page title. The stored kind ids are the
// item's own (`otp` is the "MFA code"), so a route and a filter speak in them.
import type { MessageId } from '@/i18n';

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

export type ListedKind = (typeof KIND_ORDER)[number];

const PLURAL: Record<ListedKind, MessageId> = {
  login: 'lists.plural.login',
  note: 'lists.plural.note',
  file: 'lists.plural.file',
  otp: 'lists.plural.otp',
  'backup-codes': 'lists.plural.backupCodes',
  passkey: 'lists.plural.passkey',
  card: 'lists.plural.card',
  identity: 'lists.plural.identity',
  contact: 'lists.plural.contact',
  certificate: 'lists.plural.certificate',
  'ssh-key': 'lists.plural.sshKey',
  'pgp-key': 'lists.plural.pgpKey',
};

const SUBTITLE: Record<ListedKind, MessageId> = {
  login: 'lists.sub.login',
  note: 'lists.sub.note',
  file: 'lists.sub.file',
  otp: 'lists.sub.otp',
  'backup-codes': 'lists.sub.backupCodes',
  passkey: 'lists.sub.passkey',
  card: 'lists.sub.card',
  identity: 'lists.sub.identity',
  contact: 'lists.sub.contact',
  certificate: 'lists.sub.certificate',
  'ssh-key': 'lists.sub.sshKey',
  'pgp-key': 'lists.sub.pgpKey',
};

export function isListedKind(kind: unknown): kind is ListedKind {
  return typeof kind === 'string' && (KIND_ORDER as readonly string[]).includes(kind);
}

/** "Logins", "MFA codes"…; "Items" for a kind this app has no name for. */
export function kindPlural(kind: string): MessageId {
  return isListedKind(kind) ? PLURAL[kind] : 'lists.plural.other';
}

/** The line under the page title: the type's own, or the one for All items. */
export function kindSubtitle(kind: string | undefined): MessageId {
  return kind !== undefined && isListedKind(kind) ? SUBTITLE[kind] : 'lists.sub.all';
}

/** The type a list route asks for: `undefined` is All items; the route's own `kind`, otherwise. */
export function listKind(raw: string | undefined): string | undefined {
  return raw === undefined || raw === '' || raw === 'all' ? undefined : raw;
}
