// What the list pages add to the shared item kinds (kinds.ts): the gray line under each type's page
// title, and the type a route asks for. The stored kind ids are the item's own (`otp` is the "MFA
// code"), so a route and a filter speak in them.
import type { MessageId } from '@/i18n';
import { type KnownKind, isKnownKind } from './kinds';

const SUBTITLE: Record<KnownKind, MessageId> = {
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

/** The line under the page title: the type's own, or the one for All items. */
export function kindSubtitle(kind: string | undefined): MessageId {
  return kind !== undefined && isKnownKind(kind) ? SUBTITLE[kind] : 'lists.sub.all';
}

/** The type a list route asks for: `undefined` is All items; the route's own `kind`, otherwise. */
export function listKind(raw: string | undefined): string | undefined {
  return raw === undefined || raw === '' || raw === 'all' ? undefined : raw;
}
