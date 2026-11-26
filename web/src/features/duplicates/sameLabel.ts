// What the merge preview says is the same in every copy. The group matched on some values (a
// card's number and expiry, a key's fingerprint), and the label names those. The design's fuller
// labels ("Card number, expiry and security code", "Private key and fingerprint") are used only when
// the extra fields are really equal in every copy, so "the same" is never said of values that differ.
import type { MessageId } from '@/i18n';
import type { VaultItem } from '@/features/vault/vault';
import { type DuplicateGroup, SAME_LABEL } from './detect';
import { lacks, stable } from './mergeFill';

/** The members of a kind that must be equal in every copy for the fuller label, and the label. */
const FULLER: Record<string, { keys: readonly string[]; label: MessageId }> = {
  card: { keys: ['code'], label: 'dup.same.cardFull' },
  certificate: { keys: ['private'], label: 'dup.same.certificateFull' },
  'ssh-key': { keys: ['private'], label: 'dup.same.sshFull' },
  'pgp-key': { keys: ['public'], label: 'dup.same.pgpFull' },
  identity: { keys: ['givenName', 'familyName', 'documents'], label: 'dup.same.identityFull' },
};

/** Whether every copy holds the same, non-empty value of `key`. */
function equalEverywhere(items: readonly VaultItem[], key: string): boolean {
  const values = items.map((item) => item.data?.[key]);
  return values.every((value) => !lacks(value)) && new Set(values.map(stable)).size === 1;
}

/** The label of what is the same in the group's copies. */
export function sameLabel(group: Pick<DuplicateGroup, 'kind' | 'why' | 'items'>): MessageId {
  const fuller = FULLER[group.kind];
  // An identity matched by name and email alone has no document to call the same.
  const applies = fuller !== undefined && (group.kind !== 'identity' || group.why === 'document');
  if (fuller && applies && fuller.keys.every((key) => equalEverywhere(group.items, key))) return fuller.label;
  return SAME_LABEL[group.why];
}
