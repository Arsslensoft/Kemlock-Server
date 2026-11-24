// The kinds with a form of their own in forms/: the one place NewItem asks about them.
import type { MessageId } from '@/i18n';
import type { ItemData, VaultItem } from '../vault';
import { BackupCodesForm, backupCodesDefaults, backupCodesFields } from './backupCodes';
import { CardForm, cardDefaults, cardFields } from './card';
import { IdentityForm, identityDefaults, identityFields } from './identity';
import { OtpForm, otpDefaults, otpFields } from './otp';
import type { Described } from './parts';

export const ENTRY_KINDS = ['otp', 'backup-codes', 'card', 'identity'] as const;
export type EntryKind = (typeof ENTRY_KINDS)[number];

export function isEntryKind(kind: string): kind is EntryKind {
  return (ENTRY_KINDS as readonly string[]).includes(kind);
}

export const ENTRY_TITLES: Record<EntryKind, MessageId> = {
  otp: 'newItem.otpTitle',
  'backup-codes': 'newItem.backupCodesTitle',
  card: 'newItem.cardTitle',
  identity: 'newItem.identityTitle',
};

interface Props {
  kind: EntryKind;
  item?: VaultItem | undefined;
  submitLabel: string;
  pending?: boolean | undefined;
  error?: Described;
  onCancel: () => void;
  /** The fields the form owns, to hand to `save`. */
  onSubmit: (fields: ItemData) => void;
}

export function EntryForm({ kind, item, submitLabel, pending, error, onCancel, onSubmit }: Props) {
  const common = { submitLabel, pending, error, onCancel };
  const key = `${kind}-${item?.id ?? 'new'}`;
  switch (kind) {
    case 'otp':
      return (
        <OtpForm key={key} {...common} initial={otpDefaults(item)} onSubmit={(v) => onSubmit(otpFields(v, item))} />
      );
    case 'backup-codes':
      return (
        <BackupCodesForm
          key={key}
          {...common}
          initial={backupCodesDefaults(item)}
          onSubmit={(v) => onSubmit(backupCodesFields(v, item))}
        />
      );
    case 'card':
      return (
        <CardForm key={key} {...common} initial={cardDefaults(item)} onSubmit={(v) => onSubmit(cardFields(v, item))} />
      );
    case 'identity':
      return (
        <IdentityForm
          key={key}
          {...common}
          initial={identityDefaults(item)}
          onSubmit={(v) => onSubmit(identityFields(v, item))}
        />
      );
  }
}
