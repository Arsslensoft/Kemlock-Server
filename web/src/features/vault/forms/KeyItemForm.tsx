// The form for an ssh-key, pgp-key, certificate or contact item: picks the one of its kind and
// hands the fields to `onSave`. The item is saved as an entry of the Kemlock app (`entry: true`).
import type { VaultItem } from '../vault';
import { CertificateForm, certificateDefaults, certificateFields } from './CertificateForm';
import { ContactForm, contactDefaults, contactFields } from './ContactForm';
import { PgpKeyForm, pgpKeyDefaults, pgpKeyFields } from './PgpKeyForm';
import { SshKeyForm, sshKeyDefaults, sshKeyFields } from './SshKeyForm';
import type { Described } from './shared';
import type { ItemData } from '../vault';

export const KEY_KINDS = ['ssh-key', 'pgp-key', 'certificate', 'contact'] as const;
export type KeyKind = (typeof KEY_KINDS)[number];

export function isKeyKind(kind: string): kind is KeyKind {
  return (KEY_KINDS as readonly string[]).includes(kind);
}

interface Props {
  kind: KeyKind;
  item?: VaultItem | undefined;
  submitLabel: string;
  pending?: boolean;
  error?: Described;
  onCancel: () => void;
  onSave: (fields: ItemData) => void;
}

export function KeyItemForm({ kind, item, submitLabel, pending, error, onCancel, onSave }: Props) {
  const editing = item !== undefined;
  const common = { editing, submitLabel, pending, error, onCancel };
  switch (kind) {
    case 'ssh-key':
      return (
        <SshKeyForm
          key={`ssh-${item?.id ?? 'new'}`}
          initial={sshKeyDefaults(item)}
          {...common}
          onSubmit={(values, material) => onSave(sshKeyFields(values, material))}
        />
      );
    case 'pgp-key':
      return (
        <PgpKeyForm
          key={`pgp-${item?.id ?? 'new'}`}
          initial={pgpKeyDefaults(item)}
          {...common}
          onSubmit={(values) => {
            const fields = pgpKeyFields(values, editing);
            if (fields) onSave(fields);
          }}
        />
      );
    case 'certificate':
      return (
        <CertificateForm
          key={`cert-${item?.id ?? 'new'}`}
          initial={certificateDefaults(item)}
          {...common}
          onSubmit={(values) => {
            const fields = certificateFields(values, editing);
            if (fields) onSave(fields);
          }}
        />
      );
    case 'contact':
      return (
        <ContactForm
          key={`contact-${item?.id ?? 'new'}`}
          initial={contactDefaults(item)}
          {...common}
          onSubmit={(values) => {
            const fields = contactFields(values, editing);
            if (fields) onSave(fields);
          }}
        />
      );
  }
}
