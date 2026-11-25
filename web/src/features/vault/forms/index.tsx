// One form for each kind of item, picked by kind. Create and edit are the same form: Edit opens it
// filled in, and a copy opens it filled from another item. `KindForm` turns what a form submits into
// a `FormResult` for the save: the fields to write, the links, and the files whose bytes still have
// to go up (see saveFlow.ts).
import { type AttachmentEntry, entryBody, noteAttachmentFields, pendingEntries } from '../attachments';
import type { KnownKind } from '../kinds';
import type { FormResult } from '../saveFlow';
import type { ItemData, VaultItem } from '../vault';
import { BackupCodesForm, backupCodesDefaults, backupCodesFields } from './backupCodes';
import { CardForm, cardDefaults, cardFields } from './card';
import { CertificateForm, certificateDefaults, certificateFields } from './CertificateForm';
import { ContactForm, contactDefaults, contactFields } from './ContactForm';
import { FileForm, fileDefaults, fileFields } from './file';
import { IdentityForm, identityDefaults, identityFields } from './identity';
import { LoginForm, loginDefaults, loginFields } from './login';
import { NoteForm, noteDefaults, noteFields } from './note';
import { OtpForm, otpDefaults, otpFields } from './otp';
import type { Described } from './parts';
import { PasskeyPage } from './passkey';
import { PgpKeyForm, pgpKeyDefaults, pgpKeyFields } from './PgpKeyForm';
import { SshKeyForm, sshKeyDefaults, sshKeyFields } from './SshKeyForm';

interface Props {
  kind: KnownKind;
  /** The item being edited; absent for a new one. It names the form and makes it an edit. */
  item?: VaultItem | undefined;
  /**
   * What the fields are written against: the item, or the one an earlier try of this form already
   * saved (so a retry updates it, keeps its `addedAt` and its key, and doesn't make it twice).
   */
  existing?: VaultItem | undefined;
  /** An item a new one is filled from (a copy): it prefills the form and is not edited. */
  seed?: VaultItem | undefined;
  /** The ids of the codes that name this item as their login (`linkedLoginId`), shown as linked. */
  incoming?: string[] | undefined;
  submitLabel: string;
  pending?: boolean | undefined;
  error?: Described;
  onCancel: () => void;
  onSubmit: (result: FormResult) => void;
}

/** A form with nothing to upload: the fields, the links it holds, and whether it is an entry of the app. */
function plain(fields: ItemData, links: string[], entry: boolean): FormResult {
  return { fields, entry, links, files: [], uploads: [], withUploaded: () => ({}), rollbackOnFailure: false };
}

export function KindForm({
  kind,
  item,
  existing,
  seed,
  incoming = [],
  submitLabel,
  pending,
  error,
  onCancel,
  onSubmit,
}: Props) {
  // A form opened from a copy is filled like an edit and written against the copy's body (so what
  // the form doesn't show is kept), yet it saves a new item.
  const editing = item !== undefined || seed !== undefined;
  const source = item ?? seed;
  const base = existing ?? source;
  const common = { submitLabel, pending, error, onCancel, editing };
  const key = `${kind}-${item?.id ?? (seed ? 'copy' : 'new')}`;
  // The codes that name this item as their login are linked to it, though its own body says nothing.
  const linked = <T extends { links: string[] }>(values: T): T =>
    incoming.length === 0 ? values : { ...values, links: [...new Set([...values.links, ...incoming])].sort() };
  switch (kind) {
    case 'login':
      return (
        <LoginForm
          key={key}
          {...common}
          initial={linked(loginDefaults(source))}
          onSubmit={(v) => onSubmit(plain(loginFields(v, base), v.links, false))}
        />
      );
    case 'note':
      return (
        <NoteForm
          key={key}
          {...common}
          initial={linked(noteDefaults(source))}
          onSubmit={(v) => {
            const entries = v.attachments as AttachmentEntry[];
            onSubmit({
              ...plain(noteFields(v, base), v.links, false),
              files: entries,
              uploads: pendingEntries(entries),
              // The entries in the order the person left them, the new ones with their server ids.
              withUploaded: (uploaded) => {
                const sent = new Map(uploaded.map((entry) => [entry.id, entry]));
                return noteAttachmentFields(
                  entries.map((entry) => sent.get(entry.id) ?? entry),
                  base?.data,
                );
              },
            });
          }}
        />
      );
    case 'file':
      return (
        <FileForm
          key={key}
          {...common}
          initial={linked(fileDefaults(source))}
          onSubmit={(v) => {
            const file = v.file as AttachmentEntry | undefined;
            onSubmit({
              ...plain(fileFields(v, base), v.links, false),
              files: file ? [file] : [],
              uploads: file ? pendingEntries([file]) : [],
              withUploaded: (uploaded) => {
                const sent = uploaded[0];
                return sent ? { file: entryBody(sent) } : {};
              },
              // A File item with no file is useless: a new one that couldn't be sent is not kept.
              rollbackOnFailure: item === undefined,
            });
          }}
        />
      );
    case 'otp':
      return (
        <OtpForm
          key={key}
          {...common}
          initial={linked(otpDefaults(source))}
          onSubmit={(v) => onSubmit(plain(otpFields(v, base), v.links, true))}
        />
      );
    case 'backup-codes':
      return (
        <BackupCodesForm
          key={key}
          {...common}
          initial={linked(backupCodesDefaults(source))}
          onSubmit={(v) => onSubmit(plain(backupCodesFields(v, base), v.links, true))}
        />
      );
    case 'passkey':
      return <PasskeyPage onDone={onCancel} />;
    case 'card':
      return (
        <CardForm
          key={key}
          {...common}
          initial={linked(cardDefaults(source))}
          onSubmit={(v) => onSubmit(plain(cardFields(v, base), v.links, true))}
        />
      );
    case 'identity':
      return (
        <IdentityForm
          key={key}
          {...common}
          initial={linked(identityDefaults(source))}
          onSubmit={(v) => onSubmit(plain(identityFields(v, base), v.links, true))}
        />
      );
    case 'contact':
      return (
        <ContactForm
          key={key}
          {...common}
          initial={linked(contactDefaults(source))}
          onSubmit={(v) => onSubmit(plain(contactFields(v, base), v.links, true))}
        />
      );
    case 'certificate':
      return (
        <CertificateForm
          key={key}
          {...common}
          initial={linked(certificateDefaults(source))}
          onSubmit={(v, material) => {
            const fields = certificateFields(v, base, material);
            if (fields) onSubmit(plain(fields, v.links, true));
          }}
        />
      );
    case 'ssh-key':
      return (
        <SshKeyForm
          key={key}
          {...common}
          initial={linked(sshKeyDefaults(source))}
          onSubmit={(v, material) => onSubmit(plain(sshKeyFields(v, base, material), v.links, true))}
        />
      );
    case 'pgp-key':
      return (
        <PgpKeyForm
          key={key}
          {...common}
          initial={linked(pgpKeyDefaults(source))}
          onSubmit={(v) => {
            const fields = pgpKeyFields(v, base);
            if (fields) onSubmit(plain(fields, v.links, true));
          }}
        />
      );
  }
}
