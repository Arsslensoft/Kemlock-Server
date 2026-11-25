// One form for each kind of item, picked by kind. Create and edit are the same form: Edit opens it
// filled in. `KindForm` turns what a form submits into a `FormResult` for the save: the fields to
// write, the links, and the files whose bytes still have to go up (see saveFlow.ts).
import type { ItemData, VaultItem } from '../vault';
import {
  type AttachmentEntry,
  entryBody,
  noteAttachmentFields,
  pendingEntries,
  readFileEntry,
  removedServerFiles,
  readAttachments,
} from '../attachments';
import type { KnownKind } from '../kinds';
import type { FormResult } from '../saveFlow';
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
  /** The item being edited; absent for a new one. */
  item?: VaultItem | undefined;
  submitLabel: string;
  pending?: boolean | undefined;
  error?: Described;
  onCancel: () => void;
  onSubmit: (result: FormResult) => void;
}

/** A form with nothing to upload: the fields, the links it holds, and whether it is an entry of the app. */
function plain(fields: ItemData, links: string[], entry: boolean): FormResult {
  return { fields, entry, links, uploads: [], removedFiles: [], withUploaded: () => ({}), rollbackOnFailure: false };
}

export function KindForm({ kind, item, submitLabel, pending, error, onCancel, onSubmit }: Props) {
  const editing = item !== undefined;
  const common = { submitLabel, pending, error, onCancel, editing };
  const key = `${kind}-${item?.id ?? 'new'}`;
  switch (kind) {
    case 'login':
      return (
        <LoginForm
          key={key}
          {...common}
          initial={loginDefaults(item)}
          onSubmit={(v) => onSubmit(plain(loginFields(v, item), v.links, false))}
        />
      );
    case 'note':
      return (
        <NoteForm
          key={key}
          {...common}
          initial={noteDefaults(item)}
          onSubmit={(v) => {
            const entries = v.attachments as AttachmentEntry[];
            onSubmit({
              ...plain(noteFields(v, item), v.links, false),
              uploads: pendingEntries(entries),
              removedFiles: removedServerFiles(readAttachments(item?.data), entries),
              // The entries in the order the person left them, the new ones with their server ids.
              withUploaded: (uploaded) => {
                const sent = new Map(uploaded.map((entry) => [entry.id, entry]));
                return noteAttachmentFields(entries.map((entry) => sent.get(entry.id) ?? entry));
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
          initial={fileDefaults(item)}
          onSubmit={(v) => {
            const file = v.file as AttachmentEntry | undefined;
            const before = readFileEntry(item?.data);
            onSubmit({
              ...plain(fileFields(v, item), v.links, false),
              uploads: file ? pendingEntries([file]) : [],
              removedFiles: removedServerFiles(before ? [before] : [], file && file.file === undefined ? [file] : []),
              withUploaded: (uploaded) => {
                const sent = uploaded[0];
                return sent ? { file: entryBody(sent) } : {};
              },
              // A File item with no file is useless: a new one that couldn't be sent is not kept.
              rollbackOnFailure: !editing,
            });
          }}
        />
      );
    case 'otp':
      return (
        <OtpForm
          key={key}
          {...common}
          initial={otpDefaults(item)}
          onSubmit={(v) => onSubmit(plain(otpFields(v, item), v.links, true))}
        />
      );
    case 'backup-codes':
      return (
        <BackupCodesForm
          key={key}
          {...common}
          initial={backupCodesDefaults(item)}
          onSubmit={(v) => onSubmit(plain(backupCodesFields(v, item), v.links, true))}
        />
      );
    case 'passkey':
      return <PasskeyPage onDone={onCancel} />;
    case 'card':
      return (
        <CardForm
          key={key}
          {...common}
          initial={cardDefaults(item)}
          onSubmit={(v) => onSubmit(plain(cardFields(v, item), v.links, true))}
        />
      );
    case 'identity':
      return (
        <IdentityForm
          key={key}
          {...common}
          initial={identityDefaults(item)}
          onSubmit={(v) => onSubmit(plain(identityFields(v, item), v.links, true))}
        />
      );
    case 'contact':
      return (
        <ContactForm
          key={key}
          {...common}
          initial={contactDefaults(item)}
          onSubmit={(v) => onSubmit(plain(contactFields(v, item), v.links, true))}
        />
      );
    case 'certificate':
      return (
        <CertificateForm
          key={key}
          {...common}
          initial={certificateDefaults(item)}
          onSubmit={(v, material) => {
            const fields = certificateFields(v, item, material);
            if (fields) onSubmit(plain(fields, v.links, true));
          }}
        />
      );
    case 'ssh-key':
      return (
        <SshKeyForm
          key={key}
          {...common}
          initial={sshKeyDefaults(item)}
          onSubmit={(v, material) => onSubmit(plain(sshKeyFields(v, item, material), v.links, true))}
        />
      );
    case 'pgp-key':
      return (
        <PgpKeyForm
          key={key}
          {...common}
          initial={pgpKeyDefaults(item)}
          onSubmit={(v) => {
            const fields = pgpKeyFields(v, item);
            if (fields) onSubmit(plain(fields, v.links, true));
          }}
        />
      );
  }
}
