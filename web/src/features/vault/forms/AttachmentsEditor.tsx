// The files of a secure note: a row for each, "Add a file", and a note that they are encrypted in
// this browser before upload. Only a note has attachments; a File item holds its one file in its
// own form (file.tsx).
import { useId, useRef } from 'react';
import { useT } from '@/i18n';
import { Icon } from '@/ui/Icon';
import { type AttachmentEntry, MAX_ATTACHMENTS, formatSize, newAttachment, typeLabel } from '../attachments';

/** One file: its icon, name, "PDF · 2.4 MB" and the Remove button. */
export function FileRow({
  entry,
  status,
  onRemove,
}: {
  entry: AttachmentEntry;
  /** A word after the size, such as "ready to encrypt and upload". */
  status?: string;
  onRemove: () => void;
}) {
  const t = useT();
  const detail = [typeLabel(entry), formatSize(entry.size), status].filter((part) => part !== undefined && part !== '');
  return (
    <div className="file-row">
      <span className="file-icon" aria-hidden="true">
        <Icon name="file" />
      </span>
      <div className="file-text">
        <div className="file-name">{entry.name}</div>
        <div className="hint">{detail.join(' · ')}</div>
      </div>
      <button
        type="button"
        className="btn s"
        aria-label={t('itemForm.file.removeNamed', { name: entry.name })}
        onClick={onRemove}
      >
        {t('itemForm.file.remove')}
      </button>
    </div>
  );
}

interface Props {
  value: AttachmentEntry[];
  onChange: (next: AttachmentEntry[]) => void;
}

export function AttachmentsEditor({ value, onChange }: Props) {
  const t = useT();
  const id = useId();
  const input = useRef<HTMLInputElement>(null);
  return (
    <div className="field">
      <span id={`${id}-h`} className="fl">
        {t('itemForm.attachments.title')}
      </span>
      <div role="group" aria-labelledby={`${id}-h`} className="cf-list">
        {value.map((entry) => (
          <FileRow
            key={entry.id}
            entry={entry}
            {...(entry.file ? { status: t('itemForm.file.ready') } : {})}
            onRemove={() => onChange(value.filter((other) => other.id !== entry.id))}
          />
        ))}
        {value.length < MAX_ATTACHMENTS ? (
          <div>
            <label className="btn s" htmlFor={`${id}-add`}>
              <Icon name="file" />
              {t('itemForm.attachments.add')}
            </label>
            <input
              id={`${id}-add`}
              ref={input}
              type="file"
              multiple
              className="sr"
              onChange={(event) => {
                const chosen = [...(event.target.files ?? [])];
                // The same file can be chosen again once it was removed.
                event.target.value = '';
                if (chosen.length === 0) return;
                const room = MAX_ATTACHMENTS - value.length;
                onChange([...value, ...chosen.slice(0, room).map((file) => newAttachment(file))]);
              }}
            />
          </div>
        ) : null}
        <span className="hint">{t('itemForm.attachments.hint')}</span>
      </div>
    </div>
  );
}
