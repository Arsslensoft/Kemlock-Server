// The File form: a drop area ("Choose a file"), the name and notes, and linked items. The file is
// encrypted in this browser before it is uploaded through the item's files route, and counts
// against the person's attachment quota. A File item has no custom fields and no attachments of its
// own: the file is the item.
import { zodResolver } from '@hookform/resolvers/zod';
import { useId, useState } from 'react';
import { type Control, useController, useForm } from 'react-hook-form';
import { z } from 'zod';
import { useT } from '@/i18n';
import { CheckField, Field } from '@/ui/fields';
import { Icon } from '@/ui/Icon';
import { type AttachmentEntry, attachmentSchema, entryBody, newAttachment, readFileEntry } from '../attachments';
import { formLinks, linksFields } from '../links';
import { type ItemData, type VaultItem, itemName } from '../vault';
import { FileRow } from './AttachmentsEditor';
import { LinkedSection } from './ExtrasSections';
import { extrasShape } from './extras';
import { Actions, type FormProps } from './parts';

export const fileFormSchema = z
  .object({
    name: z.string().trim().min(1, 'error.required').max(200, 'error.tooLong'),
    notes: z.string().max(10000, 'error.tooLong'),
    favorite: z.boolean(),
    file: attachmentSchema.optional(),
    links: extrasShape.links,
  })
  .refine((values) => values.file !== undefined, { path: ['file'], message: 'itemForm.file.required' });
export type FileFormValues = z.infer<typeof fileFormSchema>;

export function fileDefaults(item?: VaultItem): FileFormValues {
  return {
    name: item ? itemName(item) : '',
    notes: typeof item?.data?.['notes'] === 'string' ? (item.data['notes'] as string) : '',
    favorite: item?.data?.favorite === true,
    file: readFileEntry(item?.data),
    links: formLinks(item?.data),
  };
}

/**
 * The fields a File form owns. The `file` member is only written for a file that is on the server
 * already (the one it had, kept as it was): a file chosen in this form is added once its bytes are
 * uploaded (saveFlow.ts).
 */
export function fileFields(values: FileFormValues, existing?: VaultItem): ItemData {
  const file = values.file as AttachmentEntry | undefined;
  const stored = file !== undefined && file.file === undefined ? entryBody(file) : undefined;
  return {
    name: values.name,
    notes: values.notes === '' ? undefined : values.notes,
    favorite: values.favorite ? true : undefined,
    // A replaced or removed file leaves the body as it was until the new one is up.
    ...(stored !== undefined ? { file: stored } : {}),
    ...linksFields(existing?.data, values.links),
  };
}

function Drop({ control, setName }: { control: Control<FileFormValues>; setName: (name: string) => void }) {
  const t = useT();
  const id = useId();
  const { field, fieldState } = useController({ control, name: 'file' });
  const [over, setOver] = useState(false);
  const entry = field.value as AttachmentEntry | undefined;
  const choose = (file: File | undefined) => {
    if (!file) return;
    // The name is looked at before the file changes, to tell whether it was the old file's.
    setName(file.name);
    field.onChange(newAttachment(file));
  };
  return (
    <div className="field">
      <div
        className={over ? 'drop over' : 'drop'}
        onDragOver={(event) => {
          event.preventDefault();
          setOver(true);
        }}
        onDragLeave={() => setOver(false)}
        onDrop={(event) => {
          event.preventDefault();
          setOver(false);
          choose(event.dataTransfer.files[0]);
        }}
      >
        <span className="drop-icon" aria-hidden="true">
          <Icon name="file" />
        </span>
        <p className="drop-title">{t('itemForm.file.drop')}</p>
        {/* The input comes first so its focus ring can be drawn on the button after it. */}
        <input
          id={`${id}-file`}
          type="file"
          className="sr file-input"
          onChange={(event) => {
            const file = event.target.files?.[0];
            event.target.value = '';
            choose(file);
          }}
        />
        <label className="btn s" htmlFor={`${id}-file`}>
          {t('itemForm.file.choose')}
        </label>
        <p className="hint">{t('itemForm.file.quota')}</p>
      </div>
      {entry ? (
        <FileRow
          entry={entry}
          {...(entry.file ? { status: t('itemForm.file.ready') } : {})}
          onRemove={() => field.onChange(undefined)}
        />
      ) : null}
      {fieldState.error ? (
        <span className="error" role="alert">
          {t('itemForm.file.required')}
        </span>
      ) : null}
    </div>
  );
}

export function FileForm({ initial, onSubmit, onCancel, pending, error, submitLabel }: FormProps<FileFormValues>) {
  const t = useT();
  const { control, handleSubmit, getValues, setValue } = useForm<FileFormValues>({
    resolver: zodResolver(fileFormSchema),
    defaultValues: initial,
  });
  return (
    <form className="stack form-wide" noValidate onSubmit={handleSubmit(onSubmit)}>
      <section className="card pad" aria-labelledby="h-file">
        <h2 id="h-file" className="sr">
          {t('kind.file')}
        </h2>
        <Drop
          control={control}
          // The name follows the file until the person has typed one of their own.
          setName={(name) => {
            const current = getValues('name');
            const previous = (getValues('file') as AttachmentEntry | undefined)?.name;
            if (current === '' || current === previous || current === initial.file?.name) {
              setValue('name', name, { shouldDirty: true });
            }
          }}
        />
        <Field control={control} name="name" label={t('newItem.name')} />
      </section>
      <LinkedSection control={control} />
      <section className="card pad" aria-labelledby="h-more">
        <h2 id="h-more" className="sr">
          {t('newItem.more')}
        </h2>
        <Field control={control} name="notes" label={t('item.notes')} multiline />
        <CheckField control={control} name="favorite">
          {t('newItem.favorite')}
        </CheckField>
      </section>
      <Actions pending={pending} onCancel={onCancel} submitLabel={submitLabel} error={error} />
    </form>
  );
}
