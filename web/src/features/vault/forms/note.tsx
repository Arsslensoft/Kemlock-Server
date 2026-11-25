// The secure note form: name and text, linked items, custom fields, and the note's attachments
// (only a note has them), then the favorite box.
import { zodResolver } from '@hookform/resolvers/zod';
import { type Control, useController, useForm } from 'react-hook-form';
import { z } from 'zod';
import { useT } from '@/i18n';
import { CheckField, Field } from '@/ui/fields';
import {
  type AttachmentEntry,
  MAX_ATTACHMENTS,
  attachmentSchema,
  copiedEntries,
  noteAttachmentFields,
  readAttachments,
} from '../attachments';
import { type ItemData, type VaultItem, itemName, noteOf } from '../vault';
import { AttachmentsEditor } from './AttachmentsEditor';
import { ExtrasSections } from './ExtrasSections';
import { extrasDefaults, extrasFields, extrasShape } from './extras';
import { Actions, type FormProps } from './parts';
import { noteSchema } from '@/lib/schemas';

export const noteFormSchema = noteSchema.extend({
  attachments: z.array(attachmentSchema).max(MAX_ATTACHMENTS, 'error.tooLong'),
  ...extrasShape,
});
export type NoteFormValues = z.infer<typeof noteFormSchema>;

/**
 * What the form opens with. For a copy (`copying`) the original's files are listed as files still to
 * be sent again under the copy, and the copy names none until they have been.
 */
export function noteDefaults(item?: VaultItem, copying = false): NoteFormValues {
  const attachments = readAttachments(item?.data);
  return {
    name: item ? itemName(item) : '',
    text: item ? noteOf(item) : '',
    favorite: item?.data?.favorite === true,
    attachments: copying && item ? copiedEntries(attachments, item.id) : attachments,
    ...extrasDefaults(item),
  };
}

/**
 * The fields a note form owns. Its attachments are the ones already stored: a file chosen in this
 * form is added once its bytes are on the server (saveFlow.ts).
 */
export function noteFields(values: NoteFormValues, existing?: VaultItem): ItemData {
  return {
    name: values.name,
    text: values.text,
    favorite: values.favorite ? true : undefined,
    ...noteAttachmentFields(values.attachments as AttachmentEntry[], existing?.data),
    ...extrasFields(values, existing),
  };
}

function Attachments({ control }: { control: Control<NoteFormValues> }) {
  const { field } = useController({ control, name: 'attachments' });
  return <AttachmentsEditor value={field.value as AttachmentEntry[]} onChange={field.onChange} />;
}

export function NoteForm({ initial, onSubmit, onCancel, pending, error, submitLabel }: FormProps<NoteFormValues>) {
  const t = useT();
  const { control, handleSubmit } = useForm<NoteFormValues>({
    resolver: zodResolver(noteFormSchema),
    defaultValues: initial,
  });
  return (
    <form className="stack form-wide" noValidate onSubmit={handleSubmit(onSubmit)}>
      <section className="card pad">
        <h2>{t('kind.note')}</h2>
        <Field control={control} name="name" label={t('newItem.name')} autoFocus />
        <Field control={control} name="text" label={t('itemForm.note.text')} multiline />
      </section>
      <ExtrasSections control={control} kind="note" />
      <section className="card pad" aria-labelledby="h-more">
        <h2 id="h-more" className="sr">
          {t('newItem.more')}
        </h2>
        <Attachments control={control} />
        <CheckField control={control} name="favorite">
          {t('newItem.favorite')}
        </CheckField>
      </section>
      <Actions pending={pending} onCancel={onCancel} submitLabel={submitLabel} error={error} />
    </form>
  );
}
