// A contact: someone else's OpenPGP public key, pasted as ASCII armor. It holds no private key.
// An item that exists changes only its name and note.
import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { z } from 'zod';
import { useT } from '@/i18n';
import { Field } from '@/ui/fields';
import { pgpHalves } from './keyMaterial';
import { FormActions, type KeyFormProps } from './shared';
import type { ItemData, VaultItem } from '../vault';
import { itemName } from '../vault';

const base = {
  name: z.string().trim().min(1, 'error.required').max(200, 'error.tooLong'),
  note: z.string().max(10000, 'error.tooLong'),
  armor: z.string().max(200000, 'error.tooLong'),
};

export const contactSchema = z.object(base).refine((v) => v.armor.trim() !== '', {
  path: ['armor'],
  message: 'error.required',
});
export const contactEditSchema = z.object(base);
export type ContactValues = z.infer<typeof contactSchema>;

export function contactDefaults(item?: VaultItem): ContactValues {
  return {
    name: item ? itemName(item) : '',
    note: typeof item?.data?.['note'] === 'string' ? item.data['note'] : '',
    armor: '',
  };
}

/** The fields a contact form owns; undefined when the paste is not exactly one public key. */
export function contactFields(values: ContactValues, editing: boolean): ItemData | undefined {
  const fields: ItemData = { name: values.name, note: values.note === '' ? undefined : values.note };
  if (editing) return fields;
  const halves = pgpHalves(values.armor);
  if (!halves?.public || halves.private) return undefined;
  return { ...fields, public: halves.public, source: 'paste' };
}

export function ContactForm({ initial, editing, onSubmit, onCancel, pending, error, submitLabel }: KeyFormProps<ContactValues>) {
  const t = useT();
  const { control, handleSubmit, setError } = useForm<ContactValues>({
    resolver: zodResolver(editing ? contactEditSchema : contactSchema),
    defaultValues: initial,
  });
  return (
    <form
      className="stack form-wide"
      noValidate
      onSubmit={handleSubmit((values) => {
        if (!editing && !contactFields(values, false)) {
          setError('armor', { message: 'keys.contact.error.armor' });
          return;
        }
        onSubmit(values);
      })}
    >
      <section className="card pad" aria-labelledby="h-contact">
        <h2 id="h-contact" className="sr">
          {t('keys.contact.details')}
        </h2>
        <Field control={control} name="name" label={t('newItem.name')} autoFocus />
        {editing ? (
          <p className="hint">{t('keys.halvesFixed')}</p>
        ) : (
          <Field
            control={control}
            name="armor"
            label={t('keys.contact.armor')}
            hint={t('keys.contact.armorHint')}
            multiline
            mono
            autoComplete="off"
            placeholder="-----BEGIN PGP PUBLIC KEY BLOCK-----"
          />
        )}
        <Field control={control} name="note" label={t('item.notes')} multiline />
      </section>
      <FormActions pending={pending} onCancel={onCancel} submitLabel={submitLabel} error={error} />
    </form>
  );
}
