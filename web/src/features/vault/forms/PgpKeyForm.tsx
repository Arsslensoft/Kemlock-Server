// A PGP key: pasted as ASCII armor (a private block, and a public block when there is one). The
// halves are stored as the binary transferable keys, base64, exactly as given. An item that exists
// changes only its name, notes and extras.
import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { z } from 'zod';
import { useT } from '@/i18n';
import { CheckField, Field } from '@/ui/fields';
import { type ItemData, type VaultItem, itemName } from '../vault';
import { ExtrasSections } from './ExtrasSections';
import { extrasDefaults, extrasFields, extrasShape } from './extras';
import { pgpHalves, pgpSecretProtected } from './keyMaterial';
import { Actions, type FormProps, isPinned } from './parts';

const base = {
  name: z.string().trim().min(1, 'error.required').max(200, 'error.tooLong'),
  note: z.string().max(10000, 'error.tooLong'),
  pinned: z.boolean(),
  armor: z.string().max(200000, 'error.tooLong'),
  ...extrasShape,
};

export const pgpKeySchema = z.object(base).refine((v) => v.armor.trim() !== '', {
  path: ['armor'],
  message: 'error.required',
});
export const pgpKeyEditSchema = z.object(base);
export type PgpKeyValues = z.infer<typeof pgpKeySchema>;

export function pgpKeyDefaults(item?: VaultItem): PgpKeyValues {
  return {
    name: item ? itemName(item) : '',
    note: typeof item?.data?.['note'] === 'string' ? item.data['note'] : '',
    pinned: isPinned(item),
    armor: '',
    ...extrasDefaults(item),
  };
}

/**
 * The fields a PGP key form owns; undefined when the pasted armor is not an OpenPGP key. `existing`
 * is the item being edited, whose key stays as it was.
 */
export function pgpKeyFields(values: PgpKeyValues, existing?: VaultItem): ItemData | undefined {
  const fields: ItemData = {
    name: values.name,
    note: values.note === '' ? undefined : values.note,
    pinned: values.pinned ? true : undefined,
    ...extrasFields(values, existing),
  };
  if (existing) return fields;
  const halves = pgpHalves(values.armor);
  // A private half is what makes it a key of the vault; a public-only paste belongs to Contacts.
  if (!halves?.private) return undefined;
  return {
    ...fields,
    kind: 'pgp',
    algorithm: 'pgp',
    private: halves.private,
    public: halves.public,
    // A passphrase on the private half: its S2K usage octet is not zero.
    protected: pgpSecretProtected(halves.private) ? true : undefined,
    origin: 'imported',
  };
}

export function PgpKeyForm({ initial, editing, onSubmit, onCancel, pending, error, submitLabel }: FormProps<PgpKeyValues>) {
  const t = useT();
  const { control, handleSubmit, setError } = useForm<PgpKeyValues>({
    resolver: zodResolver(editing ? pgpKeyEditSchema : pgpKeySchema),
    defaultValues: initial,
  });
  return (
    <form
      className="stack form-wide"
      noValidate
      onSubmit={handleSubmit((values) => {
        if (!editing && !pgpKeyFields(values)) {
          setError('armor', { message: 'keys.pgp.error.armor' });
          return;
        }
        onSubmit(values);
      })}
    >
      <section className="card pad" aria-labelledby="h-pgp">
        <h2 id="h-pgp">{t('keys.pgp.details')}</h2>
        <Field control={control} name="name" label={t('newItem.name')} autoFocus />
        {editing ? (
          <p className="hint">{t('keys.halvesFixed')}</p>
        ) : (
          <Field
            control={control}
            name="armor"
            label={t('keys.pgp.armor')}
            hint={t('keys.pgp.armorHint')}
            multiline
            mono
            autoComplete="off"
            placeholder="-----BEGIN PGP PRIVATE KEY BLOCK-----"
          />
        )}
      </section>
      <ExtrasSections control={control} kind="pgp-key" />
      <section className="card pad" aria-labelledby="h-pgp-more">
        <h2 id="h-pgp-more" className="sr">
          {t('newItem.more')}
        </h2>
        <Field control={control} name="note" label={t('item.notes')} multiline />
        <CheckField control={control} name="pinned">
          {t('newItem.favorite')}
        </CheckField>
      </section>
      <Actions pending={pending} onCancel={onCancel} submitLabel={submitLabel} error={error} />
    </form>
  );
}
