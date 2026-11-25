// A contact: a person (name, company, email, phone, address) and, optionally, their OpenPGP public
// key, pasted as ASCII armor. It holds no private key. The Kemlock app's contact is a public key
// (kemlock-core `Contact`: `public`, `source`); a contact without a key has neither, and the person
// fields are additions an app that doesn't know them keeps (docs/crypto.md, "Item bodies").
import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { z } from 'zod';
import { useT } from '@/i18n';
import { CheckField, Field } from '@/ui/fields';
import { type ItemData, type VaultItem, itemName } from '../vault';
import { ExtrasSections } from './ExtrasSections';
import { extrasDefaults, extrasFields, extrasShape } from './extras';
import { pgpHalves } from './keyMaterial';
import { Actions, type FormProps, entryBase, isPinned, orUndefined, str } from './parts';

const short = z.string().trim().max(200, 'error.tooLong');

export const contactSchema = z.object({
  name: z.string().trim().min(1, 'error.required').max(200, 'error.tooLong'),
  company: short,
  email: z
    .string()
    .trim()
    .refine((v) => v === '' || z.email().safeParse(v).success, 'error.email'),
  phone: short,
  address: z.string().max(2000, 'error.tooLong'),
  /** A pasted public key block; empty keeps the key the contact has, or leaves it with none. */
  armor: z.string().max(200000, 'error.tooLong'),
  /** The contact has a key already. */
  hadKey: z.boolean(),
  removeKey: z.boolean(),
  note: z.string().max(10000, 'error.tooLong'),
  pinned: z.boolean(),
  ...extrasShape,
});
export type ContactValues = z.infer<typeof contactSchema>;

export function contactDefaults(item?: VaultItem): ContactValues {
  return {
    name: item ? itemName(item) : '',
    company: str(item?.data, 'company'),
    email: str(item?.data, 'email'),
    phone: str(item?.data, 'phone'),
    address: str(item?.data, 'address'),
    armor: '',
    hadKey: str(item?.data, 'public') !== '',
    removeKey: false,
    note: str(item?.data, 'note'),
    pinned: isPinned(item),
    ...extrasDefaults(item),
  };
}

/** The public half of a pasted block, when it is exactly one public key (no private half). */
export function pastedPublicKey(armor: string): string | undefined {
  const halves = pgpHalves(armor);
  return halves?.public && !halves.private ? halves.public : undefined;
}

/** Whether something is pasted that is not exactly one public key. */
export function armorProblem(armor: string): boolean {
  return armor.trim() !== '' && pastedPublicKey(armor) === undefined;
}

/**
 * The fields a contact form owns. A pasted key replaces the key; "Remove the key" clears it and
 * what was checked against it; otherwise the key stays as it was. A contact with no key at all is
 * `source: manual`.
 */
export function contactFields(values: ContactValues, existing?: VaultItem): ItemData {
  const fields: ItemData = {
    ...entryBase(existing),
    name: values.name,
    company: orUndefined(values.company),
    email: orUndefined(values.email),
    phone: orUndefined(values.phone),
    address: orUndefined(values.address),
    note: orUndefined(values.note),
    pinned: values.pinned ? true : undefined,
    ...extrasFields(values, existing),
  };
  const pasted = pastedPublicKey(values.armor);
  if (pasted !== undefined) {
    return {
      ...fields,
      public: pasted,
      source: 'paste',
      checkedAt: undefined,
      checkedFingerprint: undefined,
      checkedAddresses: undefined,
    };
  }
  const hasKey = str(existing?.data, 'public') !== '';
  if (hasKey && !values.removeKey) return fields;
  return {
    ...fields,
    public: undefined,
    source: 'manual',
    checkedAt: undefined,
    checkedFingerprint: undefined,
    checkedAddresses: undefined,
  };
}

export function ContactForm({ initial, onSubmit, onCancel, pending, error, submitLabel }: FormProps<ContactValues>) {
  const t = useT();
  const { control, handleSubmit, setError } = useForm<ContactValues>({
    resolver: zodResolver(contactSchema),
    defaultValues: initial,
  });
  return (
    <form
      className="stack form-wide"
      noValidate
      onSubmit={handleSubmit((values) => {
        if (armorProblem(values.armor)) {
          setError('armor', { message: 'keys.contact.error.armor' });
          return;
        }
        onSubmit(values);
      })}
    >
      <section className="card pad" aria-labelledby="h-contact">
        <h2 id="h-contact">{t('keys.contact.details')}</h2>
        <div className="pair">
          <Field control={control} name="name" label={t('newItem.name')} autoFocus />
          <Field control={control} name="company" label={t('newItem.identity.company')} autoComplete="off" />
        </div>
        <div className="pair">
          <Field control={control} name="email" label={t('newItem.identity.email')} type="email" autoComplete="off" />
          <Field control={control} name="phone" label={t('newItem.identity.phone')} type="tel" autoComplete="off" />
        </div>
        <Field control={control} name="address" label={t('itemForm.contact.address')} multiline autoComplete="off" />
      </section>
      <section className="card pad" aria-labelledby="h-contact-key">
        <h2 id="h-contact-key">
          {t('itemForm.contact.keyTitle')} <span className="hint optional">{t('itemForm.contact.optional')}</span>
        </h2>
        <Field
          control={control}
          name="armor"
          label={t('keys.contact.armor')}
          hint={t(initial.hadKey ? 'itemForm.contact.armorHintHasKey' : 'itemForm.contact.armorHint')}
          multiline
          mono
          autoComplete="off"
          placeholder="-----BEGIN PGP PUBLIC KEY BLOCK-----"
        />
        {initial.hadKey ? (
          <CheckField control={control} name="removeKey">
            {t('itemForm.contact.removeKey')}
          </CheckField>
        ) : null}
      </section>
      <ExtrasSections control={control} kind="contact" />
      <section className="card pad" aria-labelledby="h-contact-more">
        <h2 id="h-contact-more" className="sr">
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
