import { zodResolver } from '@hookform/resolvers/zod';
import { useForm, useWatch } from 'react-hook-form';
import { z } from 'zod';
import { useT } from '@/i18n';
import { CheckField, Field, SelectField } from '@/ui/fields';
import type { ItemData, VaultItem } from '../vault';
import { ExtrasSections } from './ExtrasSections';
import { extrasDefaults, extrasFields, extrasShape } from './extras';
import { Actions, type FormProps, entryBase, isPinned, orUndefined, str } from './parts';

const short = z.string().trim().max(200, 'error.tooLong');

/** The titles the form offers; a title an item already has is offered too. */
export const TITLES = ['Mr', 'Mrs', 'Ms', 'Mx', 'Dr'];

export const identitySchema = z.object({
  name: z.string().trim().min(1, 'error.required').max(200, 'error.tooLong'),
  title: short,
  givenName: short,
  middleName: short,
  familyName: short,
  company: short,
  email: z
    .string()
    .trim()
    .refine((v) => v === '' || z.email().safeParse(v).success, 'error.email'),
  phone: short,
  birthDate: z
    .string()
    .trim()
    .refine((v) => v === '' || /^\d{4}-\d{2}-\d{2}$/.test(v), 'error.date'),
  line1: short,
  line2: short,
  line3: short,
  city: short,
  region: short,
  postalCode: short,
  country: short,
  note: z.string().max(10000, 'error.tooLong'),
  pinned: z.boolean(),
  ...extrasShape,
});
export type IdentityValues = z.infer<typeof identitySchema>;

function addressOf(item?: VaultItem): Record<string, unknown> {
  const address = item?.data?.['address'];
  return typeof address === 'object' && address !== null && !Array.isArray(address)
    ? (address as Record<string, unknown>)
    : {};
}

export function identityDefaults(item?: VaultItem): IdentityValues {
  const data = item?.data;
  const address = addressOf(item);
  const lines = Array.isArray(address['lines'])
    ? address['lines'].filter((line): line is string => typeof line === 'string')
    : [];
  const text = (key: string) => (typeof address[key] === 'string' ? (address[key] as string) : '');
  return {
    name: str(data, 'name'),
    title: str(data, 'title'),
    givenName: str(data, 'givenName'),
    middleName: str(data, 'middleName'),
    familyName: str(data, 'familyName'),
    company: str(data, 'company'),
    email: str(data, 'email'),
    phone: str(data, 'phone'),
    birthDate: str(data, 'birthDate'),
    line1: lines[0] ?? '',
    line2: lines[1] ?? '',
    line3: lines[2] ?? '',
    city: text('city'),
    region: text('region'),
    postalCode: text('postalCode'),
    country: text('country'),
    note: str(data, 'note'),
    pinned: isPinned(item),
    ...extrasDefaults(item),
  };
}

const ADDRESS_KEYS = ['lines', 'city', 'region', 'postalCode', 'country'];

/**
 * `Identity.toJson`. The address is `{lines (up to 3), city, region, postalCode, country}` and is
 * left out when empty; keys of it this form doesn't edit stay. `documents` is not edited here and
 * stays as it was.
 */
export function identityFields(values: IdentityValues, existing?: VaultItem): ItemData {
  const lines = [values.line1, values.line2, values.line3].map((line) => line.trim()).filter((line) => line !== '');
  const kept = Object.fromEntries(Object.entries(addressOf(existing)).filter(([key]) => !ADDRESS_KEYS.includes(key)));
  const address: Record<string, unknown> = { ...kept };
  if (lines.length > 0) address['lines'] = lines;
  for (const key of ['city', 'region', 'postalCode', 'country'] as const) {
    const value = orUndefined(values[key]);
    if (value !== undefined) address[key] = value;
  }
  return {
    ...entryBase(existing),
    name: values.name,
    title: orUndefined(values.title),
    givenName: orUndefined(values.givenName),
    middleName: orUndefined(values.middleName),
    familyName: orUndefined(values.familyName),
    company: orUndefined(values.company),
    email: orUndefined(values.email),
    phone: orUndefined(values.phone),
    birthDate: orUndefined(values.birthDate),
    address: Object.keys(address).length > 0 ? address : undefined,
    note: orUndefined(values.note),
    pinned: values.pinned ? true : undefined,
    ...extrasFields(values, existing),
  };
}

export function IdentityForm({
  initial,
  onSubmit,
  onCancel,
  pending,
  error,
  submitLabel,
}: FormProps<IdentityValues>) {
  const t = useT();
  const { control, handleSubmit } = useForm<IdentityValues>({
    resolver: zodResolver(identitySchema),
    defaultValues: initial,
  });
  const title = useWatch({ control, name: 'title' });
  const titles = title === '' || TITLES.includes(title) ? TITLES : [...TITLES, title];
  return (
    <form className="stack form-wide" noValidate onSubmit={handleSubmit(onSubmit)}>
      <section className="card pad" aria-labelledby="h-identity">
        <h2 id="h-identity">{t('newItem.identity.details')}</h2>
        <Field control={control} name="name" label={t('newItem.name')} autoFocus />
        <div className="pair">
          <SelectField
            control={control}
            name="title"
            label={t('newItem.identity.title')}
            options={['', ...titles].map((value) => ({ value, label: value }))}
          />
          <Field control={control} name="givenName" label={t('newItem.identity.givenName')} autoComplete="off" />
        </div>
        <div className="pair">
          <Field control={control} name="middleName" label={t('newItem.identity.middleName')} autoComplete="off" />
          <Field control={control} name="familyName" label={t('newItem.identity.familyName')} autoComplete="off" />
        </div>
        <div className="pair">
          <Field control={control} name="company" label={t('newItem.identity.company')} autoComplete="off" />
          <Field
            control={control}
            name="birthDate"
            label={t('newItem.identity.birthDate')}
            type="date"
            autoComplete="off"
          />
        </div>
        <div className="pair">
          <Field control={control} name="email" label={t('newItem.identity.email')} type="email" autoComplete="off" />
          <Field control={control} name="phone" label={t('newItem.identity.phone')} type="tel" autoComplete="off" />
        </div>
      </section>
      <section className="card pad" aria-labelledby="h-identity-address">
        <h2 id="h-identity-address">{t('newItem.identity.address')}</h2>
        <Field control={control} name="line1" label={t('newItem.identity.line1')} autoComplete="off" />
        <div className="pair">
          <Field control={control} name="line2" label={t('newItem.identity.line2')} autoComplete="off" />
          <Field control={control} name="line3" label={t('newItem.identity.line3')} autoComplete="off" />
        </div>
        <div className="pair">
          <Field control={control} name="city" label={t('newItem.identity.city')} autoComplete="off" />
          <Field control={control} name="region" label={t('newItem.identity.region')} autoComplete="off" />
        </div>
        <div className="pair">
          <Field control={control} name="postalCode" label={t('newItem.identity.postalCode')} autoComplete="off" />
          <Field control={control} name="country" label={t('newItem.identity.country')} autoComplete="off" />
        </div>
      </section>
      <ExtrasSections control={control} kind="identity" />
      <section className="card pad" aria-labelledby="h-identity-more">
        <h2 id="h-identity-more" className="sr">
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
