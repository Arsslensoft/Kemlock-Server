// The MFA code form (the stored kind is `otp`). Its items are the Kemlock app's own entries
// (kemlock-core `OtpAccount`), so the keys are the app's: `issuer`, `label`, `secret`, `websites`.
import { zodResolver } from '@hookform/resolvers/zod';
import { useForm, useWatch } from 'react-hook-form';
import { z } from 'zod';
import { useT } from '@/i18n';
import { CheckField, Field, SelectField } from '@/ui/fields';
import { hostsText, websiteFields } from '../linkedSites';
import type { ItemData, VaultItem } from '../vault';
import { ExtrasSections } from './ExtrasSections';
import { WebsiteField, useLinkedWebsites } from './WebsiteField';
import { extrasDefaults, extrasFields, extrasShape } from './extras';
import { Actions, type FormProps, entryBase, isPinned, num, orUndefined, str } from './parts';

/** A secret as authenticator apps print it: base32, spaces and case are free. */
export function normaliseSecret(value: string): string {
  return value.replace(/[\s-]/g, '').toUpperCase();
}

const wholeNumber = (min: number, max: number) =>
  z.string().refine((v) => /^\d+$/.test(v.trim()) && Number(v) >= min && Number(v) <= max, 'error.number');

export const otpSchema = z
  .object({
    name: z.string().trim().max(200, 'error.tooLong'),
    /** Left out (undefined) when the website comes from a linked item. */
    website: z.string().max(2000, 'error.tooLong').optional(),
    issuer: z.string().trim().max(200, 'error.tooLong'),
    label: z.string().trim().max(200, 'error.tooLong'),
    secret: z.string().refine((v) => /^[A-Z2-7]{16,}=*$/.test(normaliseSecret(v)), 'error.otpSecret'),
    type: z.enum(['totp', 'hotp', 'steam']),
    algorithm: z.enum(['SHA1', 'SHA256', 'SHA512']),
    digits: wholeNumber(5, 10),
    period: wholeNumber(1, 3600),
    counter: z.string().refine((v) => v.trim() === '' || /^\d+$/.test(v.trim()), 'error.number'),
    note: z.string().max(10000, 'error.tooLong'),
    pinned: z.boolean(),
    ...extrasShape,
  })
  .refine((v) => v.name !== '' || v.issuer !== '' || v.label !== '', { path: ['name'], message: 'error.required' });
export type OtpValues = z.infer<typeof otpSchema>;

const TYPES = ['totp', 'hotp', 'steam'] as const;
const ALGORITHMS = ['SHA1', 'SHA256', 'SHA512'] as const;

function pick<T extends string>(value: string, allowed: readonly T[], fallback: T): T {
  return allowed.find((option) => option === value) ?? fallback;
}

export function otpDefaults(item?: VaultItem): OtpValues {
  const data = item?.data;
  const type = pick(str(data, 'type'), TYPES, 'totp');
  return {
    name: str(data, 'name'),
    website: hostsText(data),
    issuer: str(data, 'issuer'),
    label: str(data, 'label'),
    secret: str(data, 'secret'),
    type,
    algorithm: pick(str(data, 'algorithm'), ALGORITHMS, 'SHA1'),
    digits: num(data, 'digits') || (type === 'steam' ? '5' : '6'),
    period: num(data, 'period') || '30',
    counter: num(data, 'counter'),
    note: str(data, 'note'),
    pinned: isPinned(item),
    ...extrasDefaults(item),
  };
}

/** The keys `OtpAccount.toJson` writes; `counter` only for a counter-based code. */
export function otpFields(values: OtpValues, existing?: VaultItem): ItemData {
  return {
    ...entryBase(existing),
    type: values.type,
    name: orUndefined(values.name),
    issuer: values.issuer,
    label: values.label,
    secret: normaliseSecret(values.secret).replace(/=+$/, ''),
    algorithm: values.algorithm,
    digits: Number(values.digits),
    period: Number(values.period),
    counter: values.type === 'hotp' ? Number(values.counter === '' ? '0' : values.counter) : undefined,
    // The websites of a linked item are not this code's to write.
    ...(values.website === undefined ? {} : websiteFields(values.website, existing?.data)),
    note: orUndefined(values.note),
    pinned: values.pinned ? true : undefined,
    ...extrasFields(values, existing),
  };
}

/** The digits a code may have: the usual ones, and the one it has if that is another. */
function digitOptions(current: string): Array<{ value: string; label: string }> {
  const values = ['6', '7', '8'];
  if (current !== '' && !values.includes(current)) values.push(current);
  return values.sort((a, b) => Number(a) - Number(b)).map((value) => ({ value, label: value }));
}

export function OtpForm({ initial, onSubmit, onCancel, pending, error, submitLabel }: FormProps<OtpValues>) {
  const t = useT();
  const { control, handleSubmit } = useForm<OtpValues>({
    resolver: zodResolver(otpSchema),
    defaultValues: initial,
  });
  const type = useWatch({ control, name: 'type' });
  const digits = useWatch({ control, name: 'digits' });
  const linked = useLinkedWebsites(control);
  return (
    <form
      className="stack form-wide"
      noValidate
      onSubmit={handleSubmit((values) => onSubmit({ ...values, website: linked ? undefined : values.website }))}
    >
      <section className="card pad" aria-labelledby="h-otp">
        <h2 id="h-otp">{t('newItem.otp.details')}</h2>
        <Field control={control} name="name" label={t('newItem.name')} autoFocus />
        <WebsiteField control={control} linked={linked} />
        <div className="pair">
          <Field control={control} name="issuer" label={t('newItem.otp.issuer')} autoComplete="off" />
          <Field control={control} name="label" label={t('newItem.otp.label')} autoComplete="off" />
        </div>
        <Field
          control={control}
          name="secret"
          label={t('newItem.otp.secret')}
          mono
          autoComplete="off"
          hint={t('newItem.otp.secretHint')}
        />
      </section>
      <section className="card pad" aria-labelledby="h-otp-more">
        <h2 id="h-otp-more">{t('newItem.otp.settings')}</h2>
        <div className="pair">
          <SelectField
            control={control}
            name="type"
            label={t('newItem.otp.type')}
            options={[
              { value: 'totp', label: t('newItem.otp.type.totp') },
              { value: 'hotp', label: t('newItem.otp.type.hotp') },
              { value: 'steam', label: t('newItem.otp.type.steam') },
            ]}
          />
          <SelectField
            control={control}
            name="algorithm"
            label={t('newItem.otp.algorithm')}
            options={ALGORITHMS.map((value) => ({ value, label: value }))}
          />
        </div>
        <div className="pair">
          <SelectField control={control} name="digits" label={t('newItem.otp.digits')} options={digitOptions(digits)} />
          {type === 'hotp' ? (
            <Field control={control} name="counter" label={t('newItem.otp.counter')} inputMode="numeric" />
          ) : (
            <Field control={control} name="period" label={t('newItem.otp.period')} inputMode="numeric" />
          )}
        </div>
      </section>
      <ExtrasSections control={control} kind="otp" />
      <section className="card pad" aria-labelledby="h-otp-notes">
        <h2 id="h-otp-notes" className="sr">
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
