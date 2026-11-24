import { zodResolver } from '@hookform/resolvers/zod';
import { useForm, useWatch } from 'react-hook-form';
import { z } from 'zod';
import { useT } from '@/i18n';
import { CheckField, Field, SelectField } from '@/ui/fields';
import type { ItemData, VaultItem } from '../vault';
import { Actions, type FormProps, entryBase, isPinned, num, orUndefined, str } from './parts';

/** A secret as authenticator apps print it: base32, spaces and case are free. */
export function normaliseSecret(value: string): string {
  return value.replace(/[\s-]/g, '').toUpperCase();
}

const wholeNumber = (min: number, max: number) =>
  z.string().refine((v) => /^\d+$/.test(v.trim()) && Number(v) >= min && Number(v) <= max, 'error.number');

export const otpSchema = z
  .object({
    issuer: z.string().trim().max(200, 'error.tooLong'),
    label: z.string().trim().max(200, 'error.tooLong'),
    secret: z.string().refine((v) => /^[A-Z2-7]+=*$/.test(normaliseSecret(v)), 'error.otpSecret'),
    type: z.enum(['totp', 'hotp', 'steam']),
    algorithm: z.enum(['SHA1', 'SHA256', 'SHA512']),
    digits: wholeNumber(5, 10),
    period: wholeNumber(1, 3600),
    counter: z.string().refine((v) => v.trim() === '' || /^\d+$/.test(v.trim()), 'error.number'),
    note: z.string().max(10000, 'error.tooLong'),
    pinned: z.boolean(),
  })
  .refine((v) => v.issuer !== '' || v.label !== '', { path: ['issuer'], message: 'error.required' });
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
  };
}

/** The keys `OtpAccount.toJson` writes; `counter` only for a counter-based code. */
export function otpFields(values: OtpValues, existing?: VaultItem): ItemData {
  return {
    ...entryBase(existing),
    type: values.type,
    issuer: values.issuer,
    label: values.label,
    secret: normaliseSecret(values.secret).replace(/=+$/, ''),
    algorithm: values.algorithm,
    digits: Number(values.digits),
    period: Number(values.period),
    counter: values.type === 'hotp' ? Number(values.counter === '' ? '0' : values.counter) : undefined,
    note: orUndefined(values.note),
    pinned: values.pinned ? true : undefined,
  };
}

export function OtpForm({ initial, onSubmit, onCancel, pending, error, submitLabel }: FormProps<OtpValues>) {
  const t = useT();
  const { control, handleSubmit } = useForm<OtpValues>({
    resolver: zodResolver(otpSchema),
    defaultValues: initial,
  });
  const type = useWatch({ control, name: 'type' });
  return (
    <form className="stack form-wide" noValidate onSubmit={handleSubmit(onSubmit)}>
      <section className="card pad" aria-labelledby="h-otp">
        <h2 id="h-otp" className="sr">
          {t('newItem.otp.details')}
        </h2>
        <Field control={control} name="issuer" label={t('newItem.otp.issuer')} autoFocus />
        <Field control={control} name="label" label={t('newItem.otp.label')} autoComplete="off" />
        <Field
          control={control}
          name="secret"
          label={t('newItem.otp.secret')}
          type="password"
          mono
          autoComplete="off"
          hint={t('newItem.otp.secretHint')}
        />
      </section>
      <section className="card pad" aria-labelledby="h-otp-more">
        <h2 id="h-otp-more" className="sr">
          {t('newItem.otp.settings')}
        </h2>
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
        <Field control={control} name="digits" label={t('newItem.otp.digits')} inputMode="numeric" />
        {type === 'hotp' ? (
          <Field control={control} name="counter" label={t('newItem.otp.counter')} inputMode="numeric" />
        ) : (
          <Field control={control} name="period" label={t('newItem.otp.period')} inputMode="numeric" />
        )}
        <Field control={control} name="note" label={t('item.notes')} multiline />
        <CheckField control={control} name="pinned">
          {t('newItem.favorite')}
        </CheckField>
      </section>
      <Actions pending={pending} onCancel={onCancel} submitLabel={submitLabel} error={error} />
    </form>
  );
}
