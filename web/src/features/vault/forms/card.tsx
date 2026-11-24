import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { z } from 'zod';
import { useT } from '@/i18n';
import { CheckField, Field } from '@/ui/fields';
import type { ItemData, VaultItem } from '../vault';
import { Actions, type FormProps, entryBase, isPinned, orUndefined, str } from './parts';

/** The digits of a card number typed or pasted (kemlock-core `cardDigits`). */
export function cardDigits(text: string): string {
  return text.replace(/[^0-9]/g, '');
}

/** A year from one or two digits: 29 is 2029, 2029 stays (kemlock-core `cardYear`). */
function cardYear(year: number | undefined): number | undefined {
  if (year === undefined || Number.isNaN(year)) return undefined;
  if (year >= 0 && year <= 99) return 2000 + year;
  if (year >= 1000 && year <= 9999) return year;
  return undefined;
}

function month(value: number | undefined): number | undefined {
  return value !== undefined && value >= 1 && value <= 12 ? value : undefined;
}

/** A month and a year from "05/29", "5/2029", "05-29" or "0529" (kemlock-core `parseCardExpiry`). */
export function parseCardExpiry(text: string): { month?: number; year?: number } {
  const parts = text
    .trim()
    .split(/[\s/\-.]+/)
    .filter((part) => part !== '');
  if (parts.some((part) => !/^[0-9]+$/.test(part))) return {};
  const int = (value: string | undefined) => (value === undefined ? undefined : Number.parseInt(value, 10));
  const only = parts[0];
  const out: { month?: number; year?: number } = {};
  const set = (m: number | undefined, y: number | undefined) => {
    if (m !== undefined) out.month = m;
    if (y !== undefined) out.year = y;
    return out;
  };
  if (parts.length === 1 && only !== undefined && only.length === 4) {
    return set(month(int(only.slice(0, 2))), cardYear(int(only.slice(2))));
  }
  if (parts.length === 1) return set(month(int(only)), undefined);
  if (parts.length !== 2) return out;
  return set(month(int(parts[0])), cardYear(int(parts[1])));
}

export const cardSchema = z
  .object({
    name: z.string().trim().min(1, 'error.required').max(200, 'error.tooLong'),
    cardholder: z.string().trim().max(200, 'error.tooLong'),
    number: z.string().refine((v) => /^[0-9 -]*$/.test(v) && cardDigits(v).length <= 19, 'error.cardNumber'),
    brand: z.string().trim().max(100, 'error.tooLong'),
    expiry: z.string().refine((v) => {
      if (v.trim() === '') return true;
      const parsed = parseCardExpiry(v);
      return parsed.month !== undefined && parsed.year !== undefined;
    }, 'error.cardExpiry'),
    code: z.string().max(20, 'error.tooLong'),
    pin: z.string().max(20, 'error.tooLong'),
    note: z.string().max(10000, 'error.tooLong'),
    pinned: z.boolean(),
  })
  .refine((v) => cardDigits(v.number) !== '' || v.cardholder !== '', {
    path: ['number'],
    message: 'error.cardIncomplete',
  });
export type CardValues = z.infer<typeof cardSchema>;

export function cardDefaults(item?: VaultItem): CardValues {
  const data = item?.data;
  const expMonth = data?.['expMonth'];
  const expYear = data?.['expYear'];
  const expiry =
    typeof expMonth === 'number' && typeof expYear === 'number'
      ? `${String(expMonth).padStart(2, '0')}/${String(expYear)}`
      : '';
  return {
    name: str(data, 'name'),
    cardholder: str(data, 'cardholder'),
    number: str(data, 'number'),
    brand: str(data, 'brand'),
    expiry,
    code: str(data, 'code'),
    pin: str(data, 'pin'),
    note: str(data, 'note'),
    pinned: isPinned(item),
  };
}

/** `PaymentCard.toJson`: the number as digits, the expiry as `expMonth` and a four-digit `expYear`. */
export function cardFields(values: CardValues, existing?: VaultItem): ItemData {
  const expiry = values.expiry.trim() === '' ? {} : parseCardExpiry(values.expiry);
  return {
    ...entryBase(existing),
    name: values.name,
    cardholder: orUndefined(values.cardholder),
    number: orUndefined(cardDigits(values.number)),
    brand: orUndefined(values.brand),
    expMonth: expiry.month,
    expYear: expiry.year,
    code: orUndefined(values.code),
    pin: orUndefined(values.pin),
    note: orUndefined(values.note),
    pinned: values.pinned ? true : undefined,
  };
}

export function CardForm({ initial, onSubmit, onCancel, pending, error, submitLabel }: FormProps<CardValues>) {
  const t = useT();
  const { control, handleSubmit } = useForm<CardValues>({
    resolver: zodResolver(cardSchema),
    defaultValues: initial,
  });
  return (
    <form className="stack form-wide" noValidate onSubmit={handleSubmit(onSubmit)}>
      <section className="card pad" aria-labelledby="h-card">
        <h2 id="h-card" className="sr">
          {t('newItem.card.details')}
        </h2>
        <Field control={control} name="name" label={t('newItem.name')} autoFocus />
        <Field control={control} name="cardholder" label={t('newItem.card.cardholder')} autoComplete="off" />
        <Field
          control={control}
          name="number"
          label={t('newItem.card.number')}
          mono
          inputMode="numeric"
          autoComplete="off"
        />
        <Field control={control} name="brand" label={t('newItem.card.brand')} autoComplete="off" />
        <Field
          control={control}
          name="expiry"
          label={t('newItem.card.expiry')}
          placeholder="MM/YY"
          autoComplete="off"
        />
        <Field control={control} name="code" label={t('newItem.card.code')} type="password" mono autoComplete="off" />
        <Field control={control} name="pin" label={t('newItem.card.pin')} type="password" mono autoComplete="off" />
      </section>
      <section className="card pad" aria-labelledby="h-card-more">
        <h2 id="h-card-more" className="sr">
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
