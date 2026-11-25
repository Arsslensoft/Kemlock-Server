// The card form. Its items are the Kemlock app's own entries (kemlock-core `PaymentCard`). The
// brand is read from the number as it is typed and shown as a badge in the field, the number is
// grouped for its brand and checked by length and the Luhn check, and the security code takes 3 or 4
// digits (4 for American Express). There is no Brand box.
import { zodResolver } from '@hookform/resolvers/zod';
import { useId, useState } from 'react';
import { type Control, useController, useForm, useWatch } from 'react-hook-form';
import { z } from 'zod';
import { type MessageId, useT } from '@/i18n';
import { CheckField, Field } from '@/ui/fields';
import type { ItemData, VaultItem } from '../vault';
import { ExtrasSections } from './ExtrasSections';
import {
  type CardBrand,
  cardCodeProblem,
  cardDigits,
  cardNumberProblem,
  cvcStatus,
  detectBrand,
  formatCardNumber,
  formatStoredNumber,
  numberStatus,
} from './cardBrand';
import { extrasDefaults, extrasFields, extrasShape } from './extras';
import { Actions, type FormProps, entryBase, isPinned, orUndefined, str } from './parts';

export { cardDigits } from './cardBrand';

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
    number: z.string().max(40, 'error.tooLong'),
    /** The brand the item had; written only when the number names none. Not a box in the form. */
    brand: z.string().trim().max(100, 'error.tooLong'),
    expiry: z.string().refine((v) => {
      if (v.trim() === '') return true;
      const parsed = parseCardExpiry(v);
      return parsed.month !== undefined && parsed.year !== undefined;
    }, 'error.cardExpiry'),
    code: z.string().max(20, 'error.tooLong'),
    /** The digits and the code the item had: what is unchanged from them is not checked again. */
    storedNumber: z.string(),
    storedCode: z.string(),
    pin: z.string().max(20, 'error.tooLong'),
    note: z.string().max(10000, 'error.tooLong'),
    pinned: z.boolean(),
    ...extrasShape,
  })
  .superRefine((v, ctx) => {
    const digits = cardDigits(v.number);
    if (digits === '' && v.cardholder === '') {
      ctx.addIssue({ code: 'custom', path: ['number'], message: 'error.cardIncomplete' });
      return;
    }
    // A card is checked where the person changed it: what it held before is theirs to keep as it is.
    const number = digits === v.storedNumber ? undefined : cardNumberProblem(digits);
    if (number) ctx.addIssue({ code: 'custom', path: ['number'], message: number });
    const code = v.code.trim() === v.storedCode ? undefined : cardCodeProblem(v.code.trim(), digits);
    if (code) ctx.addIssue({ code: 'custom', path: ['code'], message: code });
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
    number: formatStoredNumber(str(data, 'number')),
    brand: str(data, 'brand'),
    expiry,
    code: str(data, 'code'),
    storedNumber: cardDigits(str(data, 'number')),
    storedCode: str(data, 'code').trim(),
    pin: str(data, 'pin'),
    note: str(data, 'note'),
    pinned: isPinned(item),
    ...extrasDefaults(item),
  };
}

/**
 * `PaymentCard.toJson`: the number as digits, the expiry as `expMonth` and a four-digit `expYear`.
 * The brand is the one the number names, written when the number changed or the item had no brand;
 * a card whose number is as it was keeps the brand it had, and so does a number that names none.
 */
export function cardFields(values: CardValues, existing?: VaultItem): ItemData {
  const expiry = values.expiry.trim() === '' ? {} : parseCardExpiry(values.expiry);
  const digits = cardDigits(values.number);
  const had = str(existing?.data, 'brand');
  const changed = digits !== cardDigits(str(existing?.data, 'number'));
  const brand = changed || had === '' ? (detectBrand(digits)?.name ?? orUndefined(values.brand)) : orUndefined(values.brand);
  return {
    ...entryBase(existing),
    name: values.name,
    cardholder: orUndefined(values.cardholder),
    number: orUndefined(digits),
    brand,
    expMonth: expiry.month,
    expYear: expiry.year,
    code: orUndefined(values.code),
    pin: orUndefined(values.pin),
    note: orUndefined(values.note),
    pinned: values.pinned ? true : undefined,
    ...extrasFields(values, existing),
  };
}

function CardNumberField({ control }: { control: Control<CardValues> }) {
  const t = useT();
  const id = useId();
  const { field, fieldState } = useController({ control, name: 'number' });
  const [blurred, setBlurred] = useState(false);
  const stored = useWatch({ control, name: 'storedNumber' });
  const digits = cardDigits(field.value);
  const brand = detectBrand(digits);
  // A number as the card had it is not checked: only one the person typed is.
  const unchanged = digits !== '' && digits === stored;
  const status = unchanged ? undefined : numberStatus(digits, blurred);
  // A refused Save says why even when the number is only incomplete so far.
  const refused = status?.state === 'pending' ? fieldState.error?.message : undefined;
  const tone = refused ? 'err' : (status?.state ?? 'pending');
  return (
    <div className="field" data-invalid={tone === 'err' ? true : undefined}>
      <label htmlFor={`${id}-n`}>{t('newItem.card.number')}</label>
      <div className="brand-box">
        <input
          id={`${id}-n`}
          ref={field.ref}
          name={field.name}
          className="mono"
          type="text"
          inputMode="numeric"
          autoComplete="off"
          spellCheck={false}
          value={field.value}
          aria-describedby={status ? `${id}-msg` : undefined}
          aria-invalid={tone === 'err' ? true : undefined}
          onChange={(event) => field.onChange(formatCardNumber(event.target.value))}
          onBlur={() => {
            setBlurred(true);
            field.onBlur();
          }}
        />
        {brand ? <span className="brand-badge">{brand.name}</span> : null}
      </div>
      {status ? (
        <span
          id={`${id}-msg`}
          className={tone === 'err' ? 'hint bad' : tone === 'ok' ? 'hint good' : 'hint'}
          role={tone === 'err' ? 'alert' : undefined}
        >
          {refused ? t(refused as MessageId) : t(status.message, status.values)}
        </span>
      ) : null}
    </div>
  );
}

function SecurityCodeField({ control, brand }: { control: Control<CardValues>; brand: CardBrand | undefined }) {
  const t = useT();
  const id = useId();
  const { field, fieldState } = useController({ control, name: 'code' });
  const [blurred, setBlurred] = useState(false);
  const stored = useWatch({ control, name: 'storedCode' });
  // A code as the card had it is not checked: only one the person typed is.
  const unchanged = field.value !== '' && field.value.trim() === stored;
  const status = cvcStatus(unchanged ? '' : field.value, brand, blurred || Boolean(fieldState.error));
  return (
    <div className="field" data-invalid={status.state === 'err' ? true : undefined}>
      <label htmlFor={`${id}-c`}>{t('newItem.card.code')}</label>
      <input
        id={`${id}-c`}
        ref={field.ref}
        name={field.name}
        className="mono"
        type="text"
        inputMode="numeric"
        autoComplete="off"
        spellCheck={false}
        maxLength={4}
        value={field.value}
        aria-describedby={`${id}-msg`}
        aria-invalid={status.state === 'err' ? true : undefined}
        onChange={(event) => field.onChange(cardDigits(event.target.value).slice(0, 4))}
        onBlur={() => {
          setBlurred(true);
          field.onBlur();
        }}
      />
      <span
        id={`${id}-msg`}
        className={status.state === 'err' ? 'hint bad' : 'hint'}
        role={status.state === 'err' ? 'alert' : undefined}
      >
        {t(status.message, status.values)}
      </span>
    </div>
  );
}

export function CardForm({ initial, onSubmit, onCancel, pending, error, submitLabel }: FormProps<CardValues>) {
  const t = useT();
  const { control, handleSubmit } = useForm<CardValues>({
    resolver: zodResolver(cardSchema),
    defaultValues: initial,
  });
  const number = useWatch({ control, name: 'number' });
  const brand = detectBrand(cardDigits(number));
  return (
    <form className="stack form-wide" noValidate onSubmit={handleSubmit(onSubmit)}>
      <section className="card pad" aria-labelledby="h-card">
        <h2 id="h-card">{t('newItem.card.details')}</h2>
        <Field control={control} name="name" label={t('newItem.name')} autoFocus />
        <Field control={control} name="cardholder" label={t('newItem.card.cardholder')} autoComplete="off" />
        <CardNumberField control={control} />
        <div className="pair">
          <Field
            control={control}
            name="expiry"
            label={t('newItem.card.expiry')}
            placeholder="MM/YY"
            mono
            inputMode="numeric"
            autoComplete="off"
          />
          <SecurityCodeField control={control} brand={brand} />
        </div>
        <Field
          control={control}
          name="pin"
          label={t('newItem.card.pin')}
          type="password"
          mono
          inputMode="numeric"
          autoComplete="off"
          hint={t('itemForm.card.optional')}
        />
      </section>
      <ExtrasSections control={control} kind="card" />
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
