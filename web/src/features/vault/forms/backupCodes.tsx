import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { z } from 'zod';
import { useT } from '@/i18n';
import { Field } from '@/ui/fields';
import type { ItemData, VaultItem } from '../vault';
import { Actions, type FormProps, entryBase, orUndefined, str } from './parts';

/** One code per line; blank lines go. */
export function parseCodes(text: string): string[] {
  return text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line !== '');
}

export const backupCodesSchema = z.object({
  serviceName: z.string().trim().min(1, 'error.required').max(200, 'error.tooLong'),
  codes: z
    .string()
    .max(50000, 'error.tooLong')
    .refine((v) => parseCodes(v).length > 0, 'error.required'),
  note: z.string().max(10000, 'error.tooLong'),
});
export type BackupCodesValues = z.infer<typeof backupCodesSchema>;

type Code = { code: string; used: boolean; usedAt?: number; [key: string]: unknown };

function codesOf(item?: VaultItem): Code[] {
  const list = item?.data?.['codes'];
  if (!Array.isArray(list)) return [];
  return list.filter(
    (entry): entry is Code =>
      typeof entry === 'object' && entry !== null && typeof (entry as Code).code === 'string',
  );
}

export function backupCodesDefaults(item?: VaultItem): BackupCodesValues {
  return {
    serviceName: str(item?.data, 'serviceName'),
    codes: codesOf(item)
      .map((entry) => entry.code)
      .join('\n'),
    note: str(item?.data, 'note'),
  };
}

/**
 * `BackupService.toJson`: `codes` is a list of `{code, used, usedAt?}`. A code that was already
 * in the item keeps its used flag and anything else the app wrote on it.
 */
export function backupCodesFields(values: BackupCodesValues, existing?: VaultItem): ItemData {
  const known = new Map(codesOf(existing).map((entry) => [entry.code, entry]));
  return {
    ...entryBase(existing),
    serviceName: values.serviceName,
    codes: parseCodes(values.codes).map((code) => known.get(code) ?? { code, used: false }),
    note: orUndefined(values.note),
  };
}

export function BackupCodesForm({
  initial,
  onSubmit,
  onCancel,
  pending,
  error,
  submitLabel,
}: FormProps<BackupCodesValues>) {
  const t = useT();
  const { control, handleSubmit } = useForm<BackupCodesValues>({
    resolver: zodResolver(backupCodesSchema),
    defaultValues: initial,
  });
  return (
    <form className="stack form-wide" noValidate onSubmit={handleSubmit(onSubmit)}>
      <section className="card pad" aria-labelledby="h-codes">
        <h2 id="h-codes" className="sr">
          {t('newItem.backupCodes.details')}
        </h2>
        <Field control={control} name="serviceName" label={t('newItem.backupCodes.service')} autoFocus />
        <Field
          control={control}
          name="codes"
          label={t('newItem.backupCodes.codes')}
          multiline
          mono
          hint={t('newItem.backupCodes.codesHint')}
        />
        <Field control={control} name="note" label={t('item.notes')} multiline />
      </section>
      <Actions pending={pending} onCancel={onCancel} submitLabel={submitLabel} error={error} />
    </form>
  );
}
