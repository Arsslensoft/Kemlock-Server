// The backup codes form. Its items are the Kemlock app's own entries (kemlock-core
// `BackupService`): `serviceName` and `codes`, a list of `{ code, used, usedAt? }`.
import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { z } from 'zod';
import { useT } from '@/i18n';
import { CheckField, Field } from '@/ui/fields';
import { hostsText, websiteFields } from '../linkedSites';
import type { ItemData, VaultItem } from '../vault';
import { ExtrasSections } from './ExtrasSections';
import { WebsiteField, useLinkedWebsites } from './WebsiteField';
import { extrasDefaults, extrasFields, extrasShape } from './extras';
import { Actions, type FormProps, entryBase, orUndefined, str } from './parts';

/** One code per line; blank lines go. */
export function parseCodes(text: string): string[] {
  return text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line !== '');
}

export const backupCodesSchema = z.object({
  name: z.string().trim().max(200, 'error.tooLong'),
  /** Left out (undefined) when the website comes from a linked item. */
  website: z.string().max(2000, 'error.tooLong').optional(),
  serviceName: z.string().trim().min(1, 'error.required').max(200, 'error.tooLong'),
  codes: z
    .string()
    .max(50000, 'error.tooLong')
    .refine((v) => parseCodes(v).length > 0, 'error.required'),
  note: z.string().max(10000, 'error.tooLong'),
  pinned: z.boolean(),
  ...extrasShape,
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
    name: str(item?.data, 'name'),
    website: hostsText(item?.data),
    serviceName: str(item?.data, 'serviceName'),
    codes: codesOf(item)
      .map((entry) => entry.code)
      .join('\n'),
    note: str(item?.data, 'note'),
    pinned: item?.data?.['pinned'] === true,
    ...extrasDefaults(item),
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
    name: orUndefined(values.name),
    serviceName: values.serviceName,
    codes: parseCodes(values.codes).map((code) => known.get(code) ?? { code, used: false }),
    // The websites of a linked item are not these codes' to write.
    ...(values.website === undefined ? {} : websiteFields(values.website, existing?.data)),
    note: orUndefined(values.note),
    pinned: values.pinned ? true : undefined,
    ...extrasFields(values, existing),
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
  const linked = useLinkedWebsites(control);
  return (
    <form
      className="stack form-wide"
      noValidate
      onSubmit={handleSubmit((values) => onSubmit({ ...values, website: linked ? undefined : values.website }))}
    >
      <section className="card pad" aria-labelledby="h-codes">
        <h2 id="h-codes">{t('newItem.backupCodes.details')}</h2>
        <div className="pair">
          <Field control={control} name="name" label={t('newItem.name')} autoFocus />
          <WebsiteField control={control} linked={linked} />
          <Field control={control} name="serviceName" label={t('newItem.backupCodes.service')} />
        </div>
        <Field
          control={control}
          name="codes"
          label={t('newItem.backupCodes.codes')}
          multiline
          mono
          hint={t('newItem.backupCodes.codesHint')}
        />
      </section>
      <ExtrasSections control={control} kind="backup-codes" />
      <section className="card pad" aria-labelledby="h-codes-more">
        <h2 id="h-codes-more" className="sr">
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
