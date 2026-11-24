// A certificate: a PEM `CERTIFICATE` block, with its PKCS#8 private key when it has one. The
// vault holds it as a key entry that carries a `certificate` (the PEM text), the shape the Kemlock
// app's sync reads as the `certificate` kind.
import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { z } from 'zod';
import { useT } from '@/i18n';
import { Field } from '@/ui/fields';
import { pemBlocks, sshAlgorithmOf, fromB64 } from './keyMaterial';
import { FormActions, type KeyFormProps } from './shared';
import type { ItemData, VaultItem } from '../vault';
import { itemName } from '../vault';

const base = {
  name: z.string().trim().min(1, 'error.required').max(200, 'error.tooLong'),
  note: z.string().max(10000, 'error.tooLong'),
  certificate: z.string().max(100000, 'error.tooLong'),
  privateKey: z.string().max(20000, 'error.tooLong'),
};

export const certificateSchema = z.object(base).refine((v) => v.certificate.trim() !== '', {
  path: ['certificate'],
  message: 'error.required',
});
export const certificateEditSchema = z.object(base);
export type CertificateValues = z.infer<typeof certificateSchema>;

export function certificateDefaults(item?: VaultItem): CertificateValues {
  return {
    name: item ? itemName(item) : '',
    note: typeof item?.data?.['note'] === 'string' ? item.data['note'] : '',
    certificate: '',
    privateKey: '',
  };
}

/** The PEM of the one certificate in a paste, normalised to 64-column lines; undefined if not one. */
export function certificatePem(text: string): string | undefined {
  const blocks = pemBlocks(text);
  const only = blocks.length === 1 ? blocks[0] : undefined;
  if (!only || (only.label !== 'CERTIFICATE' && only.label !== 'TRUSTED CERTIFICATE' && only.label !== 'X509 CERTIFICATE')) {
    return undefined;
  }
  try {
    if (fromB64(only.body).length === 0) return undefined;
  } catch {
    return undefined;
  }
  const lines = only.body.match(/.{1,64}/g) ?? [];
  return `-----BEGIN CERTIFICATE-----\n${lines.join('\n')}\n-----END CERTIFICATE-----\n`;
}

/** The PKCS#8 DER (base64) of a pasted private key; '' for none, undefined for one this cannot read. */
export function certificateKey(text: string): string | undefined {
  if (text.trim() === '') return '';
  const blocks = pemBlocks(text);
  const only = blocks.length === 1 ? blocks[0] : undefined;
  if (only?.label !== 'PRIVATE KEY') return undefined;
  try {
    return fromB64(only.body).length > 0 ? only.body : undefined;
  } catch {
    return undefined;
  }
}

/** The fields a certificate form owns; undefined when a paste cannot be read. */
export function certificateFields(values: CertificateValues, editing: boolean): ItemData | undefined {
  const fields: ItemData = { name: values.name, note: values.note === '' ? undefined : values.note };
  if (editing) return fields;
  const pem = certificatePem(values.certificate);
  const key = certificateKey(values.privateKey);
  if (!pem || key === undefined) return undefined;
  const algorithm = key === '' ? undefined : sshAlgorithmOf(fromB64(key));
  return {
    ...fields,
    kind: 'other',
    algorithm: algorithm ?? '',
    private: key,
    certificate: pem,
    origin: 'imported',
  };
}

export function CertificateForm({ initial, editing, onSubmit, onCancel, pending, error, submitLabel }: KeyFormProps<CertificateValues>) {
  const t = useT();
  const { control, handleSubmit, setError } = useForm<CertificateValues>({
    resolver: zodResolver(editing ? certificateEditSchema : certificateSchema),
    defaultValues: initial,
  });
  return (
    <form
      className="stack form-wide"
      noValidate
      onSubmit={handleSubmit((values) => {
        if (!editing) {
          if (!certificatePem(values.certificate)) {
            setError('certificate', { message: 'keys.certificate.error.pem' });
            return;
          }
          if (certificateKey(values.privateKey) === undefined) {
            setError('privateKey', { message: 'keys.certificate.error.key' });
            return;
          }
        }
        onSubmit(values);
      })}
    >
      <section className="card pad" aria-labelledby="h-cert">
        <h2 id="h-cert" className="sr">
          {t('keys.certificate.details')}
        </h2>
        <Field control={control} name="name" label={t('newItem.name')} autoFocus />
        {editing ? (
          <p className="hint">{t('keys.halvesFixed')}</p>
        ) : (
          <>
            <Field
              control={control}
              name="certificate"
              label={t('keys.certificate.pem')}
              multiline
              mono
              autoComplete="off"
              placeholder="-----BEGIN CERTIFICATE-----"
            />
            <Field
              control={control}
              name="privateKey"
              label={t('keys.certificate.key')}
              hint={t('keys.certificate.keyHint')}
              multiline
              mono
              autoComplete="off"
              placeholder="-----BEGIN PRIVATE KEY-----"
            />
          </>
        )}
        <Field control={control} name="note" label={t('item.notes')} multiline />
      </section>
      <FormActions pending={pending} onCancel={onCancel} submitLabel={submitLabel} error={error} />
    </form>
  );
}
