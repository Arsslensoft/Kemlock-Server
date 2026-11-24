// A certificate: a PEM `CERTIFICATE` block, with its PKCS#8 private key when it has one. The
// vault holds it as a key entry that carries a `certificate` (the PEM text), the shape the Kemlock
// app's sync reads as the `certificate` kind.
import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { z } from 'zod';
import { useT } from '@/i18n';
import { Field } from '@/ui/fields';
import { type SshMaterial, fromB64, pemBlocks, readPastedSshKey } from './keyMaterial';
import { FormActions, type KeyFormProps } from './shared';
import type { ItemData, VaultItem } from '../vault';
import { itemName } from '../vault';

const base = {
  name: z.string().trim().min(1, 'error.required').max(200, 'error.tooLong'),
  note: z.string().max(10000, 'error.tooLong'),
  certificate: z.string().max(100000, 'error.tooLong'),
  privateKey: z.string().max(20000, 'error.tooLong'),
};

export const certificateSchema = z
  .object(base)
  .refine((v) => v.certificate.trim() !== '', { path: ['certificate'], message: 'error.required' })
  .refine((v) => v.privateKey.trim() !== '', { path: ['privateKey'], message: 'error.required' });
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

/** The key pasted with a certificate: PKCS#8, Ed25519 or ECDSA P-256; undefined if it cannot be read. */
export const certificateKey = readPastedSshKey;

/**
 * The fields a certificate form owns; undefined when the certificate cannot be read. A certificate
 * is a key entry that carries a `certificate`, so it needs the key it belongs to: the model has no
 * entry without its private half. The key's own algorithm and halves are written, as for an SSH key.
 */
export function certificateFields(
  values: CertificateValues,
  editing: boolean,
  key?: SshMaterial,
): ItemData | undefined {
  const fields: ItemData = { name: values.name, note: values.note === '' ? undefined : values.note };
  if (editing) return fields;
  const pem = certificatePem(values.certificate);
  if (!pem || !key) return undefined;
  return {
    ...fields,
    kind: 'signing',
    algorithm: key.algorithm,
    private: key.private,
    public: key.public,
    certificate: pem,
    origin: 'imported',
  };
}

type Props = Omit<KeyFormProps<CertificateValues>, 'onSubmit'> & {
  onSubmit: (values: CertificateValues, key?: SshMaterial) => void;
};

export function CertificateForm({ initial, editing, onSubmit, onCancel, pending, error, submitLabel }: Props) {
  const t = useT();
  const { control, handleSubmit, setError } = useForm<CertificateValues>({
    resolver: zodResolver(editing ? certificateEditSchema : certificateSchema),
    defaultValues: initial,
  });
  return (
    <form
      className="stack form-wide"
      noValidate
      onSubmit={handleSubmit(async (values) => {
        if (editing) return onSubmit(values);
        if (!certificatePem(values.certificate)) {
          setError('certificate', { message: 'keys.certificate.error.pem' });
          return undefined;
        }
        const key = await certificateKey(values.privateKey);
        if (!key) {
          setError('privateKey', { message: 'keys.certificate.error.key' });
          return undefined;
        }
        return onSubmit(values, key);
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
