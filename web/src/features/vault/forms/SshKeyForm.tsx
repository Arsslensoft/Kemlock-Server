// An SSH key: made in the browser (Ed25519, WebCrypto) or pasted as a PKCS#8 private key.
// An item that exists keeps its halves; only its name and note change.
import { zodResolver } from '@hookform/resolvers/zod';
import { useState } from 'react';
import { useForm, useWatch } from 'react-hook-form';
import { z } from 'zod';
import { useT } from '@/i18n';
import { Button } from '@/ui/Button';
import { Field } from '@/ui/fields';
import { type SshMaterial, generateEd25519, readPastedSshKey } from './keyMaterial';
import { FormActions, type KeyFormProps } from './shared';
import type { ItemData, VaultItem } from '../vault';
import { itemName } from '../vault';

const text = (max: number) => z.string().max(max, 'error.tooLong');

const base = {
  name: z.string().trim().min(1, 'error.required').max(200, 'error.tooLong'),
  note: text(10000),
  pasted: text(20000),
  generatedPrivate: z.string(),
  generatedPublic: z.string(),
};

export const sshKeySchema = z.object(base).refine((v) => v.generatedPrivate !== '' || v.pasted.trim() !== '', {
  path: ['pasted'],
  message: 'error.required',
});
export const sshKeyEditSchema = z.object(base);
export type SshKeyValues = z.infer<typeof sshKeySchema>;

export function sshKeyDefaults(item?: VaultItem): SshKeyValues {
  return {
    name: item ? itemName(item) : '',
    note: typeof item?.data?.['note'] === 'string' ? item.data['note'] : '',
    pasted: '',
    generatedPrivate: '',
    generatedPublic: '',
  };
}

/** The fields an SSH key form owns. A key that exists changes only its name and note. */
export function sshKeyFields(values: SshKeyValues, material?: SshMaterial): ItemData {
  const fields: ItemData = { name: values.name, note: values.note === '' ? undefined : values.note };
  if (!material) return fields;
  return {
    ...fields,
    kind: 'ssh',
    algorithm: material.algorithm,
    private: material.private,
    public: material.public,
    origin: values.generatedPrivate !== '' ? 'generated' : 'imported',
  };
}

type Props = Omit<KeyFormProps<SshKeyValues>, 'onSubmit'> & {
  onSubmit: (values: SshKeyValues, material?: SshMaterial) => void;
};

export function SshKeyForm({ initial, editing, onSubmit, onCancel, pending, error, submitLabel }: Props) {
  const t = useT();
  const { control, handleSubmit, setValue, setError } = useForm<SshKeyValues>({
    resolver: zodResolver(editing ? sshKeyEditSchema : sshKeySchema),
    defaultValues: initial,
  });
  const [busy, setBusy] = useState(false);
  const [unsupported, setUnsupported] = useState(false);
  const generated = useWatch({ control, name: 'generatedPrivate' }) !== '';
  const [material, setMaterial] = useState<SshMaterial>();

  async function generate() {
    setBusy(true);
    setUnsupported(false);
    try {
      const made = await generateEd25519();
      setMaterial(made);
      setValue('generatedPrivate', made.private);
      setValue('generatedPublic', made.public);
      setValue('pasted', '');
    } catch {
      setUnsupported(true);
    } finally {
      setBusy(false);
    }
  }

  async function submit(values: SshKeyValues) {
    if (editing) return onSubmit(values);
    if (material && values.generatedPrivate !== '') return onSubmit(values, material);
    const read = await readPastedSshKey(values.pasted);
    if (!read) {
      setError('pasted', { message: 'keys.ssh.error.paste' });
      return undefined;
    }
    return onSubmit(values, read);
  }

  return (
    <form className="stack form-wide" noValidate onSubmit={handleSubmit(submit)}>
      <section className="card pad" aria-labelledby="h-ssh">
        <h2 id="h-ssh" className="sr">
          {t('keys.ssh.details')}
        </h2>
        <Field control={control} name="name" label={t('newItem.name')} autoFocus />
        {editing ? (
          <p className="hint">{t('keys.halvesFixed')}</p>
        ) : (
          <>
            <div className="field">
              <Button onPress={() => void generate()} isDisabled={busy}>
                {t('keys.ssh.generate')}
              </Button>
              {generated ? <p className="hint">{t('keys.ssh.generated')}</p> : null}
              {unsupported ? <p className="error">{t('keys.ssh.error.unsupported')}</p> : null}
            </div>
            {generated ? null : (
              <Field
                control={control}
                name="pasted"
                label={t('keys.ssh.paste')}
                hint={t('keys.ssh.pasteHint')}
                multiline
                mono
                autoComplete="off"
                placeholder="-----BEGIN PRIVATE KEY-----"
              />
            )}
          </>
        )}
        <Field control={control} name="note" label={t('item.notes')} multiline />
      </section>
      <FormActions pending={pending || busy} onCancel={onCancel} submitLabel={submitLabel} error={error} />
    </form>
  );
}
