// An SSH key: made in the browser (Ed25519, WebCrypto) or pasted as a PKCS#8 private key.
// An item that exists keeps its halves; only its name, notes and extras change.
import { zodResolver } from '@hookform/resolvers/zod';
import { useState } from 'react';
import { useForm, useWatch } from 'react-hook-form';
import { z } from 'zod';
import { useT } from '@/i18n';
import { Button } from '@/ui/Button';
import { CheckField, Field } from '@/ui/fields';
import { type ItemData, type VaultItem, itemName } from '../vault';
import { ExtrasSections } from './ExtrasSections';
import { extrasDefaults, extrasFields, extrasShape } from './extras';
import { type SshMaterial, generateEd25519, readPastedSshKey } from './keyMaterial';
import { Actions, type FormProps, isPinned } from './parts';

const text = (max: number) => z.string().max(max, 'error.tooLong');

const base = {
  name: z.string().trim().min(1, 'error.required').max(200, 'error.tooLong'),
  note: text(10000),
  pinned: z.boolean(),
  pasted: text(20000),
  generatedPrivate: z.string(),
  generatedPublic: z.string(),
  ...extrasShape,
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
    pinned: isPinned(item),
    pasted: '',
    generatedPrivate: '',
    generatedPublic: '',
    ...extrasDefaults(item),
  };
}

/** The fields an SSH key form owns. A key that exists changes only its name, notes and extras. */
export function sshKeyFields(values: SshKeyValues, existing: VaultItem | undefined, material?: SshMaterial): ItemData {
  const fields: ItemData = {
    name: values.name,
    note: values.note === '' ? undefined : values.note,
    pinned: values.pinned ? true : undefined,
    ...extrasFields(values, existing),
  };
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

type Props = Omit<FormProps<SshKeyValues>, 'onSubmit'> & {
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
        <h2 id="h-ssh">{t('keys.ssh.details')}</h2>
        <Field control={control} name="name" label={t('newItem.name')} autoFocus />
        {editing ? (
          <p className="hint">{t('keys.halvesFixed')}</p>
        ) : (
          <>
            <div className="gen-row">
              <Button onPress={() => void generate()} isDisabled={busy}>
                {t('keys.ssh.generate')}
              </Button>
              <span className="hint">{t('itemForm.ssh.orPaste')}</span>
            </div>
            {generated ? <p className="hint">{t('keys.ssh.generated')}</p> : null}
            {unsupported ? <p className="error">{t('keys.ssh.error.unsupported')}</p> : null}
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
      </section>
      <ExtrasSections control={control} kind="ssh-key" />
      <section className="card pad" aria-labelledby="h-ssh-more">
        <h2 id="h-ssh-more" className="sr">
          {t('newItem.more')}
        </h2>
        <Field control={control} name="note" label={t('item.notes')} multiline />
        <CheckField control={control} name="pinned">
          {t('newItem.favorite')}
        </CheckField>
      </section>
      <Actions pending={pending || busy} onCancel={onCancel} submitLabel={submitLabel} error={error} />
    </form>
  );
}
