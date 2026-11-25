// The login and note forms. They take no router or network: `onSubmit` gets validated values.
import { zodResolver } from '@hookform/resolvers/zod';
import { useId, useState } from 'react';
import { useForm, useWatch } from 'react-hook-form';
import { type MessageId, useT } from '@/i18n';
import {
  DEFAULT_GENERATOR,
  type GeneratorOptions,
  generatePassword,
  passwordStrength,
} from '@/lib/password';
import { type LoginValues, type NoteValues, loginSchema, noteSchema } from '@/lib/schemas';
import { Button, IconButton } from '@/ui/Button';
import { CheckField, Field } from '@/ui/fields';
import { Icon } from '@/ui/Icon';
import { Notice } from '@/ui/Notice';

type Described = { id: MessageId; values?: Record<string, string | number> } | undefined;

interface FormProps<T> {
  initial: T;
  onSubmit: (values: T) => void;
  onCancel: () => void;
  pending?: boolean;
  error?: Described;
  submitLabel: string;
}

function Actions({
  pending,
  onCancel,
  submitLabel,
  error,
}: Pick<FormProps<unknown>, 'pending' | 'onCancel' | 'submitLabel' | 'error'>) {
  const t = useT();
  return (
    <>
      {error ? (
        <Notice tone="error" live>
          <p>{t(error.id, error.values)}</p>
        </Notice>
      ) : null}
      <div className="actions">
        <Button onPress={onCancel}>{t('action.cancel')}</Button>
        <Button type="submit" variant="primary" isDisabled={pending}>
          {submitLabel}
        </Button>
      </div>
    </>
  );
}

function GeneratorCard({
  options,
  onChange,
}: {
  options: GeneratorOptions;
  onChange: (next: GeneratorOptions) => void;
}) {
  const t = useT();
  const id = useId();
  const toggle = (key: 'upper' | 'lower' | 'digits' | 'symbols', label: string) => (
    <div className="check-row">
      <input
        id={`${id}-${key}`}
        type="checkbox"
        checked={options[key]}
        onChange={(event) => onChange({ ...options, [key]: event.target.checked })}
      />
      <label htmlFor={`${id}-${key}`}>{label}</label>
    </div>
  );
  return (
    <section className="card pad" aria-labelledby={`${id}-h`}>
      <h2 id={`${id}-h`}>{t('newItem.generator.title')}</h2>
      <div className="field">
        <label htmlFor={`${id}-len`}>{t('newItem.generator.length', { length: options.length })}</label>
        <input
          id={`${id}-len`}
          type="range"
          min={8}
          max={64}
          value={options.length}
          onChange={(event) => onChange({ ...options, length: Number(event.target.value) })}
        />
      </div>
      {toggle('upper', 'A to Z')}
      {toggle('lower', 'a to z')}
      {toggle('digits', '0 to 9')}
      {toggle('symbols', '!@#$%^&*')}
      <p className="hint">{t('newItem.generator.note')}</p>
    </section>
  );
}

export function LoginForm({ initial, onSubmit, onCancel, pending, error, submitLabel }: FormProps<LoginValues>) {
  const t = useT();
  const { control, handleSubmit, setValue } = useForm<LoginValues>({
    resolver: zodResolver(loginSchema),
    defaultValues: initial,
  });
  const [generator, setGenerator] = useState<GeneratorOptions>(DEFAULT_GENERATOR);
  const [visible, setVisible] = useState(false);
  const password = useWatch({ control, name: 'password' });
  const strength = passwordStrength(password);
  return (
    <form className="stack form-wide" noValidate onSubmit={handleSubmit(onSubmit)}>
      <section className="card pad" aria-labelledby="h-main">
        <h2 id="h-main" className="sr">
          {t('newItem.login.details')}
        </h2>
        <Field control={control} name="name" label={t('newItem.name')} autoFocus />
        <div className="pair wide">
          <Field control={control} name="username" label={t('item.username')} autoComplete="off" />
          <Field
            control={control}
            name="password"
            label={t('item.password')}
            type={visible ? 'text' : 'password'}
            mono
            autoComplete="new-password"
            hint={password ? t(`newItem.strength.${strength}` as MessageId, { length: password.length }) : undefined}
            action={
              <>
                <IconButton
                  className="big"
                  aria-label={visible ? t('item.hidePassword') : t('item.showPassword')}
                  onPress={() => setVisible((value) => !value)}
                >
                  <Icon name={visible ? 'eyeOff' : 'eye'} />
                </IconButton>
                <Button
                  onPress={() => {
                    setValue('password', generatePassword(generator), {
                      shouldDirty: true,
                      shouldValidate: true,
                    });
                    setVisible(true);
                  }}
                >
                  {t('newItem.generate')}
                </Button>
              </>
            }
          />
        </div>
        <Field control={control} name="url" label={t('item.website')} type="url" autoComplete="off" placeholder="https://" />
      </section>
      <section className="card pad" aria-labelledby="h-more">
        <h2 id="h-more" className="sr">
          {t('newItem.more')}
        </h2>
        <Field control={control} name="notes" label={t('item.notes')} multiline />
        <CheckField control={control} name="favorite">
          {t('newItem.favorite')}
        </CheckField>
      </section>
      <Actions pending={pending} onCancel={onCancel} submitLabel={submitLabel} error={error} />
      <GeneratorCard options={generator} onChange={setGenerator} />
    </form>
  );
}

export function NoteForm({ initial, onSubmit, onCancel, pending, error, submitLabel }: FormProps<NoteValues>) {
  const t = useT();
  const { control, handleSubmit } = useForm<NoteValues>({
    resolver: zodResolver(noteSchema),
    defaultValues: initial,
  });
  return (
    <form className="stack form-wide" noValidate onSubmit={handleSubmit(onSubmit)}>
      <section className="card pad" aria-labelledby="h-note">
        <h2 id="h-note" className="sr">
          {t('newItem.note.details')}
        </h2>
        <Field control={control} name="name" label={t('newItem.name')} autoFocus />
        <Field control={control} name="text" label={t('item.text')} multiline />
        <CheckField control={control} name="favorite">
          {t('newItem.favorite')}
        </CheckField>
      </section>
      <Actions pending={pending} onCancel={onCancel} submitLabel={submitLabel} error={error} />
    </form>
  );
}
