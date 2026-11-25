// The login form: name, username and password with a compact generator under it, a list of
// websites each with its match rule, linked items, custom fields, notes and the favorite box.
import { zodResolver } from '@hookform/resolvers/zod';
import { useState } from 'react';
import { type Control, useController, useForm, useWatch } from 'react-hook-form';
import type { z } from 'zod';
import { type MessageId, useT } from '@/i18n';
import { DEFAULT_GENERATOR, type GeneratorOptions, generatePassword, passwordStrength } from '@/lib/password';
import { loginSchema } from '@/lib/schemas';
import { Button } from '@/ui/Button';
import { CheckField, Field } from '@/ui/fields';
import { type ItemData, type VaultItem, itemName, loginOf } from '../vault';
import { ExtrasSections } from './ExtrasSections';
import { GeneratorPanel } from './GeneratorPanel';
import { WebsitesEditor } from './WebsitesEditor';
import { extrasDefaults, extrasFields, extrasShape } from './extras';
import { Actions, type FormProps } from './parts';
import { siteRowsOf, sitesFields, sitesSchema } from './siteRows';

export const loginFormSchema = loginSchema.omit({ url: true }).extend({ websites: sitesSchema, ...extrasShape });
export type LoginFormValues = z.infer<typeof loginFormSchema>;

export function loginDefaults(item?: VaultItem): LoginFormValues {
  const login = item ? loginOf(item) : undefined;
  return {
    name: item ? itemName(item) : '',
    username: login?.username ?? '',
    password: login?.password ?? '',
    websites: siteRowsOf(item?.data),
    notes: typeof item?.data?.notes === 'string' ? item.data.notes : '',
    favorite: item?.data?.favorite === true,
    ...extrasDefaults(item),
  };
}

/**
 * The fields a login form owns. The websites are written the way `websites.ts` describes, and
 * what other apps wrote (password history, passkeys, tags) stays because `saveItem` merges over it.
 */
export function loginFields(values: LoginFormValues, existing?: VaultItem): ItemData {
  return {
    name: values.name,
    username: values.username,
    password: values.password,
    ...sitesFields(values.websites),
    notes: values.notes === '' ? undefined : values.notes,
    favorite: values.favorite ? true : undefined,
    ...extrasFields(values, existing),
  };
}

function Websites({ control }: { control: Control<LoginFormValues> }) {
  const { field, fieldState } = useController({ control, name: 'websites' });
  return <WebsitesEditor value={field.value} onChange={field.onChange} showProblems={Boolean(fieldState.error)} />;
}

export function LoginForm({ initial, onSubmit, onCancel, pending, error, submitLabel }: FormProps<LoginFormValues>) {
  const t = useT();
  const { control, handleSubmit, setValue } = useForm<LoginFormValues>({
    resolver: zodResolver(loginFormSchema),
    defaultValues: initial,
  });
  const [generator, setGenerator] = useState<GeneratorOptions>(DEFAULT_GENERATOR);
  const password = useWatch({ control, name: 'password' });
  const strength = passwordStrength(password);
  return (
    <form className="stack form-wide" noValidate onSubmit={handleSubmit(onSubmit)}>
      <section className="card pad" aria-labelledby="h-main">
        <h2 id="h-main" className="sr">
          {t('newItem.login.details')}
        </h2>
        <Field control={control} name="name" label={t('newItem.name')} autoFocus />
        <div className="pair">
          <Field control={control} name="username" label={t('item.username')} autoComplete="off" />
          <Field
            control={control}
            name="password"
            label={t('item.password')}
            type="password"
            mono
            autoComplete="new-password"
            hint={password ? t(`newItem.strength.${strength}` as MessageId, { length: password.length }) : undefined}
            action={
              <Button
                onPress={() =>
                  setValue('password', generatePassword(generator), { shouldDirty: true, shouldValidate: true })
                }
              >
                {t('newItem.generate')}
              </Button>
            }
          />
        </div>
        <GeneratorPanel options={generator} onChange={setGenerator} />
        <Websites control={control} />
      </section>
      <ExtrasSections control={control} kind="login" />
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
    </form>
  );
}
