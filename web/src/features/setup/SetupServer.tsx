import { zodResolver } from '@hookform/resolvers/zod';
import { useNavigate } from '@tanstack/react-router';
import { useState } from 'react';
import { useForm, useWatch } from 'react-hook-form';
import { api, queryClient } from '@/app/services';
import { type MessageId, useRich, useT } from '@/i18n';
import { describeError } from '@/lib/errors';
import { type ServerBasicsValues, serverBasicsResolverSchema } from '@/lib/schemas';
import { AuthPage } from '@/ui/AuthPage';
import { Button } from '@/ui/Button';
import { CheckField, Field, RadioCards, SelectField, SwitchField } from '@/ui/fields';
import { Icon } from '@/ui/Icon';
import { Notice } from '@/ui/Notice';
import { SetupSteps } from '@/ui/SetupSteps';
import { setupMemory } from './memory';

export function defaultBasics(address: string): ServerBasicsValues {
  return {
    address,
    join: 'invite',
    joinDomains: '',
    mailHost: '',
    mailPort: '587',
    mailSecurity: 'starttls',
    mailFrom: '',
    mailUser: '',
    push: false,
    files: 'local',
    folder: '/data/files',
    backups: false,
    backupEvery: 'night',
    backupKeep: '7',
    backupRecipient: '',
    serverKeyStored: false,
  };
}

/** The server-basics form. Takes no router or network. */
export function SetupServerForm({
  initial,
  onSubmit,
  pending,
  error,
  onBack,
}: {
  initial: ServerBasicsValues;
  onSubmit: (values: ServerBasicsValues) => void;
  pending?: boolean;
  error?: { id: MessageId; values?: Record<string, string | number> } | undefined;
  onBack?: () => void;
}) {
  const t = useT();
  const rich = useRich();
  const { control, handleSubmit } = useForm<ServerBasicsValues>({
    resolver: zodResolver(serverBasicsResolverSchema),
    defaultValues: initial,
  });
  const [join, files, backups] = useWatch({ control, name: ['join', 'files', 'backups'] });
  return (
    <form className="stack" noValidate onSubmit={handleSubmit(onSubmit)}>
      <section className="section first" aria-labelledby="h-addr">
        <h2 id="h-addr">{t('setup.server.address')}</h2>
        <Field
          control={control}
          name="address"
          label={t('setup.server.addressLabel')}
          type="url"
          mono
          hint={t('setup.server.addressHint')}
        />
        <p className="footnote">
          <Icon name="server" />
          <span>{rich('setup.server.port')}</span>
        </p>
      </section>

      <section className="section" aria-labelledby="h-join">
        <h2 id="h-join">{t('setup.server.join')}</h2>
        <RadioCards
          control={control}
          name="join"
          legend={t('setup.server.join')}
          options={[
            {
              value: 'invite',
              title: t('setup.server.join.invite'),
              hint: t('setup.server.join.inviteHint'),
            },
            {
              value: 'domains',
              title: t('setup.server.join.domains'),
              hint: t('setup.server.join.domainsHint'),
            },
            { value: 'anyone', title: t('setup.server.join.anyone') },
          ]}
        />
        {join === 'domains' ? (
          <Field control={control} name="joinDomains" label={t('setup.server.joinDomains')} mono />
        ) : null}
      </section>

      <section className="section" aria-labelledby="h-mail">
        <h2 id="h-mail">
          {t('setup.server.mail')} <span className="tag-chip">{t('setup.optional')}</span>
        </h2>
        <p className="hint">{t('setup.server.mailHint')}</p>
        <div className="grid">
          <Field control={control} name="mailHost" label={t('setup.server.mailHost')} mono />
          <Field control={control} name="mailPort" label={t('setup.server.mailPort')} inputMode="numeric" />
          <SelectField
            control={control}
            name="mailSecurity"
            label={t('setup.server.mailSecurity')}
            options={[
              { value: 'starttls', label: 'STARTTLS' },
              { value: 'tls', label: 'TLS' },
            ]}
          />
          <Field control={control} name="mailFrom" label={t('setup.server.mailFrom')} type="email" />
          <Field control={control} name="mailUser" label={t('setup.server.mailUser')} />
        </div>
        <div className="actions">
          <Button size="small" isDisabled>
            {t('setup.server.mailTest')}
          </Button>
          <span className="hint">{t('setup.server.needsApi')}</span>
        </div>
      </section>

      <section className="section" aria-labelledby="h-push">
        <h2 id="h-push">{t('setup.server.push')}</h2>
        <SwitchField
          control={control}
          name="push"
          label={t('setup.server.pushLabel')}
          hint={t('setup.server.pushHint')}
        />
      </section>

      <section className="section" aria-labelledby="h-store">
        <h2 id="h-store">{t('setup.server.storage')}</h2>
        <RadioCards
          control={control}
          name="files"
          legend={t('setup.server.files')}
          columns
          options={[
            {
              value: 'local',
              title: t('setup.server.files.local'),
              hint: t('setup.server.files.localHint'),
            },
            {
              value: 's3',
              title: t('setup.server.files.s3'),
              hint: t('setup.server.files.s3Hint'),
            },
          ]}
        />
        {files === 'local' ? (
          <Field control={control} name="folder" label={t('setup.server.folder')} mono />
        ) : (
          <p className="hint">{t('setup.server.s3Config')}</p>
        )}
      </section>

      <section className="section" aria-labelledby="h-bak">
        <h2 id="h-bak">{t('setup.server.backups')}</h2>
        <SwitchField
          control={control}
          name="backups"
          label={t('setup.server.backupsLabel')}
          hint={t('setup.server.backupsHint')}
        />
        {backups ? (
          <>
            <div className="grid">
              <SelectField
                control={control}
                name="backupEvery"
                label={t('setup.server.backupEvery')}
                options={[
                  { value: 'night', label: t('setup.server.backupNight') },
                  { value: 'six-hours', label: t('setup.server.backupSixHours') },
                ]}
              />
              <SelectField
                control={control}
                name="backupKeep"
                label={t('setup.server.backupKeep')}
                options={[
                  { value: '7', label: '7' },
                  { value: '14', label: '14' },
                  { value: '30', label: '30' },
                ]}
              />
            </div>
            <Field
              control={control}
              name="backupRecipient"
              label={t('setup.server.backupRecipient')}
              mono
              hint={t('setup.server.backupRecipientHint')}
            />
            <Notice tone="warn" icon="key">
              <h3>{rich('setup.server.keyTitle')}</h3>
              <p>{t('setup.server.keyBody')}</p>
              <p>{rich('setup.server.keyPath')}</p>
              <CheckField control={control} name="serverKeyStored">
                {t('setup.server.keyStored')}
              </CheckField>
            </Notice>
          </>
        ) : null}
      </section>

      {error ? (
        <Notice tone="error" live>
          <p>{t(error.id, error.values)}</p>
        </Notice>
      ) : null}
      <div className="actions">
        {onBack ? (
          <Button size="large" onPress={onBack}>
            {t('action.back')}
          </Button>
        ) : null}
        <Button type="submit" variant="primary" size="large" isDisabled={pending}>
          {t('setup.server.submit')}
        </Button>
      </div>
    </form>
  );
}

export default function SetupServer() {
  const t = useT();
  const navigate = useNavigate();
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<ReturnType<typeof describeError>>();
  const initial = setupMemory.get().basics ?? defaultBasics(window.location.origin);

  async function finish(values: ServerBasicsValues) {
    setPending(true);
    setError(undefined);
    try {
      await api.setupFinish();
      setupMemory.set({ basics: values });
      await queryClient.invalidateQueries({ queryKey: ['config'] });
      await navigate({ to: '/setup/done' });
    } catch (caught) {
      setError(describeError(caught));
    } finally {
      setPending(false);
    }
  }

  return (
    <AuthPage badge="setup" width={760}>
      <SetupSteps current={3} />
      <div>
        <h1>{t('setup.server.title')}</h1>
        <p className="lede">{t('setup.server.lede')}</p>
      </div>
      <Notice icon="info">
        <p>{t('setup.server.notStored')}</p>
      </Notice>
      <SetupServerForm
        initial={initial}
        onSubmit={(values) => void finish(values)}
        pending={pending}
        error={error}
        onBack={() => void navigate({ to: '/setup/two-step' })}
      />
    </AuthPage>
  );
}
