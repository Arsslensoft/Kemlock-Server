import { zodResolver } from '@hookform/resolvers/zod';
import { Link, useNavigate } from '@tanstack/react-router';
import { useState } from 'react';
import { Checkbox } from 'react-aria-components';
import { useForm, useWatch } from 'react-hook-form';
import { api, queryClient, session } from '@/app/services';
import { vaultCrypto } from '@/crypto-port';
import { type MessageId, useRich, useT } from '@/i18n';
import { describeError } from '@/lib/errors';
import { thisDevice } from '@/lib/device';
import { passwordStrength } from '@/lib/password';
import { type SetupAdminValues, setupAdminSchema } from '@/lib/schemas';
import { createSignIn } from '@/features/auth/signIn';
import { AuthPage } from '@/ui/AuthPage';
import { Button, buttonClass } from '@/ui/Button';
import { Field } from '@/ui/fields';
import { Icon } from '@/ui/Icon';
import { Notice } from '@/ui/Notice';
import { SetupSteps } from '@/ui/SetupSteps';
import { setupMemory } from './memory';
import { registerAccount } from './registerAccount';

function StrengthMeter({ password }: { password: string }) {
  const t = useT();
  const strength = passwordStrength(password);
  return (
    <>
      <div className="meter" aria-hidden="true">
        {[1, 2, 3, 4].map((n) => (
          <span key={n} className={n <= strength ? 'on' : undefined} />
        ))}
      </div>
      {password ? (
        <span className="hint" aria-live="polite">
          {t(`setup.admin.strength.${strength}` as MessageId)}
        </span>
      ) : null}
    </>
  );
}

/** The admin form. It takes no router or network: submitting hands the values to `onSubmit`. */
export function SetupAdminForm({
  onSubmit,
  pending,
  error,
}: {
  onSubmit: (values: SetupAdminValues, options: { passkey: boolean }) => void;
  pending?: boolean;
  error?: { id: MessageId; values?: Record<string, string | number> } | undefined;
}) {
  const t = useT();
  const { control, handleSubmit } = useForm<SetupAdminValues>({
    resolver: zodResolver(setupAdminSchema),
    defaultValues: { name: '', email: '', password: '', confirm: '' },
  });
  const [password, confirm] = useWatch({ control, name: ['password', 'confirm'] });
  const [passkey, setPasskey] = useState(false);
  return (
    <form className="stack" noValidate onSubmit={handleSubmit((values) => onSubmit(values, { passkey }))}>
      <div className="pair">
        <Field
          control={control}
          name="name"
          label={t('setup.admin.name')}
          placeholder={t('setup.admin.namePlaceholder')}
          autoComplete="name"
          maxLength={100}
          large
        />
        <Field
          control={control}
          name="email"
          label={t('field.email')}
          type="email"
          placeholder={t('setup.admin.emailPlaceholder')}
          autoComplete="username"
          maxLength={254}
          large
        />
      </div>
      <div className="pair">
        <Field
          control={control}
          name="password"
          label={t('field.masterPassword')}
          type="password"
          autoComplete="new-password"
          large
          below={<StrengthMeter password={password} />}
          hint={t('setup.admin.passwordHint')}
        />
        <Field
          control={control}
          name="confirm"
          label={t('setup.admin.confirm')}
          type="password"
          autoComplete="new-password"
          large
          hint={confirm && confirm === password ? t('setup.admin.match') : undefined}
        />
      </div>
      <Checkbox className="check" isSelected={passkey} onChange={setPasskey}>
        <span className="box">
          <Icon name="check" />
        </span>
        <span>
          <span className="t">{t('setup.admin.passkey')}</span>
          <span className="hint">{t('setup.admin.passkeyHint')}</span>
        </span>
      </Checkbox>
      {error ? (
        <Notice tone="error" live>
          <p>{t(error.id, error.values)}</p>
        </Notice>
      ) : null}
      <KeysNotice />
      <Button type="submit" variant="primary" size="large" block isDisabled={pending}>
        {pending ? t('setup.admin.making') : t('setup.admin.submit')}
      </Button>
    </form>
  );
}

function KeysNotice() {
  const t = useT();
  const rich = useRich();
  return (
    <section className="notice" aria-labelledby="h-keys">
      <Icon name="shield" />
      <div className="stack">
        <h2 id="h-keys">{t('setup.admin.keys.title')}</h2>
        <p>{t('setup.admin.keys.body')}</p>
        <details open>
          <summary>{t('setup.admin.keys.summary')}</summary>
          <ul className="stack">
            <li>{rich('setup.admin.keys.user')}</li>
            <li>{rich('setup.admin.keys.exchange')}</li>
            <li>{rich('setup.admin.keys.signing')}</li>
          </ul>
        </details>
      </div>
    </section>
  );
}

export default function SetupAdmin() {
  const t = useT();
  const navigate = useNavigate();
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<ReturnType<typeof describeError>>();

  async function make(values: SetupAdminValues, options: { passkey: boolean }) {
    const grant = setupMemory.get().grant;
    if (!grant) {
      await navigate({ to: '/setup' });
      return;
    }
    setPending(true);
    setError(undefined);
    try {
      const email = values.email.trim();
      const registered = await registerAccount(
        { api, crypto: vaultCrypto },
        { email, name: values.name.trim(), password: values.password, setupGrant: grant },
      );
      setupMemory.set({ adminName: values.name.trim(), adminEmail: email, wantPasskey: options.passkey });
      // The first admin is signed in at once: the next step enrols two-step login, which needs
      // tokens. The sign-in takes ownership of the master key and wipes it when done.
      const signIn = createSignIn({ api, crypto: vaultCrypto, session, device: thisDevice });
      await signIn.start(
        email,
        registered.masterKey,
        registered.wrappedRootKey,
        registered.sealedPrivateKeys,
      );
      // The server is no longer waiting for an admin; the route guard must not read the old answer.
      await queryClient.invalidateQueries({ queryKey: ['config'] });
      await navigate({ to: '/setup/two-step' });
    } catch (caught) {
      setError(describeError(caught));
    } finally {
      setPending(false);
    }
  }

  return (
    <AuthPage badge="setup" width={560}>
      <SetupSteps current={2} />
      <div>
        <h1>{t('setup.admin.title')}</h1>
        <p className="lede">{t('setup.admin.lede')}</p>
      </div>
      <SetupAdminForm onSubmit={(values, options) => void make(values, options)} pending={pending} error={error} />
      <div className="actions">
        <Link to="/setup" className={buttonClass({ size: 'large' })}>
          {t('action.back')}
        </Link>
      </div>
    </AuthPage>
  );
}
