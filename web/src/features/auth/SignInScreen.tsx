import { zodResolver } from '@hookform/resolvers/zod';
import { getRouteApi, useNavigate, useRouter } from '@tanstack/react-router';
import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { createDevicesApi } from '@/api/devices';
import { createPasskeySignInApi } from '@/api/passkeys';
import { createSsoApi } from '@/api/sso';
import { api, session } from '@/app/services';
import { vaultCrypto } from '@/crypto-port';
import { type MessageId, useT } from '@/i18n';
import { thisDevice } from '@/lib/device';
import { describeError } from '@/lib/errors';
import { PasskeyError, assertWithPasskeyAndPrf, passkeysAvailable } from '@/lib/passkey';
import { type EmailValues, emailSchema } from '@/lib/schemas';
import { AuthPage } from '@/ui/AuthPage';
import { Button } from '@/ui/Button';
import { Field } from '@/ui/fields';
import { Icon } from '@/ui/Icon';
import { Notice } from '@/ui/Notice';
import { afterSignIn } from './afterSignIn';
import { signInWithPasskey } from './passkeySignIn';
import { unlockWithTrustedDevice } from './trustedDevice';
import { beginSso } from './ssoFlow';

const route = getRouteApi('/sign-in');
const passkeyApi = createPasskeySignInApi(api);
const ssoApi = createSsoApi(api);
const devicesApi = createDevicesApi(api);

/** The email box. Takes no router or network. */
export function EmailForm({
  onSubmit,
  pending,
  error,
}: {
  onSubmit: (email: string) => void;
  pending?: boolean;
  error?: { id: MessageId; values?: Record<string, string | number> } | undefined;
}) {
  const t = useT();
  const { control, handleSubmit } = useForm<EmailValues>({
    resolver: zodResolver(emailSchema),
    defaultValues: { email: '' },
  });
  return (
    <form className="stack" noValidate onSubmit={handleSubmit((values) => onSubmit(values.email.trim()))}>
      <Field
        control={control}
        name="email"
        label={t('field.email')}
        type="email"
        autoComplete="username"
        large
        autoFocus
      />
      {error ? (
        <Notice tone="error" live>
          <p>{t(error.id, error.values)}</p>
        </Notice>
      ) : null}
      <Button type="submit" variant="primary" size="large" block isDisabled={pending}>
        {t('action.continue')}
      </Button>
    </form>
  );
}

/** The words for a passkey that did not answer; anything else is described as everywhere else. */
function describeSignInError(error: unknown): ReturnType<typeof describeError> {
  if (error instanceof PasskeyError) {
    return { id: error.reason === 'cancelled' ? 'signIn.passkeyCancelled' : 'signIn.passkeyUnavailable' };
  }
  return describeError(error);
}

export default function SignIn() {
  const t = useT();
  const navigate = useNavigate();
  const router = useRouter();
  const { next } = route.useSearch();
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<ReturnType<typeof describeError>>();
  const [offered, setOffered] = useState<{ email: string; methods: string[]; provider?: string }>();

  async function choose(email: string) {
    setPending(true);
    setError(undefined);
    try {
      const info = await api.methodsInfo(email);
      // The server lists "sso" among the methods when a provider is on for this email. It never
      // lists "passkey" (it answers every email alike, so it can't say who has one): a passkey
      // sign-in needs no email to start, so it is offered wherever the browser has passkeys.
      const methods =
        passkeysAvailable() && !info.methods.includes('passkey')
          ? [...info.methods, 'passkey']
          : info.methods;
      const others = methods.filter((m) => m !== 'password');
      if (others.length === 0) {
        await navigate({ to: '/sign-in/password', search: { email, next } });
      } else {
        setOffered({ email, methods, ...(info.sso ? { provider: info.sso.providerName } : {}) });
      }
    } catch (caught) {
      setError(describeError(caught));
    } finally {
      setPending(false);
    }
  }

  async function withPasskey(email: string) {
    setPending(true);
    setError(undefined);
    try {
      const result = await signInWithPasskey(
        {
          passkeys: passkeyApi,
          api,
          crypto: vaultCrypto,
          session,
          device: thisDevice,
          assert: assertWithPasskeyAndPrf,
        },
        email,
      );
      // A passkey with no PRF output signs in with the vault shut: this browser's own copy of
      // the root key opens it if it holds one, else the master password does.
      const opened =
        result.status === 'unlocked' ||
        (await unlockWithTrustedDevice({ devices: devicesApi, api, crypto: vaultCrypto, session }));
      if (opened) {
        await afterSignIn(router, { status: 'signed-in', admin: result.admin }, next);
      } else {
        await navigate({ to: '/unlock', search: { next } });
      }
    } catch (caught) {
      setError(describeSignInError(caught));
    } finally {
      setPending(false);
    }
  }

  async function withSso(email: string) {
    setPending(true);
    setError(undefined);
    try {
      const address = await beginSso(
        { sso: ssoApi, api, session, device: thisDevice, origin: location.origin },
        email,
        next,
      );
      location.assign(address);
    } catch (caught) {
      setError(describeSignInError(caught));
      setPending(false);
    }
  }

  return (
    <AuthPage>
      <div>
        <h1>{t('signIn.title')}</h1>
        <p className="lede">{t('signIn.lede')}</p>
      </div>
      <EmailForm onSubmit={(email) => void choose(email)} pending={pending} error={error} />
      {offered ? (
        <div className="stack">
          <div className="or">{t('signIn.or')}</div>
          {offered.methods.includes('sso') ? (
            <Button block isDisabled={pending} onPress={() => void withSso(offered.email)}>
              <Icon name="key" />
              {t('signIn.ssoNamed', { provider: offered.provider ?? '' })}
            </Button>
          ) : null}
          {offered.methods.includes('passkey') && passkeysAvailable() ? (
            <Button block isDisabled={pending} onPress={() => void withPasskey(offered.email)}>
              <Icon name="login" />
              {t('signIn.passkey')}
            </Button>
          ) : null}
          <Button
            block
            onPress={() =>
              void navigate({ to: '/sign-in/device', search: { email: offered.email, next } })
            }
          >
            <Icon name="device" />
            {t('signIn.approve')}
          </Button>
          {offered.methods.includes('password') ? (
            <Button
              block
              onPress={() =>
                void navigate({ to: '/sign-in/password', search: { email: offered.email, next } })
              }
            >
              <Icon name="lock" />
              {t('signIn.password')}
            </Button>
          ) : null}
        </div>
      ) : null}
      <p className="hint">{t('signIn.footer')}</p>
      <p className="hint">{t('legal.notAffiliated')}</p>
    </AuthPage>
  );
}
