import { useState } from 'react';
import { useT } from '@/i18n';
import { AuthPage } from '@/ui/AuthPage';
import { Button } from '@/ui/Button';
import { Notice } from '@/ui/Notice';
import { useLinkParams } from './linkParams';

/**
 * Where the link that proves a new address lands (`/finish-signup#email=…&token=…`, which Bitwarden
 * clients and mails write as `/#/finish-signup/…`). The master password and the keys are made in an
 * app, never here, so the page says the address is proven and how to go on there; the token is the
 * verification code the app's registration asks for, and can be copied.
 */
export default function FinishSignup() {
  const t = useT();
  const { email, token } = useLinkParams();
  const [copied, setCopied] = useState(false);

  async function copy() {
    if (!token) return;
    try {
      await navigator.clipboard.writeText(token);
      setCopied(true);
    } catch {
      setCopied(false);
    }
  }

  return (
    <AuthPage>
      <div>
        <h1>{t('invitation.signup.title')}</h1>
      </div>
      {token ? (
        <>
          <Notice icon="check" live>
            <p>{t('invitation.signup.proven', { email: email ?? '' })}</p>
          </Notice>
          <p>{t('invitation.signup.next')}</p>
          <Button onPress={() => void copy()}>{t(copied ? 'invitation.signup.copied' : 'invitation.signup.copy')}</Button>
        </>
      ) : (
        <Notice tone="error" live>
          <p>{t('invitation.incomplete')}</p>
        </Notice>
      )}
    </AuthPage>
  );
}
