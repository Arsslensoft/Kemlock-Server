import { type MessageId, useT } from '@/i18n';
import { Button } from '@/ui/Button';
import { CodeForm } from '@/ui/CodeForm';
import { Icon } from '@/ui/Icon';
import { Notice } from '@/ui/Notice';

const NOTES = {
  password: {
    code: 'password.codeNote',
    key: 'password.keyNote',
    either: 'password.eitherNote',
  },
  sso: {
    code: 'sso.codeNote',
    key: 'sso.keyNote',
    either: 'sso.eitherNote',
  },
} as const satisfies Record<string, Record<string, MessageId>>;

/**
 * The second step of a sign-in, as the account has it: a code from an authenticator app (`totp`),
 * a security key (`webauthn`), or both, in which case both are offered. A list with neither (a
 * method this page can't do) falls back to the code box.
 */
export function SecondStep({
  methods,
  source,
  pending,
  error,
  onCode,
  onSecurityKey,
}: {
  methods: string[];
  /** Which sign-in this is: SSO says its provider did not ask for a second step. */
  source: keyof typeof NOTES;
  pending?: boolean;
  error?: { id: MessageId; values?: Record<string, string | number> } | undefined;
  onCode: (code: string) => void;
  onSecurityKey: () => void;
}) {
  const t = useT();
  const key = methods.includes('webauthn');
  const code = methods.includes('totp') || !key;
  const notes = NOTES[source];
  return (
    <>
      <Notice icon="shield">
        <p>{t(key && code ? notes.either : key ? notes.key : notes.code)}</p>
      </Notice>
      {code ? (
        <CodeForm
          label={t('password.codeLabel')}
          submitLabel={t('password.codeSubmit')}
          pending={pending}
          error={error}
          onSubmit={onCode}
        />
      ) : null}
      {key && code ? <div className="or">{t('signIn.or')}</div> : null}
      {key ? (
        <>
          {code ? null : error ? (
            <Notice tone="error" live>
              <p>{t(error.id, error.values)}</p>
            </Notice>
          ) : null}
          <Button
            variant={code ? 'default' : 'primary'}
            size={code ? 'medium' : 'large'}
            block
            isDisabled={pending}
            onPress={onSecurityKey}
          >
            <Icon name="key" />
            {t('password.keySubmit')}
          </Button>
        </>
      ) : null}
    </>
  );
}
