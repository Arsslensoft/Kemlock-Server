import { Link } from '@tanstack/react-router';
import { type FormEvent, type ReactNode, useState } from 'react';
import { TextInput } from '@/features/account/controls';
import { type MessageId, useT } from '@/i18n';
import { AuthPage } from '@/ui/AuthPage';
import { Button, buttonClass } from '@/ui/Button';
import { Notice } from '@/ui/Notice';
import type { Outcome } from './useAcceptInvitation';

/** One line of who an invitation is from and to: a label and what the link says. */
export interface Fact {
  label: MessageId;
  value: string;
}

/**
 * What an invitation link's page says: who it is from, and a master password field with a button.
 * Nothing is sent until the button is pressed. The password leaves the field as it is submitted and
 * is not kept; a wrong one leaves the form open for the person to try again, and says how long to
 * wait when the server limits the tries. A successful accept starts no session, so it ends with a
 * link to sign in, not a page that is signed in.
 */
export function InvitationLanding({
  title,
  done,
  outcome,
  facts,
  acceptLabel,
  onAccept,
}: {
  title: MessageId;
  /** The sentence for success. */
  done: ReactNode;
  outcome: Outcome;
  facts: Fact[];
  acceptLabel: MessageId;
  onAccept: (password: string) => void;
}) {
  const t = useT();
  const [password, setPassword] = useState('');
  function submit(event: FormEvent) {
    event.preventDefault();
    const typed = password;
    // Out of the field first: what the form holds is not the password any more once it is sent.
    setPassword('');
    onAccept(typed);
  }
  const open = outcome.status === 'ready' || outcome.status === 'working' || outcome.status === 'wrong' ||
    outcome.status === 'limited' || outcome.status === 'unavailable' || outcome.status === 'refused';
  return (
    <AuthPage>
      <div>
        <h1>{t(title)}</h1>
      </div>
      {open ? (
        <form onSubmit={submit} className="stack">
          <dl>
            {facts.map((fact) => (
              <div key={fact.label}>
                <dt className="muted">{t(fact.label)}</dt>
                <dd>{fact.value}</dd>
              </div>
            ))}
          </dl>
          <p className="muted">{t('invitation.unchecked')}</p>
          <TextInput label={t('invitation.password')} value={password} onChange={setPassword} type="password" required />
          <p className="hint">{t('invitation.password.hint')}</p>
          <Button type="submit" variant="primary" isDisabled={outcome.status === 'working' || password === ''}>
            {t(acceptLabel)}
          </Button>
        </form>
      ) : null}
      {outcome.status === 'working' ? (
        <p role="status" className="muted">
          {t('invitation.working')}
        </p>
      ) : null}
      {outcome.status === 'done' ? (
        <>
          <Notice icon="check" live>
            <p>{done}</p>
          </Notice>
          <Link to="/sign-in" className={buttonClass({ variant: 'primary' })}>
            {t('invitation.signIn')}
          </Link>
        </>
      ) : null}
      {outcome.status === 'wrong' ? (
        <Notice tone="error" live>
          <p>{t('invitation.wrong')}</p>
        </Notice>
      ) : null}
      {outcome.status === 'limited' ? (
        <Notice tone="error" live>
          <p>
            {outcome.retryAfter === undefined
              ? t('invitation.limited')
              : t('invitation.limited.wait', { seconds: outcome.retryAfter })}
          </p>
        </Notice>
      ) : null}
      {outcome.status === 'unavailable' ? (
        <Notice tone="error" live>
          <p>{t('invitation.unavailable')}</p>
        </Notice>
      ) : null}
      {outcome.status === 'refused' ? (
        <Notice tone="error" live>
          <p>{t('invitation.refused')}</p>
          {outcome.message ? <p className="muted">{outcome.message}</p> : null}
        </Notice>
      ) : null}
      {outcome.status === 'incomplete' ? (
        <Notice tone="error" live>
          <p>{t('invitation.incomplete')}</p>
        </Notice>
      ) : null}
    </AuthPage>
  );
}
