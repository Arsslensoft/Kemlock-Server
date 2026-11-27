import { Link } from '@tanstack/react-router';
import { type MessageId, useT } from '@/i18n';
import { AuthPage } from '@/ui/AuthPage';
import { buttonClass } from '@/ui/Button';
import { Notice } from '@/ui/Notice';

/** One line of who an invitation is from and to: a label and what the link says. */
export interface Fact {
  label: MessageId;
  value: string;
}

/**
 * What an invitation link's page says: who it is from, and that the invitation waits for the person
 * to accept it themselves once they have signed in. The link accepts nothing and carries no proof
 * the server would take: acceptance is the invitee's own, from their own session. `next` is the page
 * the sign-in leads on to, where the invitation is.
 */
export function InvitationLanding({
  title,
  facts,
  next,
  where,
  incomplete,
}: {
  title: MessageId;
  facts: Fact[];
  /** The path the invitation appears at once signed in: `/spaces`, or `/security` for emergency access. */
  next: '/spaces' | '/security';
  /** A sentence saying where the invitation shows. */
  where: MessageId;
  /** The link lacks what it needs: say so instead of offering a sign-in. */
  incomplete: boolean;
}) {
  const t = useT();
  return (
    <AuthPage>
      <div>
        <h1>{t(title)}</h1>
      </div>
      {incomplete ? (
        <Notice tone="error" live>
          <p>{t('invitation.incomplete')}</p>
        </Notice>
      ) : (
        <>
          <Notice icon="check" live>
            <p>{t('invitation.waiting')}</p>
          </Notice>
          <dl>
            {facts.map((fact) => (
              <div key={fact.label}>
                <dt className="muted">{t(fact.label)}</dt>
                <dd>{fact.value}</dd>
              </div>
            ))}
          </dl>
          <p>{t(where)}</p>
          <p className="muted">{t('invitation.unchecked')}</p>
          <Link to="/sign-in" search={{ next }} className={buttonClass({ variant: 'primary' })}>
            {t('invitation.signIn')}
          </Link>
          <p className="muted">{t('invitation.app')}</p>
        </>
      )}
    </AuthPage>
  );
}
