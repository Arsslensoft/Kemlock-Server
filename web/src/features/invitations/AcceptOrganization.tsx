import { bwInvitations } from '@/api/bwInvitations';
import { useT } from '@/i18n';
import { InvitationLanding } from './InvitationLanding';
import { claimText, tokenClaims, useLinkParams } from './linkParams';
import { useAcceptInvitation } from './useAcceptInvitation';

/**
 * Where the link of an invitation to an organization lands (`/accept-organization#organizationId=…
 * &organizationUserId=…&token=…`, which Bitwarden clients and mails write as
 * `/#/accept-organization/…`). The page shows the organization and who invited the person, and asks
 * for their master password. Pressing the button, and only that, makes the master password hash in
 * the crypto worker from the account's KDF and sends it with the token, with no sign-in: most invitees
 * have a Bitwarden-only account. Nothing is sent on load, so a mail scanner that runs the page's script
 * accepts nothing, and the token is taken out of the address as the page opens. A successful accept
 * starts no session: the page ends with a link to sign in. An administrator then confirms the member.
 */
export default function AcceptOrganization() {
  const t = useT();
  const { organizationId, organizationUserId, organizationName, email, token } = useLinkParams();
  const claims = tokenClaims(token);
  const invitee = email ?? claimText(claims, 'email');
  const unknown = t('invitation.unknown');
  const { outcome, submit } = useAcceptInvitation(
    invitee,
    organizationId && organizationUserId && token
      ? (hash) => bwInvitations.acceptOrganization(organizationId, organizationUserId, token, hash)
      : undefined,
  );
  return (
    <InvitationLanding
      title="invitation.organization.title"
      outcome={outcome}
      done={t('invitation.organization.done')}
      facts={[
        { label: 'invitation.fact.organization', value: organizationName ?? unknown },
        { label: 'invitation.fact.inviter', value: claimText(claims, 'invited_by_email') ?? unknown },
        { label: 'invitation.fact.invitee', value: invitee ?? unknown },
      ]}
      acceptLabel="invitation.organization.accept"
      onAccept={submit}
    />
  );
}
