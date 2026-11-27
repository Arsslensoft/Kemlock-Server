import { bwInvitations } from '@/api/bwInvitations';
import { useT } from '@/i18n';
import { InvitationLanding } from './InvitationLanding';
import { claimText, tokenClaims, useLinkParams } from './linkParams';
import { useAcceptOnce } from './useAcceptOnce';

/**
 * Where the link of an invitation to an organization lands (`/accept-organization#organizationId=…
 * &organizationUserId=…&token=…`, which Bitwarden clients and mails write as
 * `/#/accept-organization/…`). The page shows the organization and who invited the person, and
 * accepts only when its button is pressed: a mail scanner that opens the link and runs its script
 * accepts nothing. The token is taken out of the address as the page opens. An administrator then
 * confirms the member before they see anything.
 */
export default function AcceptOrganization() {
  const t = useT();
  const { organizationId, organizationUserId, organizationName, email, token } = useLinkParams();
  const claims = tokenClaims(token);
  const unknown = t('invitation.unknown');
  const { outcome, start } = useAcceptOnce(
    organizationId && organizationUserId && token
      ? () => bwInvitations.acceptOrganization(organizationId, organizationUserId, token)
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
        { label: 'invitation.fact.invitee', value: email ?? claimText(claims, 'email') ?? unknown },
      ]}
      acceptLabel="invitation.organization.accept"
      onAccept={start}
    />
  );
}
