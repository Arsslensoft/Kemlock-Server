import { useT } from '@/i18n';
import { InvitationLanding } from './InvitationLanding';
import { claimText, tokenClaims, useLinkParams } from './linkParams';

/**
 * Where the link of an invitation to an organization lands (`/accept-organization#organizationId=…
 * &organizationUserId=…&token=…`, which Bitwarden clients and mails write as
 * `/#/accept-organization/…`). The server accepts an invitation only for the invitee's own
 * session, so this page accepts nothing and posts no token: it says who invited the person and to
 * what, and leads to the sign-in. Once signed in, the organization is a space with an invitation in
 * Spaces, where the person accepts it themselves. The values are taken out of the address as the
 * page opens.
 */
export default function AcceptOrganization() {
  const t = useT();
  const { organizationId, organizationUserId, organizationName, email, token } = useLinkParams();
  const claims = tokenClaims(token);
  const unknown = t('invitation.unknown');
  return (
    <InvitationLanding
      title="invitation.organization.title"
      facts={[
        { label: 'invitation.fact.organization', value: organizationName ?? unknown },
        { label: 'invitation.fact.inviter', value: claimText(claims, 'invited_by_email') ?? unknown },
        { label: 'invitation.fact.invitee', value: email ?? claimText(claims, 'email') ?? unknown },
      ]}
      next="/spaces"
      where="invitation.organization.where"
      incomplete={!(organizationId && organizationUserId && token)}
    />
  );
}
