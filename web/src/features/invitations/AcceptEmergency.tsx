import { useT } from '@/i18n';
import { InvitationLanding } from './InvitationLanding';
import { claimText, tokenClaims, useLinkParams } from './linkParams';

/**
 * Where the link of an emergency-contact invitation lands (`/accept-emergency#id=…&token=…`, which
 * Bitwarden clients and mails write as `/#/accept-emergency/…`). As for an organization, the server
 * accepts only for the invitee's own session, so this page accepts nothing and posts no token: it
 * says who named the person and leads to the sign-in. Once signed in, the invitation shows in
 * Emergency access, where the person accepts it themselves. The values are taken out of the address
 * as the page opens.
 */
export default function AcceptEmergency() {
  const t = useT();
  const { id, name, email, token } = useLinkParams();
  const claims = tokenClaims(token);
  const unknown = t('invitation.unknown');
  const grantor = claimText(claims, 'grantor_name') ?? name;
  const grantorEmail = claimText(claims, 'grantor_email');
  return (
    <InvitationLanding
      title="invitation.emergency.title"
      facts={[
        {
          label: 'invitation.fact.grantor',
          value: grantor ? (grantorEmail ? `${grantor} (${grantorEmail})` : grantor) : (grantorEmail ?? unknown),
        },
        { label: 'invitation.fact.invitee', value: email ?? claimText(claims, 'email') ?? unknown },
      ]}
      next="/security"
      where="invitation.emergency.where"
      incomplete={!(id && token)}
    />
  );
}
