import { bwInvitations } from '@/api/bwInvitations';
import { useT } from '@/i18n';
import { InvitationLanding } from './InvitationLanding';
import { claimText, tokenClaims, useLinkParams } from './linkParams';
import { useAcceptOnce } from './useAcceptOnce';

/**
 * Where the link of an emergency-contact invitation lands (`/accept-emergency#id=…&token=…`, which
 * Bitwarden clients and mails write as `/#/accept-emergency/…`). The page shows who named the
 * person and accepts only when its button is pressed, as the organization page does, and takes the
 * token out of the address as it opens. The person who named the contact then confirms them.
 */
export default function AcceptEmergency() {
  const t = useT();
  const { id, name, email, token } = useLinkParams();
  const claims = tokenClaims(token);
  const unknown = t('invitation.unknown');
  const grantor = claimText(claims, 'grantor_name') ?? name;
  const grantorEmail = claimText(claims, 'grantor_email');
  const { outcome, start } = useAcceptOnce(id && token ? () => bwInvitations.acceptEmergency(id, token) : undefined);
  return (
    <InvitationLanding
      title="invitation.emergency.title"
      outcome={outcome}
      done={t('invitation.emergency.done')}
      facts={[
        {
          label: 'invitation.fact.grantor',
          value: grantor ? (grantorEmail ? `${grantor} (${grantorEmail})` : grantor) : (grantorEmail ?? unknown),
        },
        { label: 'invitation.fact.invitee', value: email ?? claimText(claims, 'email') ?? unknown },
      ]}
      acceptLabel="invitation.emergency.accept"
      onAccept={start}
    />
  );
}
