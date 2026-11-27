import { bwInvitations } from '@/api/bwInvitations';
import { useT } from '@/i18n';
import { InvitationLanding } from './InvitationLanding';
import { claimText, tokenClaims, useLinkParams } from './linkParams';
import { useAcceptInvitation } from './useAcceptInvitation';

/**
 * Where the link of an emergency-contact invitation lands (`/accept-emergency#id=…&token=…`, which
 * Bitwarden clients and mails write as `/#/accept-emergency/…`). As for an organization: the page
 * shows who named the person, asks for their master password, and on the button press only sends the
 * master password hash the worker made with the token, with no sign-in. A successful accept starts no
 * session: the page ends with a link to sign in. The person who named the contact then confirms them.
 */
export default function AcceptEmergency() {
  const t = useT();
  const { id, name, email, token } = useLinkParams();
  const claims = tokenClaims(token);
  const invitee = email ?? claimText(claims, 'email');
  const unknown = t('invitation.unknown');
  const grantor = claimText(claims, 'grantor_name') ?? name;
  const grantorEmail = claimText(claims, 'grantor_email');
  const { outcome, submit } = useAcceptInvitation(
    invitee,
    id && token ? (hash) => bwInvitations.acceptEmergency(id, token, hash) : undefined,
  );
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
        { label: 'invitation.fact.invitee', value: invitee ?? unknown },
      ]}
      acceptLabel="invitation.emergency.accept"
      onAccept={submit}
    />
  );
}
