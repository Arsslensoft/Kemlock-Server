import { getRouteApi } from '@tanstack/react-router';
import { bwInvitations } from '@/api/bwInvitations';
import { useT } from '@/i18n';
import { InvitationLanding } from './InvitationLanding';
import { useAcceptOnce } from './useAcceptOnce';

const route = getRouteApi('/accept-emergency');

/**
 * Where the link of an emergency-contact invitation lands (`/accept-emergency?id=…&token=…`, which
 * Bitwarden clients and mails write as `/#/accept-emergency/…`). The token is the proof, so nothing
 * is asked. The person who named the contact then confirms them.
 */
export default function AcceptEmergency() {
  const t = useT();
  const { id, token } = route.useSearch();
  const outcome = useAcceptOnce(id && token ? () => bwInvitations.acceptEmergency(id, token) : undefined);
  return <InvitationLanding title="invitation.emergency.title" outcome={outcome} done={t('invitation.emergency.done')} />;
}
