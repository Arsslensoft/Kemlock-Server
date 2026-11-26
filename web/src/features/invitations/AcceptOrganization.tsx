import { getRouteApi } from '@tanstack/react-router';
import { bwInvitations } from '@/api/bwInvitations';
import { useT } from '@/i18n';
import { InvitationLanding } from './InvitationLanding';
import { useAcceptOnce } from './useAcceptOnce';

const route = getRouteApi('/accept-organization');

/**
 * Where the link of an invitation to an organization lands (`/accept-organization?organizationId=…
 * &organizationUserId=…&token=…`, which Bitwarden clients and mails write as
 * `/#/accept-organization/…`). The token is the proof, so nothing is asked: the page accepts once
 * and says what happened. An administrator then confirms the member before they see anything.
 */
export default function AcceptOrganization() {
  const t = useT();
  const { organizationId, organizationUserId, token } = route.useSearch();
  const outcome = useAcceptOnce(
    organizationId && organizationUserId && token
      ? () => bwInvitations.acceptOrganization(organizationId, organizationUserId, token)
      : undefined,
  );
  return <InvitationLanding title="invitation.organization.title" outcome={outcome} done={t('invitation.organization.done')} />;
}
