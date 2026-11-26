// The link that accepts a Bitwarden organization's invitation (crates/kemlock-api-kem/src/routes/
// invite_link.rs). A server that can't mail has no mail to carry it, so an owner or admin of the
// organization copies it here and hands it over. Whoever opens the link accepts for that account.
import type { Api } from './client';

/** `GET /kem/v1/spaces/{id}/members/{user}/invite-link` */
export interface InviteLinkDto {
  /** The address to open in the web vault, with the token that accepts the invitation. */
  link: string;
  /** When the link stops working, in Unix seconds. */
  expiresAt: number;
}

type Http = Pick<Api, 'request'>;

const part = encodeURIComponent;

export function createInviteLinkApi(http: Http) {
  return {
    /**
     * 404 when the space isn't a Bitwarden organization, 403 when the caller may not hand the link
     * over, 409 `not-invited` when the member accepted already.
     */
    get: (space: string, user: string) =>
      http.request<InviteLinkDto>({
        method: 'GET',
        path: `/kem/v1/spaces/${part(space)}/members/${part(user)}/invite-link`,
      }),
  };
}

export type InviteLinkApi = ReturnType<typeof createInviteLinkApi>;
