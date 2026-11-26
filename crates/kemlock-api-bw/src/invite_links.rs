//! The Bitwarden API's invitation links, offered to the Kemlock API and the admin API through
//! `kemlock_app::bitwarden::BwInviteLinks`.
//!
//! The Bitwarden route `GET /api/organizations/{id}/users/{member}/invite-link` needs a Bitwarden
//! access token, which a Kemlock account's session and the admin console don't hold. This is the
//! same link, asked for by a caller those APIs have already authenticated. The rules are the
//! route's: the organization has an organization side, the asker is a confirmed admin (an owner
//! when the invitation is for a manager, admin or owner) and the member is still invited.

use crate::app::{App, BwStore};
use crate::orgs::members::{LinkRefusal, pending_link_of};
use crate::orgs::model::{ADMIN, OWNER, level};
use kemlock_app::bitwarden::{
    Asker, BwInviteLinks, InviteLinkError, MemberInviteLink, SharedInviteLinks,
};
use kemlock_app::notices::BoxFuture;
use kemlock_domain::{SpaceId, UserId};
use std::sync::Arc;

/// The links of one Bitwarden API state.
struct Links<S>(App<S>);

impl<S: BwStore> BwInviteLinks for Links<S> {
    fn member_link(
        &self,
        space: SpaceId,
        member: UserId,
        asker: Asker,
    ) -> BoxFuture<'_, Result<MemberInviteLink, InviteLinkError>> {
        Box::pin(async move {
            let app = &self.0;
            let org = app
                .load_org(space)
                .await
                .map_err(|e| InviteLinkError::Server(format!("{e:?}")))?
                .ok_or(InviteLinkError::NotOrganization)?;
            let asker_owns = match asker {
                Asker::Server => true,
                Asker::Member(me) => {
                    let doc = org.member(me).ok_or(InviteLinkError::NotFound)?;
                    if doc.revoked() {
                        return Err(InviteLinkError::NotFound);
                    }
                    if !doc.confirmed() || level(doc.atype) < level(ADMIN) {
                        return Err(InviteLinkError::Forbidden(
                            "only a confirmed owner or admin may hand over an invitation link",
                        ));
                    }
                    doc.atype == OWNER
                }
            };
            match pending_link_of(app, &org, member, asker_owns)
                .await
                .map_err(|e| InviteLinkError::Server(format!("{e:?}")))?
            {
                Ok(link) => Ok(MemberInviteLink {
                    link: link.link,
                    expires_at: link.expires_at,
                }),
                Err(LinkRefusal::Unknown) => Err(InviteLinkError::NotFound),
                Err(LinkRefusal::Settled) => Err(InviteLinkError::NotInvited),
                Err(LinkRefusal::OwnerOnly) => Err(InviteLinkError::Forbidden(
                    "only an owner may hand over the invitation of a manager, admin or owner",
                )),
            }
        })
    }
}

/// The invitation links of this Bitwarden API, for the server to hand to the Kemlock API and the
/// admin API (see `kemlock_app::bitwarden::SharedInviteLinks`).
pub fn invite_links<S: BwStore>(app: &App<S>) -> SharedInviteLinks {
    Arc::new(Links(app.clone()))
}
