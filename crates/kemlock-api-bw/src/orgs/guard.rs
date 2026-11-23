//! Who may call an organization route: Vaultwarden's `OrgMemberHeaders`, `ManagerHeaders`,
//! `AdminHeaders` and `OwnerHeaders`. A failed guard is a bare 401, as a failed Rocket request
//! guard is.

use super::model::{ADMIN, MANAGER, MemberDoc, OWNER, Org, level};
use crate::app::{App, Authed, BwStore};
use crate::error::{BwError, BwResult};
use crate::events::{Acting, log_event};
use kemlock_domain::spaces::CollectionId;
use kemlock_domain::{SpaceId, UserId};
use uuid::Uuid;

/// How much of an organization a route asks the caller to be.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Need {
    /// Not revoked; an invited or accepted member will do.
    Member,
    /// Confirmed, and at least a manager.
    Manager,
    /// Confirmed, and at least an admin.
    Admin,
    /// Confirmed, and an owner.
    Owner,
}

/// The organization a request is about, and the caller's place in it.
#[derive(Debug)]
pub(crate) struct Ctx {
    pub org: Org,
    pub me: UserId,
    pub doc: MemberDoc,
    /// Who is calling and from where, for the events the call raises.
    pub acting: Acting,
}

/// An organization id in a path: anything that isn't a UUID is a route that doesn't exist.
pub(crate) fn space_id(text: &str) -> BwResult<SpaceId> {
    Uuid::parse_str(text)
        .map(SpaceId)
        .map_err(|_| BwError::NotFound)
}

impl<S: BwStore> App<S> {
    pub(crate) async fn guard(&self, authed: &Authed, org_id: &str, need: Need) -> BwResult<Ctx> {
        let space = space_id(org_id)?;
        let me = authed.user.id;
        let org = self.load_org(space).await?.ok_or(BwError::Unauthorized)?;
        let doc = org.member(me).cloned().ok_or(BwError::Unauthorized)?;
        if doc.revoked() {
            return Err(BwError::Unauthorized);
        }
        let allowed = match need {
            Need::Member => true,
            Need::Manager => doc.confirmed() && level(doc.atype) >= level(MANAGER),
            Need::Admin => doc.confirmed() && level(doc.atype) >= level(ADMIN),
            Need::Owner => doc.confirmed() && doc.atype == OWNER,
        };
        if !allowed {
            return Err(BwError::Unauthorized);
        }
        let acting = Acting::of(authed);
        Ok(Ctx {
            org,
            me,
            doc,
            acting,
        })
    }

    /// `ManagerHeaders`: a manager of this very collection.
    pub(crate) async fn guard_collection(
        &self,
        authed: &Authed,
        org_id: &str,
        collection: &str,
    ) -> BwResult<(Ctx, CollectionId)> {
        let ctx = self.guard(authed, org_id, Need::Manager).await?;
        let id = Uuid::parse_str(collection)
            .map(CollectionId)
            .map_err(|_| BwError::Unauthorized)?;
        if ctx.org.collection(id).is_none() || !ctx.org.collection_manageable(ctx.me, id) {
            return Err(BwError::Unauthorized);
        }
        Ok((ctx, id))
    }
}

impl Ctx {
    /// Logs an event of this organization made by the caller (see [`log_event`]).
    pub(crate) async fn log<S: BwStore>(&self, app: &App<S>, event_type: i32, source: &str) {
        log_event(app, event_type, source, self.org.id.0, &self.acting).await;
    }
}
