//! The link that accepts a Bitwarden organization's invitation, for the people who may hand it
//! over: an owner or admin of the organization in the Kemlock web vault, and the server admin in
//! the console.
//!
//! The link is signed by the Bitwarden API's token key, and its shape is the one Vaultwarden mails,
//! so the minting stays in `kemlock-api-bw`. The Kemlock API and the admin API call it through this
//! port, which the server wires from the Bitwarden API's state: the web layers never depend on each
//! other. A server with the Bitwarden API off provides none.
//!
//! The link accepts nothing by itself: the invitee signs in and accepts for themselves. It still goes
//! only to someone who could remove the member, and only for a member who is still invited.

use crate::notices::BoxFuture;
use kemlock_domain::{SpaceId, UserId};
use std::sync::Arc;

/// Who asks for a link.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Asker {
    /// A member of the organization, who must be a confirmed admin or owner (an owner when the
    /// invitation is for a manager, admin or owner).
    Member(UserId),
    /// The server admin, whom the admin API has already checked.
    Server,
}

/// The link of one invitation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberInviteLink {
    /// The address to open in the web vault, with the token that accepts the invitation.
    pub link: String,
    /// When the link stops working, in seconds since the epoch.
    pub expires_at: i64,
}

/// Why there is no link to give.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum InviteLinkError {
    /// The space has no organization side: it is not a Bitwarden organization (or the Bitwarden
    /// API is off).
    #[error("the space isn't a Bitwarden organization")]
    NotOrganization,
    /// The asking member isn't in the organization, or the member asked about isn't.
    #[error("not found")]
    NotFound,
    /// The asker isn't allowed to hand the link over; the text says why.
    #[error("forbidden: {0}")]
    Forbidden(&'static str),
    /// The member has accepted already, or was never invited: there is nothing to accept.
    #[error("the member isn't waiting to accept an invitation")]
    NotInvited,
    /// The store or the signing failed; the text is for logs.
    #[error("{0}")]
    Server(String),
}

/// The Bitwarden API's invitation links, as the Kemlock API and the admin API ask for them.
pub trait BwInviteLinks: Send + Sync {
    /// The link of `member`'s invitation to the organization `space`, for `asker`.
    fn member_link(
        &self,
        space: SpaceId,
        member: UserId,
        asker: Asker,
    ) -> BoxFuture<'_, Result<MemberInviteLink, InviteLinkError>>;

    /// Whether `space` is a Bitwarden organization (it has an organization side), so a page can
    /// offer the invitation link only where it applies. Any failure to tell is "no".
    fn is_organization(&self, space: SpaceId) -> BoxFuture<'_, bool>;

    /// The members of the organization `space` who are still invited and have a Bitwarden
    /// invitation, which is what a link can be made for; `None` when the space is not a Bitwarden
    /// organization. A member invited through the Kemlock API alone (a space row and no Bitwarden
    /// member document) is not in it. Any failure to tell is `None`.
    fn pending_invitations(&self, space: SpaceId) -> BoxFuture<'_, Option<Vec<UserId>>>;
}

/// What the server layers on its router as a request extension, so both APIs can reach the port.
pub type SharedInviteLinks = Arc<dyn BwInviteLinks>;
