//! Members: invite, accept, confirm, edit, remove, revoke and restore, with Vaultwarden's rules
//! and messages.

use super::guard::Ctx;
use super::model::{
    ACCEPTED, ADMIN, AccessDoc, CONFIRMED, INVITED, KIND_PENDING, MemberDoc, OWNER, Org,
    PendingDoc, USER, level, parse_type, permission_of,
};
use super::policy::check_user_allowed;
use crate::app::{App, Authed, BwStore};
use crate::error::{BwError, BwResult};
use crate::events::kind;
use kemlock_app::bitwarden::BwAccountRepo;
use kemlock_app::notices::{BwOrgInviteNotice, InvitationNotice, Notice};
use kemlock_app::ports::UserRepo;
use kemlock_domain::spaces::{CollectionGrant, CollectionId, Grantee, GroupId};
use kemlock_domain::{Email, User, UserId};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashMap;
use uuid::Uuid;

/// The claims of an invitation link: what `accept` and the policies-by-token route read back.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct InviteClaims {
    pub nbf: i64,
    pub exp: i64,
    pub iss: String,
    pub sub: String,
    pub email: String,
    pub org_id: String,
    pub member_id: String,
    pub invited_by_email: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct InviteData {
    pub emails: Vec<String>,
    pub groups: Vec<String>,
    pub r#type: Value,
    pub collections: Option<Vec<AccessDoc>>,
    #[serde(default)]
    pub permissions: HashMap<String, Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EditData {
    pub r#type: Value,
    pub collections: Option<Vec<AccessDoc>>,
    pub groups: Option<Vec<String>>,
    #[serde(default)]
    pub permissions: HashMap<String, Value>,
}

fn type_text(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

/// The custom role with "manage all collections" ticked is sent as its three child permissions.
fn custom_all(permissions: &HashMap<String, Value>) -> bool {
    [
        "editAnyCollection",
        "deleteAnyCollection",
        "createNewCollections",
    ]
    .iter()
    .all(|key| permissions.get(*key) == Some(&json!(true)))
}

pub(crate) fn parse_collection(text: &str) -> Option<CollectionId> {
    Uuid::parse_str(text).ok().map(CollectionId)
}

pub(crate) fn parse_group(text: &str) -> Option<GroupId> {
    Uuid::parse_str(text).ok().map(GroupId)
}

fn parse_member(text: &str) -> Option<UserId> {
    Uuid::parse_str(text).ok().map(UserId)
}

/// Grants for a member from the flags a request sent. Collections that aren't the organization's
/// are an error, as Vaultwarden's "Collection not found in Organization".
pub(crate) fn grants_of(
    org: &Org,
    user: UserId,
    selections: &[AccessDoc],
) -> BwResult<Vec<CollectionGrant>> {
    selections
        .iter()
        .map(|c| {
            let id = parse_collection(&c.id)
                .filter(|id| org.collection(*id).is_some())
                .ok_or_else(|| BwError::msg("Collection not found in Organization"))?;
            Ok(CollectionGrant {
                collection: id,
                grantee: Grantee::Member(user),
                permission: permission_of(c.read_only, c.hide_passwords, c.manage),
            })
        })
        .collect()
}

fn group_ids_of(org: &Org, groups: &[String]) -> BwResult<Vec<GroupId>> {
    groups
        .iter()
        .map(|g| {
            parse_group(g)
                .filter(|id| org.group(*id).is_some())
                .ok_or_else(|| BwError::msg("Group not found in Organization"))
        })
        .collect()
}

/// Whether an invitation to this existing account is taken as accepted at once, as Vaultwarden does
/// with its mailer off: only when the operator set `KEMLOCK_BW_INVITES_AUTO_ACCEPT`, the server
/// doesn't mail, and the account has a password. The invitee has not agreed to anything then; the
/// default is that they accept for themselves.
pub(crate) async fn auto_accepts<S: BwStore>(app: &App<S>, user: UserId) -> BwResult<bool> {
    if !app.settings.bw_invites_auto_accept() || app.notices.mails() {
        return Ok(false);
    }
    Ok(BwAccountRepo::get(&app.store, user)
        .await?
        .is_some_and(|account| !account.password_hash.is_empty()))
}

/// How long the link of an invitation works: Vaultwarden's `INVITATION_EXPIRATION_HOURS`, 120.
const INVITE_DAYS: i64 = 5;

/// The signed token of an invitation and the link that carries it, in the shape Vaultwarden's
/// mail has (`/#/accept-organization/?organizationId=...&token=...`), which the web vault opens.
/// The token alone accepts the invitation, so the link is a secret.
#[derive(Clone)]
pub(crate) struct InviteLink {
    pub token: String,
    pub link: String,
    /// When the token stops working, in seconds since the epoch.
    pub expires_at: i64,
}

pub(crate) fn invite_link<S: BwStore>(
    app: &App<S>,
    org: &Org,
    user: UserId,
    email: &str,
    invited_by_email: Option<&str>,
) -> BwResult<InviteLink> {
    let now = app.now_secs();
    let expires_at = now + INVITE_DAYS * 24 * 3600;
    let claims = InviteClaims {
        nbf: now,
        exp: expires_at,
        iss: app.settings.issuer("invite"),
        sub: user.to_string(),
        email: email.to_owned(),
        org_id: org.id.to_string(),
        member_id: user.to_string(),
        invited_by_email: invited_by_email.map(str::to_owned),
    };
    let token = app
        .keys
        .encode(&claims)
        .map_err(|e| BwError::Server(e.to_string()))?;
    let encoded = |text: &str| -> String {
        url::form_urlencoded::byte_serialize(text.as_bytes()).collect()
    };
    let link = format!(
        "{}/#/accept-organization/?organizationId={}&organizationUserId={}&email={}&organizationName={}&token={}",
        app.host(),
        org.id,
        user,
        encoded(email),
        encoded(&org.name),
        token
    );
    Ok(InviteLink {
        token,
        link,
        expires_at,
    })
}

/// Mails an account its invitation to an organization, when the server mails. An account that can
/// sign in to the web vault is sent the Kemlock space invitation, which links to its space page; one
/// that can't (an account made through the Bitwarden API has no OPAQUE record) is sent the link
/// that carries the token, which accepts the invitation by itself. The mail is best effort; the
/// invitation stands without it, and an administrator can copy the link to hand over.
pub(crate) async fn mail_invitation<S: BwStore>(
    app: &App<S>,
    org: &Org,
    to: &User,
    inviter_email: &str,
) {
    if !app.notices.mails() {
        return;
    }
    let notice = if to.opaque_record.is_some() {
        Notice::Invitation(InvitationNotice {
            to: to.email.clone(),
            space: Some(org.name.clone()),
            inviter: Some(inviter_email.to_owned()),
            space_id: Some(org.id),
        })
    } else {
        let link = match invite_link(app, org, to.id, to.email.as_str(), Some(inviter_email)) {
            Ok(link) => link,
            Err(error) => {
                tracing::warn!(?error, "couldn't make an invitation link");
                return;
            }
        };
        Notice::BwOrgInvite(BwOrgInviteNotice {
            to: to.email.clone(),
            organization: org.name.clone(),
            inviter: Some(inviter_email.to_owned()).filter(|s| !s.is_empty()),
            link: link.link,
        })
    };
    app.notices.send(notice).await;
}


/// `POST /api/organizations/{id}/users/invite`.
pub(crate) async fn invite<S: BwStore>(
    app: &App<S>,
    ctx: &Ctx,
    inviter_email: &str,
    data: InviteData,
) -> BwResult<()> {
    let collections = data.collections.clone().unwrap_or_default();
    if collections.iter().any(|c| {
        parse_collection(&c.id)
            .and_then(|id| ctx.org.collection(id))
            .is_none()
    }) {
        return Err(BwError::msg("Invalid collection"));
    }
    if data
        .groups
        .iter()
        .any(|g| parse_group(g).and_then(|id| ctx.org.group(id)).is_none())
    {
        return Err(BwError::msg("Invalid group"));
    }

    let raw = type_text(&data.r#type);
    let Some(new_type) = parse_type(&raw) else {
        return Err(BwError::msg("Invalid type"));
    };
    if new_type != USER && ctx.doc.atype != OWNER {
        return Err(BwError::msg(
            "Only Owners can invite Managers, Admins or Owners",
        ));
    }
    let access_all =
        level(new_type) >= level(ADMIN) || (raw == "4" && custom_all(&data.permissions));

    for email in &data.emails {
        let parsed = Email::parse(email).map_err(|_| {
            BwError::msg(format!(
                "{} is not a valid email address",
                email.escape_debug()
            ))
        })?;
        // Each invitation reads the organization again: groups are written whole.
        let org = app
            .load_org(ctx.org.id)
            .await?
            .ok_or_else(|| BwError::msg("Error looking up organization"))?;
        match UserRepo::by_email(&app.store, &parsed).await? {
            Some(user) => {
                if org.member(user.id).is_some() {
                    return Err(BwError::msg(format!(
                        "User already in organization: {}",
                        email.escape_debug()
                    )));
                }
                // An account that already exists is invited and waits: nobody joins an
                // organization they have not agreed to, so the invitee accepts, with the mail or
                // from the web vault's spaces. (Vaultwarden with its mailer off would take an
                // account with a password as accepted at once.)
                let status = if auto_accepts(app, user.id).await? {
                    ACCEPTED
                } else {
                    INVITED
                };
                let mut doc = MemberDoc::new(new_type, access_all, status);
                doc.invited_by_email = Some(inviter_email.to_owned());
                app.put_member(&org, user.id, &doc, ctx.me).await?;
                if !access_all {
                    let grants = grants_of(&org, user.id, &collections)?;
                    app.set_member_grants(&org, user.id, grants).await?;
                }
                let groups = group_ids_of(&org, &data.groups)?;
                if !groups.is_empty() {
                    app.set_member_groups(&org, user.id, &groups).await?;
                }
                app.touch_quiet(user.id).await?;
                ctx.log(app, kind::MEMBER_INVITED, &user.id.to_string())
                    .await;
                mail_invitation(app, &org, &user, inviter_email).await;
            }
            None => {
                if org.pending.iter().any(|p| p.email == parsed.as_str()) {
                    return Err(BwError::msg(format!(
                        "User already in organization: {}",
                        email.escape_debug()
                    )));
                }
                let pending = PendingDoc {
                    id: crate::env::random_uuid(app.env.as_ref()).to_string(),
                    email: parsed.as_str().to_owned(),
                    atype: new_type,
                    access_all,
                    collections: if access_all {
                        Vec::new()
                    } else {
                        collections.clone()
                    },
                    groups: data.groups.clone(),
                    invited_by_email: Some(inviter_email.to_owned()),
                    invited_by: ctx.me.to_string(),
                    external_id: None,
                };
                app.put_doc(org.id.0, KIND_PENDING, parsed.as_str(), &pending)
                    .await?;
                ctx.log(app, kind::MEMBER_INVITED, &pending.id).await;
            }
        }
    }
    Ok(())
}

/// `POST /api/organizations/{id}/users/{member}/reinvite`: an invited account is mailed the
/// invitation again, when the server mails, and stays invited until it accepts; an invitation to
/// an address with no account stays.
pub(crate) async fn reinvite<S: BwStore>(app: &App<S>, ctx: &Ctx, member_id: &str) -> BwResult<()> {
    let org = &ctx.org;
    if let Some(user) = parse_member(member_id).filter(|u| org.member(*u).is_some()) {
        let Some(doc) = org.member(user) else {
            return Err(BwError::msg(
                "The user hasn't been invited to the organization.",
            ));
        };
        if doc.status != INVITED {
            return Err(BwError::msg(
                "The user is already accepted or confirmed to the organization",
            ));
        }
        if auto_accepts(app, user).await? {
            let mut accepted = doc.clone();
            accepted.status = ACCEPTED;
            app.put_member(org, user, &accepted, ctx.me).await?;
            return Ok(());
        }
        if let Some(account) = UserRepo::by_id(&app.store, user).await? {
            let inviter = doc.invited_by_email.clone().unwrap_or_default();
            mail_invitation(app, org, &account, &inviter).await;
        }
        return Ok(());
    }
    if org.pending.iter().any(|p| p.id == member_id) {
        return Ok(());
    }
    Err(BwError::msg(
        "The user hasn't been invited to the organization.",
    ))
}

/// Why an invitation has no link to give.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LinkRefusal {
    /// The account isn't a member of the organization.
    Unknown,
    /// The member has accepted already (or is confirmed or revoked).
    Settled,
    /// The member is a manager, admin or owner, and only an owner invites those.
    OwnerOnly,
}

/// The link of the pending invitation of `user`, which `asker_owns` (the asker is an owner of the
/// organization, or the server admin) may hand over for any role and another administrator only for
/// a plain user. The outer error is the store or the signing failing; the inner is a refusal.
pub(crate) async fn pending_link_of<S: BwStore>(
    app: &App<S>,
    org: &Org,
    user: UserId,
    asker_owns: bool,
) -> BwResult<Result<InviteLink, LinkRefusal>> {
    let Some(doc) = org.member(user) else {
        return Ok(Err(LinkRefusal::Unknown));
    };
    if doc.status != INVITED {
        return Ok(Err(LinkRefusal::Settled));
    }
    if doc.atype != USER && !asker_owns {
        return Ok(Err(LinkRefusal::OwnerOnly));
    }
    let Some(account) = UserRepo::by_id(&app.store, user).await? else {
        return Ok(Err(LinkRefusal::Unknown));
    };
    let link = invite_link(
        app,
        org,
        user,
        account.email.as_str(),
        doc.invited_by_email.as_deref(),
    )?;
    Ok(Ok(link))
}

/// `GET /api/organizations/{id}/users/{member}/invite-link` (not Vaultwarden's): the link of a
/// pending invitation of an existing account, for an administrator of a server that doesn't mail to
/// hand over themselves. Whoever opens it accepts for that account, so it is the invitation's
/// secret and goes only to the administrators who could remove the member.
pub(crate) async fn pending_link<S: BwStore>(
    app: &App<S>,
    ctx: &Ctx,
    member_id: &str,
) -> BwResult<Value> {
    let Some(user) = parse_member(member_id) else {
        return Err(BwError::msg(
            "The user hasn't been invited to the organization.",
        ));
    };
    match pending_link_of(app, &ctx.org, user, ctx.doc.atype == OWNER).await? {
        Ok(link) => Ok(json!({"object": "inviteLink", "link": link.link, "token": link.token})),
        Err(LinkRefusal::Unknown) => Err(BwError::msg(
            "The user hasn't been invited to the organization.",
        )),
        Err(LinkRefusal::Settled) => Err(BwError::msg(
            "The user is already accepted or confirmed to the organization",
        )),
        Err(LinkRefusal::OwnerOnly) => Err(BwError::msg(
            "Only Owners can invite Managers, Admins or Owners",
        )),
    }
}

/// `POST /api/organizations/{id}/users/{member}/accept`. The token of the link is the proof: a
/// caller who signed in must be the account it was made for, and one who didn't is that account.
pub(crate) async fn accept<S: BwStore>(
    app: &App<S>,
    authed: Option<&Authed>,
    org_id: &str,
    member_id: &str,
    token: &str,
    reset_key: Option<String>,
) -> BwResult<()> {
    let claims: InviteClaims = app
        .keys
        .decode(token, &app.settings.issuer("invite"), app.now_secs())
        .map_err(|e| BwError::msg(e.to_string()))?;
    let account = match authed {
        Some(authed) => authed.user.clone(),
        None => {
            let id = parse_member(&claims.member_id)
                .ok_or_else(|| BwError::msg("Error accepting the invitation"))?;
            UserRepo::by_id(&app.store, id)
                .await?
                .ok_or_else(|| BwError::msg("Error accepting the invitation"))?
        }
    };
    // An invitation is for the account it was made for.
    if claims.email != account.email.as_str() {
        return Err(BwError::msg("Invitation was issued to a different account"));
    }
    if claims.org_id != org_id || claims.member_id != member_id {
        return Err(BwError::msg("Error accepting the invitation"));
    }
    let user = account.id;
    let org_space = super::guard::space_id(&claims.org_id)?;
    let Some(org) = app.load_org(org_space).await? else {
        return Err(BwError::msg("Error accepting the invitation"));
    };
    let Some(mut doc) = org.member(user).cloned() else {
        return Err(BwError::msg("Error accepting the invitation"));
    };
    if claims.member_id != user.to_string() {
        return Err(BwError::msg("Error accepting the invitation"));
    }
    if doc.status != INVITED {
        return Err(BwError::msg("User already accepted the invitation"));
    }
    doc.status = ACCEPTED;
    doc.invited_by_email = doc.invited_by_email.or(claims.invited_by_email);
    check_user_allowed(app, &org, user, &doc, "join").await?;
    // An organization whose account recovery policy enrols by itself takes the key the client sent
    // with the acceptance.
    if let Some(key) = reset_key.filter(|k| !k.is_empty())
        && super::recovery::auto_enroll(&org)
    {
        doc.reset_password_key = Some(key);
    }
    app.put_member(&org, user, &doc, user).await?;
    app.touch_quiet(user).await
}

/// `confirm_invite_impl`: stores the organization key wrapped to the member and confirms them.
pub(crate) async fn confirm<S: BwStore>(
    app: &App<S>,
    ctx: &Ctx,
    member_id: &str,
    key: &str,
) -> BwResult<()> {
    if key.is_empty() || member_id.is_empty() {
        return Err(BwError::msg(
            "Key or UserId is not set, unable to process request",
        ));
    }
    let Some(user) = parse_member(member_id).filter(|u| ctx.org.member(*u).is_some()) else {
        return Err(BwError::msg(
            "The specified user isn't a member of the organization",
        ));
    };
    let Some(mut doc) = ctx.org.member(user).cloned() else {
        return Err(BwError::msg(
            "The specified user isn't a member of the organization",
        ));
    };
    if doc.atype != USER && ctx.doc.atype != OWNER {
        return Err(BwError::msg(
            "Only Owners can confirm Managers, Admins or Owners",
        ));
    }
    if doc.status != ACCEPTED {
        return Err(BwError::msg("User in invalid state"));
    }
    doc.status = CONFIRMED;
    doc.akey = key.to_owned();
    check_user_allowed(app, &ctx.org, user, &doc, "confirm").await?;
    app.put_member(&ctx.org, user, &doc, ctx.me).await?;
    app.touch_quiet(user).await?;
    ctx.log(app, kind::MEMBER_CONFIRMED, &user.to_string())
        .await;
    app.org_keys_changed(user);
    Ok(())
}

/// `PUT /api/organizations/{id}/users/{member}`.
pub(crate) async fn edit<S: BwStore>(
    app: &App<S>,
    ctx: &Ctx,
    member_id: &str,
    data: EditData,
) -> BwResult<()> {
    let raw = type_text(&data.r#type);
    let Some(new_type) = parse_type(&raw) else {
        return Err(BwError::msg("Invalid type"));
    };
    let access_all =
        level(new_type) >= level(ADMIN) || (raw == "4" && custom_all(&data.permissions));
    let Some(user) = parse_member(member_id).filter(|u| ctx.org.member(*u).is_some()) else {
        return Err(BwError::msg(
            "The specified user isn't member of the organization",
        ));
    };
    let Some(mut doc) = ctx.org.member(user).cloned() else {
        return Err(BwError::msg(
            "The specified user isn't member of the organization",
        ));
    };

    if new_type != doc.atype
        && (level(doc.atype) >= level(ADMIN) || level(new_type) >= level(ADMIN))
        && ctx.doc.atype != OWNER
    {
        return Err(BwError::msg(
            "Only Owners can grant and remove Admin or Owner privileges",
        ));
    }
    if doc.atype == OWNER && ctx.doc.atype != OWNER {
        return Err(BwError::msg("Only Owners can edit Owner users"));
    }
    if doc.atype == OWNER
        && new_type != OWNER
        && doc.status == CONFIRMED
        && ctx.org.confirmed_owners() <= 1
    {
        return Err(BwError::msg("Can't delete the last owner"));
    }

    doc.access_all = access_all;
    doc.atype = new_type;
    // Checked after the change, because admins are exempt.
    check_user_allowed(app, &ctx.org, user, &doc, "modify").await?;

    let collections = data.collections.clone().unwrap_or_default();
    let grants = if access_all {
        Vec::new()
    } else {
        grants_of(&ctx.org, user, &collections)?
    };
    let groups = group_ids_of(&ctx.org, &data.groups.clone().unwrap_or_default())?;

    app.set_member_grants(&ctx.org, user, grants).await?;
    app.set_member_groups(&ctx.org, user, &groups).await?;
    app.put_member(&ctx.org, user, &doc, ctx.me).await?;
    app.touch_quiet(user).await?;
    ctx.log(app, kind::MEMBER_UPDATED, &user.to_string()).await;
    Ok(())
}

/// `DELETE /api/organizations/{id}/users/{member}`.
pub(crate) async fn remove<S: BwStore>(app: &App<S>, ctx: &Ctx, member_id: &str) -> BwResult<()> {
    if let Some(pending) = ctx.org.pending.iter().find(|p| p.id == member_id) {
        if pending.atype != USER && ctx.doc.atype != OWNER {
            return Err(BwError::msg("Only Owners can delete Admins or Owners"));
        }
        app.del_doc(ctx.org.id.0, KIND_PENDING, &pending.email)
            .await?;
        ctx.log(app, kind::MEMBER_REMOVED, &pending.id).await;
        return Ok(());
    }
    let Some(user) = parse_member(member_id).filter(|u| ctx.org.member(*u).is_some()) else {
        return Err(BwError::msg(
            "User to delete isn't member of the organization",
        ));
    };
    let Some(doc) = ctx.org.member(user) else {
        return Err(BwError::msg(
            "User to delete isn't member of the organization",
        ));
    };
    if doc.atype != USER && ctx.doc.atype != OWNER {
        return Err(BwError::msg("Only Owners can delete Admins or Owners"));
    }
    if doc.atype == OWNER && doc.status == CONFIRMED && ctx.org.confirmed_owners() <= 1 {
        return Err(BwError::msg("Can't delete the last owner"));
    }
    app.remove_member(&ctx.org, user).await?;
    app.touch_quiet(user).await?;
    ctx.log(app, kind::MEMBER_REMOVED, &user.to_string()).await;
    app.org_keys_changed(user);
    Ok(())
}

/// `PUT /api/organizations/{id}/users/{member}/revoke`.
pub(crate) async fn revoke<S: BwStore>(app: &App<S>, ctx: &Ctx, member_id: &str) -> BwResult<()> {
    let Some(user) = parse_member(member_id).filter(|u| ctx.org.member(*u).is_some()) else {
        return Err(BwError::msg("User not found in organization"));
    };
    let Some(mut doc) = ctx.org.member(user).cloned() else {
        return Err(BwError::msg("User not found in organization"));
    };
    if doc.revoked() {
        return Err(BwError::msg("User is already revoked"));
    }
    if user == ctx.me {
        return Err(BwError::msg("You cannot revoke yourself"));
    }
    if doc.atype == OWNER && ctx.doc.atype != OWNER {
        return Err(BwError::msg("Only owners can revoke other owners"));
    }
    if doc.atype == OWNER && ctx.org.confirmed_owners() <= 1 {
        return Err(BwError::msg(
            "Organization must have at least one confirmed owner",
        ));
    }
    doc.revoke();
    app.put_member(&ctx.org, user, &doc, ctx.me).await?;
    app.touch_quiet(user).await?;
    ctx.log(app, kind::MEMBER_REVOKED, &user.to_string()).await;
    Ok(())
}

/// `PUT /api/organizations/{id}/users/{member}/restore`.
pub(crate) async fn restore<S: BwStore>(app: &App<S>, ctx: &Ctx, member_id: &str) -> BwResult<()> {
    let Some(user) = parse_member(member_id).filter(|u| ctx.org.member(*u).is_some()) else {
        return Err(BwError::msg("User not found in organization"));
    };
    let Some(mut doc) = ctx.org.member(user).cloned() else {
        return Err(BwError::msg("User not found in organization"));
    };
    if doc.status >= ACCEPTED {
        return Err(BwError::msg("User is already active"));
    }
    if user == ctx.me {
        return Err(BwError::msg("You cannot restore yourself"));
    }
    if doc.atype == OWNER && ctx.doc.atype != OWNER {
        return Err(BwError::msg("Only owners can restore other owners"));
    }
    doc.restore();
    // Checked after the restore, to see the status the member comes back with.
    check_user_allowed(app, &ctx.org, user, &doc, "restore").await?;
    app.put_member(&ctx.org, user, &doc, ctx.me).await?;
    app.touch_quiet(user).await?;
    ctx.log(app, kind::MEMBER_RESTORED, &user.to_string()).await;
    Ok(())
}

/// One line of a bulk answer.
pub(crate) fn bulk_line(object: &str, id: &str, error: &str) -> Value {
    json!({
        "object": object,
        "id": id,
        "error": error,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::orgs::model::MANAGER;

    #[test]
    fn a_custom_member_has_every_collection_only_with_all_three_permissions() {
        let mut permissions: HashMap<String, Value> = HashMap::new();
        assert!(!custom_all(&permissions));
        for key in ["editAnyCollection", "deleteAnyCollection"] {
            permissions.insert(key.to_owned(), json!(true));
        }
        assert!(!custom_all(&permissions));
        permissions.insert("createNewCollections".to_owned(), json!(true));
        assert!(custom_all(&permissions));
        permissions.insert("createNewCollections".to_owned(), json!(false));
        assert!(!custom_all(&permissions));
    }

    #[test]
    fn a_type_is_a_number_or_a_name() {
        assert_eq!(type_text(&json!(2)), "2");
        assert_eq!(type_text(&json!("Admin")), "Admin");
        assert_eq!(parse_type(&type_text(&json!(4))), Some(MANAGER));
    }

    #[test]
    fn an_invitation_has_the_claims_the_accept_route_reads() {
        let claims = InviteClaims {
            nbf: 1,
            exp: 2,
            iss: "https://vault.test|invite".to_owned(),
            sub: "u".to_owned(),
            email: "a@b.cd".to_owned(),
            org_id: "o".to_owned(),
            member_id: "m".to_owned(),
            invited_by_email: None,
        };
        let text = serde_json::to_string(&claims).expect("serialises");
        let back: InviteClaims = serde_json::from_str(&text).expect("parses");
        assert_eq!(back, claims);
    }
}
