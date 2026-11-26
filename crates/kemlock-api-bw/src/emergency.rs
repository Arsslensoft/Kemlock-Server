//! Emergency access, as Vaultwarden 1.37.5's `emergency_access.rs` answers it.
//!
//! A projection of `kemlock_app::emergency`: the grants are the domain's `EmergencyGrant` rows in
//! `emergency_access`, driven through the domain's own transitions (`accept`, `initiate`,
//! `approve_early`, `reject`). Bitwarden's RSA-wrapped `keyEncrypted` is an opaque string; it is
//! kept as its UTF-8 bytes in `sealed_key`, set by hand (the domain's `confirm` checks the length of
//! a `kx1` box). On the wire the domain's `Rejected` is Bitwarden's `Confirmed`, as a refused
//! request in Vaultwarden goes back to `Confirmed`.
//!
//! - An invite stays `Invited` until the contact accepts it, with the link of the mail or from the
//!   Kemlock web vault, whether or not the address has an account (Vaultwarden with mail off would
//!   accept an account that has a password at once; this server asks for the contact's consent).
//!   The domain keeps the address of a contact with no account.
//! - The wait is run out by kemlock-app's `ApproveDue` job (kemlock-server `jobs.rs`); a grant
//!   whose wait has ended is also approved when it is read here, with the same compare-and-set.
//! - The `/password` takeover sets the grantor's password hash and wrapped key, ends their
//!   sessions and two-step logins, and removes them from every organization they don't own.
//! - `/policies` lists the policies of the grantor's organizations.

use crate::account::user_name;
use crate::app::{App, Authed, BwStore, MaybeAuthed};
use crate::cipher::{FOLDER_KIND, StoredCipher};
use crate::env::random_uuid;
use crate::error::{BwError, BwResult};
use crate::password::hash_password;
use crate::routes::{EmptyResult, JsonResult, empty, ok, parse};
use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::routing::{get, post};
use kemlock_app::bitwarden::BwAccountRepo;
use kemlock_app::emergency::{EmergencyEvent, EmergencyNotice, EmergencyRepo};
use kemlock_app::notices::{BwEmergencyInviteNotice, Notice};
use kemlock_app::ports::{
    ChangePage, DeviceRepo, ItemStore, StoreError, TokenRepo, TwoFactorRepo, UserRepo,
};
use kemlock_domain::unlock::{
    EmergencyGrant, EmergencyKind, EmergencyState, GrantId, MAX_WAIT_DAYS, MIN_WAIT_DAYS,
};
use kemlock_domain::{Email, ItemFormat, Owner, UserId, VersionVector};
use serde::Deserialize;
use serde_json::{Value, json};

const NOT_VALID: &str = "Emergency access not valid.";
const OUT_OF_BOUNDS: &str = "Emergency access wait time is out-of-bounds!";
/// Items per page when a vault is read.
const PAGE: u32 = 500;

fn not_valid() -> BwError {
    BwError::msg(NOT_VALID)
}

// --- wire values ----------------------------------------------------------------------------

/// A number or a string, as Vaultwarden's `NumberOrString`.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum NumberOrString {
    Number(i64),
    Text(String),
}

impl NumberOrString {
    fn into_string(self) -> String {
        match self {
            NumberOrString::Number(n) => n.to_string(),
            NumberOrString::Text(s) => s,
        }
    }
}

fn parse_kind(value: NumberOrString) -> BwResult<EmergencyKind> {
    match value.into_string().as_str() {
        "0" | "View" => Ok(EmergencyKind::View),
        "1" | "Takeover" => Ok(EmergencyKind::Takeover),
        _ => Err(BwError::msg("Invalid emergency access type.")),
    }
}

/// A wait in days, checked against Vaultwarden's range before it becomes the domain's.
fn check_days(days: i32) -> BwResult<u32> {
    let in_range =
        i64::from(days) >= i64::from(MIN_WAIT_DAYS) && i64::from(days) <= i64::from(MAX_WAIT_DAYS);
    match u32::try_from(days) {
        Ok(days) if in_range => Ok(days),
        _ => Err(BwError::msg(OUT_OF_BOUNDS)),
    }
}

fn status_of(grant: &EmergencyGrant) -> i32 {
    match grant.state {
        EmergencyState::Invited => 0,
        EmergencyState::Accepted => 1,
        EmergencyState::Confirmed | EmergencyState::Rejected => 2,
        EmergencyState::RecoveryInitiated => 3,
        EmergencyState::Approved => 4,
    }
}

fn type_of(grant: &EmergencyGrant) -> i32 {
    match grant.kind {
        EmergencyKind::View => 0,
        EmergencyKind::Takeover => 1,
    }
}

/// `EmergencyAccess::to_json`.
fn grant_json(grant: &EmergencyGrant) -> Value {
    json!({
        "id": grant.id.to_string(),
        "status": status_of(grant),
        "type": type_of(grant),
        "waitTimeDays": grant.wait_days,
        "object": "emergencyAccess",
    })
}

fn list_json(data: Vec<Value>) -> Value {
    json!({
        "data": data,
        "object": "list",
        "continuationToken": null,
    })
}

/// The wrapped key as text, or null.
fn key_text(grant: &EmergencyGrant) -> Value {
    grant
        .sealed_key
        .as_ref()
        .and_then(|key| String::from_utf8(key.clone()).ok())
        .map_or(Value::Null, Value::String)
}

// --- store helpers --------------------------------------------------------------------------

fn parse_id(text: &str) -> BwResult<GrantId> {
    text.parse::<GrantId>().map_err(|_| BwError::NotFound)
}

/// Moves the account's revision date; a failure is logged, never the caller's, since the other
/// party of a grant may have no Bitwarden record.
async fn touch_quiet<S: BwStore>(app: &App<S>, user: UserId) {
    if let Err(e) = app.touch(user).await {
        tracing::warn!(error = ?e, "couldn't move a revision date");
    }
}

/// Approves a running request whose wait has ended, with a compare-and-set; reads the grant again
/// when the grantor's refusal won the race.
async fn settle<S: BwStore>(app: &App<S>, grant: EmergencyGrant) -> BwResult<EmergencyGrant> {
    let now = app.now();
    if !grant.is_due(now) {
        return Ok(grant);
    }
    let mut next = grant.clone();
    if next.approve_due(now).is_ok()
        && EmergencyRepo::save_grant(&app.store, &next, EmergencyState::RecoveryInitiated).await?
    {
        if let Some(contact) = next.grantee {
            touch_quiet(app, contact).await;
        }
        return Ok(next);
    }
    Ok(EmergencyRepo::grant(&app.store, grant.id)
        .await?
        .unwrap_or(grant))
}

async fn save<S: BwStore>(
    app: &App<S>,
    grant: &EmergencyGrant,
    from: EmergencyState,
) -> BwResult<()> {
    if EmergencyRepo::save_grant(&app.store, grant, from).await? {
        Ok(())
    } else {
        Err(BwError::msg("Emergency access status was changed already"))
    }
}

/// A grant the account made.
async fn owned<S: BwStore>(app: &App<S>, user: UserId, id: &str) -> BwResult<EmergencyGrant> {
    let id = parse_id(id)?;
    match EmergencyRepo::grant(&app.store, id).await? {
        Some(grant) if grant.grantor == user => settle(app, grant).await,
        _ => Err(not_valid()),
    }
}

/// A grant that names the account as its contact, once they have accepted.
async fn addressed<S: BwStore>(app: &App<S>, user: UserId, id: &str) -> BwResult<EmergencyGrant> {
    let id = parse_id(id)?;
    match EmergencyRepo::grant(&app.store, id).await? {
        Some(grant) if grant.grantee == Some(user) => settle(app, grant).await,
        _ => Err(not_valid()),
    }
}

/// `is_valid_request`: approved, for this contact, of the kind asked for.
fn valid_request(grant: &EmergencyGrant, user: UserId, kind: EmergencyKind) -> bool {
    grant.grantee == Some(user) && grant.state == EmergencyState::Approved && grant.kind == kind
}

async fn avatar_color<S: BwStore>(app: &App<S>, user: UserId) -> BwResult<Value> {
    Ok(BwAccountRepo::get(&app.store, user)
        .await?
        .and_then(|a| a.avatar_color)
        .map_or(Value::Null, Value::String))
}

/// `to_json_grantee_details`: the contact as the grantor sees them. A contact with no account yet
/// is shown by the address and the grant's id.
async fn grantee_details<S: BwStore>(app: &App<S>, grant: &EmergencyGrant) -> BwResult<Value> {
    let contact = match grant.grantee {
        Some(id) => UserRepo::by_id(&app.store, id).await?,
        None => UserRepo::by_email(&app.store, &grant.grantee_email).await?,
    };
    let (id, email, name, color) = match contact {
        Some(user) => {
            let color = avatar_color(app, user.id).await?;
            (
                user.id.to_string(),
                user.email.as_str().to_owned(),
                user_name(&user),
                color,
            )
        }
        None => (
            grant.id.to_string(),
            grant.grantee_email.as_str().to_owned(),
            grant.grantee_email.as_str().to_owned(),
            Value::Null,
        ),
    };
    Ok(json!({
        "id": grant.id.to_string(),
        "status": status_of(grant),
        "type": type_of(grant),
        "waitTimeDays": grant.wait_days,
        "granteeId": id,
        "email": email,
        "name": name,
        "avatarColor": color,
        "object": "emergencyAccessGranteeDetails",
    }))
}

/// `to_json_grantor_details`.
async fn grantor_details<S: BwStore>(app: &App<S>, grant: &EmergencyGrant) -> BwResult<Value> {
    let grantor = UserRepo::by_id(&app.store, grant.grantor)
        .await?
        .ok_or_else(|| BwError::Server("a grant has no grantor".to_owned()))?;
    let color = avatar_color(app, grantor.id).await?;
    Ok(json!({
        "id": grant.id.to_string(),
        "status": status_of(grant),
        "type": type_of(grant),
        "waitTimeDays": grant.wait_days,
        "grantorId": grantor.id.to_string(),
        "email": grantor.email.as_str(),
        "name": user_name(&grantor),
        "avatarColor": color,
        "object": "emergencyAccessGrantorDetails",
    }))
}

// --- lists and reads ------------------------------------------------------------------------

async fn contacts<S: BwStore>(State(app): State<App<S>>, authed: Authed) -> JsonResult {
    let mut out = Vec::new();
    for grant in EmergencyRepo::grants_of_grantor(&app.store, authed.user.id).await? {
        let grant = settle(&app, grant).await?;
        out.push(grantee_details(&app, &grant).await?);
    }
    ok(list_json(out))
}

async fn grantees<S: BwStore>(State(app): State<App<S>>, authed: Authed) -> JsonResult {
    let mut out = Vec::new();
    for grant in EmergencyRepo::grants_for_email(&app.store, &authed.user.email).await? {
        if grant.grantee != Some(authed.user.id) {
            continue;
        }
        let grant = settle(&app, grant).await?;
        out.push(grantor_details(&app, &grant).await?);
    }
    ok(list_json(out))
}

async fn get_one<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path(id): Path<String>,
) -> JsonResult {
    let grant = owned(&app, authed.user.id, &id).await?;
    ok(grantee_details(&app, &grant).await?)
}

// --- update and delete ----------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateData {
    r#type: NumberOrString,
    wait_time_days: i32,
    key_encrypted: Option<String>,
}

async fn update<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path(id): Path<String>,
    body: Bytes,
) -> JsonResult {
    let data: UpdateData = parse(&body)?;
    let kind = parse_kind(data.r#type)?;
    let days = check_days(data.wait_time_days)?;
    let mut grant = owned(&app, authed.user.id, &id).await?;
    grant.kind = kind;
    grant.wait_days = days;
    if let Some(key) = data.key_encrypted {
        grant.sealed_key = Some(key.into_bytes());
    }
    grant.updated_at = app.now();
    // `save_grant` writes only what a step changes; the kind and the wait are the grant's, so the
    // row is written again whole.
    EmergencyRepo::remove_grant(&app.store, grant.id).await?;
    EmergencyRepo::insert_grant(&app.store, &grant).await?;
    touch_quiet(&app, authed.user.id).await;
    ok(grant_json(&grant))
}

async fn delete_one<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path(id): Path<String>,
) -> EmptyResult {
    let id = parse_id(&id)?;
    let Some(grant) = EmergencyRepo::grant(&app.store, id).await? else {
        return Err(not_valid());
    };
    let user = authed.user.id;
    let as_grantor = grant.grantor == user;
    let as_grantee = grant.grantee == Some(user);
    if as_grantor == as_grantee {
        return Err(not_valid());
    }
    EmergencyRepo::remove_grant(&app.store, grant.id).await?;
    touch_quiet(&app, user).await;
    Ok(axum::http::StatusCode::OK)
}

// --- invite, accept, confirm ----------------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct InviteData {
    email: String,
    r#type: NumberOrString,
    wait_time_days: i32,
}

async fn invite_impl<S: BwStore>(app: &App<S>, authed: &Authed, data: InviteData) -> BwResult<()> {
    let email = data.email.to_lowercase();
    let days = check_days(data.wait_time_days)?;
    let kind = parse_kind(data.r#type)?;
    if email == authed.user.email.as_str() {
        return Err(BwError::msg(
            "You can not set yourself as an emergency contact.",
        ));
    }
    let contact = Email::parse(&email).map_err(|_| {
        BwError::msg(format!(
            "User email {} is not a valid email address",
            email.escape_debug()
        ))
    })?;
    let existing = UserRepo::by_email(&app.store, &contact).await?;
    let mine = EmergencyRepo::grants_of_grantor(&app.store, authed.user.id).await?;
    let taken = mine.iter().any(|g| {
        g.grantee_email == contact
            || existing
                .as_ref()
                .is_some_and(|user| g.grantee == Some(user.id))
    });
    if taken {
        return Err(BwError::msg(format!(
            "Grantee user already invited: {email}"
        )));
    }

    let now = app.now();
    let grant = EmergencyGrant::invite(
        GrantId(random_uuid(app.env.as_ref())),
        authed.user.id,
        contact,
        kind,
        days,
        now,
    )
    .map_err(|_| BwError::msg(OUT_OF_BOUNDS))?;
    match EmergencyRepo::insert_grant(&app.store, &grant).await {
        Ok(()) => {}
        Err(StoreError::Duplicate) => {
            return Err(BwError::msg(format!(
                "Grantee user already invited: {email}"
            )));
        }
        Err(e) => return Err(e.into()),
    }
    // The contact accepts for themselves, from the Kemlock web vault or with the link of the
    // mail, so nobody is made a grantee of someone who named them. (An operator who asked for
    // Vaultwarden's mail-off behaviour has an existing account accepted at once.)
    if let Some(user) = &existing {
        if crate::orgs::members::auto_accepts(app, user.id).await? {
            let mut accepted = grant.clone();
            accepted.accept(user.id, now).map_err(|_| not_valid())?;
            save(app, &accepted, EmergencyState::Invited).await?;
        }
        touch_quiet(app, user.id).await;
    }
    notify_contact(app, &grant).await;
    touch_quiet(app, authed.user.id).await;
    Ok(())
}

/// The signed token of an invitation to be an emergency contact and the link that carries it, in
/// the shape Vaultwarden's mail has (`/#/accept-emergency/?id=...&token=...`). Accepting needs the
/// token and nothing else, so the link is a secret.
async fn invite_link<S: BwStore>(
    app: &App<S>,
    grant: &EmergencyGrant,
) -> BwResult<(String, String)> {
    let Some(grantor) = UserRepo::by_id(&app.store, grant.grantor).await? else {
        return Err(BwError::msg("Grantor user not found."));
    };
    let now = app.now_secs();
    let name = user_name(&grantor);
    let token = app
        .keys
        .encode(&json!({
            "nbf": now,
            "exp": now + 5 * 24 * 3600,
            "iss": app.settings.issuer("emergencyaccessinvite"),
            "sub": grant.id.to_string(),
            "email": grant.grantee_email.as_str(),
            "emer_id": grant.id.to_string(),
            "grantor_name": name,
            "grantor_email": grantor.email.as_str(),
        }))
        .map_err(|e| BwError::Server(e.to_string()))?;
    let encoded =
        |text: &str| -> String { url::form_urlencoded::byte_serialize(text.as_bytes()).collect() };
    let link = format!(
        "{}/#/accept-emergency/?id={}&name={}&email={}&token={}",
        app.host(),
        grant.id,
        encoded(&name),
        encoded(grant.grantee_email.as_str()),
        token
    );
    Ok((token, link))
}

/// Mails the contact that someone named them, when the server mails. A contact who can sign in to
/// the web vault is sent the Kemlock notice; any other, the link that carries the token, which
/// accepts by itself.
async fn notify_contact<S: BwStore>(app: &App<S>, grant: &EmergencyGrant) {
    if !app.notices.mails() {
        return;
    }
    let contact = match UserRepo::by_email(&app.store, &grant.grantee_email).await {
        Ok(contact) => contact,
        Err(error) => {
            tracing::warn!(?error, "couldn't read an emergency contact");
            return;
        }
    };
    if contact.is_some_and(|c| c.opaque_record.is_some()) {
        app.notices
            .send(Notice::Emergency(EmergencyNotice {
                to: grant.grantee_email.clone(),
                grant: grant.id,
                event: EmergencyEvent::Invited,
                kind: grant.kind,
                wait_days: grant.wait_days,
            }))
            .await;
        return;
    }
    let grantor = match UserRepo::by_id(&app.store, grant.grantor).await {
        Ok(Some(grantor)) => user_name(&grantor),
        _ => return,
    };
    match invite_link(app, grant).await {
        Ok((_, link)) => {
            app.notices
                .send(Notice::BwEmergencyInvite(BwEmergencyInviteNotice {
                    to: grant.grantee_email.clone(),
                    grantor,
                    link,
                }))
                .await;
        }
        Err(error) => tracing::warn!(?error, "couldn't make an emergency invitation link"),
    }
}

/// `GET /api/emergency-access/{id}/invite-link` (not Vaultwarden's): the link of a pending
/// invitation, for the grantor of a server that doesn't mail to hand over themselves.
async fn invite_link_route<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path(id): Path<String>,
) -> JsonResult {
    let grant = owned(&app, authed.user.id, &id).await?;
    if grant.state != EmergencyState::Invited {
        return Err(BwError::msg(
            "The grantee user is already accepted or confirmed for emergency access",
        ));
    }
    let (token, link) = invite_link(&app, &grant).await?;
    ok(json!({"object": "inviteLink", "link": link, "token": token}))
}

async fn send_invite<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    body: Bytes,
) -> EmptyResult {
    let data: InviteData = parse(&body)?;
    empty(invite_impl(&app, &authed, data).await)
}

async fn resend_invite<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path(id): Path<String>,
) -> EmptyResult {
    let grant = owned(&app, authed.user.id, &id).await?;
    if grant.state != EmergencyState::Invited {
        return Err(BwError::msg(
            "The grantee user is already accepted or confirmed for emergency access",
        ));
    }
    // The grantee accepts for themselves; a resend only mails them again, when the server mails.
    // (An operator who asked for Vaultwarden's mail-off behaviour has an existing account accepted.)
    if let Some(contact) = UserRepo::by_email(&app.store, &grant.grantee_email).await?
        && crate::orgs::members::auto_accepts(&app, contact.id).await?
    {
        let mut next = grant.clone();
        next.accept(contact.id, app.now())
            .map_err(|_| not_valid())?;
        save(&app, &next, EmergencyState::Invited).await?;
        touch_quiet(&app, contact.id).await;
        return Ok(axum::http::StatusCode::OK);
    }
    notify_contact(&app, &grant).await;
    Ok(axum::http::StatusCode::OK)
}

#[derive(Deserialize)]
struct AcceptData {
    token: String,
}

/// The claims of an emergency-access invitation link, as Vaultwarden's
/// `EmergencyAccessInviteJwtClaims`.
#[derive(Debug, Deserialize)]
struct InviteClaims {
    email: String,
    emer_id: String,
    grantor_name: String,
    grantor_email: String,
}

/// `POST /api/emergency-access/{id}/accept`. The token of the link is the proof: a caller who
/// signed in must be the contact it was made for, and one who didn't is the account of that address.
async fn accept_invite<S: BwStore>(
    State(app): State<App<S>>,
    MaybeAuthed(authed): MaybeAuthed,
    Path(id): Path<String>,
    body: Bytes,
) -> EmptyResult {
    let data: AcceptData = parse(&body)?;
    let claims: InviteClaims = app
        .keys
        .decode(
            &data.token,
            &app.settings.issuer("emergencyaccessinvite"),
            app.now_secs(),
        )
        .map_err(|e| BwError::msg(e.to_string()))?;
    let signed_in;
    let me = match authed {
        Some(authed) => {
            signed_in = authed.user;
            &signed_in
        }
        None => {
            let by_address = match Email::parse(&claims.email) {
                Ok(email) => UserRepo::by_email(&app.store, &email).await?,
                Err(_) => None,
            };
            let Some(account) = by_address else {
                return Err(BwError::msg(
                    "Create an account with the address the invitation was sent to, then open the link again",
                ));
            };
            signed_in = account;
            &signed_in
        }
    };
    if claims.email != me.email.as_str() {
        return Err(BwError::msg(
            "Claim email does not match current users email",
        ));
    }
    let id = parse_id(&id)?;
    let Some(mut grant) = EmergencyRepo::grant(&app.store, id).await? else {
        return Err(not_valid());
    };
    if grant.grantee_email != me.email || grant.state != EmergencyState::Invited {
        return Err(not_valid());
    }
    let Some(grantor) = UserRepo::by_id(&app.store, grant.grantor).await? else {
        return Err(BwError::msg("Grantor user not found."));
    };
    if claims.emer_id.eq_ignore_ascii_case(&grant.id.to_string())
        && user_name(&grantor) == claims.grantor_name
        && grantor.email.as_str() == claims.grantor_email
    {
        grant.accept(me.id, app.now()).map_err(|_| not_valid())?;
        save(&app, &grant, EmergencyState::Invited).await?;
        touch_quiet(&app, grantor.id).await;
        Ok(axum::http::StatusCode::OK)
    } else {
        Err(BwError::msg("Emergency access invitation error."))
    }
}

#[derive(Deserialize)]
struct ConfirmData {
    key: String,
}

async fn confirm<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path(id): Path<String>,
    body: Bytes,
) -> JsonResult {
    let data: ConfirmData = parse(&body)?;
    let mut grant = owned(&app, authed.user.id, &id).await?;
    if grant.state != EmergencyState::Accepted {
        return Err(not_valid());
    }
    let Some(contact) = grant.grantee else {
        return Err(BwError::msg("Grantee user not found."));
    };
    if UserRepo::by_id(&app.store, contact).await?.is_none() {
        return Err(BwError::msg("Grantee user not found."));
    }
    // Set by hand: the domain's `confirm` expects a `kx1` box, and this key is Bitwarden's RSA text.
    grant.state = EmergencyState::Confirmed;
    grant.sealed_key = Some(data.key.into_bytes());
    grant.updated_at = app.now();
    save(&app, &grant, EmergencyState::Accepted).await?;
    touch_quiet(&app, contact).await;
    touch_quiet(&app, authed.user.id).await;
    ok(grant_json(&grant))
}

// --- the request: initiate, approve, reject -------------------------------------------------

async fn initiate<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path(id): Path<String>,
) -> JsonResult {
    let mut grant = addressed(&app, authed.user.id, &id).await?;
    if !matches!(
        grant.state,
        EmergencyState::Confirmed | EmergencyState::Rejected
    ) {
        return Err(not_valid());
    }
    if UserRepo::by_id(&app.store, grant.grantor).await?.is_none() {
        return Err(BwError::msg("Grantor user not found."));
    }
    let from = grant.state;
    grant.initiate(app.now()).map_err(|_| not_valid())?;
    save(&app, &grant, from).await?;
    touch_quiet(&app, grant.grantor).await;
    ok(grant_json(&grant))
}

async fn approve<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path(id): Path<String>,
) -> JsonResult {
    let mut grant = owned(&app, authed.user.id, &id).await?;
    if grant.state != EmergencyState::RecoveryInitiated {
        return Err(not_valid());
    }
    let Some(contact) = grant.grantee else {
        return Err(BwError::msg("Grantee user not found."));
    };
    grant.approve_early(app.now()).map_err(|_| not_valid())?;
    save(&app, &grant, EmergencyState::RecoveryInitiated).await?;
    touch_quiet(&app, contact).await;
    ok(grant_json(&grant))
}

async fn reject<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path(id): Path<String>,
) -> JsonResult {
    let mut grant = owned(&app, authed.user.id, &id).await?;
    if !matches!(
        grant.state,
        EmergencyState::RecoveryInitiated | EmergencyState::Approved
    ) {
        return Err(not_valid());
    }
    let Some(contact) = grant.grantee else {
        return Err(BwError::msg("Grantee user not found."));
    };
    let from = grant.state;
    grant.reject(app.now()).map_err(|_| not_valid())?;
    save(&app, &grant, from).await?;
    touch_quiet(&app, contact).await;
    ok(grant_json(&grant))
}

// --- the grantee's access: view, takeover, password, policies -------------------------------

/// The grantor's own ciphers as clients read them (`Cipher::find_owned_by_user`).
async fn owned_ciphers<S: BwStore>(app: &App<S>, user: UserId) -> BwResult<Vec<Value>> {
    let owners = [Owner::User(user)];
    let mut since = VersionVector::new();
    let mut out = Vec::new();
    loop {
        let ChangePage { items, next, more } =
            ItemStore::changes_since(&app.store, &owners, &since, PAGE).await?;
        for item in items {
            let live = item.owner == Owner::User(user)
                && item.format == ItemFormat::Bw
                && !item.is_tombstone()
                && item.kind.as_str() != FOLDER_KIND;
            if !live {
                continue;
            }
            let cipher: Option<StoredCipher> = item
                .ciphertext
                .as_deref()
                .and_then(|bytes| serde_json::from_slice(bytes).ok());
            match cipher {
                Some(cipher) => out.push(app.cipher_to_json(&cipher)?),
                None => tracing::warn!("leaving a damaged cipher out of an emergency view"),
            }
        }
        if !more {
            return Ok(out);
        }
        since = next;
    }
}

async fn view<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path(id): Path<String>,
) -> JsonResult {
    let grant = addressed(&app, authed.user.id, &id).await?;
    if !valid_request(&grant, authed.user.id, EmergencyKind::View) {
        return Err(not_valid());
    }
    let ciphers = owned_ciphers(&app, grant.grantor).await?;
    ok(json!({
        "ciphers": ciphers,
        "keyEncrypted": key_text(&grant),
        "object": "emergencyAccessView",
    }))
}

async fn takeover<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path(id): Path<String>,
) -> JsonResult {
    let grant = addressed(&app, authed.user.id, &id).await?;
    if !valid_request(&grant, authed.user.id, EmergencyKind::Takeover) {
        return Err(not_valid());
    }
    let Some(grantor) = UserRepo::by_id(&app.store, grant.grantor).await? else {
        return Err(BwError::msg("Grantor user not found."));
    };
    let account = BwAccountRepo::get(&app.store, grantor.id)
        .await?
        .ok_or_else(|| BwError::msg("Grantor user not found."))?;
    ok(json!({
        "kdf": account.kdf_type,
        "kdfIterations": account.kdf_iterations,
        "kdfMemory": account.kdf_memory,
        "kdfParallelism": account.kdf_parallelism,
        "keyEncrypted": key_text(&grant),
        "salt": grantor.email.as_str().trim().to_lowercase(),
        "object": "emergencyAccessTakeover",
    }))
}

/// The client's KDF settings in a takeover request, under either set of names.
#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct KdfData {
    #[serde(alias = "kdfType")]
    kdf: i32,
    #[serde(alias = "iterations")]
    kdf_iterations: i32,
    #[serde(alias = "memory")]
    kdf_memory: Option<i32>,
    #[serde(alias = "parallelism")]
    kdf_parallelism: Option<i32>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AuthenticationData {
    #[serde(alias = "Salt")]
    salt: String,
    #[serde(alias = "Kdf")]
    kdf: KdfData,
    #[serde(alias = "MasterPasswordAuthenticationHash")]
    master_password_authentication_hash: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UnlockData {
    salt: String,
    kdf: KdfData,
    master_key_wrapped_user_key: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PasswordData {
    // The legacy payload.
    new_master_password_hash: Option<String>,
    key: Option<String>,
    // The current one.
    authentication_data: Option<AuthenticationData>,
    unlock_data: Option<UnlockData>,
}

async fn password<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path(id): Path<String>,
    body: Bytes,
) -> EmptyResult {
    let data: PasswordData = parse(&body)?;
    let grant = addressed(&app, authed.user.id, &id).await?;
    if !valid_request(&grant, authed.user.id, EmergencyKind::Takeover) {
        return Err(not_valid());
    }
    let Some(mut grantor) = UserRepo::by_id(&app.store, grant.grantor).await? else {
        return Err(BwError::msg("Grantor user not found."));
    };
    let mut account = BwAccountRepo::get(&app.store, grantor.id)
        .await?
        .ok_or_else(|| BwError::msg("Grantor user not found."))?;

    let (new_hash, new_key) = match (
        data.authentication_data,
        data.unlock_data,
        data.new_master_password_hash,
        data.key,
    ) {
        (Some(authentication), Some(unlock), _, _) => {
            if authentication.kdf != unlock.kdf {
                return Err(BwError::msg(
                    "KDF settings must be equal for authentication and unlock",
                ));
            }
            let salt = grantor.email.as_str().trim().to_lowercase();
            if authentication.salt != salt || salt != unlock.salt {
                return Err(BwError::msg("Invalid master password salt"));
            }
            let kdf = &authentication.kdf;
            let matches = kdf.kdf == account.kdf_type
                && kdf.kdf_iterations == account.kdf_iterations
                && kdf.kdf_memory == account.kdf_memory
                && kdf.kdf_parallelism == account.kdf_parallelism;
            if !matches {
                return Err(BwError::msg(
                    "KDF settings do not match the grantor account",
                ));
            }
            (
                authentication.master_password_authentication_hash,
                unlock.master_key_wrapped_user_key,
            )
        }
        (_, _, Some(hash), Some(key)) => (hash, key),
        _ => return Err(BwError::msg("Invalid request!")),
    };

    // The grantor's new password and key, and an end to every session they had.
    account.password_hash = hash_password(
        new_hash.as_bytes(),
        &account.salt,
        account.password_iterations,
    );
    account.akey = new_key;
    BwAccountRepo::update(&app.store, &account).await?;
    grantor.security_stamp = random_uuid(app.env.as_ref());
    grantor.updated_at = app.now();
    UserRepo::update(&app.store, &grantor).await?;
    for device in DeviceRepo::list(&app.store, grantor.id).await? {
        TokenRepo::revoke_device(&app.store, device.id).await?;
    }
    // Two-step providers would block the sign-in the contact is about to make.
    for enrolment in TwoFactorRepo::list(&app.store, grantor.id).await? {
        TwoFactorRepo::remove(&app.store, grantor.id, enrolment.method).await?;
    }
    // The grantor leaves every organization they don.t own.
    crate::orgs::leave_unowned(&app, grantor.id).await?;
    app.touch(grantor.id).await?;
    Ok(axum::http::StatusCode::OK)
}

async fn policies<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path(id): Path<String>,
) -> JsonResult {
    let grant = addressed(&app, authed.user.id, &id).await?;
    if !valid_request(&grant, authed.user.id, EmergencyKind::Takeover) {
        return Err(not_valid());
    }
    if UserRepo::by_id(&app.store, grant.grantor).await?.is_none() {
        return Err(BwError::msg("Grantor user not found."));
    }
    let policies = crate::orgs::policy::policies_json(&app, grant.grantor, false).await?;
    ok(list_json(policies))
}

/// The routes, under `/api/emergency-access`.
pub(crate) fn routes<S: BwStore>() -> Router<App<S>> {
    Router::new()
        .route("/api/emergency-access/trusted", get(contacts::<S>))
        .route("/api/emergency-access/granted", get(grantees::<S>))
        .route("/api/emergency-access/invite", post(send_invite::<S>))
        .route(
            "/api/emergency-access/{id}",
            get(get_one::<S>)
                .put(update::<S>)
                .post(update::<S>)
                .delete(delete_one::<S>),
        )
        .route("/api/emergency-access/{id}/delete", post(delete_one::<S>))
        .route(
            "/api/emergency-access/{id}/reinvite",
            post(resend_invite::<S>),
        )
        .route(
            "/api/emergency-access/{id}/accept",
            post(accept_invite::<S>),
        )
        .route(
            "/api/emergency-access/{id}/invite-link",
            get(invite_link_route::<S>),
        )
        .route("/api/emergency-access/{id}/confirm", post(confirm::<S>))
        .route("/api/emergency-access/{id}/initiate", post(initiate::<S>))
        .route("/api/emergency-access/{id}/approve", post(approve::<S>))
        .route("/api/emergency-access/{id}/reject", post(reject::<S>))
        .route("/api/emergency-access/{id}/view", post(view::<S>))
        .route("/api/emergency-access/{id}/takeover", post(takeover::<S>))
        .route("/api/emergency-access/{id}/password", post(password::<S>))
        .route("/api/emergency-access/{id}/policies", get(policies::<S>))
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::OffsetDateTime;

    #[test]
    fn types_and_waits_are_checked_as_vaultwarden_does() {
        assert!(matches!(
            parse_kind(NumberOrString::Number(0)),
            Ok(EmergencyKind::View)
        ));
        assert!(matches!(
            parse_kind(NumberOrString::Text("Takeover".to_owned())),
            Ok(EmergencyKind::Takeover)
        ));
        assert!(parse_kind(NumberOrString::Number(2)).is_err());
        assert_eq!(check_days(1).ok(), Some(1));
        assert_eq!(check_days(90).ok(), Some(90));
        assert!(check_days(0).is_err());
        assert!(check_days(91).is_err());
        assert!(check_days(-3).is_err());
    }

    #[test]
    fn a_rejected_request_reads_as_confirmed() {
        let mut grant = EmergencyGrant::invite(
            GrantId::random(),
            UserId::random(),
            Email::parse("a@example.com").expect("an email"),
            EmergencyKind::View,
            7,
            OffsetDateTime::UNIX_EPOCH,
        )
        .expect("a grant");
        assert_eq!(status_of(&grant), 0);
        grant.state = EmergencyState::Rejected;
        assert_eq!(status_of(&grant), 2);
        grant.state = EmergencyState::Approved;
        assert_eq!(status_of(&grant), 4);
        assert_eq!(grant_json(&grant)["object"], "emergencyAccess");
    }
}
