//! Events: what clients report to `POST /events/collect`, what organization actions record, and
//! the event lists of `/api`.
//!
//! Events are stored through the `EventLog` port as rows with the action `bw.event` and a JSON
//! `target` that holds what Vaultwarden's `event` table has columns for (the event type, the
//! cipher, collection, group, member or policy it is about, the organization, the device type,
//! the address). The row's actor is the account that acted. They are read back through the
//! `EventReader` port, which matches text in the target.
//!
//! Where this departs from Vaultwarden 1.37.5, on purpose:
//!
//! - `POST /events/collect` stores the events a client may report (a vault export, a banner click,
//!   a cipher viewed or copied) whether or not `ORG_EVENTS_ENABLED` is on; Vaultwarden drops them
//!   when it is off. The checks on who may report what are Vaultwarden's, over spaces: an
//!   organization event needs a confirmed membership, a cipher event a cipher of a space the
//!   account is confirmed in.
//! - An address is stored cut to its /24 or /48 (the design's privacy rule), so `ipAddress` in an
//!   event reads `203.0.113.0/24` where Vaultwarden shows the whole address.
//! - [`log_event`], which the organization code calls as Vaultwarden's `log_event`, waits for
//!   `org_events_enabled`, as Vaultwarden's does; the three event lists answer an empty page while
//!   it is off.

use crate::app::{App, Authed, BwStore};
use crate::dates::{format_date, parse_date};
use crate::error::{BwError, BwResult};
use crate::routes::{EmptyResult, JsonResult, Peer, empty, ok, parse};
use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::routing::{get, post};
use kemlock_app::event_reader::{EventMatch, EventQuery, EventReader, StoredEvent};
use kemlock_app::ports::{Event, EventLog, ItemStore};
use kemlock_app::spaces::SpaceRepo;
use kemlock_domain::spaces::SpaceRole;
use kemlock_domain::unlock::truncate_ip;
use kemlock_domain::{DeviceKind, ItemId, Owner, SpaceId, UserId};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::net::IpAddr;
use time::OffsetDateTime;
use uuid::Uuid;

/// The action every stored client event has.
const ACTION: &str = "bw.event";

/// `EventType::UserClientExportedVault`.
const USER_EXPORTED_VAULT: i32 = 1007;
/// `EventType::OrganizationUserNotificationBannerActionClicked`.
const BANNER_CLICKED: i32 = 1522;
/// `EventType::OrganizationClientExportedVault`.
const ORG_EXPORTED_VAULT: i32 = 1602;

/// Which of Vaultwarden's event columns a source id belongs in, by the type's range.
fn source_key(event_type: i32) -> Option<&'static str> {
    match event_type {
        1100..=1199 => Some("cipherId"),
        1300..=1399 => Some("collectionId"),
        1400..=1499 => Some("groupId"),
        1500..=1599 => Some("organizationUserId"),
        1700..=1799 => Some("policyId"),
        _ => None,
    }
}

/// The client event types a cipher can be the subject of: viewed, copied, toggled, autofilled.
fn is_cipher_event(event_type: i32) -> bool {
    matches!(event_type, 1107..=1114 | 1117 | 1119..=1133)
}

/// The JSON kept in an event's `target`.
fn target_json(
    event_type: i32,
    source: Option<&str>,
    org: Option<Uuid>,
    device_type: Option<i32>,
    ip: IpAddr,
) -> String {
    let mut target = json!({
        "type": event_type,
        "organizationId": org.map(|o| o.to_string()),
        "deviceType": device_type,
        "ipAddress": truncate_ip(ip),
    });
    if let (Some(key), Some(source)) = (source_key(event_type), source) {
        target[key] = Value::String(source.to_owned());
    }
    target.to_string()
}

async fn record<S: BwStore>(
    app: &App<S>,
    actor: UserId,
    at: OffsetDateTime,
    target: String,
) -> BwResult<()> {
    let event = Event {
        actor: Some(actor),
        device: None,
        action: ACTION,
        target: Some(target),
        at,
    };
    EventLog::record(&app.store, event).await?;
    Ok(())
}

/// Who did something and from where: what an event records of its maker.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Acting {
    pub user: UserId,
    /// Bitwarden's device type number.
    pub device_type: i32,
    pub ip: IpAddr,
}

impl Acting {
    pub(crate) fn of(authed: &Authed) -> Self {
        Acting {
            user: authed.user.id,
            device_type: device_type_of(authed.device.kind),
            ip: authed.ip,
        }
    }
}

/// The device type a device's kind says: the type isn't kept, so the kind stands for it (as the
/// token's `devicetype` does for a refreshed sign-in).
fn device_type_of(device: DeviceKind) -> i32 {
    match device {
        DeviceKind::KemlockAndroid => 0,
        DeviceKind::KemlockIos => 1,
        DeviceKind::KemlockCli => 25,
        DeviceKind::Amethystora => 8,
        _ => 14,
    }
}

/// Vaultwarden's `EventType` numbers for what the organization code logs.
pub(crate) mod kind {
    pub(crate) const CIPHER_CREATED: i32 = 1100;
    pub(crate) const CIPHER_UPDATED: i32 = 1101;
    pub(crate) const CIPHER_DELETED: i32 = 1102;
    pub(crate) const CIPHER_ATTACHMENT_CREATED: i32 = 1103;
    pub(crate) const CIPHER_ATTACHMENT_DELETED: i32 = 1104;
    pub(crate) const CIPHER_SHARED: i32 = 1105;
    pub(crate) const CIPHER_UPDATED_COLLECTIONS: i32 = 1106;
    pub(crate) const CIPHER_SOFT_DELETED: i32 = 1115;
    pub(crate) const CIPHER_RESTORED: i32 = 1116;
    pub(crate) const COLLECTION_CREATED: i32 = 1300;
    pub(crate) const COLLECTION_UPDATED: i32 = 1301;
    pub(crate) const COLLECTION_DELETED: i32 = 1302;
    pub(crate) const GROUP_CREATED: i32 = 1400;
    pub(crate) const GROUP_UPDATED: i32 = 1401;
    pub(crate) const GROUP_DELETED: i32 = 1402;
    pub(crate) const MEMBER_INVITED: i32 = 1500;
    pub(crate) const MEMBER_CONFIRMED: i32 = 1501;
    pub(crate) const MEMBER_UPDATED: i32 = 1502;
    pub(crate) const MEMBER_REMOVED: i32 = 1503;
    pub(crate) const MEMBER_UPDATED_GROUPS: i32 = 1504;
    pub(crate) const MEMBER_RESET_PASSWORD_ENROLLED: i32 = 1506;
    pub(crate) const MEMBER_RESET_PASSWORD_WITHDRAWN: i32 = 1507;
    pub(crate) const MEMBER_ADMIN_RESET_PASSWORD: i32 = 1508;
    pub(crate) const MEMBER_REVOKED: i32 = 1511;
    pub(crate) const MEMBER_RESTORED: i32 = 1512;
    pub(crate) const MEMBER_LEFT: i32 = 1516;
    pub(crate) const MEMBER_ADMIN_RESET_TWO_FACTOR: i32 = 1519;
    pub(crate) const MEMBER_REVOKED_SINGLE_ORG: i32 = 1521;
    pub(crate) const ORGANIZATION_UPDATED: i32 = 1600;
    pub(crate) const POLICY_UPDATED: i32 = 1700;
    /// `EventType::UserRecovered2fa`: the recovery code switched the account's two-step login off.
    /// Vaultwarden's 1005 is `UserFailedLogIn`, which is what a client shows for that number.
    pub(crate) const USER_RECOVERED_2FA: i32 = 1004;
}

/// Vaultwarden's `log_event`: an organization event made by the server, logged only when
/// organization events are on. `source_uuid` is the cipher, collection, group, member or policy it
/// is about, by the event type's range. A failure to record is logged, never the request's.
pub(crate) async fn log_event<S: BwStore>(
    app: &App<S>,
    event_type: i32,
    source_uuid: &str,
    org_id: Uuid,
    acting: &Acting,
) {
    if !app.settings.org_events_enabled {
        return;
    }
    let target = target_json(
        event_type,
        Some(source_uuid),
        Some(org_id),
        Some(acting.device_type),
        acting.ip,
    );
    if let Err(e) = record(app, acting.user, app.now(), target).await {
        tracing::warn!(error = ?e, "couldn't record an event");
    }
}

/// Vaultwarden's `log_user_event`: an event about the account itself, made by the server, logged only
/// when organization events are on. A failure to record is logged, never the request's.
pub(crate) async fn log_user_event<S: BwStore>(app: &App<S>, event_type: i32, acting: &Acting) {
    if !app.settings.org_events_enabled {
        return;
    }
    let target = target_json(event_type, None, None, Some(acting.device_type), acting.ip);
    if let Err(e) = record(app, acting.user, app.now(), target).await {
        tracing::warn!(error = ?e, "couldn't record an event");
    }
}

// --- POST /events/collect -------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EventCollection {
    r#type: i32,
    date: String,
    cipher_id: Option<String>,
    organization_id: Option<String>,
}

/// Whether the account is a confirmed member of the space.
async fn confirmed_in<S: BwStore>(app: &App<S>, user: UserId, space: Uuid) -> BwResult<bool> {
    Ok(SpaceRepo::memberships(&app.store, user)
        .await?
        .iter()
        .any(|m| m.space == SpaceId(space) && m.is_confirmed()))
}

/// Whether the account is a confirmed member of the space who may see the item: an owner or admin,
/// or one with a grant on the item's collection (directly or through a group).
async fn can_see<S: BwStore>(
    app: &App<S>,
    user: UserId,
    space: SpaceId,
    item: ItemId,
) -> BwResult<bool> {
    let Some(state) = SpaceRepo::load(&app.store, space).await? else {
        return Ok(false);
    };
    let Some(me) = state.member(user).filter(|m| m.is_confirmed()) else {
        return Ok(false);
    };
    if matches!(me.role, SpaceRole::Owner | SpaceRole::Admin) {
        return Ok(true);
    }
    let Some((_, collection)) = SpaceRepo::item_collections(&app.store, &[item])
        .await?
        .into_iter()
        .next()
    else {
        return Ok(false);
    };
    Ok(state.access(user, collection).is_some())
}

/// How far back a cipher event may be dated (a client keeps events while it is offline), and how far
/// ahead (a clock that runs fast). Anything else is not an event of now.
const EVENT_AGE: time::Duration = time::Duration::days(7);
const EVENT_AHEAD: time::Duration = time::Duration::minutes(5);

/// Whether an event dated `at` is one of now (`now`).
fn near_now(at: OffsetDateTime, now: OffsetDateTime) -> bool {
    at >= now - EVENT_AGE && at <= now + EVENT_AHEAD
}

async fn collect_one<S: BwStore>(
    app: &App<S>,
    user: UserId,
    ip: IpAddr,
    event: &EventCollection,
) -> BwResult<()> {
    let at = parse_date(&event.date).ok_or_else(|| BwError::msg("Invalid event date"))?;
    let org = event
        .organization_id
        .as_deref()
        .and_then(|id| Uuid::parse_str(id).ok());
    match event.r#type {
        USER_EXPORTED_VAULT => {
            let target = target_json(event.r#type, None, None, None, ip);
            record(app, user, at, target).await
        }
        ORG_EXPORTED_VAULT => {
            if let Some(org) = org
                && confirmed_in(app, user, org).await?
            {
                let target = target_json(event.r#type, None, Some(org), None, ip);
                record(app, user, at, target).await?;
            }
            Ok(())
        }
        BANNER_CLICKED => {
            if let Some(org) = org
                && confirmed_in(app, user, org).await?
            {
                // The membership's id is the account's.
                let source = user.to_string();
                let target = target_json(event.r#type, Some(&source), Some(org), None, ip);
                record(app, user, at, target).await?;
            }
            Ok(())
        }
        t if is_cipher_event(t) => {
            // The cipher decides which organization the event belongs to, so the account must be
            // in the space that owns it, not just say so.
            let Some(cipher) = event
                .cipher_id
                .as_deref()
                .and_then(|id| Uuid::parse_str(id).ok())
            else {
                return Ok(());
            };
            let Some(item) = ItemStore::get(&app.store, ItemId(cipher)).await? else {
                return Ok(());
            };
            let now = app.now();
            if let Owner::Space(space) = item.owner
                && !item.is_tombstone()
                && near_now(at, now)
                && can_see(app, user, space, item.id).await?
            {
                let source = cipher.to_string();
                let target = target_json(t, Some(&source), Some(space.0), None, ip);
                record(app, user, at, target).await?;
            }
            Ok(())
        }
        // Everything else is written by the server; a client can't forge it.
        _ => Ok(()),
    }
}

async fn collect<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Peer(ip): Peer,
    body: Bytes,
) -> EmptyResult {
    let events: Vec<EventCollection> = parse(&body)?;
    let user = authed.user.id;
    let result = async {
        for event in &events {
            collect_one(&app, user, ip, event).await?;
        }
        Ok::<(), BwError>(())
    }
    .await;
    empty(result)
}

// --- the event lists ------------------------------------------------------------------------

/// Vaultwarden's `Event::PAGE_SIZE`.
const PAGE_SIZE: u32 = 30;

/// `start` and `end` are required; a request without them matches no route (Rocket's form guard
/// forwards it, and nothing else answers).
fn range(query: &HashMap<String, String>) -> BwResult<(&str, &str)> {
    match (query.get("start"), query.get("end")) {
        (Some(start), Some(end)) => Ok((start, end)),
        _ => Err(BwError::NotFound),
    }
}

/// The time range of a list: `None` while events are off, and then the list is empty. With events
/// on, the dates must parse, as Vaultwarden's `date_range` requires; a continuation token stands
/// for the end.
fn date_range<S: BwStore>(
    app: &App<S>,
    query: &HashMap<String, String>,
) -> BwResult<Option<(OffsetDateTime, OffsetDateTime)>> {
    let (start, end) = range(query)?;
    if !app.settings.org_events_enabled {
        return Ok(None);
    }
    let from = parse_date(start).ok_or_else(|| BwError::msg("Invalid start date"))?;
    let end = query.get("continuationToken").map_or(end, String::as_str);
    let to = parse_date(end).ok_or_else(|| BwError::msg("Invalid end date"))?;
    Ok(Some((from, to)))
}

/// `Event::to_json`. An event whose target isn't what [`target_json`] writes isn't shown.
fn event_json(event: &StoredEvent) -> Option<Value> {
    let target: Value = serde_json::from_str(event.target.as_deref()?).ok()?;
    let event_type = target.get("type")?.as_i64()?;
    let actor = event.actor.map(|a| a.to_string());
    // The 1000s are what an account did to itself; the rest are done to something by an account.
    let own = event_type < 1100;
    let user_id = if own { actor.clone() } else { None };
    let acting_id = if own { None } else { actor };
    let field = |key: &str| target.get(key).cloned().unwrap_or(Value::Null);
    Some(json!({
        "type": event_type,
        "userId": user_id,
        "organizationId": field("organizationId"),
        "cipherId": field("cipherId"),
        "collectionId": field("collectionId"),
        "groupId": field("groupId"),
        "organizationUserId": field("organizationUserId"),
        "actingUserId": acting_id,
        "date": format_date(event.at),
        "deviceType": field("deviceType"),
        "ipAddress": field("ipAddress"),
        "policyId": field("policyId"),
        "providerId": null,
        "providerUserId": null,
        "providerOrganizationId": null,
    }))
}

/// A list of events, with the continuation token Vaultwarden gives: the date of the last event
/// when the page is full.
fn page(events: &[StoredEvent]) -> Value {
    let shown: Vec<Value> = events.iter().filter_map(event_json).collect();
    let token = if events.len() == PAGE_SIZE as usize {
        shown.last().and_then(|e| e.get("date")).cloned()
    } else {
        None
    };
    json!({
        "data": shown,
        "object": "list",
        "continuationToken": token,
    })
}

fn empty_page() -> Value {
    page(&[])
}

/// The text a stored event holds for `key` being `id`.
fn holds(key: &str, id: &str) -> String {
    format!("\"{key}\":\"{id}\"")
}

async fn read<S: BwStore>(app: &App<S>, query: &EventQuery) -> BwResult<Value> {
    Ok(page(&EventReader::read_events(&app.store, query).await?))
}

/// `AdminHeaders`: a confirmed owner or admin of the organization, or a 401.
async fn require_admin<S: BwStore>(app: &App<S>, user: UserId, org: &str) -> BwResult<Uuid> {
    let org = Uuid::parse_str(org).map_err(|_| BwError::NotFound)?;
    let admin = SpaceRepo::memberships(&app.store, user)
        .await?
        .iter()
        .any(|m| {
            m.space == SpaceId(org)
                && m.is_confirmed()
                && matches!(m.role, SpaceRole::Owner | SpaceRole::Admin)
        });
    if admin {
        Ok(org)
    } else {
        Err(BwError::Unauthorized)
    }
}

async fn org_events<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path(org_id): Path<String>,
    Query(query): Query<HashMap<String, String>>,
) -> JsonResult {
    let org = require_admin(&app, authed.user.id, &org_id).await?;
    let Some((from, to)) = date_range(&app, &query)? else {
        return ok(empty_page());
    };
    let events = EventQuery::new(ACTION, from, to, PAGE_SIZE)
        .containing(holds("organizationId", &org.to_string()));
    ok(read(&app, &events).await?)
}

/// `Membership::user_has_ge_admin_access_to_cipher`: an owner or admin, confirmed, of the space
/// that owns the cipher.
async fn admin_of_cipher<S: BwStore>(app: &App<S>, user: UserId, cipher: Uuid) -> BwResult<bool> {
    let Some(item) = ItemStore::get(&app.store, ItemId(cipher)).await? else {
        return Ok(false);
    };
    let Owner::Space(space) = item.owner else {
        return Ok(false);
    };
    Ok(SpaceRepo::memberships(&app.store, user)
        .await?
        .iter()
        .any(|m| {
            m.space == space
                && m.is_confirmed()
                && matches!(m.role, SpaceRole::Owner | SpaceRole::Admin)
        }))
}

async fn cipher_events<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path(id): Path<String>,
    Query(query): Query<HashMap<String, String>>,
) -> JsonResult {
    let Some((from, to)) = date_range(&app, &query)? else {
        return ok(empty_page());
    };
    let Ok(cipher) = Uuid::parse_str(&id) else {
        return ok(empty_page());
    };
    if !admin_of_cipher(&app, authed.user.id, cipher).await? {
        return ok(empty_page());
    }
    let events = EventQuery::new(ACTION, from, to, PAGE_SIZE)
        .containing(holds("cipherId", &cipher.to_string()));
    ok(read(&app, &events).await?)
}

/// What the events of one member are: about their membership, or made by their account.
async fn user_events<S: BwStore>(
    State(app): State<App<S>>,
    authed: Authed,
    Path((org_id, member_id)): Path<(String, String)>,
    Query(query): Query<HashMap<String, String>>,
) -> JsonResult {
    let org = require_admin(&app, authed.user.id, &org_id).await?;
    let Some((from, to)) = date_range(&app, &query)? else {
        return ok(empty_page());
    };
    // Only a member of this organization has events here, as Vaultwarden's join on the
    // membership has it.
    let Some(found) = app.load_org(SpaceId(org)).await? else {
        return ok(empty_page());
    };
    let account = Uuid::parse_str(&member_id).ok().map(UserId);
    let is_member = account.is_some_and(|u| found.member(u).is_some())
        || found.pending.iter().any(|p| p.id == member_id);
    if !is_member {
        return ok(empty_page());
    }
    let mut events = EventQuery::new(ACTION, from, to, PAGE_SIZE)
        .containing(holds("organizationId", &org.to_string()))
        .or(EventMatch::Target(holds(
            "organizationUserId",
            &member_id.to_lowercase(),
        )));
    if let Some(account) = account {
        events = events.or(EventMatch::Actor(account));
    }
    ok(read(&app, &events).await?)
}

pub(crate) fn routes<S: BwStore>() -> Router<App<S>> {
    Router::new()
        .route("/events/collect", post(collect::<S>))
        .route("/api/organizations/{org_id}/events", get(org_events::<S>))
        .route("/api/ciphers/{id}/events", get(cipher_events::<S>))
        .route(
            "/api/organizations/{org_id}/users/{member_id}/events",
            get(user_events::<S>),
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn the_source_id_goes_where_vaultwardens_column_is() {
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let org = Uuid::nil();
        let cipher = target_json(1107, Some("c1"), Some(org), Some(9), ip);
        let cipher: Value = serde_json::from_str(&cipher).expect("json");
        assert_eq!(cipher["cipherId"], "c1");
        assert_eq!(cipher["type"], 1107);
        assert_eq!(cipher["deviceType"], 9);
        assert_eq!(cipher["ipAddress"], "127.0.0.0/24");

        let user: Value =
            serde_json::from_str(&target_json(1522, Some("m1"), None, None, ip)).expect("json");
        assert_eq!(user["organizationUserId"], "m1");
        assert!(user["organizationId"].is_null());

        // An organization event (1600s) has no source column.
        let org_event: Value =
            serde_json::from_str(&target_json(1602, Some("x"), Some(org), None, ip)).expect("json");
        assert!(org_event.get("cipherId").is_none());
        assert_eq!(org_event["organizationId"], org.to_string());
    }

    #[test]
    fn a_two_step_recovery_is_vaultwardens_user_recovered_2fa() {
        // `EventType::UserRecovered2fa` in Vaultwarden's src/db/models/event.rs; 1005 next to it is
        // `UserFailedLogIn`, which a client would show instead.
        assert_eq!(kind::USER_RECOVERED_2FA, 1004);
    }

    #[test]
    fn only_the_client_cipher_types_are_cipher_events() {
        for t in [1107, 1114, 1117, 1119, 1133] {
            assert!(is_cipher_event(t), "{t}");
        }
        for t in [1115, 1116, 1118, 1134, 1000, 1602] {
            assert!(!is_cipher_event(t), "{t}");
        }
    }
}

#[cfg(test)]
mod collect_tests {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn a_cipher_event_is_dated_within_a_week_back_and_minutes_ahead() {
        let now = datetime!(2026-11-26 12:00 UTC);
        assert!(near_now(now, now));
        assert!(near_now(now - time::Duration::days(6), now));
        assert!(near_now(now + time::Duration::minutes(4), now));
        assert!(!near_now(now - time::Duration::days(8), now));
        assert!(!near_now(now + time::Duration::hours(1), now));
        assert!(!near_now(now + time::Duration::days(365), now));
    }
}
