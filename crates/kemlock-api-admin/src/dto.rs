//! The JSON bodies of `/admin/v1`. Names are camelCase, times are Unix seconds, ids are UUIDs,
//! binary values are base64url without padding; request bodies refuse unknown fields.

use kemlock_api_kem::KindsDto;
use kemlock_app::admin::settings::{Kind, SettingView};
use kemlock_app::admin::{
    AdminSpaceRow, AdminUserRow, ComplianceRequest, EventRecord, Invite, InviteIssued,
    MigrationState, MigrationStatus, OverviewCounts, RelayStatus, SsoView,
};
use kemlock_app::sso::{GroupRule, SpaceRole, VerifiedDomain};
use kemlock_domain::{AccountMode, Role};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

fn secs(t: OffsetDateTime) -> i64 {
    t.unix_timestamp()
}

// ---- who am I, and step-up ----

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MeResponse {
    pub user_id: Uuid,
    pub device_id: Uuid,
    /// How long a step-up token lasts, in seconds.
    pub step_up_ttl_seconds: i64,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StepUpStartRequest {
    /// OPAQUE's `CredentialRequest`, unpadded base64url.
    pub request: String,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct StepUpStartResponse {
    /// OPAQUE's `CredentialResponse`.
    pub response: String,
    /// The sealed server state; send it back unread with the last message.
    pub login_state: String,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StepUpFinishRequest {
    pub login_state: String,
    /// OPAQUE's `CredentialFinalization`.
    pub finalization: String,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StepUpTotpRequest {
    /// A code from the admin's authenticator app.
    pub code: String,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct StepUpResponse {
    /// Send it as the `Step-Up-Token` header on writes.
    pub token: String,
    /// When it stops working, in Unix seconds.
    pub expires_at: i64,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct StepUpPasskeyOptionsResponse {
    /// `PublicKeyCredentialRequestOptions` for `navigator.credentials.get`, listing the admin's
    /// own passkeys and requiring user verification.
    #[schema(value_type = Object)]
    pub options: serde_json::Value,
    /// The sealed challenge; send it back unread with the answer, within two minutes, from the
    /// same device. It is good once.
    pub challenge: String,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StepUpPasskeyRequest {
    pub challenge: String,
    /// The browser's `PublicKeyCredential.toJSON()` from `navigator.credentials.get`.
    #[schema(value_type = Object)]
    pub credential: serde_json::Value,
}

// ---- overview ----

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct OverviewDto {
    pub users: u64,
    pub admins: u64,
    pub disabled_users: u64,
    pub devices: u64,
    pub spaces: u64,
    pub live_items: u64,
    pub events_24h: u64,
    pub pending_invites: u64,
    pub open_requests: u64,
    pub overdue_requests: u64,
    pub mail_configured: bool,
}

impl From<OverviewCounts> for OverviewDto {
    fn from(c: OverviewCounts) -> Self {
        OverviewDto {
            users: c.users,
            admins: c.admins,
            disabled_users: c.disabled_users,
            devices: c.devices,
            spaces: c.spaces,
            live_items: c.live_items,
            events_24h: c.events_24h,
            pending_invites: c.pending_invites,
            open_requests: c.open_requests,
            overdue_requests: c.overdue_requests,
            mail_configured: c.mail_configured,
        }
    }
}

// ---- users and invitations ----

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AdminUserDto {
    pub id: Uuid,
    pub email: String,
    pub name: Option<String>,
    /// `user` or `admin`.
    pub role: String,
    /// `kemlock-only` or `compatible`.
    pub mode: String,
    pub created_at: i64,
    /// Set while the account is disabled.
    pub disabled_at: Option<i64>,
    pub devices: u32,
    /// Whether the account has a confirmed two-step method.
    pub two_step: bool,
    pub last_seen_at: Option<i64>,
    /// The owner deleted the account and its grace period is running: it cannot sign in, and an
    /// admin can cancel the deletion.
    pub erasure_pending: bool,
}

impl From<&AdminUserRow> for AdminUserDto {
    fn from(u: &AdminUserRow) -> Self {
        AdminUserDto {
            id: u.id.0,
            email: u.email.clone(),
            name: u.name.clone(),
            role: match u.role {
                Role::User => "user",
                Role::Admin => "admin",
            }
            .to_owned(),
            mode: match u.mode {
                AccountMode::KemlockOnly => "kemlock-only",
                AccountMode::Compatible => "compatible",
            }
            .to_owned(),
            created_at: secs(u.created_at),
            disabled_at: u.disabled_at.map(secs),
            devices: u.devices,
            two_step: u.two_step,
            last_seen_at: u.last_seen_at.map(secs),
            erasure_pending: u.erasure_pending,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UsersPageDto {
    pub users: Vec<AdminUserDto>,
    /// Every account that matches, not only this page.
    pub total: u64,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InviteRequest {
    pub email: String,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct InviteDto {
    pub id: Uuid,
    pub email: String,
    pub invited_by: Uuid,
    pub created_at: i64,
    pub expires_at: i64,
    pub last_sent_at: i64,
    pub sent: u32,
    pub accepted: bool,
    /// Neither accepted nor expired.
    pub pending: bool,
}

impl InviteDto {
    pub(crate) fn new(i: &Invite, now: i64) -> Self {
        InviteDto {
            id: i.id,
            email: i.email.as_str().to_owned(),
            invited_by: i.invited_by.0,
            created_at: secs(i.created_at),
            expires_at: secs(i.expires_at),
            last_sent_at: secs(i.last_sent_at),
            sent: i.sent,
            accepted: i.accepted_at.is_some(),
            pending: i.accepted_at.is_none() && now < secs(i.expires_at),
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct InviteIssuedDto {
    pub invite: InviteDto,
    /// The link that accepts the invitation. It is shown only now: the server keeps no copy of
    /// its token.
    pub link: String,
    /// Whether the mail went out. When it didn't (no SMTP server, or it failed), pass the link
    /// on by hand.
    pub mailed: bool,
}

impl InviteIssuedDto {
    pub(crate) fn new(i: &InviteIssued, now: i64) -> Self {
        InviteIssuedDto {
            invite: InviteDto::new(&i.invite, now),
            link: i.link.clone(),
            mailed: i.mailed,
        }
    }
}

// ---- spaces ----

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SpaceOwnerDto {
    pub user_id: Uuid,
    pub email: String,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AdminSpaceDto {
    pub id: Uuid,
    pub created_at: i64,
    pub members: u32,
    pub confirmed: u32,
    pub owners: Vec<SpaceOwnerDto>,
    pub live_items: u64,
    /// Set while the space waits for its keys to be replaced.
    pub keys_pending_since: Option<i64>,
    /// Whether the space is a Bitwarden organization. Only the list and one-space routes say; the
    /// answer to a change of owner leaves it false.
    pub bitwarden_organization: bool,
    /// The members of a Bitwarden organization who are still invited and have a Bitwarden
    /// invitation, whose link the console can copy. Empty outside an organization.
    pub bitwarden_invitations: Vec<SpaceOwnerDto>,
    /// Only in the answer to a change of owner: the space has a chain, which takes a change of roles
    /// only as a signed record, so the change is queued for its owners or admins to sign and
    /// `owners` are still the old ones.
    pub owner_change_queued: bool,
}

impl From<&AdminSpaceRow> for AdminSpaceDto {
    fn from(s: &AdminSpaceRow) -> Self {
        AdminSpaceDto {
            id: s.id.0,
            created_at: secs(s.created_at),
            members: s.members,
            confirmed: s.confirmed,
            owners: s
                .owners
                .iter()
                .map(|o| SpaceOwnerDto {
                    user_id: o.user.0,
                    email: o.email.clone(),
                })
                .collect(),
            live_items: s.live_items,
            keys_pending_since: s.keys_pending_since.map(secs),
            bitwarden_organization: false,
            bitwarden_invitations: Vec::new(),
            owner_change_queued: false,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SpacesPageDto {
    pub spaces: Vec<AdminSpaceDto>,
    pub total: u64,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChangeOwnerRequest {
    /// A confirmed member of the space.
    pub new_owner: Uuid,
    /// Make the other owners admins, so the space has the one owner named here. Default true.
    #[serde(default = "default_true")]
    pub demote_previous: bool,
}

fn default_true() -> bool {
    true
}

// ---- custom fields ----

/// A field an admin offers, as the console sends it to add or change one.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CustomFieldRequest {
    /// 1 to 64 characters, no control characters, unique whatever the case.
    pub name: String,
    /// `text`, `hidden` or `checkbox`.
    #[serde(rename = "type")]
    pub field_type: String,
    pub kinds: KindsDto,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AllowOwnRequest {
    /// Whether people may add fields of their own to an item.
    pub allow: bool,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AllowOwnDto {
    pub allow_own: bool,
}

// ---- events ----

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct EventDto {
    pub id: Uuid,
    pub at: i64,
    pub actor: Option<Uuid>,
    pub actor_email: Option<String>,
    pub device: Option<Uuid>,
    pub action: String,
    pub target: Option<String>,
    /// The client's address cut to its /24 or /48.
    pub ip: Option<String>,
}

impl From<&EventRecord> for EventDto {
    fn from(e: &EventRecord) -> Self {
        EventDto {
            id: e.id,
            at: secs(e.at),
            actor: e.actor.map(|a| a.0),
            actor_email: e.actor_email.clone(),
            device: e.device.map(|d| d.0),
            action: e.action.clone(),
            target: e.target.clone(),
            ip: e.ip.clone(),
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct EventsPageDto {
    /// Newest first.
    pub events: Vec<EventDto>,
    /// Send it as `cursor` for the next page; absent on the last one.
    pub next: Option<String>,
}

// ---- settings ----

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SettingDto {
    pub key: String,
    /// `smtp`, `signups`, `files`, `trash`, `retention` or `rate-limits`.
    pub group: String,
    /// `bool`, `int`, `text`, `choice`, `secret`, `email` or `domains`. Values travel as text:
    /// `"true"`, `"587"`.
    pub kind: String,
    pub min: Option<i64>,
    pub max: Option<i64>,
    pub max_length: Option<usize>,
    pub choices: Option<Vec<String>>,
    pub default: Option<String>,
    /// The value in effect. Absent for a secret and for a text setting that is unset.
    pub value: Option<String>,
    /// For a secret: whether one is set.
    pub secret_set: bool,
    /// `default`, `saved` or `env`.
    pub source: String,
    /// The environment sets it: the console can't change it.
    pub read_only: bool,
    /// The environment variable that sets it.
    pub env: String,
}

impl From<&SettingView> for SettingDto {
    fn from(v: &SettingView) -> Self {
        let d = v.definition;
        let (kind, min, max, max_length, choices) = match d.kind {
            Kind::Bool => ("bool", None, None, None, None),
            Kind::Int { min, max } => ("int", Some(min), Some(max), None, None),
            Kind::Text { max_len } => ("text", None, None, Some(max_len), None),
            Kind::Choice(c) => (
                "choice",
                None,
                None,
                None,
                Some(c.iter().map(|s| (*s).to_owned()).collect()),
            ),
            Kind::Secret => ("secret", None, None, None, None),
            Kind::Email => ("email", None, None, None, None),
            Kind::Domains => ("domains", None, None, None, None),
        };
        SettingDto {
            key: d.key.to_owned(),
            group: d.group.to_owned(),
            kind: kind.to_owned(),
            min,
            max,
            max_length,
            choices,
            default: (!d.default.is_empty()).then(|| d.default.to_owned()),
            value: v.value.clone(),
            secret_set: v.secret_set,
            source: v.source.as_str().to_owned(),
            read_only: v.read_only,
            env: d.env.to_owned(),
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SettingsResponse {
    pub settings: Vec<SettingDto>,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SettingsRequest {
    /// Setting name to its new value as text, or `null` to go back to the default. All or none
    /// apply. A setting the environment sets is refused.
    pub changes: BTreeMap<String, Option<String>>,
}

// ---- SSO ----

#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GroupRuleDto {
    /// A value of the ID token's `groups` claim, compared exactly.
    pub group: String,
    pub space: Uuid,
    /// `member`, `admin` or `owner`.
    pub role: String,
    #[serde(default)]
    pub collections: Vec<Uuid>,
}

impl GroupRuleDto {
    pub(crate) fn from_rule(r: &GroupRule) -> Self {
        GroupRuleDto {
            group: r.group.clone(),
            space: r.space.0,
            role: match r.role {
                SpaceRole::Member => "member",
                SpaceRole::Admin => "admin",
                SpaceRole::Owner => "owner",
            }
            .to_owned(),
            collections: r.collections.clone(),
        }
    }

    pub(crate) fn to_rule(&self) -> Result<GroupRule, String> {
        let role = match self.role.as_str() {
            "member" => SpaceRole::Member,
            "admin" => SpaceRole::Admin,
            "owner" => SpaceRole::Owner,
            _ => return Err("a group rule's role must be member, admin or owner".to_owned()),
        };
        Ok(GroupRule {
            group: self.group.clone(),
            space: kemlock_domain::SpaceId(self.space),
            role,
            collections: self.collections.clone(),
        })
    }
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SsoDto {
    /// Whether a provider has been set up at all.
    pub configured: bool,
    pub enabled: bool,
    pub display_name: String,
    pub issuer: String,
    pub client_id: String,
    pub client_secret_set: bool,
    pub scopes: Vec<String>,
    pub allow_unknown_email_verification: bool,
    pub link_by_email: bool,
    pub create_accounts: bool,
    pub require_verified_domain: bool,
    pub group_rules: Vec<GroupRuleDto>,
    pub updated_at: Option<i64>,
    /// The redirect address to register at the provider.
    pub callback_url: String,
}

impl From<&SsoView> for SsoDto {
    fn from(v: &SsoView) -> Self {
        match &v.settings {
            Some(s) => SsoDto {
                configured: true,
                enabled: s.enabled,
                display_name: s.display_name.clone(),
                issuer: s.issuer.clone(),
                client_id: s.client_id.clone(),
                client_secret_set: v.client_secret_set,
                scopes: s.scopes.clone(),
                allow_unknown_email_verification: s.allow_unknown_email_verification,
                link_by_email: s.link_by_email,
                create_accounts: s.create_accounts,
                require_verified_domain: s.require_verified_domain,
                group_rules: s.group_rules.iter().map(GroupRuleDto::from_rule).collect(),
                updated_at: Some(secs(s.updated_at)),
                callback_url: v.callback_url.clone(),
            },
            None => SsoDto {
                configured: false,
                enabled: false,
                display_name: "Single sign-on".to_owned(),
                issuer: String::new(),
                client_id: String::new(),
                client_secret_set: false,
                scopes: kemlock_app::sso::model::DEFAULT_SCOPES
                    .iter()
                    .map(|s| (*s).to_owned())
                    .collect(),
                allow_unknown_email_verification: false,
                link_by_email: false,
                create_accounts: true,
                require_verified_domain: true,
                group_rules: Vec::new(),
                updated_at: None,
                callback_url: v.callback_url.clone(),
            },
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SsoRequest {
    pub enabled: bool,
    pub display_name: String,
    pub issuer: String,
    pub client_id: String,
    /// A new client secret. Absent keeps the stored one.
    #[serde(default)]
    pub client_secret: Option<String>,
    /// Remove the stored secret (a public client). Ignored when `clientSecret` is given.
    #[serde(default)]
    pub clear_client_secret: bool,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub allow_unknown_email_verification: bool,
    #[serde(default)]
    pub link_by_email: bool,
    #[serde(default = "default_true")]
    pub create_accounts: bool,
    #[serde(default = "default_true")]
    pub require_verified_domain: bool,
    #[serde(default)]
    pub group_rules: Vec<GroupRuleDto>,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DomainDto {
    pub domain: String,
    /// Publish this as a TXT record at the domain.
    pub txt_value: String,
    pub created_at: i64,
    pub verified_at: Option<i64>,
    pub verified: bool,
}

impl From<&VerifiedDomain> for DomainDto {
    fn from(d: &VerifiedDomain) -> Self {
        DomainDto {
            domain: d.domain.clone(),
            txt_value: d.txt_value(),
            created_at: secs(d.created_at),
            verified_at: d.verified_at.map(secs),
            verified: d.is_verified(),
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DomainRequest {
    pub domain: String,
}

// ---- migration ----

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MigrationDto {
    /// `idle`, `planned`, `running`, `done` or `failed`.
    pub state: String,
    pub source: Option<String>,
    /// The plan of what the move does, in words, once the source was read.
    pub plan: Option<String>,
    pub error: Option<String>,
    /// When it was started, in Unix seconds.
    pub at: Option<i64>,
    pub started_by: Option<Uuid>,
    /// While running: what it is doing now (`reading the Vaultwarden data`, `writing`, …).
    pub stage: Option<String>,
    /// When done: what was written, in words.
    pub report: Option<String>,
    /// When it ended, done or failed, in Unix seconds.
    pub finished_at: Option<i64>,
    /// Whether a move writes to Kemlock Server. It does: `start` runs the import in the
    /// background, and a `done` status says what it wrote.
    pub applies: bool,
}

impl From<&MigrationStatus> for MigrationDto {
    fn from(m: &MigrationStatus) -> Self {
        MigrationDto {
            state: match m.state {
                MigrationState::Idle => "idle",
                MigrationState::Planned => "planned",
                MigrationState::Running => "running",
                MigrationState::Done => "done",
                MigrationState::Failed => "failed",
            }
            .to_owned(),
            source: m.source.clone(),
            plan: m.plan.clone(),
            error: m.error.clone(),
            at: m.at,
            started_by: m.started_by.map(|u| u.0),
            stage: m.stage.clone(),
            report: m.report.clone(),
            finished_at: m.finished_at,
            applies: true,
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MigrationStartRequest {
    /// A Vaultwarden SQLite file, or a folder holding `db.sqlite3`, inside the `import` folder of
    /// the server's data folder (a name relative to it). Database URLs and paths outside it are
    /// refused; `kemlock-cli import-vaultwarden` takes those.
    pub from: String,
    /// A folder inside the import folder with the attachments, sends, `rsa_key.pem` and
    /// `config.json`, when they aren't beside the database.
    #[serde(default)]
    pub files: Option<String>,
}

// ---- compliance ----

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ComplianceRequestDto {
    pub id: Uuid,
    /// `access`, `erasure`, `correction`, `opt-out` or `other`.
    pub kind: String,
    pub requester: String,
    pub user_id: Option<Uuid>,
    pub received_at: i64,
    pub due_at: i64,
    /// Whether the deadline was extended once.
    pub extended: bool,
    /// `open`, `in-progress`, `done` or `rejected`.
    pub status: String,
    pub note: Option<String>,
    pub closed_at: Option<i64>,
    pub handled_by: Option<Uuid>,
    /// Open and past its due date.
    pub overdue: bool,
}

impl ComplianceRequestDto {
    pub(crate) fn new(r: &ComplianceRequest, now: i64) -> Self {
        ComplianceRequestDto {
            id: r.id,
            kind: r.kind.as_str().to_owned(),
            requester: r.requester.clone(),
            user_id: r.user.map(|u| u.0),
            received_at: secs(r.received_at),
            due_at: secs(r.due_at),
            extended: r.extended,
            status: r.status.as_str().to_owned(),
            note: r.note.clone(),
            closed_at: r.closed_at.map(secs),
            handled_by: r.handled_by.map(|u| u.0),
            overdue: r.status.is_open() && secs(r.due_at) < now,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ComplianceListDto {
    /// Soonest due first.
    pub requests: Vec<ComplianceRequestDto>,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LogRequestRequest {
    /// `access`, `erasure`, `correction`, `opt-out` or `other`.
    pub kind: String,
    /// Who asked, as they gave it (an email, a name).
    pub requester: String,
    /// The account the request is about, when it is one of this server's.
    #[serde(default)]
    pub user_id: Option<Uuid>,
    /// When it arrived, in Unix seconds; default now.
    #[serde(default)]
    pub received_at: Option<i64>,
    /// A due date that overrides the CCPA's 45 days (15 business days for an opt-out).
    #[serde(default)]
    pub due_at: Option<i64>,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdateRequestRequest {
    /// `open`, `in-progress`, `done` or `rejected`.
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
    /// Push the due date out by another 45 days, once.
    #[serde(default)]
    pub extend: bool,
}

// ---- push relay ----

/// Where push stands: the Apple push and UnifiedPush the server sends itself, and Kemlock's
/// optional relay.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PushRelayDto {
    /// Whether this server has registered with the optional relay, so iPhones it has no Apple key
    /// for are pushed to through it.
    pub enabled: bool,
    /// The relay's id for this server. The key it holds is never shown.
    pub installation_id: Option<String>,
    /// The relay the server talks to.
    pub relay_url: String,
    /// Whether the server holds an Apple push key and sends to iPhones itself, with no relay.
    pub apns_configured: bool,
    /// Whether that Apple key pushes through Apple's sandbox, for development builds of the app.
    pub apns_sandbox: bool,
    /// Always true: the server pushes to Android phones through UnifiedPush itself.
    pub unified_push: bool,
}

impl From<&RelayStatus> for PushRelayDto {
    fn from(status: &RelayStatus) -> Self {
        PushRelayDto {
            enabled: status.enabled,
            installation_id: status.installation_id.clone(),
            relay_url: status.relay_url.clone(),
            apns_configured: status.apns_configured,
            apns_sandbox: status.apns_sandbox,
            unified_push: true,
        }
    }
}

/// The server's address and data folder: configuration, shown rather than edited, because
/// sign-in proofs are checked against the address and the store lives in the folder.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ServerAddressDto {
    /// `DOMAIN` as the server runs with it.
    pub domain: String,
    /// The address chosen at setup, when one was recorded.
    pub recorded_domain: Option<String>,
    /// A recorded address that is not the one in use: change `DOMAIN` in the configuration and
    /// restart to move, or ignore the record.
    pub differs: bool,
    /// `DATA_FOLDER`, when the server says; the environment alone sets it.
    pub data_folder: Option<String>,
}

/// The link that accepts a member's invitation to a Bitwarden organization.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct InviteLinkDto {
    /// The address to open in the web vault. Whoever opens it accepts for the invited account.
    pub link: String,
    /// When the link stops working, in Unix seconds.
    pub expires_at: i64,
}
