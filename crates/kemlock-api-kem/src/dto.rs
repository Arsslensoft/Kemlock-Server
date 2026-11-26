//! The JSON bodies of `/kem/v1`. Binary values are base64url without padding (docs/crypto.md);
//! bodies refuse unknown fields.

use crate::problem::Problem;
use kemlock_app::devices::MAX_IDENTIFIER_LEN;
use kemlock_app::federation_view::{SiblingSet, VaultServers};
use kemlock_app::{AppError, DeviceInfo, JoinPolicy, ServerBasics, b64url};
use kemlock_domain::spaces::CollectionId;
use kemlock_domain::{
    DeviceId, DeviceKind, Item, ItemFormat, ItemId, ItemKind, ItemWrite, KdfParams, Owner,
    Revision, Sealed,
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use utoipa::ToSchema;
use uuid::Uuid;

/// Decodes a base64url field, naming it when it's bad.
pub fn decode(field: &str, value: &str) -> Result<Vec<u8>, Problem> {
    b64url::decode(value)
        .ok_or_else(|| Problem::bad_request(format!("{field} must be unpadded base64url")))
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConfigResponse {
    /// Always `"kemlock-server"`: how a client tells this is a Kemlock Server.
    pub server: String,
    /// The API version families served.
    pub api_versions: Vec<String>,
    pub version: String,
    /// The git commit this server was built from; absent when the build did not know it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
    /// The licence of the server: always the SPDX identifier `AGPL-3.0-only`.
    pub license: String,
    /// Where the Corresponding Source of this exact version can be had (AGPL-3.0 section 13).
    pub source_url: String,
    pub server_id: Uuid,
    /// The address the server believes it has (`DOMAIN`); proofs are checked against it.
    pub domain: String,
    /// `"needs-admin"`, `"pending"` or `"complete"`.
    pub setup: String,
    pub signups_allowed: bool,
    pub features: Vec<String>,
    /// The servers of each federated vault asked for with `?vault=`: the home first, then the
    /// replicas. A vault that isn't federated here is left out, so the answer says nothing about
    /// whether it exists. Empty when none was asked for or the server doesn't federate.
    pub vaults: Vec<VaultServersDto>,
}

/// One server a vault is held on.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ServerEntryDto {
    pub server_id: Uuid,
    /// The base URL a device reaches the server at.
    pub address: String,
    /// The server's federation identity key, base64url.
    pub identity_key: String,
    /// `"home"` or `"replica"`.
    pub role: String,
}

/// A federated vault's servers in failover order.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct VaultServersDto {
    /// `user:<uuid>` or `space:<uuid>`.
    #[schema(value_type = String)]
    pub vault: Owner,
    /// The vault's home epoch, from 1.
    pub epoch: u64,
    pub servers: Vec<ServerEntryDto>,
    /// The signed promotion record that made this epoch, base64url; `null` at epoch 1.
    pub promotion: Option<String>,
}

impl VaultServersDto {
    pub fn from_view(servers: &VaultServers) -> Self {
        VaultServersDto {
            vault: servers.vault,
            epoch: servers.epoch,
            servers: servers
                .servers
                .iter()
                .map(|s| ServerEntryDto {
                    server_id: s.server.0,
                    address: s.address.clone(),
                    identity_key: b64url::encode(&s.identity_key),
                    role: s.role.as_str().to_owned(),
                })
                .collect(),
            promotion: servers.promotion.as_deref().map(b64url::encode),
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SetupVerifyRequest {
    pub code: String,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SetupVerifyResponse {
    /// Send it as `setupGrant` when registering the first admin.
    pub grant: String,
    pub expires_in: i64,
}

/// The optional body of `POST /kem/v1/setup/finish`.
#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SetupFinishRequest {
    /// The "Server basics" the setup screens collected; saved as the settings the admin console
    /// edits.
    pub basics: Option<ServerBasicsDto>,
}

/// The server basics a setup screen sends. The public address is only recorded (the server's
/// `DOMAIN` is configuration). The file folder has no setting and is accepted and ignored, so a
/// client may send its whole form.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ServerBasicsDto {
    /// `invite`, `domains` or `anyone`.
    pub join: String,
    /// Comma-separated; needed for `domains`.
    #[serde(default)]
    pub join_domains: String,
    /// The outgoing mail server; empty for no mail.
    #[serde(default)]
    pub mail_host: String,
    #[serde(default = "default_mail_port")]
    pub mail_port: String,
    /// `starttls` or `tls`.
    #[serde(default = "default_mail_security")]
    pub mail_security: String,
    #[serde(default)]
    pub mail_from: String,
    #[serde(default)]
    pub mail_user: String,
    /// The public address chosen at setup; recorded for the console, not applied.
    #[serde(default)]
    pub address: String,
    /// Register with Kemlock's push relay.
    #[serde(default)]
    pub push: bool,
    /// Turn scheduled backups on.
    #[serde(default)]
    pub backups: bool,
    /// `night` or `six-hours`.
    #[serde(default = "default_backup_every")]
    pub backup_every: String,
    /// `7`, `14` or `30`.
    #[serde(default = "default_backup_keep")]
    pub backup_keep: String,
    /// The age recipient the backups are encrypted to.
    #[serde(default)]
    pub backup_recipient: String,
}

fn default_backup_every() -> String {
    "night".to_owned()
}

fn default_backup_keep() -> String {
    "30".to_owned()
}

fn default_mail_port() -> String {
    "587".to_owned()
}

fn default_mail_security() -> String {
    "starttls".to_owned()
}

impl ServerBasicsDto {
    pub fn into_basics(self) -> Result<ServerBasics, AppError> {
        let join = JoinPolicy::parse(&self.join).ok_or(AppError::Invalid(
            "server basics: join must be invite, domains or anyone",
        ))?;
        Ok(ServerBasics {
            join,
            join_domains: self.join_domains,
            mail_host: self.mail_host,
            mail_port: self.mail_port,
            mail_security: self.mail_security,
            mail_from: self.mail_from,
            mail_user: self.mail_user,
            address: self.address,
            push: self.push,
            backups: self.backups.then_some(kemlock_app::BackupBasics {
                every: self.backup_every,
                keep: self.backup_keep,
                recipient: self.backup_recipient,
            }),
        })
    }
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EmailRequest {
    pub email: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KdfDto {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
    /// The salt, base64url.
    pub salt: String,
}

impl KdfDto {
    pub fn from_params(kdf: &KdfParams) -> Self {
        KdfDto {
            memory_kib: kdf.memory_kib,
            iterations: kdf.iterations,
            parallelism: kdf.parallelism,
            salt: b64url::encode(&kdf.salt),
        }
    }

    pub fn to_params(&self) -> Result<KdfParams, Problem> {
        Ok(KdfParams {
            memory_kib: self.memory_kib,
            iterations: self.iterations,
            parallelism: self.parallelism,
            salt: decode("kdf.salt", &self.salt)?,
        })
    }
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PreloginResponse {
    pub kdf: KdfDto,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MethodsResponse {
    /// The ways in the server offers for the email: `"password"`, and `"sso"` when single sign-on
    /// is set up for its domain.
    pub methods: Vec<String>,
    /// Present exactly when `methods` has `"sso"`: what the sign-in button says.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sso: Option<SsoOffer>,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SsoOffer {
    /// The provider's display name; the issuer's host when the admin left it blank.
    pub provider_name: String,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegisterStartRequest {
    pub email: String,
    /// OPAQUE's `RegistrationRequest`, base64url.
    pub request: String,
    pub setup_grant: Option<String>,
    /// The token of an invitation link. With sign-ups closed, an invited address registers with
    /// it; the token must be for this email and neither used nor expired.
    pub invite_token: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RegisterStartResponse {
    /// OPAQUE's `RegistrationResponse`, base64url.
    pub response: String,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegisterFinishRequest {
    /// The account id the client chose; the key bundle and the root-key wrap are bound to it.
    pub user_id: Uuid,
    pub email: String,
    pub name: Option<String>,
    /// OPAQUE's `RegistrationUpload`, base64url.
    pub upload: String,
    pub kdf: KdfDto,
    pub public_bundle: String,
    pub bundle_signature: String,
    pub sealed_private_keys: String,
    pub wrapped_root_key: String,
    pub setup_grant: Option<String>,
    /// The invitation token sent with `register/start`; it is consumed once the account exists.
    pub invite_token: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RegisterFinishResponse {
    pub user_id: Uuid,
    /// Whether the account is the first admin.
    pub admin: bool,
    /// Present (true) only when the server verifies the address of a new account and this one is
    /// held back: it can't sign in until the link mailed to its address is opened.
    #[serde(skip_serializing_if = "is_false")]
    pub email_confirmation_required: bool,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpaqueStartRequest {
    pub email: String,
    /// OPAQUE's `CredentialRequest`, base64url.
    pub request: String,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct OpaqueStartResponse {
    /// OPAQUE's `CredentialResponse`, base64url.
    pub response: String,
    /// Sealed server state: send it back unread with the last message. Valid for 5 minutes.
    pub login_state: String,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeviceDto {
    /// The id the device kept from an earlier sign-in; omit it on the first.
    pub id: Option<Uuid>,
    pub name: String,
    /// `"kemlock-android"`, `"kemlock-ios"`, `"kemlock-web"`, `"kemlock-browser"` (the browser
    /// extension), `"kemlock-cli"`, `"amethystora"`, `"bitwarden"` or `"other"`.
    #[schema(value_type = Option<String>)]
    pub kind: Option<kemlock_domain::DeviceKind>,
    /// With `kind` `"kemlock-browser"`: the browser, numbered as Bitwarden numbers its device
    /// types: 2 Chrome, 3 Firefox, 5 Edge. The server adds the browser's name to the device's name
    /// when it isn't there. Refused with any other kind.
    pub device_type: Option<i32>,
    /// The identifier this phone sends the Bitwarden API as `deviceIdentifier`, when it signs in
    /// there too. The device then has the id the Bitwarden API makes from it, so the phone is one
    /// device on both APIs, and `id` is ignored. 1 to 256 bytes, exactly as the Bitwarden API got
    /// it.
    pub bitwarden_device_identifier: Option<String>,
}

impl DeviceDto {
    /// What the use cases take, refusing an identifier that is empty or too long.
    pub fn into_info(self) -> Result<DeviceInfo, Problem> {
        if let Some(identifier) = &self.bitwarden_device_identifier
            && (identifier.is_empty() || identifier.len() > MAX_IDENTIFIER_LEN)
        {
            return Err(Problem::bad_request(
                "bitwardenDeviceIdentifier must be 1 to 256 bytes",
            ));
        }
        let kind = self.kind.unwrap_or(DeviceKind::Other);
        let mut name = self.name;
        if let Some(device_type) = self.device_type {
            let browser = (kind == DeviceKind::KemlockBrowser)
                .then(|| kemlock_domain::browser_name(device_type))
                .flatten()
                .ok_or_else(|| {
                    Problem::bad_request(
                        "deviceType is 2, 3 or 5 and goes with kind \"kemlock-browser\"",
                    )
                })?;
            if !name
                .to_ascii_lowercase()
                .contains(&browser.to_ascii_lowercase())
            {
                name = format!("{}, {browser}", name.trim_end());
            }
        }
        Ok(DeviceInfo {
            id: self.id.map(DeviceId),
            name,
            kind,
            bitwarden_identifier: self.bitwarden_device_identifier,
        })
    }
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpaqueFinishRequest {
    pub email: String,
    pub login_state: String,
    /// OPAQUE's `CredentialFinalization`, base64url.
    pub finalization: String,
    pub device: DeviceDto,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TokenResponse {
    /// Always `"DPoP"`: send `Authorization: DPoP <accessToken>` with a proof.
    pub token_type: String,
    pub access_token: String,
    /// Seconds until the access token expires.
    pub expires_in: i64,
    pub refresh_token: String,
    pub refresh_expires_in: i64,
    pub user_id: Uuid,
    pub device_id: Uuid,
    pub admin: bool,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SignInResponse {
    /// `"signed_in"` or `"two_factor_required"`.
    pub status: String,
    pub tokens: Option<TokenResponse>,
    /// With `two_factor_required`: send it to `/auth/two-factor` with the code.
    pub challenge: Option<String>,
    /// With `two_factor_required`: the account's methods, such as `"totp"`.
    pub methods: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TwoFactorRequest {
    pub challenge: String,
    /// `"totp"`.
    pub method: String,
    pub code: String,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RefreshRequest {
    /// Must be `"refresh_token"`.
    pub grant_type: String,
    pub refresh_token: String,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TotpEnrolResponse {
    /// The secret in base32, for typing into an authenticator app.
    pub secret: String,
    /// An `otpauth://` URI for a QR code.
    pub uri: String,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TotpConfirmRequest {
    pub code: String,
    /// The recovery code, when another second step is on already: a session alone may add the
    /// first step, and a fresh proof is needed beside one that is on.
    pub proof: Option<FreshProof>,
}

/// Asks for the account's recovery code.
#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecoveryCodeRequest {
    /// A fresh proof that is not the recovery code itself: a code mailed by
    /// `POST /kem/v1/account/two-factor/proof`, or a current code of the authenticator app. Not
    /// needed while the account holds no recovery code.
    pub proof: Option<FreshProof>,
}

/// The account's two-step recovery code.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryCodeResponse {
    /// 32 characters of upper-case base32, or null when the account has never had a second step
    /// (or has spent its code). Entering it as the second step switches every method off.
    pub code: Option<String>,
}

/// An item on the wire (docs/crypto.md, "`kem1`: the item envelope").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ItemDto {
    #[schema(value_type = String)]
    pub id: ItemId,
    /// `user:<uuid>` or `space:<uuid>`.
    #[schema(value_type = String)]
    pub owner: Owner,
    /// 1 to 64 characters of `a-z`, `0-9`, `-` and `_`.
    #[schema(value_type = String)]
    pub kind: ItemKind,
    /// `"kem1"` or `"bw"`.
    #[schema(value_type = String)]
    pub format: ItemFormat,
    /// Assigned by the client: 1 for a new item, then the previous revision plus one.
    pub revision: u64,
    pub key_version: u32,
    /// `nonce ‖ ciphertext ‖ tag`, base64url. Absent on a tombstone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ciphertext: Option<String>,
    /// The wrapped item key, base64url. Absent on a tombstone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item_key: Option<String>,
    #[serde(default)]
    pub deleted: bool,
    /// The collection an item of a space is in. Required when writing an item whose `owner` is a
    /// space, which needs edit on it; shown on items of spaces that are read; absent for items of
    /// a vault.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collection_id: Option<Uuid>,
    /// When the server recorded the deletion, RFC 3339 in UTC. On a tombstone only, set by the
    /// server: a client may send it back unchanged but the server ignores it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<String>,
    /// Set by the server on an item of a space that a key replacement left **held**: stored but
    /// not live, sent to every confirmed member of the space, with the `keyVersion` it had.
    /// It stays held until a write under the collection's current key version, or a delete,
    /// replaces it, and that revision is then served as live (docs/crypto.md, I4). Absent when
    /// false; a client may send it back unchanged but the server ignores it.
    #[serde(default, skip_serializing_if = "is_false")]
    pub held: bool,
}

fn is_false(value: &bool) -> bool {
    !*value
}

/// A time as RFC 3339 in UTC.
pub fn rfc3339(time: OffsetDateTime) -> Option<String> {
    time.to_offset(time::UtcOffset::UTC).format(&Rfc3339).ok()
}

impl ItemDto {
    pub fn from_item(item: &Item) -> Self {
        ItemDto {
            id: item.id,
            owner: item.owner,
            kind: item.kind.clone(),
            format: item.format,
            revision: item.revision.0,
            key_version: item.key_version,
            ciphertext: item.ciphertext.as_deref().map(b64url::encode),
            item_key: item.item_key.as_deref().map(b64url::encode),
            deleted: item.is_tombstone(),
            collection_id: None,
            deleted_at: item.deleted_at.and_then(rfc3339),
            held: false,
        }
    }

    /// The item as shown when it is held: see [`ItemDto::held`].
    pub fn held(mut self, held: bool) -> Self {
        self.held = held;
        self
    }

    /// The item as shown with the collection it is in.
    pub fn in_collection(mut self, collection: Option<CollectionId>) -> Self {
        self.collection_id = collection.map(|c| c.0);
        self
    }

    /// The collection the writer names, if any.
    pub fn collection(&self) -> Option<CollectionId> {
        self.collection_id.map(CollectionId)
    }

    /// The write this body asks for; `expected` comes from `If-Match` or `If-None-Match`.
    pub fn into_write(self, expected: Option<Revision>) -> Result<ItemWrite, Problem> {
        let sealed = if self.deleted {
            if self.ciphertext.is_some() || self.item_key.is_some() {
                return Err(Problem::bad_request(
                    "a deleted item carries no ciphertext or itemKey",
                ));
            }
            None
        } else {
            let ciphertext = self
                .ciphertext
                .as_deref()
                .ok_or_else(|| Problem::bad_request("ciphertext is required"))?;
            let item_key = self
                .item_key
                .as_deref()
                .ok_or_else(|| Problem::bad_request("itemKey is required"))?;
            Some(Sealed {
                ciphertext: decode("ciphertext", ciphertext)?,
                item_key: decode("itemKey", item_key)?,
            })
        };
        Ok(ItemWrite {
            id: self.id,
            owner: self.owner,
            kind: self.kind,
            format: self.format,
            expected,
            revision: Revision(self.revision),
            key_version: self.key_version,
            sealed,
        })
    }
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BatchWrite {
    /// The revision the writer last saw; `null` or absent for a new item.
    pub expected_revision: Option<u64>,
    pub item: ItemDto,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BatchRequest {
    pub writes: Vec<BatchWrite>,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct BatchResponse {
    pub items: Vec<ItemDto>,
}

// The dedup tags ride beside the item in the JSON of a write, and `routes::duplicates` takes them
// out before `ItemDto` (which refuses unknown fields) reads the rest. The types below describe
// that wire form for the OpenAPI document only; nothing reads or writes them.

/// An item write as `PUT /kem/v1/items/{id}` and each entry of `POST /kem/v1/items:batch` take
/// it: the item, and optionally the duplicate cleaner's tags.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ItemWriteDto {
    #[serde(flatten)]
    pub item: ItemDto,
    /// The item's dedup tags, 32 bytes each, base64url. Come with `tagVersion` or not at all
    /// (400 otherwise). Ignored while server matching is off for the owner.
    pub tags: Option<Vec<String>>,
    /// The dedup key version the tags were made under.
    pub tag_version: Option<u32>,
}

/// The answer to `PUT /kem/v1/items/{id}`: the item, and what became of its tags when the write
/// carried some.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ItemWriteAnswerDto {
    #[serde(flatten)]
    pub item: ItemDto,
    /// Present when the write carried tags: whether they were stored.
    pub tags_stored: Option<bool>,
    /// Present when the tags were stored: the other items of the owner that share a tag.
    pub matches: Option<Vec<Uuid>>,
}

/// One write of `POST /kem/v1/items:batch`.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TaggedBatchWriteDto {
    /// The revision the writer last saw; `null` or absent for a new item.
    pub expected_revision: Option<u64>,
    pub item: ItemWriteDto,
}

/// The body of `POST /kem/v1/items:batch`.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TaggedBatchRequest {
    pub writes: Vec<TaggedBatchWriteDto>,
}

/// What became of the tags of one write of a batch.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TagOutcomeDto {
    /// The item the tags were for.
    pub item: Uuid,
    pub stored: bool,
    /// The other items of the owner that share a tag with it.
    pub matches: Vec<Uuid>,
}

/// The answer to `POST /kem/v1/items:batch`.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TaggedBatchResponse {
    pub items: Vec<ItemDto>,
    /// One entry per write that carried tags; absent when none did.
    pub tags: Option<Vec<TagOutcomeDto>>,
}
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SyncQuery {
    /// The cursor of the last sync; absent for a first sync.
    pub since: Option<String>,
    /// The most items to return, up to 500.
    pub limit: Option<u32>,
}

/// The body of `POST /kem/v1/sync`: the same two values as the query of the `GET`.
#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SyncBody {
    /// The cursor of the last sync; absent for a first sync.
    pub since: Option<String>,
    /// The most items to return, up to 500.
    pub limit: Option<u32>,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SyncResponse {
    pub items: Vec<ItemDto>,
    /// Opaque: send it back as `since`.
    pub cursor: String,
    /// Whether another page follows.
    pub more: bool,
    /// Items that two servers wrote apart: the versions held beside the item `items` lists (the
    /// head). Merge them with the item and write the result, then post to
    /// `/items/{id}/siblings/resolve`. Always present; empty on a server with no federation.
    pub siblings: Vec<SiblingSetDto>,
}

/// The versions of one item held beside its head.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SiblingSetDto {
    #[schema(value_type = String)]
    pub item_id: ItemId,
    pub versions: Vec<ItemDto>,
}

impl SiblingSetDto {
    pub fn from_set(set: &SiblingSet) -> Self {
        SiblingSetDto {
            item_id: set.item,
            versions: set.siblings.iter().map(ItemDto::from_item).collect(),
        }
    }
}

/// What resolving an item's siblings did.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ResolveResponse {
    /// How many siblings were replaced by the item's head.
    pub resolved: u64,
}

/// A fresh proof that it is the account's owner at a keyboard, not only a session. Either a code
/// (the mailed one, a current code of the authenticator app, or, where the route takes it, the
/// recovery code) as a string, or the answer of a security key or passkey as
/// `{ "webauthn": <PublicKeyCredential.toJSON()> }`, to the options at
/// `POST /kem/v1/account/two-factor/proof/webauthn/options`.
#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(untagged)]
pub enum FreshProof {
    /// A code, as typed.
    Code(String),
    /// A security key's or passkey's assertion.
    Assertion(KeyAssertion),
}

/// The answer of a security key or passkey, as the browser makes it.
#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct KeyAssertion {
    /// The browser's `PublicKeyCredential.toJSON()` from `navigator.credentials.get`.
    #[schema(value_type = Object)]
    pub webauthn: serde_json::Value,
}

impl FreshProof {
    /// Whether it is a code with nothing in it.
    pub fn is_blank(&self) -> bool {
        matches!(self, FreshProof::Code(code) if code.trim().is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kemlock_domain::{ChangeId, Hlc, ServerId, UserId};
    use time::OffsetDateTime;

    fn item() -> Item {
        Item {
            id: ItemId::random(),
            owner: Owner::User(UserId::random()),
            kind: ItemKind::try_from("login".to_owned()).expect("a valid kind"),
            format: ItemFormat::Kem1,
            revision: Revision(4),
            key_version: 1,
            ciphertext: Some(vec![1; 40]),
            item_key: Some(vec![2; 60]),
            deleted_at: None,
            updated_at: OffsetDateTime::UNIX_EPOCH,
            change: ChangeId {
                origin: ServerId::random(),
                seq: 9,
                hlc: Hlc(1),
            },
        }
    }

    #[test]
    fn an_item_has_docs_crypto_md_shape() {
        let dto = ItemDto::from_item(&item());
        let json = serde_json::to_value(&dto).expect("serializes");
        assert_eq!(json["format"], "kem1");
        assert_eq!(json["kind"], "login");
        assert_eq!(json["revision"], 4);
        assert_eq!(json["keyVersion"], 1);
        assert_eq!(json["deleted"], false);
        assert!(json.get("deletedAt").is_none());
        assert!(
            json["owner"]
                .as_str()
                .is_some_and(|o| o.starts_with("user:"))
        );
        assert!(json["ciphertext"].is_string());
    }

    #[test]
    fn held_is_written_only_when_true_and_a_write_ignores_it() {
        let plain = serde_json::to_value(ItemDto::from_item(&item())).expect("serializes");
        assert!(plain.get("held").is_none());
        let mut stored = item();
        stored.key_version = 2;
        let held = ItemDto::from_item(&stored).held(true);
        let json = serde_json::to_value(&held).expect("serializes");
        assert_eq!(json["held"], true);
        assert_eq!(json["keyVersion"], 2);
        // A client may send it back: it reads, and the write doesn't depend on it.
        let back: ItemDto = serde_json::from_value(json).expect("reads");
        assert!(back.held);
        let write = back.into_write(Some(Revision(3))).expect("converts");
        assert_eq!(write.key_version, 2);
    }

    #[test]
    fn a_tombstone_omits_ciphertext_and_key() {
        let mut stored = item();
        stored.ciphertext = None;
        stored.item_key = None;
        stored.deleted_at = Some(OffsetDateTime::UNIX_EPOCH);
        let json = serde_json::to_value(ItemDto::from_item(&stored)).expect("serializes");
        assert_eq!(json["deleted"], true);
        assert_eq!(json["deletedAt"], "1970-01-01T00:00:00Z");
        assert!(json.get("ciphertext").is_none());
        assert!(json.get("itemKey").is_none());
    }

    #[test]
    fn a_dto_round_trips_into_a_write() {
        let stored = item();
        let write = ItemDto::from_item(&stored)
            .into_write(Some(Revision(3)))
            .expect("converts");
        assert_eq!(write.id, stored.id);
        assert_eq!(write.expected, Some(Revision(3)));
        assert_eq!(write.revision, Revision(4));
        assert_eq!(
            write.sealed.expect("sealed").ciphertext,
            stored.ciphertext.expect("ciphertext")
        );
    }

    #[test]
    fn bad_base64_and_missing_values_are_refused() {
        let mut dto = ItemDto::from_item(&item());
        dto.ciphertext = Some("not base64!".to_owned());
        assert!(dto.clone().into_write(None).is_err());
        dto.ciphertext = None;
        assert!(dto.clone().into_write(None).is_err());
        dto.deleted = true;
        dto.item_key = Some("AAAA".to_owned());
        assert!(dto.into_write(None).is_err(), "a tombstone carries no key");
    }

    #[test]
    fn unknown_fields_are_refused() {
        let json = r#"{"id":"00000000-0000-0000-0000-000000000001","owner":"user:00000000-0000-0000-0000-000000000002","kind":"login","format":"kem1","revision":1,"keyVersion":1,"extra":true}"#;
        assert!(serde_json::from_str::<ItemDto>(json).is_err());
    }

    #[test]
    fn a_kdf_round_trips() {
        let kdf = KdfParams::new_account([9; 16]);
        let dto = KdfDto::from_params(&kdf);
        assert_eq!(dto.to_params().expect("converts"), kdf);
    }
}
