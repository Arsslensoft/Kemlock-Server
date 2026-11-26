//! The SQL side of the move from Vaultwarden: [`SqlImportSink`] implements
//! [`kemlock_vaultwarden::ImportSink`] over the store's tables.
//!
//! The whole of one pass (a first copy, or the second pass that applies what changed) runs in one
//! transaction on the writer: [`SqlImportSink::begin`] opens it, every call writes into it, and
//! `finish` commits. A sink dropped before that rolls everything back, so a failed pass leaves the
//! database as it was (the files it already copied stay, which is harmless: a rerun finds them).
//! Every put is an upsert keyed by Vaultwarden's primary key, so running a pass again changes
//! nothing.
//!
//! Where Vaultwarden's data lands:
//!
//! - a user becomes a Compatible `users` row (its Kemlock key columns empty until its owner
//!   enrols OPAQUE) with a `bw_accounts` row, and the remaining columns in `bw_account_extras`;
//! - a cipher becomes a `bw` item holding the cipher JSON Vaultwarden would return, a folder a
//!   `bw-folder` item, and the attachments are listed in `bw_attachments` and inside the cipher
//!   document;
//! - an organization becomes a space with its members, collections, groups and grants (keys kept
//!   as stored, opaque), and an `emergency_access` row stays one;
//! - two-step setups become `two_factor` rows sealed with the server key, one per method (an
//!   authenticator app, email, Duo, a YubiKey, security keys: see `accounts::rebuild_two_factor`);
//! - devices become `devices` rows of kind Bitwarden, with their refresh tokens hashed;
//! - events go to `events` (those older than the retention window are dropped) and `config.json`
//!   settings to `settings`;
//! - everything else, and a copy of each carried row, goes to `vw_rows`, for what the server
//!   doesn't serve yet (policies, Sends, ...).
//!
//! Attachments and Send files go to the [`ImportFiles`] the options carry, which the server makes
//! its Bitwarden blob store (the same folder or bucket the API reads, so imported files are found
//! wherever files are kept, and a Send's file where the API looks for it). `rsa_key.pem` goes in
//! the data folder, where the API reads its token key.

mod accounts;
mod delete;
mod files;
mod org_docs;
mod orgs;
mod rows;
mod scope;
mod vault;

use crate::error::StoreResult;
use crate::store::SqlStore;
use kemlock_app::ports::StoreError;
use kemlock_crypto::seal::ServerSeal;
use kemlock_domain::ServerId;
use kemlock_vaultwarden::ImportSink;
use kemlock_vaultwarden::mapping::{
    FileCopy, MappedAccount, MappedAttachment, MappedCipherState, MappedFolder, MappedItem,
    MappedRsaKey,
};
use kemlock_vaultwarden::settings::MappedSettings;
use kemlock_vaultwarden::snapshot::{RowKey, Table};
use sea_orm::{DatabaseTransaction, TransactionTrait};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::PathBuf;
use time::OffsetDateTime;
use uuid::Uuid;

/// Events older than this many days are not imported, unless the options say otherwise.
pub const DEFAULT_EVENTS_RETENTION_DAYS: i64 = 90;

/// Why a pass failed.
#[derive(Debug, thiserror::Error)]
pub enum ImportError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("{what}: {source}")]
    Io {
        what: String,
        #[source]
        source: std::io::Error,
    },
    /// Data the store can't take; the text says which.
    #[error("{0}")]
    Invalid(String),
    #[error("this import pass is already finished")]
    Finished,
}

pub(super) type Res<T> = Result<T, ImportError>;

pub(super) fn invalid(text: impl Into<String>) -> ImportError {
    ImportError::Invalid(text.into())
}

/// Where the Bitwarden API keeps attachments and Send files, as it names them: its blob store.
/// The keys are the API's own, `<cipher id>/<attachment id>` for an attachment and
/// `sends/<send id>/<file id>` for a Send's file, so a file put here is one the API finds, in
/// whichever folder or bucket the server is set to keep files in.
pub trait ImportFiles: fmt::Debug + Send + Sync {
    /// Stores `bytes` under `key`, replacing what was there.
    fn put<'a>(&'a self, key: &'a str, bytes: Vec<u8>) -> ImportFilesFuture<'a>;
    /// Removes `key`; removing what isn't there is fine.
    fn delete<'a>(&'a self, key: &'a str) -> ImportFilesFuture<'a>;
}

/// What [`ImportFiles`] returns: nothing, or the reason in words.
pub type ImportFilesFuture<'a> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + 'a>>;

/// What a pass needs besides the data.
#[derive(Clone, Debug)]
pub struct ImportOptions {
    /// The data folder: `rsa_key.pem` goes here, where the Bitwarden API reads its token key.
    pub files_root: PathBuf,
    /// Where attachments and Send files go: the server's file storage, as the Bitwarden API reads
    /// it. There is no folder fallback, because a Send's file is kept by the API at a blob named
    /// by the Send's id and a copy made anywhere else is never found.
    pub files: std::sync::Arc<dyn ImportFiles>,
    /// The time of the import, for what Vaultwarden has no timestamp for.
    pub now: OffsetDateTime,
    /// Events older than this many days before `now` are not imported; `None` imports them all.
    pub events_retention_days: Option<i64>,
    /// Writes over users and spaces that already exist even though no earlier pass recorded
    /// creating them. Off unless an operator asks for it on the command line; the admin console
    /// never sets it. See `scope`.
    pub adopt_existing: bool,
}

impl ImportOptions {
    pub fn new(
        files_root: impl Into<PathBuf>,
        files: std::sync::Arc<dyn ImportFiles>,
        now: OffsetDateTime,
    ) -> Self {
        ImportOptions {
            files_root: files_root.into(),
            files,
            now,
            events_retention_days: Some(DEFAULT_EVENTS_RETENTION_DAYS),
            adopt_existing: false,
        }
    }
}

/// An open pass.
pub(super) struct Ctx {
    pub(super) txn: DatabaseTransaction,
    pub(super) origin: ServerId,
    pub(super) seal: ServerSeal,
    pub(super) opts: ImportOptions,
    /// Accounts whose vault changed: their revision date moves at the end, so apps sync.
    pub(super) touched: BTreeSet<Uuid>,
    /// The users the import owns that this pass has taken or found (see `scope`).
    pub(super) users: BTreeSet<Uuid>,
    /// The spaces the import owns that this pass has taken or found.
    pub(super) spaces: BTreeSet<Uuid>,
    /// What the pass left alone because the import doesn't own it: ids by kind.
    pub(super) refused: BTreeMap<&'static str, BTreeSet<String>>,
}

/// The store side of a move, over one transaction. See the module docs.
pub struct SqlImportSink {
    ctx: Option<Ctx>,
}

impl fmt::Debug for SqlImportSink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SqlImportSink")
            .field("open", &self.ctx.is_some())
            .finish_non_exhaustive()
    }
}

impl SqlImportSink {
    /// Opens the transaction of one pass. `seal` is the server's key, for the two-step secrets
    /// and other secrets that are kept sealed.
    pub async fn begin(
        store: &SqlStore,
        seal: ServerSeal,
        options: ImportOptions,
    ) -> Result<SqlImportSink, ImportError> {
        let txn = store.writer().begin().await.store()?;
        Ok(SqlImportSink {
            ctx: Some(Ctx {
                txn,
                origin: store.origin(),
                seal,
                opts: options,
                touched: BTreeSet::new(),
                users: BTreeSet::new(),
                spaces: BTreeSet::new(),
                refused: BTreeMap::new(),
            }),
        })
    }

    fn ctx(&mut self) -> Res<&mut Ctx> {
        self.ctx.as_mut().ok_or(ImportError::Finished)
    }
}

impl ImportSink for SqlImportSink {
    type Error = ImportError;

    async fn put_accounts(&mut self, accounts: &[MappedAccount]) -> Result<(), ImportError> {
        accounts::put_accounts(self.ctx()?, accounts).await
    }

    async fn put_folders(&mut self, folders: &[MappedFolder]) -> Result<(), ImportError> {
        vault::put_folders(self.ctx()?, folders).await
    }

    async fn put_items(&mut self, items: &[MappedItem]) -> Result<(), ImportError> {
        vault::put_items(self.ctx()?, items).await
    }

    async fn put_cipher_states(&mut self, states: &[MappedCipherState]) -> Result<(), ImportError> {
        vault::put_cipher_states(self.ctx()?, states).await
    }

    async fn put_attachments(
        &mut self,
        attachments: &[MappedAttachment],
    ) -> Result<(), ImportError> {
        vault::put_attachments(self.ctx()?, attachments).await
    }

    async fn put_carried(&mut self, table: &Table) -> Result<(), ImportError> {
        let ctx = self.ctx()?;
        // Only the rows of users and spaces the import owns are written.
        let table = &scope::admit(ctx, table).await?;
        rows::put_table(ctx, table).await?;
        match table.name() {
            "devices" => accounts::put_devices(ctx, table).await,
            "twofactor" => accounts::put_twofactor(ctx, table).await,
            "organizations" => orgs::put_organizations(ctx, table).await,
            "users_organizations" => orgs::put_members(ctx, table).await,
            "collections" => orgs::put_collections(ctx, table).await,
            "ciphers_collections" => orgs::put_item_collections(ctx, table).await,
            "users_collections" => orgs::put_member_grants(ctx, table).await,
            "groups" => orgs::put_groups(ctx, table).await,
            "collections_groups" => orgs::put_group_grants(ctx, table).await,
            "groups_users" => orgs::put_group_members(ctx, table).await,
            "emergency_access" => orgs::put_emergency_access(ctx, table).await,
            "event" => orgs::put_events(ctx, table).await,
            // Policies, Sends, organization API keys, SSO links and invitations are kept in
            // `vw_rows` until the server serves them.
            _ => Ok(()),
        }
    }

    async fn put_settings(&mut self, settings: &MappedSettings) -> Result<(), ImportError> {
        orgs::put_settings(self.ctx()?, settings).await
    }

    async fn put_rsa_key(&mut self, key: &MappedRsaKey) -> Result<(), ImportError> {
        files::put_rsa_key(self.ctx()?, key).await
    }

    async fn copy_file(&mut self, file: &FileCopy) -> Result<(), ImportError> {
        files::copy_file(self.ctx()?, file).await
    }

    async fn delete_rows(
        &mut self,
        table: &'static str,
        keys: &[RowKey],
    ) -> Result<(), ImportError> {
        delete::delete_rows(self.ctx()?, table, keys).await
    }

    fn refused(&self) -> BTreeMap<&'static str, Vec<String>> {
        self.ctx.as_ref().map_or_else(BTreeMap::new, |ctx| {
            ctx.refused
                .iter()
                .map(|(kind, ids)| (*kind, ids.iter().cloned().collect()))
                .collect()
        })
    }

    /// Moves the revision date of every account whose vault changed, then commits.
    async fn finish(&mut self) -> Result<(), ImportError> {
        let ctx = self.ctx.take().ok_or(ImportError::Finished)?;
        org_docs::sync(&ctx).await?;
        vault::bump_revisions(&ctx).await?;
        scope::refresh_marks(&ctx).await?;
        ctx.txn.commit().await.store()?;
        Ok(())
    }
}
