//! The Migration screen: where the move from Vaultwarden stands, and what starts it.
//!
//! A move reads a Vaultwarden server's data (read-only) and writes it into this one, which takes
//! far longer than a request may, so `POST start` only starts it: a [`MigrationRunner`] takes a
//! lease so one replica runs it, records the move as running and carries on in the background;
//! `GET` shows its stage while it runs and its result when it ends.
//!
//! The status is one JSON value in the `settings` table (`migration.status`), so a restart
//! doesn't forget it and every replica shows the same one. The runner is the server's: it owns the
//! store, the server key and the data folder the import writes to (`kemlock-vaultwarden` reads
//! and maps, `kemlock-store-sql` writes).

use super::error::AdminError;
use super::ports::SettingsRepo;
use crate::notices::BoxFuture;
use crate::ports::Clock;
use kemlock_domain::UserId;
use serde::{Deserialize, Serialize};

/// The `settings` key the status is kept under.
pub const STATUS_KEY: &str = "migration.status";

/// Where a move stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MigrationState {
    /// Nothing was started.
    Idle,
    /// The source was read and the plan made; nothing was written to Kemlock Server. (How a move
    /// ended before the import was wired in; kept so an old status still reads.)
    Planned,
    /// A move is under way; `stage` says where.
    Running,
    /// The move finished; `report` says what was written.
    Done,
    /// The last attempt failed; `error` says why.
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationStatus {
    pub state: MigrationState,
    /// The source as it may be shown: a data folder, or a URL without its password.
    pub source: Option<String>,
    /// The plan of what the move does, in words, once the source was read.
    pub plan: Option<String>,
    pub error: Option<String>,
    /// When it was started, in Unix seconds.
    pub at: Option<i64>,
    pub started_by: Option<UserId>,
    /// While running: what it is doing now.
    #[serde(default)]
    pub stage: Option<String>,
    /// When done: what was written, in words.
    #[serde(default)]
    pub report: Option<String>,
    /// When it ended, done or failed, in Unix seconds.
    #[serde(default)]
    pub finished_at: Option<i64>,
}

impl MigrationStatus {
    pub fn idle() -> MigrationStatus {
        MigrationStatus {
            state: MigrationState::Idle,
            source: None,
            plan: None,
            error: None,
            at: None,
            started_by: None,
            stage: None,
            report: None,
            finished_at: None,
        }
    }
}

/// What starting a move needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MigrationRequest {
    /// A SQLite file (or folder with `db.sqlite3`) inside the data folder's `import` folder.
    pub from: String,
    /// A folder inside the import folder with the attachments, sends and `rsa_key.pem`.
    pub files: Option<String>,
    /// The admin who started it.
    pub by: UserId,
}

/// Starts moves. Object safe, so the admin API holds one without knowing the store.
pub trait MigrationRunner: Send + Sync {
    /// Starts the move in the background and returns the status it just recorded (running).
    ///
    /// `Invalid` when the source can't be one (a path that isn't there, say); `State` when a
    /// move is already running, here or on another replica. A source that is there but can't be
    /// read (not a Vaultwarden database, no access) is not refused here: reading is part of the
    /// background work, and the status says it failed.
    fn start<'a>(
        &'a self,
        request: MigrationRequest,
    ) -> BoxFuture<'a, Result<MigrationStatus, AdminError>>;
}

#[derive(Debug)]
pub struct MigrationRecord<R, C> {
    pub repo: R,
    pub clock: C,
}

impl<R: SettingsRepo, C: Clock> MigrationRecord<R, C> {
    /// The status; `Idle` when none was recorded or the record is unreadable.
    pub async fn status(&self) -> Result<MigrationStatus, AdminError> {
        let rows = self.repo.settings_with_prefix(STATUS_KEY).await?;
        Ok(rows
            .into_iter()
            .find(|(key, _)| key == STATUS_KEY)
            .and_then(|(_, value)| serde_json::from_str(&value).ok())
            .unwrap_or_else(MigrationStatus::idle))
    }

    fn now(&self) -> i64 {
        self.clock.now().unix_timestamp()
    }

    /// Records the plan the admin started a move with.
    pub async fn planned(
        &self,
        by: UserId,
        source: String,
        plan: String,
    ) -> Result<MigrationStatus, AdminError> {
        self.save(MigrationStatus {
            state: MigrationState::Planned,
            source: Some(source),
            plan: Some(plan),
            at: Some(self.now()),
            started_by: Some(by),
            ..MigrationStatus::idle()
        })
        .await
    }

    /// Records that a move was started, replacing whatever the last one left.
    pub async fn running(&self, by: UserId, source: String) -> Result<MigrationStatus, AdminError> {
        self.save(MigrationStatus {
            state: MigrationState::Running,
            source: Some(source),
            at: Some(self.now()),
            started_by: Some(by),
            stage: Some("starting".to_owned()),
            ..MigrationStatus::idle()
        })
        .await
    }

    /// Records the stage a running move reached, and its plan once it has one. Nothing changes
    /// when no move is running (a stage that arrives after the move ended is stale).
    pub async fn progress(
        &self,
        stage: &str,
        plan: Option<String>,
    ) -> Result<MigrationStatus, AdminError> {
        let mut status = self.status().await?;
        if status.state != MigrationState::Running {
            return Ok(status);
        }
        status.stage = Some(stage.to_owned());
        if plan.is_some() {
            status.plan = plan;
        }
        self.save(status).await
    }

    /// Records that the running move finished, with what it wrote.
    pub async fn finished(&self, report: String) -> Result<MigrationStatus, AdminError> {
        let mut status = self.status().await?;
        status.state = MigrationState::Done;
        status.stage = None;
        status.error = None;
        status.report = Some(report);
        status.finished_at = Some(self.now());
        self.save(status).await
    }

    /// Records that the attempt failed.
    pub async fn failed(
        &self,
        by: UserId,
        source: String,
        error: String,
    ) -> Result<MigrationStatus, AdminError> {
        // A move that was running keeps its start time and the plan it had made.
        let (at, plan) = match self.status().await {
            Ok(s) if s.state == MigrationState::Running => (s.at, s.plan),
            _ => (Some(self.now()), None),
        };
        self.save(MigrationStatus {
            state: MigrationState::Failed,
            source: Some(source),
            plan,
            error: Some(error),
            at,
            started_by: Some(by),
            finished_at: Some(self.now()),
            ..MigrationStatus::idle()
        })
        .await
    }

    async fn save(&self, status: MigrationStatus) -> Result<MigrationStatus, AdminError> {
        let text = serde_json::to_string(&status)
            .map_err(|_| AdminError::App(crate::AppError::Store("status doesn't encode".into())))?;
        self.repo.put_setting(STATUS_KEY, &text).await?;
        Ok(status)
    }
}
