//! The move from Vaultwarden, started from the admin console and run in the background.
//!
//! `POST /admin/v1/migration/start` must answer inside the request timeout, and a move reads a
//! whole Vaultwarden server and copies its files, so [`VaultwardenMove`] (the admin API's
//! `MigrationRunner`) only takes the lease [`MIGRATION_LEASE`], records the move as running and
//! hands the work to a task. The task does what `kemlock-cli import-vaultwarden --apply` does:
//! `kemlock-vaultwarden` reads and maps the source (read-only), and `kemlock-store-sql`'s
//! `SqlImportSink` writes the accounts, vaults, files and carried rows in one transaction, so a
//! failed move leaves nothing half written and a rerun finds what an earlier one put. Its stage
//! and its result or error go to the status the Migration screen shows (`MigrationRecord`), which
//! every replica reads from the same table.
//!
//! Where the console may read from: only a SQLite file (and, optionally, a folder of its files)
//! inside the `import` folder of the data folder, resolved with symlinks followed and refused when
//! it lands outside. No database URL and no other path is taken from the console, because an admin
//! who could name any file or database could make the server connect anywhere, probe which files
//! exist, or read a database built to overwrite other accounts. `kemlock-cli import-vaultwarden`
//! (run by whoever runs the server) still takes URLs and any folder. Both paths write only what an
//! import created (see `kemlock-store-sql`'s `vaultwarden::scope`).
//!
//! One move runs at a time on the whole cluster: the lease is taken before anything starts and
//! given back when the task ends. A holder that crashed leaves a running status behind and a
//! lease that lapses after [`LEASE_TTL`]; [`VaultwardenMove::recover`], at start, turns such a
//! status into a failure the admin can retry from.

use crate::adapters::ServerCrypto;
use kemlock_app::admin::{
    AdminError, AdminEvent, AdminEventRepo, MigrationRecord, MigrationRequest, MigrationRunner,
    MigrationState, MigrationStatus,
};
use kemlock_app::notices::BoxFuture;
use kemlock_app::ports::{Clock, Zeroizing};
use kemlock_crypto::rand;
use kemlock_crypto::seal::ServerSeal;
use kemlock_domain::UserId;
use kemlock_store_sql::{ImportFiles, ImportOptions, SqlImportSink, SqlStore};
use kemlock_vaultwarden::{
    ApplyReport, Database, ReadError, Source, apply, map_snapshot, read_snapshot, render_plan,
};
use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use time::OffsetDateTime;

/// The lease that lets one move run at a time.
pub const MIGRATION_LEASE: &str = "vaultwarden-migration";
/// How long a replica holds the lease: a move can take hours, and a crashed holder is an obstacle
/// only until this lapses.
pub const LEASE_TTL: time::Duration = time::Duration::hours(12);

/// What the task says when the server stopped under a running move.
const INTERRUPTED: &str =
    "the server stopped before the move finished; nothing was half written, start it again";

/// The folder inside the data folder that the console reads Vaultwarden's data from. Whoever runs
/// the server puts a copy of the data folder (or just `db.sqlite3`) there; an admin can't.
pub const IMPORT_FOLDER: &str = "import";

/// What the console says of every source it won't take, missing or refused alike, so the answer
/// shows nothing about the host.
const NOT_A_SOURCE: &str = "that isn't a Vaultwarden SQLite database in the import folder: copy \
    db.sqlite3 into the import folder of the server's data folder and name it relative to that \
    folder (database URLs and other folders are for kemlock-cli import-vaultwarden)";

/// Why the console won't start a second move.
const ALREADY_DONE: &str = "a move from Vaultwarden has already finished; run any later pass \
    with kemlock-cli import-vaultwarden";

fn not_a_source() -> AdminError {
    AdminError::Invalid(NOT_A_SOURCE.to_owned())
}

fn holder_name() -> String {
    rand::bytes::<16>()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// A source typed in the console as a path relative to the import folder: plain names joined by
/// `/`, nothing else. An absolute path, a drive letter or UNC share, `.` or `..`, a backslash and
/// a `:` are refused before anything touches the file system, because merely resolving a path
/// like `\\host\share` on Windows is a network connection that hands over the service account's
/// credentials.
fn relative(name: &str) -> Option<PathBuf> {
    let name = name.trim();
    if name.is_empty() || name.contains('\\') || name.contains(':') {
        return None;
    }
    let mut out = PathBuf::new();
    for component in Path::new(name).components() {
        match component {
            Component::Normal(part) => out.push(part),
            _ => return None,
        }
    }
    (!out.as_os_str().is_empty()).then_some(out)
}

/// `relative` inside `root`, with symlinks followed; `None` when it isn't there or lands outside.
fn inside(root: &Path, relative: &Path) -> Option<PathBuf> {
    let found = root.join(relative).canonicalize().ok()?;
    found.starts_with(root).then_some(found)
}

/// The source the console may read, from what the admin typed, and how to show it: a SQLite file
/// (or a folder holding `db.sqlite3`) inside `<data folder>/import`, and optionally a folder of
/// attachments, Sends, `rsa_key.pem` and `config.json` inside it too, all named relative to the
/// import folder. Any other source is refused with the same error.
fn console_source(
    data_folder: &Path,
    from: &str,
    files: Option<&str>,
) -> Result<(Source, String), AdminError> {
    // Whatever is typed is checked as text before the file system is asked anything.
    let from = relative(from).ok_or_else(not_a_source)?;
    let files = match files {
        Some(files) => Some(relative(files).ok_or_else(not_a_source)?),
        None => None,
    };
    let root = data_folder
        .join(IMPORT_FOLDER)
        .canonicalize()
        .map_err(|_| not_a_source())?;
    let found = inside(&root, &from).ok_or_else(not_a_source)?;
    let database = if found.is_dir() {
        // The database may itself be a link that leads out.
        let inner = found.strip_prefix(&root).map_err(|_| not_a_source())?;
        inside(&root, &inner.join("db.sqlite3")).ok_or_else(not_a_source)?
    } else {
        found
    };
    if !database.is_file() {
        return Err(not_a_source());
    }
    let folder = match files {
        Some(files) => {
            let folder = inside(&root, &files).ok_or_else(not_a_source)?;
            if !folder.is_dir() {
                return Err(not_a_source());
            }
            folder
        }
        None => database
            .parent()
            .map(Path::to_path_buf)
            .ok_or_else(not_a_source)?,
    };
    let relative = database.strip_prefix(&root).unwrap_or(&database);
    // Relative to the import folder, as the console takes it, so the form can send it back.
    let shown = relative.to_string_lossy().replace('\\', "/");
    Ok((
        Source {
            database: Database::Sqlite(database),
            folder: Some(folder),
        },
        shown,
    ))
}

/// What the console is told of a source that couldn't be read. Only what is about the Vaultwarden
/// data itself (its version, its `config.json`) is passed on; the rest of the text, which can
/// name paths, goes to the server's log.
fn read_failure(error: &ReadError) -> String {
    match error {
        ReadError::SchemaOlder { .. }
        | ReadError::SchemaUnknown { .. }
        | ReadError::BadConfig(_) => error.to_string(),
        ReadError::NotVaultwarden(_) => "this isn't a Vaultwarden database".to_owned(),
        _ => "couldn't read the Vaultwarden database; the server's log says why".to_owned(),
    }
}

/// What the console is told when writing failed: a store error can quote a constraint, a row or a
/// path, so the text goes to the server's log and the console gets this.
pub const WRITE_FAILED: &str =
    "writing to Kemlock Server failed and nothing was written; the server's log says why";

fn write_failure(error: &dyn std::fmt::Display) -> String {
    tracing::warn!(%error, "couldn't write the Vaultwarden data into Kemlock Server");
    WRITE_FAILED.to_owned()
}

/// How many ids of one kind the text lists before it says how many more there were.
const SHOWN_IDS: usize = 20;

/// The ids a pass left alone, in words: `user 2 (id, id); space 1 (id)`.
fn refused_text(refused: &BTreeMap<&'static str, Vec<String>>) -> String {
    refused
        .iter()
        .filter(|(_, ids)| !ids.is_empty())
        .map(|(kind, ids)| {
            let shown: Vec<&str> = ids.iter().take(SHOWN_IDS).map(String::as_str).collect();
            let more = ids.len().saturating_sub(SHOWN_IDS);
            let tail = if more > 0 {
                format!(", and {more} more")
            } else {
                String::new()
            };
            format!("{kind} {} ({}{tail})", ids.len(), shown.join(", "))
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// Starts and runs moves from Vaultwarden into this server's own database and data folder.
#[derive(Clone)]
pub struct VaultwardenMove {
    store: SqlStore,
    crypto: ServerCrypto,
    /// What `ServerSeal` is made from for each move; wiped when the last clone is dropped.
    server_key: Arc<Zeroizing<[u8; 32]>>,
    /// Where the import copies `rsa_key.pem`.
    data_folder: PathBuf,
    holder: Arc<str>,
    files: Arc<dyn ImportFiles>,
}

impl std::fmt::Debug for VaultwardenMove {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultwardenMove").finish_non_exhaustive()
    }
}

/// What a finished pass wrote, in words.
pub fn describe(report: &ApplyReport) -> String {
    let mut text = format!(
        "wrote {} accounts, {} folders, {} items, {} attachments ({} files, {} bytes), \
         {} carried rows, {} settings",
        report.accounts,
        report.folders,
        report.items,
        report.attachments,
        report.files,
        report.file_bytes,
        report.carried_rows,
        report.settings,
    );
    if report.rsa_key {
        text.push_str(
            ". Vaultwarden's rsa_key.pem was carried over: restart Kemlock Server so it loads it",
        );
    }
    // Settings the console doesn't have are not carried: that is about the file, not about ids.
    let mut refused = report.refused.clone();
    if let Some(settings) = refused.remove("setting") {
        text.push_str(&format!(
            ". Settings that are not in the console's list were not carried: {}",
            settings.join(", ")
        ));
    }
    // The source's token key is never put over the key of a server that has Bitwarden accounts.
    if refused.remove("rsa_key").is_some() {
        text.push_str(
            ". Vaultwarden's rsa_key.pem was not carried over: this server has Bitwarden accounts \
             of its own, and its token key stays as it is",
        );
    }
    let refused = refused_text(&refused);
    if !refused.is_empty() {
        text.push_str(&format!(
            ". Left alone, because the import didn't create them or this server changed them \
             since: {refused}. To overwrite them on purpose, run kemlock-cli import-vaultwarden \
             --adopt-existing"
        ));
    }
    text
}

impl VaultwardenMove {
    /// A runner over `store`, sealing under `server_key`, writing `rsa_key.pem` into `data_folder`
    /// and attachments and Send files into `files`, the file storage the Bitwarden API reads.
    pub fn new(
        store: SqlStore,
        crypto: ServerCrypto,
        server_key: &[u8; 32],
        data_folder: PathBuf,
        files: Arc<dyn ImportFiles>,
    ) -> VaultwardenMove {
        VaultwardenMove {
            store,
            crypto,
            server_key: Arc::new(Zeroizing::new(*server_key)),
            data_folder,
            holder: holder_name().into(),
            files,
        }
    }

    fn record(&self) -> MigrationRecord<SqlStore, ServerCrypto> {
        MigrationRecord {
            repo: self.store.clone(),
            clock: self.crypto.clone(),
        }
    }

    /// Turns a status left `running` by a server that stopped into a failure, when no replica
    /// holds the lease any more. Called once at start. `Ok(true)` when it did.
    pub async fn recover(&self) -> Result<bool, AdminError> {
        let record = self.record();
        let status = record.status().await?;
        if status.state != MigrationState::Running {
            return Ok(false);
        }
        // A running move on another replica holds the lease; only an orphan can be taken.
        if !self
            .store
            .try_lease(MIGRATION_LEASE, &self.holder, LEASE_TTL)
            .await?
        {
            return Ok(false);
        }
        let outcome = record
            .failed(
                status.started_by.unwrap_or(UserId(uuid::Uuid::nil())),
                status.source.unwrap_or_default(),
                INTERRUPTED.to_owned(),
            )
            .await;
        if let Err(e) = self
            .store
            .release_lease(MIGRATION_LEASE, &self.holder)
            .await
        {
            tracing::warn!(error = %e, "couldn't release the migration lease");
        }
        outcome.map(|_| true)
    }

    async fn begin(&self, request: MigrationRequest) -> Result<MigrationStatus, AdminError> {
        let (source, shown) =
            console_source(&self.data_folder, &request.from, request.files.as_deref())?;
        if !self
            .store
            .try_lease(MIGRATION_LEASE, &self.holder, LEASE_TTL)
            .await?
        {
            return Err(AdminError::State(
                "a move from Vaultwarden is already running",
            ));
        }
        // One move from the console. What this server holds has been changed here since, and a
        // second console move would be a person's one click away from undoing it; later passes
        // are the operator's, with kemlock-cli import-vaultwarden.
        match self.record().status().await {
            Ok(status) if status.state == MigrationState::Done => {
                self.release().await;
                return Err(AdminError::State(ALREADY_DONE));
            }
            Ok(_) => {}
            Err(e) => {
                self.release().await;
                return Err(e);
            }
        }
        let status = match self.record().running(request.by, shown.clone()).await {
            Ok(status) => status,
            Err(e) => {
                self.release().await;
                return Err(e);
            }
        };
        let job = self.clone();
        tokio::spawn(async move { job.run(request.by, source, shown).await });
        Ok(status)
    }

    async fn release(&self) {
        if let Err(e) = self
            .store
            .release_lease(MIGRATION_LEASE, &self.holder)
            .await
        {
            tracing::warn!(error = %e, "couldn't release the migration lease");
        }
    }

    /// The background task: the move, then its outcome into the status, then the lease back.
    async fn run(self, by: UserId, source: Source, shown: String) {
        let record = self.record();
        let saved = match self.import(&source).await {
            Ok((report, carried)) => {
                tracing::info!(%report, "the move from Vaultwarden is done");
                // What it changed, and what it refused, go to the admin event log, and so does
                // each setting it carried over from `config.json`, by name and value: the source
                // is not trusted, and an admin reading the log sees what it set.
                self.audit(by, "admin.migration.done", &shown, &report)
                    .await;
                for setting in &carried {
                    self.audit(by, "admin.migration.setting", &shown, setting)
                        .await;
                }
                record.finished(report).await
            }
            Err(error) => {
                tracing::warn!(%error, "the move from Vaultwarden failed");
                self.audit(by, "admin.migration.failed", &shown, &error)
                    .await;
                record.failed(by, shown, error).await
            }
        };
        if let Err(e) = saved {
            tracing::error!(error = %e, "couldn't record the outcome of the Vaultwarden move");
        }
        self.release().await;
    }

    /// Reads, maps and writes. The error is in words for the admin.
    async fn import(&self, source: &Source) -> Result<(String, Vec<String>), String> {
        let record = self.record();
        self.stage(&record, "reading the Vaultwarden data", None)
            .await;
        let snapshot = read_snapshot(source).await.map_err(|e| {
            tracing::warn!(error = %e, "couldn't read the Vaultwarden source");
            read_failure(&e)
        })?;
        self.stage(&record, "mapping the data", None).await;
        let mapped = map_snapshot(&snapshot).map_err(|e| format!("can't map the data: {e}"))?;
        let plan = render_plan(&snapshot.meta, &mapped, None);
        self.stage(&record, "writing to Kemlock Server", Some(plan))
            .await;
        let options = ImportOptions::new(
            self.data_folder.clone(),
            self.files.clone(),
            OffsetDateTime::now_utc(),
        );
        let mut sink =
            SqlImportSink::begin(&self.store, ServerSeal::new(&self.server_key), options)
                .await
                .map_err(|e| write_failure(&e))?;
        let report = apply(&mapped, &[], &mut sink)
            .await
            .map_err(|e| write_failure(&e))?;
        // The settings that were written, each as `name = value`, for the event log.
        let refused = report.refused.get("setting").cloned().unwrap_or_default();
        let carried = mapped
            .settings
            .values
            .iter()
            .filter(|(name, _)| !refused.contains(name))
            .map(|(name, value)| format!("{name} = {value}"))
            .collect();
        Ok((describe(&report), carried))
    }

    /// Writes a line of the admin event log for the move, as the admin who started it. A failure to
    /// write it is logged and changes nothing: the move has happened.
    async fn audit(&self, by: UserId, action: &str, source: &str, what: &str) {
        let event = AdminEvent {
            actor: Some(by),
            device: None,
            action: action.to_owned(),
            target: Some(format!("{IMPORT_FOLDER}/{source}: {what}")),
            ip: None,
            at: self.crypto.now(),
        };
        if let Err(e) = self.store.record_admin_event(event).await {
            tracing::error!(action, error = %e, "couldn't record the Vaultwarden move in the event log");
        }
    }

    async fn stage(
        &self,
        record: &MigrationRecord<SqlStore, ServerCrypto>,
        stage: &str,
        plan: Option<String>,
    ) {
        if let Err(e) = record.progress(stage, plan).await {
            tracing::warn!(error = %e, "couldn't record the stage of the move");
        }
    }
}

impl MigrationRunner for VaultwardenMove {
    fn start<'a>(
        &'a self,
        request: MigrationRequest,
    ) -> BoxFuture<'a, Result<MigrationStatus, AdminError>> {
        Box::pin(self.begin(request))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_report_says_what_was_written_and_when_to_restart() {
        let report = ApplyReport {
            accounts: 2,
            folders: 1,
            items: 30,
            attachments: 4,
            carried_rows: 5,
            settings: 3,
            files: 6,
            file_bytes: 1024,
            ..ApplyReport::default()
        };
        let text = describe(&report);
        assert_eq!(
            text,
            "wrote 2 accounts, 1 folders, 30 items, 4 attachments (6 files, 1024 bytes), \
             5 carried rows, 3 settings"
        );
        let with_key = describe(&ApplyReport {
            rsa_key: true,
            ..report
        });
        assert!(
            with_key.ends_with("restart Kemlock Server so it loads it"),
            "{with_key}"
        );
    }

    #[test]
    fn a_report_says_when_the_sources_token_key_was_not_carried() {
        let report = ApplyReport {
            refused: BTreeMap::from([("rsa_key", vec!["rsa_key.pem".to_owned()])]),
            ..ApplyReport::default()
        };
        let text = describe(&report);
        assert!(text.contains("rsa_key.pem was not carried over"), "{text}");
        assert!(!text.contains("restart Kemlock Server"), "{text}");
        assert!(!text.contains("Left alone"), "{text}");
    }

    #[test]
    fn a_report_names_the_ids_the_import_left_alone() {
        let id = "a1111111-1111-4111-8111-111111111111";
        let report = ApplyReport {
            refused: BTreeMap::from([("user", vec![id.to_owned()])]),
            ..ApplyReport::default()
        };
        let text = describe(&report);
        assert!(
            text.contains(&format!(
                "Left alone, because the import didn't create them or this server changed them \
                 since: user 1 ({id})"
            )),
            "{text}"
        );
        assert!(text.contains("--adopt-existing"), "{text}");
        let many = BTreeMap::from([("space", (0..25).map(|n| n.to_string()).collect())]);
        let listed = refused_text(&many);
        assert!(listed.starts_with("space 25 (0, 1, 2"), "{listed}");
        assert!(listed.ends_with(", and 5 more)"), "{listed}");
    }

    /// An import folder with a `db.sqlite3` in it, inside a data folder, and a file outside it.
    fn data_folder() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("a temp dir");
        std::fs::create_dir_all(dir.path().join(IMPORT_FOLDER).join("vw")).expect("folders");
        std::fs::write(dir.path().join(IMPORT_FOLDER).join("db.sqlite3"), b"x").expect("a file");
        std::fs::write(
            dir.path().join(IMPORT_FOLDER).join("vw").join("db.sqlite3"),
            b"x",
        )
        .expect("a file");
        std::fs::write(dir.path().join("server.key"), b"secret").expect("a file");
        dir
    }

    fn refusal(result: Result<(Source, String), AdminError>) -> String {
        match result {
            Err(AdminError::Invalid(text)) => text,
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn the_console_takes_a_sqlite_file_or_folder_inside_the_import_folder() {
        let dir = data_folder();
        let root = dir
            .path()
            .join(IMPORT_FOLDER)
            .canonicalize()
            .expect("a root");

        let (source, shown) = console_source(dir.path(), "db.sqlite3", None).expect("a file");
        assert_eq!(source.database, Database::Sqlite(root.join("db.sqlite3")));
        assert_eq!(source.folder, Some(root.clone()));
        assert_eq!(shown, "db.sqlite3");

        let (source, shown) = console_source(dir.path(), " vw ", None).expect("a folder");
        assert_eq!(
            source.database,
            Database::Sqlite(root.join("vw").join("db.sqlite3"))
        );
        assert_eq!(shown, "vw/db.sqlite3");

        // What the status shows is a source the console takes as it is: a retry from the form.
        let (again, same) = console_source(dir.path(), &shown, None).expect("the shown source");
        assert_eq!(same, shown);
        assert_eq!(again.database, source.database);

        // A folder of files, named the same way.
        let (source, _) = console_source(dir.path(), "db.sqlite3", Some("vw")).expect("files");
        assert_eq!(source.folder, Some(root.join("vw")));
    }

    #[test]
    fn only_plain_relative_names_get_as_far_as_the_file_system() {
        for ok in ["db.sqlite3", " vw/db.sqlite3 ", "a/b/c", "vw/"] {
            assert!(relative(ok).is_some(), "{ok:?}");
        }
        for bad in [
            "",
            "   ",
            ".",
            "..",
            "./db.sqlite3",
            "../server.key",
            "vw/../../x",
            "/etc/passwd",
            "//attacker/share/x",
            "\\\\attacker\\share\\x",
            "\\\\?\\C:\\x",
            "C:/x",
            "C:x",
            "db.sqlite3:stream",
            "vw\\db.sqlite3",
            "postgres://db/vw",
        ] {
            assert!(relative(bad).is_none(), "{bad:?}");
        }
        // An absolute path inside the import folder isn't taken either, only a relative name.
        let dir = data_folder();
        let inside_it = dir.path().join(IMPORT_FOLDER).join("db.sqlite3");
        let named = inside_it.display().to_string();
        refusal(console_source(dir.path(), &named, None));
    }

    #[test]
    fn the_console_refuses_everything_else_with_one_answer() {
        let dir = data_folder();
        let outside = dir.path().join("server.key").display().to_string();
        let sources = [
            "postgres://u:p@internal-db/vw",
            "mysql://u:p@10.0.0.5/vw",
            "mariadb://db/vw",
            "../server.key",
            "vw/../../server.key",
            outside.as_str(),
            "/etc/passwd",
            "missing.sqlite3",
        ];
        let mut answers = Vec::new();
        for from in sources {
            answers.push(refusal(console_source(dir.path(), from, None)));
        }
        assert!(
            answers.windows(2).all(|pair| pair[0] == pair[1]),
            "a missing source and a refused one read the same: {answers:?}"
        );
        assert!(!answers[0].contains("internal-db"));

        // The files folder follows the same rules.
        let answer = refusal(console_source(dir.path(), "db.sqlite3", Some("..")));
        assert_eq!(answer, answers[0]);
        let answer = refusal(console_source(
            dir.path(),
            "db.sqlite3",
            Some("postgres://db"),
        ));
        assert_eq!(answer, answers[0]);
        // A file where a folder is wanted, and a data folder with no import folder at all.
        let answer = refusal(console_source(dir.path(), "db.sqlite3", Some("db.sqlite3")));
        assert_eq!(answer, answers[0]);
        let bare = tempfile::tempdir().expect("a temp dir");
        assert_eq!(
            refusal(console_source(bare.path(), "db.sqlite3", None)),
            answers[0]
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_link_that_leads_out_of_the_import_folder_is_refused() {
        let dir = data_folder();
        let import = dir.path().join(IMPORT_FOLDER);
        std::os::unix::fs::symlink(dir.path().join("server.key"), import.join("link.sqlite3"))
            .expect("a link");
        std::os::unix::fs::symlink(dir.path(), import.join("up")).expect("a link");
        let first = refusal(console_source(dir.path(), "link.sqlite3", None));
        let second = refusal(console_source(dir.path(), "up/server.key", None));
        assert_eq!(first, second);
        // A folder whose db.sqlite3 is a link out is refused too.
        std::fs::create_dir_all(import.join("trap")).expect("a folder");
        std::os::unix::fs::symlink(
            dir.path().join("server.key"),
            import.join("trap").join("db.sqlite3"),
        )
        .expect("a link");
        assert_eq!(refusal(console_source(dir.path(), "trap", None)), first);
    }

    #[test]
    fn only_what_is_about_the_data_is_told_to_the_console() {
        let leaked = "/srv/secret/path: connection refused to 10.0.0.5:5432";
        for error in [
            ReadError::Database(leaked.to_owned()),
            ReadError::Io {
                path: "/srv/secret/path".to_owned(),
                message: "denied".to_owned(),
            },
            ReadError::NoDatabase("/srv/secret/path".to_owned()),
            ReadError::NotVaultwarden(leaked.to_owned()),
        ] {
            let told = read_failure(&error);
            assert!(
                !told.contains("secret") && !told.contains("10.0.0.5"),
                "{told}"
            );
        }
        let newer = ReadError::SchemaUnknown {
            unknown: vec!["2099-01-01".to_owned()],
        };
        assert!(read_failure(&newer).contains("2099-01-01"));
    }

    #[test]
    fn holder_names_differ() {
        assert_ne!(holder_name(), holder_name());
        assert_eq!(holder_name().len(), 32);
    }
}
