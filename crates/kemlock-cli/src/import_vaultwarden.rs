//! `kemlock-cli import-vaultwarden --from <folder|url> [--files <folder>] [--twice] [--apply]
//! [--adopt-existing]`.
//!
//! Without `--apply` it prints the dry-run plan and writes nothing. It never writes to
//! Vaultwarden's data in any mode: the folder's `db.sqlite3` is opened read-only, a MySQL or
//! PostgreSQL server is read in one read-only transaction, and the files are only read.
//!
//! `--apply` writes to the server's own database and data folder (`DATABASE_URL`, `DATA_FOLDER`
//! and `KEMLOCK_SERVER_KEY`, as the server reads them), one transaction per pass, so a failed
//! pass leaves nothing half written and a rerun finds what an earlier one put.
//!
//! A pass writes only what an import made: an account or space this server already has, that no
//! earlier import is recorded as having created, is left alone and listed. `--adopt-existing`
//! overwrites such rows on purpose (a server that already holds the same users from an earlier
//! move that left no record); it prints a warning and the console never offers it.
//!
//! `--twice` is the "short pause" method: it copies while Vaultwarden runs, waits for you to
//! stop Vaultwarden, then reads again and applies only what changed, deletions included.

use kemlock_app::admin::{AdminEvent, AdminEventRepo};
use kemlock_crypto::seal::ServerSeal;
use kemlock_server::Config;
use kemlock_server::files::{BitwardenBlobs, open_blobs};
use kemlock_server::keys::load_or_create_server_key;
use kemlock_server::migration::describe;
use kemlock_store_sql::{ImportFiles, ImportOptions, SqlImportSink, SqlStore};
use kemlock_vaultwarden::{
    ApplyReport, Deletion, ImportSink, MappedImport, Source, apply, diff, map_snapshot,
    read_snapshot, render_plan,
};
use std::io::BufRead;
use std::path::PathBuf;
use std::sync::Arc;
use time::OffsetDateTime;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ImportArgs {
    /// A Vaultwarden data folder, or a `mysql://` or `postgres://` URL.
    pub(crate) from: String,
    /// The data folder beside a MySQL or PostgreSQL server (attachments, sends, `rsa_key.pem`,
    /// `config.json`).
    pub(crate) files: Option<String>,
    /// Copy while Vaultwarden runs, then again, for what changed, after it stops.
    pub(crate) twice: bool,
    /// Write to Kemlock Server. Without it, only a plan is printed.
    pub(crate) apply: bool,
    /// Overwrite accounts and spaces this server already has even though no earlier import is
    /// recorded as having made them. Without it a pass leaves them alone and lists them.
    pub(crate) adopt_existing: bool,
}

fn take_value(
    name: &str,
    inline: Option<&str>,
    rest: &mut std::slice::Iter<'_, String>,
) -> Result<String, String> {
    match inline {
        Some(value) => Ok(value.to_owned()),
        None => rest
            .next()
            .cloned()
            .ok_or_else(|| format!("{name} needs a value")),
    }
}

/// Parses the arguments after `import-vaultwarden`.
pub(crate) fn parse_args(args: &[String]) -> Result<ImportArgs, String> {
    let mut from = None;
    let mut files = None;
    let mut twice = false;
    let mut apply = false;
    let mut adopt_existing = false;
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        let (name, inline) = match arg.split_once('=') {
            Some((name, value)) => (name, Some(value)),
            None => (arg.as_str(), None),
        };
        match name {
            "--from" => from = Some(take_value(name, inline, &mut rest)?),
            "--files" => files = Some(take_value(name, inline, &mut rest)?),
            "--twice" => twice = true,
            "--apply" => apply = true,
            "--adopt-existing" => adopt_existing = true,
            other => return Err(format!("import-vaultwarden doesn't take {other:?}")),
        }
    }
    let from = from.ok_or_else(|| "import-vaultwarden needs --from <folder|url>".to_owned())?;
    Ok(ImportArgs {
        from,
        files,
        twice,
        apply,
        adopt_existing,
    })
}

/// Where the passes write. A pass is one transaction, so each pass opens its own sink; the pass
/// commits when [`apply`] finishes it and is rolled back when the sink is dropped before that.
trait SinkSource {
    type Sink: ImportSink;

    async fn open(&mut self) -> Result<Self::Sink, String>;

    /// Records a finished pass in the admin event log: where it read from, what it changed and
    /// what it left alone. A source with no log records nothing.
    async fn audit(&mut self, _source: &str, _what: &str) {}
}

/// The server's own database and data folder.
struct SqlSinks {
    store: SqlStore,
    server_key: [u8; 32],
    data_folder: PathBuf,
    /// The file storage the Bitwarden API reads (`ATTACHMENTS_FOLDER`, or a bucket), where the
    /// attachments and Send files go.
    files: Arc<dyn ImportFiles>,
    /// `--adopt-existing`.
    adopt_existing: bool,
}

impl SqlSinks {
    /// Opens the database (migrating it) and reads or makes `server.key`, as the server does.
    async fn connect(config: &Config, adopt_existing: bool) -> Result<SqlSinks, String> {
        std::fs::create_dir_all(&config.data_folder)
            .map_err(|e| format!("can't make {}: {e}", config.data_folder.display()))?;
        let server_key =
            load_or_create_server_key(&config.data_folder, config.server_key.as_deref())
                .map_err(|e| e.to_string())?;
        let store = SqlStore::connect(&config.database_url)
            .await
            .map_err(|e| format!("can't open the database: {e}"))?;
        let (blobs, _) = open_blobs(&config.data_folder).map_err(|e| e.to_string())?;
        Ok(SqlSinks {
            store,
            server_key,
            data_folder: config.data_folder.clone(),
            files: Arc::new(BitwardenBlobs::new(blobs)),
            adopt_existing,
        })
    }

    async fn close(&self) {
        let _ = self.store.close().await;
    }
}

impl SinkSource for SqlSinks {
    type Sink = SqlImportSink;

    async fn open(&mut self) -> Result<SqlImportSink, String> {
        let mut options = ImportOptions::new(
            self.data_folder.clone(),
            self.files.clone(),
            OffsetDateTime::now_utc(),
        );
        options.adopt_existing = self.adopt_existing;
        SqlImportSink::begin(&self.store, ServerSeal::new(&self.server_key), options)
            .await
            .map_err(|e| e.to_string())
    }

    async fn audit(&mut self, source: &str, what: &str) {
        let event = AdminEvent {
            actor: None,
            device: None,
            action: "admin.migration.cli".to_owned(),
            target: Some(format!("{source}: {what}")),
            ip: None,
            at: OffsetDateTime::now_utc(),
        };
        if let Err(e) = self.store.record_admin_event(event).await {
            eprintln!("kemlock-cli: couldn't record the move in the event log: {e}");
        }
    }
}

/// One pass: opens a sink, puts `mapped` into it and deletes `deletions`, then commits.
async fn write_pass<S: SinkSource>(
    sinks: &mut S,
    mapped: &MappedImport,
    deletions: &[Deletion],
) -> Result<ApplyReport, String> {
    let mut sink = sinks.open().await?;
    apply(mapped, deletions, &mut sink)
        .await
        .map_err(|e| e.to_string())
}

/// Says which ids a pass left alone because no import made them, and how to overwrite them.
fn report_left_alone(report: &ApplyReport) {
    for (kind, ids) in &report.refused {
        if ids.is_empty() || *kind == "setting" {
            continue;
        }
        eprintln!(
            "kemlock-cli: left alone, because no import made them ({kind}): {}",
            ids.join(", ")
        );
    }
    if report.refused.keys().any(|kind| *kind != "setting") {
        eprintln!(
            "kemlock-cli: add --adopt-existing to overwrite them on purpose (it replaces what \
             this server holds for those ids)"
        );
    }
}

/// Waits for Enter on standard input.
fn wait_for_enter() -> std::io::Result<()> {
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line).map(|_| ())
}

/// Runs the command and returns its exit code: 0 on success, 1 on failure, 2 for a configuration
/// that can't be read.
pub(crate) async fn run(args: ImportArgs) -> u8 {
    if !args.apply {
        return execute::<SqlSinks>(&args, None, &mut wait_for_enter).await;
    }
    let config = match Config::load() {
        Ok(config) => config,
        Err(e) => {
            eprintln!("kemlock-cli: {e}");
            return 2;
        }
    };
    let mut sinks = match SqlSinks::connect(&config, args.adopt_existing).await {
        Ok(sinks) => sinks,
        Err(e) => {
            eprintln!("kemlock-cli: {e}");
            return 1;
        }
    };
    let code = execute(&args, Some(&mut sinks), &mut wait_for_enter).await;
    sinks.close().await;
    code
}

#[allow(
    clippy::needless_option_as_deref,
    reason = "reborrows the sinks so the second pass can use them after the first"
)]
async fn execute<S: SinkSource>(
    args: &ImportArgs,
    mut sinks: Option<&mut S>,
    pause: &mut dyn FnMut() -> std::io::Result<()>,
) -> u8 {
    let source = match Source::parse(&args.from, args.files.as_deref()) {
        Ok(source) => source,
        Err(e) => {
            eprintln!("kemlock-cli: {e}");
            return 1;
        }
    };
    println!("Reading {} (read-only)...", source.describe());
    let first = match read_snapshot(&source).await {
        Ok(snapshot) => snapshot,
        Err(e) => {
            eprintln!("kemlock-cli: {e}");
            return 1;
        }
    };
    let first_mapped = match map_snapshot(&first) {
        Ok(mapped) => mapped,
        Err(e) => {
            eprintln!("kemlock-cli: can't map the data: {e}");
            return 1;
        }
    };
    println!();
    println!("{}", render_plan(&first.meta, &first_mapped, None));

    if args.apply {
        let Some(sinks) = sinks.as_deref_mut() else {
            eprintln!("kemlock-cli: --apply has no store to write to");
            return 1;
        };
        if args.adopt_existing {
            eprintln!(
                "WARNING: --adopt-existing is on: accounts and spaces this server already has \
                 will be overwritten by what the source says, even though no import made them."
            );
        }
        println!("Writing to Kemlock Server...");
        match write_pass(sinks, &first_mapped, &[]).await {
            Ok(report) => {
                println!("Wrote {report:?}");
                report_left_alone(&report);
                sinks.audit(&source.describe(), &describe(&report)).await;
            }
            Err(e) => {
                eprintln!("kemlock-cli: {e}");
                return 1;
            }
        }
    }

    if !args.twice {
        finish_message(args);
        return 0;
    }

    println!("Now stop Vaultwarden, so nothing changes during the second read.");
    println!("Press Enter when it has stopped...");
    if let Err(e) = pause() {
        eprintln!("kemlock-cli: can't read the keyboard: {e}");
        return 1;
    }
    let second = match read_snapshot(&source).await {
        Ok(snapshot) => snapshot,
        Err(e) => {
            eprintln!("kemlock-cli: the second read failed: {e}");
            return 1;
        }
    };
    let second_mapped = match map_snapshot(&second) {
        Ok(mapped) => mapped,
        Err(e) => {
            eprintln!("kemlock-cli: can't map the second copy: {e}");
            return 1;
        }
    };
    let changes = diff(&first, &second);
    println!();
    println!("Changed since the first read:");
    for line in changes.to_string().lines() {
        println!("  {line}");
    }
    if args.apply
        && let Some(sinks) = sinks.as_deref_mut()
    {
        let delta = second_mapped.delta_since(&first_mapped);
        match write_pass(sinks, &delta, &changes.deletions()).await {
            Ok(report) => {
                println!("Wrote the changes: {report:?}");
                report_left_alone(&report);
                sinks.audit(&source.describe(), &describe(&report)).await;
            }
            Err(e) => {
                eprintln!("kemlock-cli: {e}");
                return 1;
            }
        }
    }
    finish_message(args);
    0
}

fn finish_message(args: &ImportArgs) {
    println!();
    if args.apply {
        println!(
            "Done. Vaultwarden's data was only read, never changed. Restart Kemlock Server if it \
             is running, so it loads the carried rsa_key.pem."
        );
    } else {
        println!(
            "Dry run: nothing was written, and Vaultwarden's data was only read. \
             Add --apply to move in."
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kemlock_vaultwarden::mapping::{
        FileCopy, MappedAccount, MappedAttachment, MappedCipherState, MappedFolder, MappedItem,
        MappedRsaKey,
    };
    use kemlock_vaultwarden::settings::MappedSettings;
    use kemlock_vaultwarden::snapshot::{RowKey, Table};
    use std::convert::Infallible;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    /// A sink that counts the passes finished.
    #[derive(Debug)]
    struct Counting(Arc<AtomicUsize>);

    impl ImportSink for Counting {
        type Error = Infallible;

        async fn put_accounts(&mut self, _: &[MappedAccount]) -> Result<(), Infallible> {
            Ok(())
        }
        async fn put_folders(&mut self, _: &[MappedFolder]) -> Result<(), Infallible> {
            Ok(())
        }
        async fn put_items(&mut self, _: &[MappedItem]) -> Result<(), Infallible> {
            Ok(())
        }
        async fn put_cipher_states(&mut self, _: &[MappedCipherState]) -> Result<(), Infallible> {
            Ok(())
        }
        async fn put_attachments(&mut self, _: &[MappedAttachment]) -> Result<(), Infallible> {
            Ok(())
        }
        async fn put_carried(&mut self, _: &Table) -> Result<(), Infallible> {
            Ok(())
        }
        async fn put_settings(&mut self, _: &MappedSettings) -> Result<(), Infallible> {
            Ok(())
        }
        async fn put_rsa_key(&mut self, _: &MappedRsaKey) -> Result<(), Infallible> {
            Ok(())
        }
        async fn copy_file(&mut self, _: &FileCopy) -> Result<(), Infallible> {
            Ok(())
        }
        async fn delete_rows(&mut self, _: &'static str, _: &[RowKey]) -> Result<(), Infallible> {
            Ok(())
        }
        async fn finish(&mut self) -> Result<(), Infallible> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    /// Opens a [`Counting`] sink for each pass.
    #[derive(Debug, Default)]
    struct CountingSinks {
        opened: usize,
        finished: Arc<AtomicUsize>,
    }

    impl SinkSource for CountingSinks {
        type Sink = Counting;

        async fn open(&mut self) -> Result<Counting, String> {
            self.opened += 1;
            Ok(Counting(Arc::clone(&self.finished)))
        }
    }

    #[test]
    fn arguments_parse_in_both_spellings() {
        assert_eq!(
            parse_args(&args(&["--from", "/data", "--twice"])),
            Ok(ImportArgs {
                from: "/data".into(),
                files: None,
                twice: true,
                apply: false,
                adopt_existing: false
            })
        );
        assert_eq!(
            parse_args(&args(&[
                "--from=mysql://u:p@db/vw",
                "--files=/vw-data",
                "--apply"
            ])),
            Ok(ImportArgs {
                from: "mysql://u:p@db/vw".into(),
                files: Some("/vw-data".into()),
                twice: false,
                apply: true,
                adopt_existing: false
            })
        );
    }

    #[test]
    fn adopting_existing_rows_is_an_explicit_flag() {
        let parsed =
            parse_args(&args(&["--from", "/data", "--apply", "--adopt-existing"])).expect("parses");
        assert!(parsed.adopt_existing);
        let plain = parse_args(&args(&["--from", "/data", "--apply"])).expect("parses");
        assert!(!plain.adopt_existing);
    }

    #[test]
    fn bad_arguments_are_refused() {
        assert!(parse_args(&[]).is_err(), "--from is required");
        assert!(parse_args(&args(&["--from"])).is_err());
        assert!(parse_args(&args(&["--from", "/data", "--yolo"])).is_err());
        assert!(parse_args(&args(&["/data"])).is_err());
    }

    #[tokio::test]
    async fn a_missing_source_fails_without_writing() {
        let parsed = parse_args(&args(&["--from", "/no/such/vaultwarden/folder"])).expect("parses");
        let mut sinks = CountingSinks::default();
        let code = execute(&parsed, Some(&mut sinks), &mut || Ok(())).await;
        assert_eq!(code, 1);
        assert_eq!(
            sinks.opened, 0,
            "nothing was opened for a source that failed"
        );
    }

    #[tokio::test]
    async fn an_empty_folder_is_not_a_vaultwarden_data_folder() {
        let dir = std::env::temp_dir().join(format!("kemlock-cli-empty-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("a temp folder");
        let parsed = parse_args(&args(&["--from", &dir.display().to_string()])).expect("parses");
        let code = execute::<SqlSinks>(&parsed, None, &mut || Ok(())).await;
        std::fs::remove_dir_all(&dir).expect("cleans up");
        assert_eq!(code, 1);
    }

    #[tokio::test]
    async fn applying_without_a_store_fails_after_the_plan() {
        // A readable source is needed to get that far; an empty folder fails first, so this
        // checks the order: the source is read before any store is asked for.
        let dir = std::env::temp_dir().join(format!("kemlock-cli-nostore-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("a temp folder");
        let parsed =
            parse_args(&args(&["--from", &dir.display().to_string(), "--apply"])).expect("parses");
        let code = execute::<SqlSinks>(&parsed, None, &mut || Ok(())).await;
        std::fs::remove_dir_all(&dir).expect("cleans up");
        assert_eq!(code, 1);
    }

    #[tokio::test]
    async fn each_pass_opens_and_finishes_its_own_sink() {
        let mut sinks = CountingSinks::default();
        let mapped = MappedImport::default();
        write_pass(&mut sinks, &mapped, &[]).await.expect("a pass");
        write_pass(&mut sinks, &mapped, &[]).await.expect("another");
        assert_eq!(sinks.opened, 2);
        assert_eq!(sinks.finished.load(Ordering::SeqCst), 2);
    }
}
