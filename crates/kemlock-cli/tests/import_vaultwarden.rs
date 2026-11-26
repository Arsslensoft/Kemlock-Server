//! `kemlock-cli import-vaultwarden`, run as a program against the sample Vaultwarden data folder
//! (a SQLite database made by running Vaultwarden 1.37.5's own migrations): the dry run writes
//! nothing, `--apply` moves in, and `--twice --apply` makes its second pass with what changed.

#[allow(clippy::unwrap_used)]
#[path = "../../kemlock-vaultwarden/tests/common/mod.rs"]
mod vwfix;

use sqlx::ConnectOptions;
use sqlx::sqlite::SqliteConnectOptions;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

/// 32 bytes as 64 hex characters, the form `KEMLOCK_SERVER_KEY` takes.
const SERVER_KEY: &str = "0707070707070707070707070707070707070707070707070707070707070707";

fn run(vw: &Path, data: &Path, extra: &[&str], stdin: &str) -> Output {
    let url = format!(
        "sqlite://{}?mode=rwc",
        data.join("kemlock.db").to_string_lossy().replace('\\', "/")
    );
    let mut child = Command::new(env!("CARGO_BIN_EXE_kemlock-cli"))
        .arg("import-vaultwarden")
        .arg("--from")
        .arg(vw)
        .args(extra)
        .env("DATABASE_URL", url)
        .env("DATA_FOLDER", data)
        .env("KEMLOCK_SERVER_KEY", SERVER_KEY)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the program starts");
    child
        .stdin
        .take()
        .expect("a stdin")
        .write_all(stdin.as_bytes())
        .expect("writes to stdin");
    child.wait_with_output().expect("the program ends")
}

async fn count(data: &Path, sql: &'static str) -> i64 {
    let mut conn = SqliteConnectOptions::new()
        .filename(data.join("kemlock.db"))
        .connect()
        .await
        .expect("opens the database");
    sqlx::query_scalar::<sqlx::Sqlite, i64>(sql)
        .fetch_one(&mut conn)
        .await
        .expect("counts")
}

#[tokio::test]
async fn the_dry_run_writes_nothing_and_apply_moves_in_once_and_twice() {
    let vw = tempfile::tempdir().expect("a temp folder");
    vwfix::create_sample_folder(vw.path()).await;
    let data = tempfile::tempdir().expect("a temp folder");

    // A dry run prints the plan and leaves the data folder and the database alone.
    let out = run(vw.path(), data.path(), &[], "");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let printed = String::from_utf8_lossy(&out.stdout);
    assert!(printed.contains("Dry run"), "{printed}");
    assert!(!data.path().join("kemlock.db").exists());
    assert!(!data.path().join("rsa_key.pem").exists());

    // --apply writes the database and the files, and Vaultwarden's data is not touched.
    let before = std::fs::read(vw.path().join("db.sqlite3")).expect("the database");
    let out = run(vw.path(), data.path(), &["--apply"], "");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        std::fs::read(vw.path().join("db.sqlite3")).expect("the database"),
        before
    );
    assert_eq!(count(data.path(), "SELECT COUNT(*) FROM users").await, 2);
    assert_eq!(
        count(data.path(), "SELECT COUNT(*) FROM bw_accounts").await,
        2
    );
    // Five ciphers and a folder.
    assert_eq!(count(data.path(), "SELECT COUNT(*) FROM items").await, 6);
    assert_eq!(
        std::fs::read(data.path().join("rsa_key.pem")).expect("the carried key"),
        vwfix::RSA_PEM
    );
    assert_eq!(
        std::fs::read(
            data.path()
                .join("attachments")
                .join(vwfix::LOGIN)
                .join(vwfix::ATTACHMENT)
        )
        .expect("the attachment file"),
        b"12345"
    );

    // Again, with --twice: the same data is put again (nothing doubles), then Enter, then the
    // second pass, which finds nothing changed.
    let out = run(vw.path(), data.path(), &["--twice", "--apply"], "\n");
    let printed = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{}\n{printed}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(printed.contains("Press Enter"), "{printed}");
    assert!(printed.contains("Wrote the changes"), "{printed}");
    assert_eq!(count(data.path(), "SELECT COUNT(*) FROM users").await, 2);
    assert_eq!(count(data.path(), "SELECT COUNT(*) FROM items").await, 6);
}

async fn execute_sql(data: &Path, sql: &'static str) {
    let mut conn = SqliteConnectOptions::new()
        .filename(data.join("kemlock.db"))
        .connect()
        .await
        .expect("opens the database");
    sqlx::query(sql)
        .execute(&mut conn)
        .await
        .expect("runs the statement");
}

#[tokio::test]
async fn accounts_no_import_made_are_left_alone_unless_the_operator_adopts_them() {
    let vw = tempfile::tempdir().expect("a temp folder");
    vwfix::create_sample_folder(vw.path()).await;
    let data = tempfile::tempdir().expect("a temp folder");

    let out = run(vw.path(), data.path(), &["--apply"], "");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        count(data.path(), "SELECT COUNT(*) FROM vw_import_ids WHERE kind = 'user'").await,
        2,
        "the import recorded the accounts it made"
    );

    // A server whose accounts came from an earlier move that left no record.
    execute_sql(data.path(), "DELETE FROM vw_import_ids").await;
    let out = run(vw.path(), data.path(), &["--apply"], "");
    let said = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{said}");
    assert!(said.contains("left alone"), "{said}");
    assert!(said.contains("--adopt-existing"), "{said}");
    assert!(!said.contains("WARNING"), "{said}");
    assert_eq!(
        count(data.path(), "SELECT COUNT(*) FROM vw_import_ids").await,
        0,
        "nothing was taken over"
    );

    // On purpose, with a warning: the accounts are the import's from then on.
    let out = run(vw.path(), data.path(), &["--apply", "--adopt-existing"], "");
    let said = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{said}");
    assert!(said.contains("WARNING"), "{said}");
    assert!(!said.contains("left alone"), "{said}");
    assert_eq!(
        count(data.path(), "SELECT COUNT(*) FROM vw_import_ids WHERE kind = 'user'").await,
        2
    );
    // The pass is in the admin event log.
    assert_eq!(
        count(
            data.path(),
            "SELECT COUNT(*) FROM events WHERE action = 'admin.migration.cli'"
        )
        .await,
        3
    );
}
