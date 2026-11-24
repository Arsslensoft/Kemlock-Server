//! `kemlock-cli reset-admin`, run as a program: it refuses without `--yes`, and with it demotes
//! every admin, clears the first-admin marker and leaves an `admin.reset` event.

use kemlock_app::FirstAdminRepo;
use kemlock_app::ports::UserRepo;
use kemlock_domain::{AccountMode, Email, KdfParams, Role, User, UserId};
use kemlock_store_sql::SqlStore;
use std::path::Path;
use std::process::{Command, Output};
use time::macros::datetime;
use uuid::Uuid;

/// 32 bytes as 64 hex characters, the form `KEMLOCK_SERVER_KEY` takes.
const SERVER_KEY: &str = "0707070707070707070707070707070707070707070707070707070707070707";

fn url(data: &Path) -> String {
    format!(
        "sqlite://{}?mode=rwc",
        data.join("kemlock.db").to_string_lossy().replace('\', "/")
    )
}

fn run(data: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_kemlock-cli"))
        .arg("reset-admin")
        .args(args)
        .env("DATABASE_URL", url(data))
        .env("DATA_FOLDER", data)
        .env("KEMLOCK_SERVER_KEY", SERVER_KEY)
        .output()
        .expect("the program starts")
}

fn admin(email: &str) -> User {
    let at = datetime!(2026-06-01 12:00:00 UTC);
    User {
        id: UserId::random(),
        email: Email::parse(email).expect("an email"),
        name: None,
        mode: AccountMode::KemlockOnly,
        role: Role::Admin,
        kdf: KdfParams::new_account([3; 16]),
        opaque_record: Some(vec![1; 192]),
        wrapped_root_key: vec![2; 100],
        public_bundle: vec![3; 5000],
        bundle_signature: vec![4; 3400],
        sealed_private_keys: vec![5; 8000],
        key_version: 1,
        security_stamp: Uuid::new_v4(),
        created_at: at,
        updated_at: at,
    }
}

#[tokio::test]
async fn it_refuses_without_yes_and_resets_with_it() {
    let data = tempfile::tempdir().expect("a temp folder");
    let store = SqlStore::connect(&url(data.path())).await.expect("opens");
    let first = admin("first@example.org");
    FirstAdminRepo::insert_first_admin(&store, &first)
        .await
        .expect("first admin");
    let second = admin("second@example.org");
    UserRepo::insert(&store, &second).await.expect("insert");
    store.close().await.expect("closes");

    // Without --yes nothing changes.
    let refused = run(data.path(), &[]);
    assert_eq!(refused.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&refused.stderr).contains("--yes"));
    let store = SqlStore::connect(&url(data.path())).await.expect("opens");
    assert_eq!(UserRepo::count_admins(&store).await.expect("count"), 2);
    store.close().await.expect("closes");

    // With it, every admin is demoted and the marker is gone.
    let done = run(data.path(), &["--yes"]);
    assert!(
        done.status.success(),
        "{}",
        String::from_utf8_lossy(&done.stderr)
    );
    let printed = String::from_utf8_lossy(&done.stdout);
    assert!(printed.contains("first@example.org"), "{printed}");
    assert!(printed.contains("second@example.org"), "{printed}");
    let store = SqlStore::connect(&url(data.path())).await.expect("opens");
    assert_eq!(UserRepo::count_admins(&store).await.expect("count"), 0);
    assert_eq!(FirstAdminRepo::first_admin(&store).await.expect("marker"), None);
    let kept = UserRepo::by_id(&store, first.id).await.expect("by id");
    assert_eq!(kept.map(|u| u.role), Some(Role::User));
    store.close().await.expect("closes");
}
