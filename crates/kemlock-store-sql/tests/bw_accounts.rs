//! `BwAccountRepo`: the Bitwarden record of an account, on in-memory SQLite.

mod common;

use common::{memory, unique_email, user};
use kemlock_app::bitwarden::{BwAccount, BwAccountRepo};
use kemlock_app::ports::{StoreError, UserRepo};
use kemlock_domain::UserId;

fn account(user: UserId) -> BwAccount {
    BwAccount {
        user,
        password_hash: vec![7; 32],
        salt: vec![8; 64],
        password_iterations: 600_000,
        kdf_type: 0,
        kdf_iterations: 600_000,
        kdf_memory: None,
        kdf_parallelism: None,
        akey: "2.iv|data|mac".to_owned(),
        private_key: Some("2.iv|private|mac".to_owned()),
        public_key: Some("MIIBIjAN".to_owned()),
        password_hint: Some("a hint".to_owned()),
        api_key: None,
        avatar_color: None,
        revision_ms: 1_000,
    }
}

#[tokio::test]
async fn an_account_is_inserted_read_back_and_updated() {
    let store = memory().await;
    let owner = user(&unique_email("bw"));
    UserRepo::insert(&store, &owner).await.expect("insert user");

    let a = account(owner.id);
    BwAccountRepo::insert(&store, &a).await.expect("insert");
    assert_eq!(
        BwAccountRepo::get(&store, owner.id).await.expect("get"),
        Some(a.clone())
    );
    assert_eq!(
        BwAccountRepo::get(&store, UserId::random())
            .await
            .expect("get"),
        None
    );

    let mut changed = a.clone();
    changed.password_iterations = 1_000;
    changed.api_key = Some("k".repeat(30));
    changed.revision_ms = 5;
    BwAccountRepo::update(&store, &changed)
        .await
        .expect("update");
    let back = BwAccountRepo::get(&store, owner.id)
        .await
        .expect("get")
        .expect("present");
    assert_eq!(back.password_iterations, 1_000);
    assert_eq!(back.api_key, changed.api_key);
    assert_eq!(
        back.revision_ms, 1_000,
        "update leaves the revision date to touch"
    );
}

#[tokio::test]
async fn a_second_record_or_one_without_a_user_is_refused() {
    let store = memory().await;
    let owner = user(&unique_email("bw"));
    UserRepo::insert(&store, &owner).await.expect("insert user");
    BwAccountRepo::insert(&store, &account(owner.id))
        .await
        .expect("insert");
    assert_eq!(
        BwAccountRepo::insert(&store, &account(owner.id)).await,
        Err(StoreError::Duplicate)
    );
    assert_eq!(
        BwAccountRepo::insert(&store, &account(UserId::random())).await,
        Err(StoreError::NotFound)
    );
    assert_eq!(
        BwAccountRepo::update(&store, &account(UserId::random())).await,
        Err(StoreError::NotFound)
    );
}

#[tokio::test]
async fn touch_only_moves_the_revision_date_forward() {
    let store = memory().await;
    let owner = user(&unique_email("bw"));
    UserRepo::insert(&store, &owner).await.expect("insert user");
    BwAccountRepo::insert(&store, &account(owner.id))
        .await
        .expect("insert");

    // A later time wins; the same or an earlier time still moves by one.
    assert_eq!(
        BwAccountRepo::touch(&store, owner.id, 5_000).await,
        Ok(5_000)
    );
    assert_eq!(
        BwAccountRepo::touch(&store, owner.id, 5_000).await,
        Ok(5_001)
    );
    assert_eq!(BwAccountRepo::touch(&store, owner.id, 1).await, Ok(5_002));
    assert_eq!(
        BwAccountRepo::get(&store, owner.id)
            .await
            .expect("get")
            .map(|a| a.revision_ms),
        Some(5_002)
    );
    assert_eq!(
        BwAccountRepo::touch(&store, UserId::random(), 1).await,
        Err(StoreError::NotFound)
    );
}

/// What `bw_accounts` holds, as the snapshot writes it: the text of every row.
async fn stored_rows(store: &kemlock_store_sql::SqlStore) -> String {
    let dir = tempfile::tempdir().expect("a folder");
    store.snapshot_to(dir.path()).await.expect("the snapshot");
    std::fs::read_to_string(dir.path().join("bw_accounts.jsonl")).expect("the table's file")
}

#[tokio::test]
async fn an_api_key_is_kept_sealed_and_read_back_whole() {
    let store = memory().await;
    store.set_secret_seal(kemlock_crypto::seal::ServerSeal::new(&[9; 32]));
    let owner = user(&unique_email("bw"));
    UserRepo::insert(&store, &owner).await.expect("insert user");
    let mut a = account(owner.id);
    a.api_key = Some("PlainApiKey0123456789abcdefghij".to_owned());
    BwAccountRepo::insert(&store, &a).await.expect("insert");

    let rows = stored_rows(&store).await;
    assert!(!rows.contains("PlainApiKey"), "the key is not at rest: {rows}");
    assert!(rows.contains("sealed:"));
    let back = BwAccountRepo::get(&store, owner.id)
        .await
        .expect("get")
        .expect("present");
    assert_eq!(back.api_key, a.api_key);

    // A new key replaces it, sealed again.
    let mut rotated = back;
    rotated.api_key = Some("RotatedKey0123456789abcdefghijk".to_owned());
    BwAccountRepo::update(&store, &rotated).await.expect("update");
    let rows = stored_rows(&store).await;
    assert!(!rows.contains("RotatedKey"), "{rows}");
    assert_eq!(
        BwAccountRepo::get(&store, owner.id)
            .await
            .expect("get")
            .expect("present")
            .api_key,
        rotated.api_key
    );
}

#[tokio::test]
async fn a_plain_key_is_sealed_the_first_time_it_is_read() {
    let store = memory().await;
    let owner = user(&unique_email("bw"));
    UserRepo::insert(&store, &owner).await.expect("insert user");
    // Before the store has a seal, as in a database that is older than the sealing, or one
    // moved from Vaultwarden, the key is kept as it comes.
    let mut a = account(owner.id);
    a.api_key = Some("OldPlainKey0123456789abcdefghijk".to_owned());
    BwAccountRepo::insert(&store, &a).await.expect("insert");
    assert!(stored_rows(&store).await.contains("OldPlainKey"));

    store.set_secret_seal(kemlock_crypto::seal::ServerSeal::new(&[9; 32]));
    let read = BwAccountRepo::get(&store, owner.id)
        .await
        .expect("get")
        .expect("present");
    assert_eq!(read.api_key, a.api_key, "the owner still sees it");
    assert!(
        !stored_rows(&store).await.contains("OldPlainKey"),
        "and it is sealed now"
    );
    assert_eq!(
        BwAccountRepo::get(&store, owner.id)
            .await
            .expect("get")
            .expect("present")
            .api_key,
        a.api_key
    );
}

#[tokio::test]
async fn a_sealed_key_that_does_not_open_is_no_key_and_does_not_lock_the_account() {
    // A database that came back with another `server.key` (here, with none): the key is lost,
    // its owner makes a new one, and the account itself still reads.
    let store = memory().await;
    let owner = user(&unique_email("bw"));
    UserRepo::insert(&store, &owner).await.expect("insert user");
    let mut a = account(owner.id);
    a.api_key = Some("sealed:AAAA".to_owned());
    BwAccountRepo::insert(&store, &a).await.expect("insert");
    let read = BwAccountRepo::get(&store, owner.id)
        .await
        .expect("get")
        .expect("present");
    assert_eq!(read.api_key, None);
    assert_eq!(read.akey, a.akey);

    store.set_secret_seal(kemlock_crypto::seal::ServerSeal::new(&[9; 32]));
    let read = BwAccountRepo::get(&store, owner.id)
        .await
        .expect("get")
        .expect("present");
    assert_eq!(read.api_key, None, "damaged, not a plain key");
}

#[tokio::test]
async fn the_start_up_pass_seals_every_plain_key_without_anyone_reading_it() {
    let store = memory().await;
    let (ana, bea, cy) = (
        user(&unique_email("bw")),
        user(&unique_email("bw")),
        user(&unique_email("bw")),
    );
    for owner in [&ana, &bea, &cy] {
        UserRepo::insert(&store, owner).await.expect("insert user");
    }
    let mut with_key = account(ana.id);
    with_key.api_key = Some("PlainOne0123456789abcdefghijklm".to_owned());
    let mut also = account(bea.id);
    also.api_key = Some("PlainTwo0123456789abcdefghijklm".to_owned());
    for a in [&with_key, &also, &account(cy.id)] {
        BwAccountRepo::insert(&store, a).await.expect("insert");
    }

    // With no seal there is nothing to do.
    assert_eq!(store.seal_stored_secrets().await.expect("pass"), 0);
    assert!(stored_rows(&store).await.contains("PlainOne"));

    store.set_secret_seal(kemlock_crypto::seal::ServerSeal::new(&[9; 32]));
    assert_eq!(store.seal_stored_secrets().await.expect("pass"), 2);
    let rows = stored_rows(&store).await;
    assert!(!rows.contains("PlainOne") && !rows.contains("PlainTwo"), "{rows}");
    // They still read back whole, and a second pass has nothing left.
    for (owner, a) in [(&ana, &with_key), (&bea, &also)] {
        let back = BwAccountRepo::get(&store, owner.id)
            .await
            .expect("get")
            .expect("present");
        assert_eq!(back.api_key, a.api_key);
    }
    assert_eq!(store.seal_stored_secrets().await.expect("pass"), 0);
}
