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
