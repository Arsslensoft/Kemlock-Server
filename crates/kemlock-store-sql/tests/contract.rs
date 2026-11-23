//! Signed manifests and per-API device use, on in-memory SQLite.

mod common;

use common::{device, memory, unique_email, user};
use kemlock_app::api_use::ApiUseRepo;
use kemlock_app::manifests::ManifestRepo;
use kemlock_app::ports::{DeviceRepo, StoreError, UserRepo};
use kemlock_domain::api_use::ApiKind;
use kemlock_domain::manifest::SignedManifest;
use kemlock_domain::{DeviceId, Owner, UserId};
use time::Duration;
use time::macros::datetime;

fn manifest(owner: UserId, counter: u64, fill: u8) -> SignedManifest {
    SignedManifest {
        owner: Owner::User(owner),
        counter,
        bytes: vec![fill; 200],
        signature: vec![fill; 3373],
        signer: owner,
        stored_at: datetime!(2026-06-01 12:00:00 UTC),
    }
}

#[tokio::test]
async fn a_manifest_is_stored_and_read_back_exactly() {
    let store = memory().await;
    let account = user(&unique_email("manifest"));
    UserRepo::insert(&store, &account).await.expect("insert");

    let owner = Owner::User(account.id);
    assert_eq!(ManifestRepo::manifest(&store, owner).await, Ok(None));
    let first = manifest(account.id, 3, 7);
    assert_eq!(store.put_manifest(&first).await, Ok(true));
    assert_eq!(ManifestRepo::manifest(&store, owner).await, Ok(Some(first)));
}

#[tokio::test]
async fn a_counter_that_is_not_above_the_stored_one_is_refused() {
    let store = memory().await;
    let account = user(&unique_email("manifest"));
    UserRepo::insert(&store, &account).await.expect("insert");
    let owner = Owner::User(account.id);

    let three = manifest(account.id, 3, 1);
    assert_eq!(store.put_manifest(&three).await, Ok(true));
    // The same counter, a lower one and a different body under the same counter all lose.
    assert_eq!(
        store.put_manifest(&manifest(account.id, 3, 2)).await,
        Ok(false)
    );
    assert_eq!(
        store.put_manifest(&manifest(account.id, 2, 3)).await,
        Ok(false)
    );
    assert_eq!(
        ManifestRepo::manifest(&store, owner).await,
        Ok(Some(three)),
        "the stored manifest is untouched"
    );

    let four = manifest(account.id, 4, 4);
    assert_eq!(store.put_manifest(&four).await, Ok(true));
    assert_eq!(ManifestRepo::manifest(&store, owner).await, Ok(Some(four)));
}

#[tokio::test]
async fn each_owner_has_its_own_counter() {
    let store = memory().await;
    let (a, b) = (user(&unique_email("a")), user(&unique_email("b")));
    UserRepo::insert(&store, &a).await.expect("insert");
    UserRepo::insert(&store, &b).await.expect("insert");
    assert_eq!(store.put_manifest(&manifest(a.id, 9, 1)).await, Ok(true));
    assert_eq!(store.put_manifest(&manifest(b.id, 1, 2)).await, Ok(true));
}

#[tokio::test]
async fn a_manifest_of_a_missing_signer_is_not_stored() {
    let store = memory().await;
    let outcome = store.put_manifest(&manifest(UserId::random(), 1, 1)).await;
    assert_eq!(outcome, Err(StoreError::NotFound));
}

#[tokio::test]
async fn use_of_each_api_is_recorded_apart() {
    let store = memory().await;
    let account = user(&unique_email("use"));
    UserRepo::insert(&store, &account).await.expect("insert");
    let phone = device(account.id, "Pixel", datetime!(2026-06-01 00:00:00 UTC));
    DeviceRepo::upsert(&store, &phone).await.expect("device");

    assert_eq!(store.uses_of(&[phone.id]).await, Ok(vec![]));

    let t0 = datetime!(2026-06-02 10:00:00 UTC);
    store
        .record_use(phone.id, ApiKind::Bitwarden, t0)
        .await
        .expect("record");
    let usage = store.uses_of(&[phone.id]).await.expect("read");
    assert_eq!(usage.len(), 1);
    assert_eq!(usage[0].bitwarden, Some(t0));
    assert_eq!(usage[0].kemlock, None);

    let t1 = t0 + Duration::hours(1);
    store
        .record_use(phone.id, ApiKind::Kemlock, t1)
        .await
        .expect("record");
    let usage = store.uses_of(&[phone.id]).await.expect("read");
    assert_eq!(usage[0].bitwarden, Some(t0), "the other API's column stays");
    assert_eq!(usage[0].kemlock, Some(t1));
}

#[tokio::test]
async fn a_use_moves_at_most_once_a_minute() {
    let store = memory().await;
    let account = user(&unique_email("use"));
    UserRepo::insert(&store, &account).await.expect("insert");
    let phone = device(account.id, "Pixel", datetime!(2026-06-01 00:00:00 UTC));
    DeviceRepo::upsert(&store, &phone).await.expect("device");

    let t0 = datetime!(2026-06-02 10:00:00 UTC);
    store
        .record_use(phone.id, ApiKind::Kemlock, t0)
        .await
        .expect("record");
    // Half a minute later: within the granularity, so nothing moves.
    store
        .record_use(phone.id, ApiKind::Kemlock, t0 + Duration::seconds(30))
        .await
        .expect("record");
    let usage = store.uses_of(&[phone.id]).await.expect("read");
    assert_eq!(usage[0].kemlock, Some(t0));
    // Two minutes later it moves.
    let later = t0 + Duration::minutes(2);
    store
        .record_use(phone.id, ApiKind::Kemlock, later)
        .await
        .expect("record");
    let usage = store.uses_of(&[phone.id]).await.expect("read");
    assert_eq!(usage[0].kemlock, Some(later));
}

#[tokio::test]
async fn use_of_a_device_that_is_gone_is_not_found_and_removal_takes_the_row() {
    let store = memory().await;
    assert_eq!(
        store
            .record_use(
                DeviceId::random(),
                ApiKind::Kemlock,
                datetime!(2026-06-02 10:00:00 UTC)
            )
            .await,
        Err(StoreError::NotFound)
    );

    let account = user(&unique_email("use"));
    UserRepo::insert(&store, &account).await.expect("insert");
    let phone = device(account.id, "Pixel", datetime!(2026-06-01 00:00:00 UTC));
    DeviceRepo::upsert(&store, &phone).await.expect("device");
    store
        .record_use(
            phone.id,
            ApiKind::Kemlock,
            datetime!(2026-06-02 10:00:00 UTC),
        )
        .await
        .expect("record");
    DeviceRepo::remove(&store, phone.id).await.expect("remove");
    assert_eq!(store.uses_of(&[phone.id]).await, Ok(vec![]));
}
