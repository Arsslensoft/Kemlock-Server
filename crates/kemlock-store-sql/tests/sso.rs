//! The SSO ports: provider settings, linked identities and proven domains.
//!
//! Each scenario runs on every backend that is available: in-memory SQLite, SQLite in a file, and
//! PostgreSQL and MySQL when `KEMLOCK_TEST_POSTGRES_URL` / `KEMLOCK_TEST_MYSQL_URL` are set.

mod common;

use common::{external, file, memory, unique_email, user};
use kemlock_app::ports::{StoreError, UserRepo};
use kemlock_app::sso::{
    GroupRule, SpaceRole, SsoIdentity, SsoIdentityRepo, SsoSettings, SsoSettingsRepo,
    VerifiedDomain, VerifiedDomainRepo,
};
use kemlock_domain::{SpaceId, UserId};
use kemlock_store_sql::SqlStore;
use time::macros::datetime;
use uuid::Uuid;

fn settings(client_id: &str) -> SsoSettings {
    let mut s = SsoSettings::new(
        "https://idp.example.org/realms/kemlock",
        client_id,
        datetime!(2026-05-06 07:08:09 UTC),
    );
    s.display_name = "Example Co SSO".to_owned();
    s.sealed_client_secret = Some(vec![9; 60]);
    s.scopes = vec!["email".into(), "profile".into(), "groups".into()];
    s.allow_unknown_email_verification = true;
    s.group_rules = vec![
        GroupRule {
            group: "eng".into(),
            space: SpaceId::random(),
            role: SpaceRole::Admin,
            collections: vec![Uuid::from_u128(1), Uuid::from_u128(2)],
        },
        GroupRule {
            group: "ops".into(),
            space: SpaceId::random(),
            role: SpaceRole::Member,
            collections: vec![],
        },
    ];
    s
}

async fn provider_settings(store: &SqlStore) {
    let first = settings("kemlock");
    SsoSettingsRepo::put_sso_settings(store, &first)
        .await
        .expect("put");
    assert_eq!(
        SsoSettingsRepo::sso_settings(store).await.expect("get"),
        Some(first.clone())
    );

    // A second put replaces the one row, secret and rules included.
    let mut second = settings("kemlock-2");
    second.enabled = false;
    second.sealed_client_secret = None;
    second.scopes.clear();
    second.group_rules.clear();
    second.link_by_email = false;
    second.create_accounts = false;
    second.require_verified_domain = true;
    second.updated_at = datetime!(2026-06-07 08:09:10 UTC);
    SsoSettingsRepo::put_sso_settings(store, &second)
        .await
        .expect("put again");
    assert_eq!(
        SsoSettingsRepo::sso_settings(store).await.expect("get"),
        Some(second)
    );

    // Putting the same value twice is fine.
    let again = SsoSettingsRepo::sso_settings(store)
        .await
        .expect("get")
        .expect("there is one");
    SsoSettingsRepo::put_sso_settings(store, &again)
        .await
        .expect("an identical put");
}

async fn identities(store: &SqlStore) {
    let ada = user(&unique_email("ada-sso"));
    let bob = user(&unique_email("bob-sso"));
    UserRepo::insert(store, &ada).await.expect("insert ada");
    UserRepo::insert(store, &bob).await.expect("insert bob");

    let issuer = format!("https://idp.example.org/{}", Uuid::new_v4().simple());
    let link = |user: UserId, subject: &str, linked: time::OffsetDateTime| SsoIdentity {
        issuer: issuer.clone(),
        subject: subject.to_owned(),
        user,
        email: "ada@example.org".to_owned(),
        linked_at: linked,
        last_login_at: linked,
    };
    let first = link(ada.id, "sub-a", datetime!(2026-01-02 03:04:05 UTC));
    let second = link(ada.id, "sub-a2", datetime!(2026-01-03 03:04:05 UTC));
    let other = link(bob.id, "sub-b", datetime!(2026-01-04 03:04:05 UTC));
    for identity in [&second, &first, &other] {
        SsoIdentityRepo::insert_identity(store, identity)
            .await
            .expect("insert");
    }

    assert_eq!(
        SsoIdentityRepo::find_identity(store, &issuer, "sub-a")
            .await
            .expect("find"),
        Some(first.clone())
    );
    assert_eq!(
        SsoIdentityRepo::find_identity(store, &issuer, "nobody")
            .await
            .expect("find"),
        None
    );
    assert_eq!(
        SsoIdentityRepo::find_identity(store, "https://other.example", "sub-a")
            .await
            .expect("find"),
        None,
        "the issuer is part of the key"
    );

    // One user may link several subjects; they list oldest first.
    assert_eq!(
        SsoIdentityRepo::identities_of(store, ada.id)
            .await
            .expect("list"),
        vec![first.clone(), second.clone()]
    );
    assert_eq!(
        SsoIdentityRepo::identities_of(store, bob.id)
            .await
            .expect("list"),
        vec![other.clone()]
    );
    assert!(
        SsoIdentityRepo::identities_of(store, UserId::random())
            .await
            .expect("list")
            .is_empty()
    );

    // A subject links once, whoever asks.
    let mut taken = first.clone();
    taken.user = bob.id;
    assert_eq!(
        SsoIdentityRepo::insert_identity(store, &taken).await,
        Err(StoreError::Duplicate)
    );
    assert_eq!(
        SsoIdentityRepo::find_identity(store, &issuer, "sub-a")
            .await
            .expect("find")
            .expect("still there")
            .user,
        ada.id
    );

    // An account that doesn't exist can't be linked.
    let ghost = link(
        UserId::random(),
        "sub-ghost",
        datetime!(2026-01-05 00:00:00 UTC),
    );
    assert_eq!(
        SsoIdentityRepo::insert_identity(store, &ghost).await,
        Err(StoreError::NotFound)
    );

    // A sign-in updates the time and the email, and nothing else.
    SsoIdentityRepo::touch_identity(
        store,
        &issuer,
        "sub-a",
        "ada.new@example.org",
        datetime!(2026-03-04 05:06:07 UTC),
    )
    .await
    .expect("touch");
    let touched = SsoIdentityRepo::find_identity(store, &issuer, "sub-a")
        .await
        .expect("find")
        .expect("there");
    assert_eq!(touched.email, "ada.new@example.org");
    assert_eq!(touched.last_login_at, datetime!(2026-03-04 05:06:07 UTC));
    assert_eq!(touched.linked_at, first.linked_at);
    assert_eq!(touched.user, ada.id);
    assert_eq!(
        SsoIdentityRepo::touch_identity(
            store,
            &issuer,
            "unknown",
            "x@example.org",
            datetime!(2026-03-04 05:06:07 UTC)
        )
        .await,
        Err(StoreError::NotFound)
    );
}

async fn domains(store: &SqlStore) {
    let name = |label: &str| format!("{label}-{}.example.org", Uuid::new_v4().simple());
    let (a, b) = (name("a"), name("b"));
    let pending = VerifiedDomain {
        domain: a.clone(),
        token: "0123456789abcdef0123456789abcdef".to_owned(),
        created_at: datetime!(2026-01-02 03:04:05 UTC),
        verified_at: None,
    };
    VerifiedDomainRepo::put_domain_claim(store, &pending)
        .await
        .expect("put");
    assert_eq!(
        VerifiedDomainRepo::domain_claim(store, &a)
            .await
            .expect("get"),
        Some(pending.clone())
    );
    assert_eq!(
        VerifiedDomainRepo::domain_claim(store, &b)
            .await
            .expect("get"),
        None
    );

    // Verifying replaces the claim.
    let verified = VerifiedDomain {
        verified_at: Some(datetime!(2026-01-03 03:04:05 UTC)),
        ..pending.clone()
    };
    VerifiedDomainRepo::put_domain_claim(store, &verified)
        .await
        .expect("put verified");
    assert_eq!(
        VerifiedDomainRepo::domain_claim(store, &a)
            .await
            .expect("get"),
        Some(verified.clone())
    );

    let other = VerifiedDomain {
        domain: b.clone(),
        token: "fedcba9876543210fedcba9876543210".to_owned(),
        created_at: datetime!(2026-02-02 03:04:05 UTC),
        verified_at: None,
    };
    VerifiedDomainRepo::put_domain_claim(store, &other)
        .await
        .expect("put other");
    let all = VerifiedDomainRepo::domain_claims(store)
        .await
        .expect("list");
    let mine: Vec<&VerifiedDomain> = all
        .iter()
        .filter(|d| d.domain == a || d.domain == b)
        .collect();
    assert_eq!(mine.len(), 2);
    assert!(mine.contains(&&verified));
    assert!(mine.contains(&&other));

    VerifiedDomainRepo::remove_domain_claim(store, &a)
        .await
        .expect("remove");
    assert_eq!(
        VerifiedDomainRepo::domain_claim(store, &a)
            .await
            .expect("get"),
        None
    );
    // Removing what isn't there is fine.
    VerifiedDomainRepo::remove_domain_claim(store, &a)
        .await
        .expect("remove again");
}

async fn run_all(store: &SqlStore) {
    provider_settings(store).await;
    identities(store).await;
    domains(store).await;
}

#[tokio::test]
async fn sqlite_in_memory() {
    run_all(&memory().await).await;
}

#[tokio::test]
async fn sqlite_in_a_file() {
    let (store, _dir) = file().await;
    run_all(&store).await;
}

#[tokio::test]
async fn postgres_when_configured() {
    if let Some(store) = external("KEMLOCK_TEST_POSTGRES_URL").await {
        run_all(&store).await;
    }
}

#[tokio::test]
async fn mysql_when_configured() {
    if let Some(store) = external("KEMLOCK_TEST_MYSQL_URL").await {
        run_all(&store).await;
    }
}

#[tokio::test]
async fn a_second_connect_keeps_the_sso_rows() {
    let (store, dir) = file().await;
    SsoSettingsRepo::put_sso_settings(&store, &settings("kemlock"))
        .await
        .expect("put");
    store.close().await.expect("closes");

    let url = common::file_url(&dir.path().join("kemlock.db"));
    let reopened = SqlStore::connect(&url).await.expect("reconnects");
    assert!(
        SsoSettingsRepo::sso_settings(&reopened)
            .await
            .expect("get")
            .is_some()
    );
}
