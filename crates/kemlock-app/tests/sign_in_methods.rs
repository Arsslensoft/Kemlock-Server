//! Which ways in the server lists for an email: the password always, single sign-on when a
//! provider is set up for the email's domain.

mod fakes;

use fakes::World;
use kemlock_app::ports::Clock;
use kemlock_app::sso::{SignInMethods, SsoSettings};

fn methods(world: &World) -> SignInMethods<fakes::FakeStore> {
    SignInMethods {
        repos: world.store.clone(),
    }
}

fn provider(world: &World) -> SsoSettings {
    SsoSettings::new("https://idp.test", "kemlock", world.env.now())
}

#[tokio::test]
async fn sso_is_not_offered_when_no_provider_is_set_up() {
    let world = World::new();
    assert!(
        !methods(&world)
            .offers_sso("sam@example.org")
            .await
            .expect("answers")
    );
}

#[tokio::test]
async fn a_provider_is_offered_for_every_email_unless_domains_must_be_verified() {
    let world = World::new();
    world.store.set_sso(provider(&world));
    assert!(
        methods(&world)
            .offers_sso("sam@example.org")
            .await
            .expect("answers")
    );
    assert!(
        methods(&world)
            .offers_sso("anyone@elsewhere.net")
            .await
            .expect("answers")
    );
}

#[tokio::test]
async fn a_disabled_provider_is_not_offered() {
    let world = World::new();
    let mut settings = provider(&world);
    settings.enabled = false;
    world.store.set_sso(settings);
    assert!(
        !methods(&world)
            .offers_sso("sam@example.org")
            .await
            .expect("answers")
    );
}

#[tokio::test]
async fn with_verified_domains_required_only_a_proven_domain_is_offered_it() {
    let world = World::new();
    let mut settings = provider(&world);
    settings.require_verified_domain = true;
    world.store.set_sso(settings);
    world
        .store
        .add_verified_domain("example.org", world.env.now());

    let offers = |email: &'static str| {
        let methods = methods(&world);
        async move { methods.offers_sso(email).await.expect("answers") }
    };
    assert!(offers("sam@example.org").await);
    // The domain is matched whatever the case, and a subdomain is another domain.
    assert!(offers("Sam@Example.ORG").await);
    assert!(!offers("sam@mail.example.org").await);
    assert!(!offers("sam@other.net").await);
    // Not an email at all: nothing to offer, and no error that tells it apart.
    assert!(!offers("not an email").await);
    assert!(!offers("").await);
}

#[tokio::test]
async fn a_pending_claim_does_not_count_as_verified() {
    let world = World::new();
    let mut settings = provider(&world);
    settings.require_verified_domain = true;
    world.store.set_sso(settings);
    let pending = kemlock_app::sso::VerifiedDomain {
        domain: "example.org".to_owned(),
        token: "abc".to_owned(),
        created_at: world.env.now(),
        verified_at: None,
    };
    kemlock_app::sso::VerifiedDomainRepo::put_domain_claim(&world.store, &pending)
        .await
        .expect("stored");
    assert!(
        !methods(&world)
            .offers_sso("sam@example.org")
            .await
            .expect("answers")
    );
}

#[tokio::test]
async fn the_provider_is_named_the_same_for_every_email() {
    let world = World::new();
    let mut settings = provider(&world);
    settings.display_name = "Example Co".to_owned();
    world.store.set_sso(settings);
    for email in ["sam@example.org", "ghost@elsewhere.net", "not an email"] {
        assert_eq!(
            methods(&world).sso_provider(email).await.expect("answers"),
            Some("Example Co".to_owned()),
            "{email}"
        );
    }
}

#[tokio::test]
async fn a_blank_display_name_is_the_issuers_host() {
    let world = World::new();
    let mut settings = provider(&world);
    settings.display_name = String::new();
    world.store.set_sso(settings);
    assert_eq!(
        methods(&world)
            .sso_provider("sam@example.org")
            .await
            .expect("answers"),
        Some("idp.test".to_owned())
    );
}

#[tokio::test]
async fn no_provider_name_without_an_enabled_provider_or_a_proven_domain() {
    let world = World::new();
    assert_eq!(
        methods(&world)
            .sso_provider("sam@example.org")
            .await
            .expect("answers"),
        None
    );
    let mut settings = provider(&world);
    settings.require_verified_domain = true;
    world.store.set_sso(settings);
    assert_eq!(
        methods(&world)
            .sso_provider("sam@example.org")
            .await
            .expect("answers"),
        None
    );
    world
        .store
        .add_verified_domain("example.org", world.env.now());
    assert!(
        methods(&world)
            .sso_provider("sam@example.org")
            .await
            .expect("answers")
            .is_some()
    );
}
