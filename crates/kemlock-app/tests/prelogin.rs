mod fakes;

use fakes::*;
use kemlock_app::AppError;
use kemlock_domain::KdfParams;

#[tokio::test]
async fn a_known_account_gets_its_own_settings() {
    let world = World::new().with_signups();
    make_user(&world, "sam@example.org").await;
    let kdf = world
        .prelogin()
        .execute("sam@example.org")
        .await
        .expect("prelogin works");
    // register_input's settings: the defaults with salt [4; 16].
    assert_eq!(kdf, KdfParams::new_account([4u8; 16]));
}

#[tokio::test]
async fn the_email_is_trimmed_and_lower_cased() {
    let world = World::new().with_signups();
    make_user(&world, "sam@example.org").await;
    let kdf = world.prelogin().execute("  SAM@Example.org ").await;
    assert_eq!(kdf, Ok(KdfParams::new_account([4u8; 16])));
}

#[tokio::test]
async fn an_unknown_email_gets_the_same_fake_answer_every_time() {
    let world = World::new();
    let a = world.prelogin().execute("nobody@example.org").await;
    let b = world.prelogin().execute("Nobody@Example.org").await;
    assert_eq!(a, b);
    assert!(a.is_ok());
}

#[tokio::test]
async fn a_fake_answer_looks_like_a_real_one() {
    let world = World::new();
    let kdf = world
        .prelogin()
        .execute("nobody@example.org")
        .await
        .expect("prelogin works");
    assert!(kdf.within_bounds());
    assert_eq!(kdf.salt.len(), KdfParams::SALT_LEN);
    assert_eq!(kdf.memory_kib, KdfParams::DEFAULT_MEMORY_KIB);
    assert_eq!(kdf.iterations, KdfParams::DEFAULT_ITERATIONS);
    assert_eq!(kdf.parallelism, KdfParams::DEFAULT_PARALLELISM);
}

#[tokio::test]
async fn fake_salts_differ_by_email_and_by_server_secret() {
    let world = World::new();
    let a = world.prelogin().execute("a@example.org").await.expect("ok");
    let b = world.prelogin().execute("b@example.org").await.expect("ok");
    assert_ne!(a.salt, b.salt);

    let mut other = World::new();
    other.prelogin_secret = [1u8; 32];
    let a2 = other.prelogin().execute("a@example.org").await.expect("ok");
    assert_ne!(a.salt, a2.salt);
}

#[tokio::test]
async fn something_that_is_not_an_email_still_gets_an_answer() {
    let world = World::new();
    assert!(world.prelogin().execute("not an email").await.is_ok());
}

#[tokio::test]
async fn an_absurdly_long_email_is_refused() {
    let world = World::new();
    let long = "a".repeat(600);
    assert_eq!(
        world.prelogin().execute(&long).await,
        Err(AppError::Invalid("the email is too long"))
    );
}
