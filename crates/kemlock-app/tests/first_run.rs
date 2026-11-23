mod fakes;

use fakes::*;
use kemlock_app::ports::Clock;
use kemlock_app::{AppError, SetupPhase};
use kemlock_domain::SetupError;
use time::Duration;

const ALPHABET: &str = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

async fn open_setup(world: &World) -> String {
    world
        .first_run()
        .start()
        .await
        .expect("start works")
        .expect("a code is made while no admin exists")
        .as_display()
}

#[tokio::test]
async fn start_makes_a_code_of_three_groups_of_four() {
    let world = World::new();
    let shown = open_setup(&world).await;
    let groups: Vec<&str> = shown.split('-').collect();
    assert_eq!(groups.len(), 3);
    assert!(groups.iter().all(|g| g.len() == 4));
    assert!(
        shown
            .chars()
            .filter(|c| *c != '-')
            .all(|c| ALPHABET.contains(c)),
        "{shown} uses only the unambiguous alphabet"
    );
    assert_eq!(world.first_run().phase(), SetupPhase::NeedsAdmin);
}

#[tokio::test]
async fn each_start_voids_the_previous_code() {
    let world = World::new();
    let first = open_setup(&world).await;
    let second = open_setup(&world).await;
    assert_ne!(first, second);
    assert_eq!(
        world.first_run().verify(&first, true, "client").await,
        Err(AppError::Setup(SetupError::WrongCode))
    );
    assert!(
        world
            .first_run()
            .verify(&second, true, "client")
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn start_with_an_admin_makes_no_code_and_closes_setup() {
    let world = World::new();
    let admin_grant = open_setup(&world).await;
    let grant = world
        .first_run()
        .verify(&admin_grant, true, "client")
        .await
        .expect("the code is right");
    let admin = register_account(&world, "admin@example.org", Some(grant.token))
        .await
        .expect("the admin registers")
        .user;
    // The admin finishes setup: two-step login confirmed, then the role is given.
    world.enrol_totp().execute(admin).await.expect("enrolment");
    let code = totp_code(&world, admin);
    world
        .confirm_totp()
        .execute(admin, &code)
        .await
        .expect("confirmed");
    world
        .finish_setup()
        .execute(admin)
        .await
        .expect("setup finishes");

    // A restart: a new FirstRun over the same store, with fresh in-memory state.
    let restarted = World::new();
    restarted.store.put_user(
        world
            .store
            .user_by_email("admin@example.org")
            .expect("the admin was stored"),
    );
    assert_eq!(restarted.first_run().start().await, Ok(None));
    assert_eq!(restarted.first_run().phase(), SetupPhase::Done);
    assert_eq!(
        restarted
            .first_run()
            .verify("AAAA-AAAA-AAAA", true, "client")
            .await,
        Err(AppError::Setup(SetupError::AlreadyDone))
    );
}

#[tokio::test]
async fn a_typed_code_is_read_like_crockford_base32() {
    let world = World::new();
    let shown = open_setup(&world).await;
    // Lower case, no dashes and stray spaces still match.
    let typed = format!(" {} ", shown.replace('-', "").to_lowercase());
    assert!(
        world
            .first_run()
            .verify(&typed, true, "client")
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn setup_needs_a_secure_context() {
    let world = World::new();
    let shown = open_setup(&world).await;
    assert_eq!(
        world.first_run().verify(&shown, false, "client").await,
        Err(AppError::Setup(SetupError::InsecureContext))
    );
}

#[tokio::test]
async fn three_wrong_codes_slow_the_fourth_down_with_doubling_delays() {
    let world = World::new();
    let shown = open_setup(&world).await;
    let wrong = "ZZZZ-ZZZZ-ZZZZ";
    assert_ne!(shown, wrong);
    let first_run = world.first_run();

    for _ in 0..3 {
        assert_eq!(
            first_run.verify(wrong, true, "client").await,
            Err(AppError::Setup(SetupError::WrongCode))
        );
    }
    // Even the right code waits out the first delay (2 s).
    assert_eq!(
        first_run.verify(&shown, true, "client").await,
        Err(AppError::SlowDown {
            retry_after_secs: 2
        })
    );
    world.env.clock.advance(Duration::seconds(2));
    // Another wrong code: the next delay doubles to 4 s.
    assert_eq!(
        first_run.verify(wrong, true, "client").await,
        Err(AppError::Setup(SetupError::WrongCode))
    );
    assert_eq!(
        first_run.verify(&shown, true, "client").await,
        Err(AppError::SlowDown {
            retry_after_secs: 4
        })
    );
    world.env.clock.advance(Duration::seconds(4));
    assert!(first_run.verify(&shown, true, "client").await.is_ok());
}

#[tokio::test]
async fn a_grant_expires() {
    let world = World::new();
    let shown = open_setup(&world).await;
    let grant = world
        .first_run()
        .verify(&shown, true, "client")
        .await
        .expect("the code is right");
    assert!(world.setup.has_grant(&grant.token, world.env.now()));
    world.env.clock.advance(Duration::minutes(16));
    assert!(!world.setup.has_grant(&grant.token, world.env.now()));
}

#[tokio::test]
async fn one_clients_wrong_codes_never_slow_another_client_down() {
    let world = World::new();
    let shown = open_setup(&world).await;
    let first_run = world.first_run();

    // An attacker burns through its free tries and earns a delay...
    for _ in 0..3 {
        assert_eq!(
            first_run.verify("ZZZZ-ZZZZ-ZZZZ", true, "attacker").await,
            Err(AppError::Setup(SetupError::WrongCode))
        );
    }
    assert!(matches!(
        first_run.verify("ZZZZ-ZZZZ-ZZZZ", true, "attacker").await,
        Err(AppError::SlowDown { .. })
    ));
    // ...and the real admin, from another address, is not held up by it.
    assert!(first_run.verify(&shown, true, "admin").await.is_ok());
}

#[tokio::test]
async fn a_wrong_code_now_and_then_from_anywhere_never_blocks_the_admin() {
    let world = World::new();
    let shown = open_setup(&world).await;
    let first_run = world.first_run();
    // One wrong code every 15 minutes, each from a new address: with a counter shared by every
    // client this would pile up delays and lock the admin out; here each client has one.
    for n in 0..20 {
        assert_eq!(
            first_run
                .verify("ZZZZ-ZZZZ-ZZZZ", true, &format!("stranger-{n}"))
                .await,
            Err(AppError::Setup(SetupError::WrongCode))
        );
        world.env.clock.advance(Duration::minutes(15));
    }
    assert!(first_run.verify(&shown, true, "admin").await.is_ok());
}

#[tokio::test]
async fn a_client_that_gets_the_code_right_starts_again() {
    let world = World::new();
    let shown = open_setup(&world).await;
    let first_run = world.first_run();
    for _ in 0..2 {
        assert_eq!(
            first_run.verify("ZZZZ-ZZZZ-ZZZZ", true, "admin").await,
            Err(AppError::Setup(SetupError::WrongCode))
        );
    }
    assert!(first_run.verify(&shown, true, "admin").await.is_ok());
    // Its count was cleared: three more wrong codes are free again.
    for _ in 0..3 {
        assert_eq!(
            first_run.verify("ZZZZ-ZZZZ-ZZZZ", true, "admin").await,
            Err(AppError::Setup(SetupError::WrongCode))
        );
    }
    assert!(matches!(
        first_run.verify(&shown, true, "admin").await,
        Err(AppError::SlowDown { .. })
    ));
}
