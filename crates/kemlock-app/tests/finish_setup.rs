mod fakes;

use fakes::*;
use kemlock_app::{AppError, FirstRun, SetupPhase, SetupState, SignedIn};
use kemlock_domain::{Role, SetupError};
use std::sync::Arc;

/// Runs setup up to the admin's registration and returns the admin's id.
async fn admin(world: &World) -> kemlock_domain::UserId {
    let code = world
        .first_run()
        .start()
        .await
        .expect("start works")
        .expect("a code")
        .as_display();
    let grant = world
        .first_run()
        .verify(&code, true, "client")
        .await
        .expect("the code is right");
    register_account(world, "admin@example.org", Some(grant.token))
        .await
        .expect("the admin registers")
        .user
}

async fn confirm_two_step(world: &World, user: kemlock_domain::UserId) {
    world.enrol_totp().execute(user).await.expect("enrolment");
    let code = totp_code(world, user);
    world
        .confirm_totp()
        .execute(user, &code)
        .await
        .expect("confirmed");
}

#[tokio::test]
async fn setup_can_not_finish_without_a_confirmed_two_step_method() {
    let world = World::new();
    let admin = admin(&world).await;
    assert_eq!(
        world.finish_setup().execute(admin).await,
        Err(AppError::Setup(SetupError::TwoStepRequired))
    );

    // Enrolled but not confirmed is still not enough.
    world.enrol_totp().execute(admin).await.expect("enrolment");
    assert_eq!(
        world.finish_setup().execute(admin).await,
        Err(AppError::Setup(SetupError::TwoStepRequired))
    );
    assert_eq!(world.setup.phase(), SetupPhase::Pending);
    // And until it is, the account is no admin: the role is only given at the end.
    assert_eq!(world.store.user(admin).expect("user").role, Role::User);
    assert_eq!(world.store.admin_count(), 0);
}

#[tokio::test]
async fn setup_closes_for_good_once_two_step_login_is_confirmed_and_makes_the_admin() {
    let world = World::new();
    let admin = admin(&world).await;
    confirm_two_step(&world, admin).await;

    world
        .finish_setup()
        .execute(admin)
        .await
        .expect("setup finishes");
    assert_eq!(world.setup.phase(), SetupPhase::Done);
    assert_eq!(world.store.user(admin).expect("user").role, Role::Admin);
    assert_eq!(world.store.admin_count(), 1);

    // Closed for good: no second finish, no more grants, no code at the next start.
    assert_eq!(
        world.finish_setup().execute(admin).await,
        Err(AppError::Setup(SetupError::AlreadyDone))
    );
    assert_eq!(
        world
            .first_run()
            .verify("AAAA-AAAA-AAAA", true, "client")
            .await,
        Err(AppError::Setup(SetupError::AlreadyDone))
    );
    assert_eq!(world.first_run().start().await, Ok(None));
}

#[tokio::test]
async fn only_the_account_setup_waits_for_can_finish_it() {
    let world = World::new().with_signups();
    let admin = admin(&world).await;
    let user = make_user(&world, "sam@example.org").await;
    confirm_two_step(&world, user).await;
    assert_eq!(
        world.finish_setup().execute(user).await,
        Err(AppError::Forbidden)
    );
    // Nothing changed for either account.
    assert_eq!(world.store.user(user).expect("user").role, Role::User);
    assert_eq!(world.store.user(admin).expect("user").role, Role::User);
    assert_eq!(world.setup.phase(), SetupPhase::Pending);
}

#[tokio::test]
async fn an_account_that_skips_finishing_setup_is_never_an_admin() {
    let world = World::new();
    let admin = admin(&world).await;
    // The account signs in and even sets up two-step login, but never calls finish.
    confirm_two_step(&world, admin).await;
    let signed = sign_in_with(
        &world,
        "admin@example.org",
        &PASSWORD,
        device("Pixel"),
        "jkt-1",
    )
    .await
    .expect("the password step passes");
    let SignedIn::SecondStep(step) = signed else {
        panic!("two-step login is set up, so a second step is expected");
    };
    let tokens = world
        .sign_in()
        .second_step(kemlock_app::SecondStepInput {
            challenge: step.challenge,
            method: kemlock_app::ports::TwoFactorMethod::Totp,
            code: totp_code(&world, admin),
            jkt: "jkt-1".to_owned(),
        })
        .await
        .expect("signs in");
    assert!(!tokens.admin, "no admin before setup finishes");
    let actor = world
        .authenticate()
        .execute(&tokens.access_token, "jkt-1")
        .await
        .expect("authenticates");
    assert!(!actor.admin);
}

#[tokio::test]
async fn a_restart_between_registration_and_finish_resumes_setup_for_that_account() {
    let world = World::new();
    let admin = admin(&world).await;
    assert_eq!(world.setup.phase(), SetupPhase::Pending);

    // The process restarts: fresh in-memory state over the same store. Nobody is an admin yet,
    // but the first-admin marker names the account that never finished.
    let setup = SetupState::new();
    let restarted = FirstRun {
        users: world.store.clone(),
        env: world.env.clone(),
        setup: Arc::clone(&setup),
        config: world.config,
    };
    assert_eq!(
        restarted.start().await,
        Ok(None),
        "no code: nobody else may register"
    );
    assert_eq!(setup.phase(), SetupPhase::Pending);
    assert_eq!(setup.pending(), Some(admin));
    assert_eq!(
        restarted.verify("AAAA-AAAA-AAAA", true, "client").await,
        Err(AppError::Setup(SetupError::AlreadyDone)),
        "registering another admin stays closed"
    );

    // The account finishes setup after the restart, with the new process's state.
    confirm_two_step(&world, admin).await;
    let finish = kemlock_app::FinishSetup {
        users: world.store.clone(),
        two_factor: world.store.clone(),
        setup: Arc::clone(&setup),
        clock: world.env.clone(),
    };
    finish.execute(admin).await.expect("setup finishes");
    assert_eq!(setup.phase(), SetupPhase::Done);
    assert_eq!(world.store.user(admin).expect("user").role, Role::Admin);
}
