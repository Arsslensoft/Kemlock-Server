mod fakes;

use fakes::*;
use kemlock_app::ports::Clock;
use kemlock_app::{AppError, RegisterStartInput, SetupPhase};
use kemlock_domain::{AccountMode, Role, SetupError, UserId};

#[tokio::test]
async fn registration_is_closed_unless_signups_are_allowed() {
    let world = World::new();
    let (_state, request) =
        kemlock_crypto::opaque::client_registration_start(&PASSWORD).expect("client start");
    let started = world
        .register()
        .start(RegisterStartInput {
            email: "sam@example.org".to_owned(),
            request,
            setup_grant: None,
        })
        .await;
    assert_eq!(started, Err(AppError::Forbidden));

    assert_eq!(
        register_account(&world, "sam@example.org", None).await,
        Err(AppError::Forbidden)
    );
    assert!(world.store.user_by_email("sam@example.org").is_none());
}

#[tokio::test]
async fn a_kemlock_only_account_is_stored_with_its_keys() {
    let world = World::new().with_signups();
    let registered = register_account(&world, "Sam@Example.org", None)
        .await
        .expect("registration works");
    assert!(!registered.admin);

    let user = world.store.user(registered.user).expect("the user exists");
    assert_eq!(user.email.as_str(), "sam@example.org");
    assert_eq!(user.mode, AccountMode::KemlockOnly);
    assert_eq!(user.role, Role::User);
    assert!(user.opaque_record.as_ref().is_some_and(|r| !r.is_empty()));
    assert_eq!(user.key_version, 1);
    assert_eq!(user.public_bundle, bundle(user.id));
    assert_eq!(user.name.as_deref(), Some("Test Person"));
    assert_ne!(user.security_stamp, uuid::Uuid::nil());
}

#[tokio::test]
async fn an_email_can_register_once() {
    let world = World::new().with_signups();
    make_user(&world, "sam@example.org").await;
    assert_eq!(
        register_account(&world, "SAM@example.org", None).await,
        Err(AppError::Duplicate)
    );
}

#[tokio::test]
async fn an_invalid_email_is_refused() {
    let world = World::new().with_signups();
    assert!(matches!(
        register_account(&world, "not-an-email", None).await,
        Err(AppError::Invalid(_))
    ));
}

#[tokio::test]
async fn weak_kdf_settings_and_malformed_keys_are_refused() {
    let world = World::new().with_signups();
    let (state, request) =
        kemlock_crypto::opaque::client_registration_start(&PASSWORD).expect("client start");
    let response = world
        .register()
        .start(RegisterStartInput {
            email: "sam@example.org".to_owned(),
            request,
            setup_grant: None,
        })
        .await
        .expect("start works");
    let (upload, _) =
        kemlock_crypto::opaque::client_registration_finish(state, &PASSWORD, &response)
            .expect("client finish");
    let user = UserId::random();

    let mut weak = register_input(user, "sam@example.org", upload.clone(), None);
    weak.kdf.iterations = 1;
    assert!(matches!(
        world.register().finish(weak).await,
        Err(AppError::Invalid(_))
    ));

    let mut wrong_bundle = register_input(user, "sam@example.org", upload.clone(), None);
    wrong_bundle.public_bundle = bundle(UserId::random());
    assert!(matches!(
        world.register().finish(wrong_bundle).await,
        Err(AppError::Invalid(_))
    ));

    // The right length, but not a signature of the bundle by the key in it.
    let mut unsigned = register_input(user, "sam@example.org", upload.clone(), None);
    unsigned.bundle_signature = vec![0x11; kemlock_app::register::BUNDLE_SIGNATURE_LEN];
    assert!(matches!(
        world.register().finish(unsigned).await,
        Err(AppError::Invalid(_))
    ));
    let mut foreign_signature = register_input(user, "sam@example.org", upload.clone(), None);
    foreign_signature.bundle_signature = bundle_signature(UserId::random());
    assert!(matches!(
        world.register().finish(foreign_signature).await,
        Err(AppError::Invalid(_))
    ));

    let mut short_wrap = register_input(user, "sam@example.org", upload, None);
    short_wrap.wrapped_root_key.truncate(10);
    assert!(matches!(
        world.register().finish(short_wrap).await,
        Err(AppError::Invalid(_))
    ));
    assert!(world.store.user_by_email("sam@example.org").is_none());
}

#[tokio::test]
async fn garbage_instead_of_an_opaque_message_is_refused() {
    let world = World::new().with_signups();
    let started = world
        .register()
        .start(RegisterStartInput {
            email: "sam@example.org".to_owned(),
            request: vec![1, 2, 3],
            setup_grant: None,
        })
        .await;
    assert!(matches!(started, Err(AppError::Invalid(_))));
    let finished = world
        .register()
        .finish(register_input(
            UserId::random(),
            "sam@example.org",
            vec![9; 5],
            None,
        ))
        .await;
    assert!(matches!(finished, Err(AppError::Invalid(_))));
}

async fn grant(world: &World) -> String {
    let code = world
        .first_run()
        .start()
        .await
        .expect("start works")
        .expect("a code")
        .as_display();
    world
        .first_run()
        .verify(&code, true, "client")
        .await
        .expect("the code is right")
        .token
}

#[tokio::test]
async fn a_setup_grant_registers_the_first_admin_even_with_signups_closed() {
    let world = World::new();
    let token = grant(&world).await;
    let registered = register_account(&world, "admin@example.org", Some(token))
        .await
        .expect("the admin registers");
    assert!(registered.admin, "registered as the first admin");
    let user = world.store.user(registered.user).expect("stored");
    // Not an admin yet: a plain user until setup finishes with a confirmed two-step method.
    assert_eq!(user.role, Role::User);
    assert_eq!(world.store.admin_count(), 0);
    assert_eq!(world.setup.phase(), SetupPhase::Pending);
}

#[tokio::test]
async fn a_grant_registers_one_admin_only() {
    let world = World::new();
    let token = grant(&world).await;
    register_account(&world, "admin@example.org", Some(token.clone()))
        .await
        .expect("the admin registers");
    // Setup is no longer open: the same grant, and any other, is refused.
    assert_eq!(
        register_account(&world, "second@example.org", Some(token.clone())).await,
        Err(AppError::Forbidden)
    );
    assert_eq!(
        world.setup.claim(&token, world.env.now()),
        Err(AppError::Setup(SetupError::AlreadyDone))
    );
    assert_eq!(
        world.store.admin_count(),
        0,
        "nobody is an admin before setup finishes"
    );
}

#[tokio::test]
async fn a_made_up_grant_is_refused() {
    let world = World::new();
    let _real = grant(&world).await;
    assert_eq!(
        register_account(&world, "admin@example.org", Some("nope".to_owned())).await,
        Err(AppError::Forbidden)
    );
}

#[tokio::test]
async fn a_refused_registration_leaves_setup_open_for_another_try() {
    let world = World::new();
    let token = grant(&world).await;
    // An invalid registration doesn't spend the grant...
    assert!(matches!(
        register_account(&world, "not-an-email", Some(token.clone())).await,
        Err(AppError::Invalid(_))
    ));
    // ...and the grant still works.
    assert!(
        register_account(&world, "admin@example.org", Some(token))
            .await
            .expect("the admin registers")
            .admin
    );
}

#[tokio::test]
async fn a_taken_email_spends_the_grant_but_not_the_setup() {
    let world = World::new().with_signups();
    make_user(&world, "taken@example.org").await;
    let token = grant(&world).await;
    assert_eq!(
        register_account(&world, "taken@example.org", Some(token)).await,
        Err(AppError::Duplicate)
    );
    // Setup is still open: the code gives a new grant.
    assert_eq!(world.setup.phase(), SetupPhase::NeedsAdmin);
}

#[tokio::test]
async fn only_the_default_kdf_registers_so_prelogin_cant_tell_accounts_apart() {
    let world = World::new().with_signups();
    let (state, request) =
        kemlock_crypto::opaque::client_registration_start(&PASSWORD).expect("client start");
    let response = world
        .register()
        .start(RegisterStartInput {
            email: "sam@example.org".to_owned(),
            request,
            setup_grant: None,
        })
        .await
        .expect("start works");
    let (upload, _) =
        kemlock_crypto::opaque::client_registration_finish(state, &PASSWORD, &response)
            .expect("client finish");
    let user = UserId::random();

    // Inside the bounds Amethystora accepts, yet not what an unknown email's fake answer shows:
    // each would make a real account tell itself apart from a fake one.
    let odd: [fn(&mut kemlock_domain::KdfParams); 4] = [
        |k| k.memory_kib = 32 * 1024,
        |k| k.iterations = 5,
        |k| k.parallelism = 2,
        |k| k.salt = vec![4; 32],
    ];
    for tweak in odd {
        let mut input = register_input(user, "sam@example.org", upload.clone(), None);
        tweak(&mut input.kdf);
        assert!(matches!(
            world.register().finish(input).await,
            Err(AppError::Invalid(_))
        ));
    }
    assert!(world.store.user_by_email("sam@example.org").is_none());

    world
        .register()
        .finish(register_input(user, "sam@example.org", upload, None))
        .await
        .expect("the defaults register");
    let kdf = world
        .prelogin()
        .execute("sam@example.org")
        .await
        .expect("prelogin answers");
    let fake = world.prelogin().fake("ghost@example.org");
    assert!(kdf.is_account_default() && fake.is_account_default());
    assert_eq!(kdf.salt.len(), fake.salt.len());
}

/// A second process of the same server: its own setup state (and so its own code) over the same
/// store.
struct Replica {
    setup: std::sync::Arc<kemlock_app::SetupState>,
    first_run: kemlock_app::FirstRun<FakeStore, FakeEnv>,
    register: kemlock_app::Register<FakeStore, FakePassword, FakeEnv>,
}

fn another_replica(world: &World) -> Replica {
    let setup = kemlock_app::SetupState::new();
    Replica {
        first_run: kemlock_app::FirstRun {
            users: world.store.clone(),
            env: world.env.clone(),
            setup: setup.clone(),
            config: world.config,
        },
        register: kemlock_app::Register {
            users: world.store.clone(),
            auth: world.password.clone(),
            env: world.env.clone(),
            setup: setup.clone(),
            config: world.config,
        },
        setup,
    }
}

#[tokio::test]
async fn two_replicas_with_their_own_codes_still_make_only_one_first_admin() {
    let world = World::new();
    let other = another_replica(&world);

    // Both processes started before any admin existed, so each has a code and grants of its own.
    let code_a = world
        .first_run()
        .start()
        .await
        .expect("start")
        .expect("a code")
        .as_display();
    let code_b = other
        .first_run
        .start()
        .await
        .expect("start")
        .expect("a code")
        .as_display();
    let grant_a = world
        .first_run()
        .verify(&code_a, true, "a")
        .await
        .expect("grant");
    let grant_b = other
        .first_run
        .verify(&code_b, true, "b")
        .await
        .expect("grant");

    // The first process registers the admin.
    register_account(&world, "first@example.org", Some(grant_a.token))
        .await
        .expect("the first admin registers");

    // The second process's own grant is still good in its memory, and nothing it knows says an
    // admin exists, but the database refuses a second first admin.
    assert!(
        other
            .setup
            .has_grant(&grant_b.token, Clock::now(&world.env))
    );
    let (state, request) =
        kemlock_crypto::opaque::client_registration_start(&PASSWORD).expect("client start");
    let response = other
        .register
        .start(RegisterStartInput {
            email: "second@example.org".to_owned(),
            request,
            setup_grant: Some(grant_b.token.clone()),
        })
        .await
        .expect("start works");
    let (upload, _) =
        kemlock_crypto::opaque::client_registration_finish(state, &PASSWORD, &response)
            .expect("client finish");
    let second = other
        .register
        .finish(register_input(
            UserId::random(),
            "second@example.org",
            upload,
            Some(grant_b.token),
        ))
        .await;
    assert_eq!(second, Err(AppError::Setup(SetupError::AlreadyDone)));
    assert!(world.store.user_by_email("second@example.org").is_none());
    // The second process learned the setup was begun elsewhere and takes no more grants.
    assert_ne!(other.setup.phase(), SetupPhase::NeedsAdmin);
}
