mod fakes;

use fakes::*;
use kemlock_app::AppError;
use kemlock_app::sealed::bound_purpose;
use kemlock_app::ports::{SecretSeal, TwoFactorMethod};
use kemlock_domain::UserId;

#[tokio::test]
async fn enrolling_stores_a_sealed_secret_that_is_not_yet_enabled() {
    let world = World::new().with_signups();
    let user = make_user(&world, "sam@example.org").await;

    let enrolment = world
        .enrol_totp()
        .execute(user)
        .await
        .expect("enrolment works");
    assert_eq!(enrolment.secret.len(), 32, "20 bytes in base32");
    assert!(
        enrolment
            .secret
            .chars()
            .all(|c| c.is_ascii_uppercase() || ('2'..='7').contains(&c))
    );
    assert!(
        enrolment
            .uri
            .starts_with("otpauth://totp/Kemlock:sam%40example.org?secret=")
    );
    assert!(enrolment.uri.contains(&enrolment.secret));
    assert!(enrolment.uri.contains("issuer=Kemlock"));

    let rows = world.store.two_factor_of(user);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].method, TwoFactorMethod::Totp);
    assert!(!rows[0].enabled);
    // Sealed: the stored bytes are not the 20-byte secret itself.
    assert!(rows[0].sealed_secret.len() > 20);
    assert!(
        world
            .seal
            .open(&bound_purpose("totp", user), &rows[0].sealed_secret)
            .is_ok()
    );
    // Bound to the account: not the bare purpose, another purpose or another account.
    assert!(world.seal.open("totp", &rows[0].sealed_secret).is_err());
    assert!(world.seal.open("webauthn", &rows[0].sealed_secret).is_err());
    assert!(
        world
            .seal
            .open(&bound_purpose("totp", UserId::random()), &rows[0].sealed_secret)
            .is_err()
    );
}

#[tokio::test]
async fn enrolling_again_before_confirming_replaces_the_secret() {
    let world = World::new().with_signups();
    let user = make_user(&world, "sam@example.org").await;
    let first = world.enrol_totp().execute(user).await.expect("first");
    let second = world.enrol_totp().execute(user).await.expect("second");
    assert_ne!(first.secret, second.secret);
    assert_eq!(world.store.two_factor_of(user).len(), 1);
}

#[tokio::test]
async fn a_right_code_enables_the_method() {
    let world = World::new().with_signups();
    let user = make_user(&world, "sam@example.org").await;
    world
        .enrol_totp()
        .execute(user)
        .await
        .expect("enrolment works");

    let code = totp_code(&world, user);
    world
        .confirm_totp()
        .execute(user, &code)
        .await
        .expect("a right code confirms");
    assert!(world.store.two_factor_of(user)[0].enabled);
}

#[tokio::test]
async fn a_wrong_code_leaves_it_disabled() {
    let world = World::new().with_signups();
    let user = make_user(&world, "sam@example.org").await;
    world
        .enrol_totp()
        .execute(user)
        .await
        .expect("enrolment works");

    let right = totp_code(&world, user);
    let wrong = if right == "000000" {
        "000001"
    } else {
        "000000"
    };
    assert_eq!(
        world.confirm_totp().execute(user, wrong).await,
        Err(AppError::Unauthorized)
    );
    assert!(!world.store.two_factor_of(user)[0].enabled);
}

#[tokio::test]
async fn confirming_without_an_enrolment_finds_nothing() {
    let world = World::new().with_signups();
    let user = make_user(&world, "sam@example.org").await;
    assert_eq!(
        world.confirm_totp().execute(user, "123456").await,
        Err(AppError::NotFound)
    );
}

#[tokio::test]
async fn a_confirmed_method_can_not_be_replaced_by_a_new_enrolment() {
    let world = World::new().with_signups();
    let user = make_user(&world, "sam@example.org").await;
    world
        .enrol_totp()
        .execute(user)
        .await
        .expect("enrolment works");
    let code = totp_code(&world, user);
    world
        .confirm_totp()
        .execute(user, &code)
        .await
        .expect("confirmed");

    assert_eq!(
        world.enrol_totp().execute(user).await.map(|_| ()),
        Err(AppError::Duplicate)
    );
}

#[tokio::test]
async fn a_code_for_the_next_step_still_passes() {
    // TOTP allows one step either side, so a slightly slow phone still works.
    let world = World::new().with_signups();
    let user = make_user(&world, "sam@example.org").await;
    world
        .enrol_totp()
        .execute(user)
        .await
        .expect("enrolment works");
    let code = totp_code(&world, user);
    world.env.clock.advance(time::Duration::seconds(30));
    world
        .confirm_totp()
        .execute(user, &code)
        .await
        .expect("the previous step's code is accepted");
}

/// A store whose account removes its authenticator in the middle of a confirmation: after the
/// confirmation read the enrolment, before it wrote anything.
#[derive(Clone)]
struct RemovesAfterReading(FakeStore);

impl kemlock_app::ports::TwoFactorRepo for RemovesAfterReading {
    async fn list(
        &self,
        user: UserId,
    ) -> Result<Vec<kemlock_app::ports::TwoFactor>, kemlock_app::ports::StoreError> {
        let read = self.0.list(user).await?;
        kemlock_app::ports::TwoFactorRepo::remove(&self.0, user, TwoFactorMethod::Totp).await?;
        Ok(read)
    }

    async fn put(
        &self,
        two_factor: &kemlock_app::ports::TwoFactor,
    ) -> Result<(), kemlock_app::ports::StoreError> {
        kemlock_app::ports::TwoFactorRepo::put(&self.0, two_factor).await
    }

    async fn accept_totp_step(
        &self,
        user: UserId,
        step: u64,
    ) -> Result<bool, kemlock_app::ports::StoreError> {
        kemlock_app::ports::TwoFactorRepo::accept_totp_step(&self.0, user, step).await
    }

    async fn remove(
        &self,
        user: UserId,
        method: TwoFactorMethod,
    ) -> Result<(), kemlock_app::ports::StoreError> {
        kemlock_app::ports::TwoFactorRepo::remove(&self.0, user, method).await
    }

    async fn replace_if_sealed(
        &self,
        from: &[u8],
        to: &kemlock_app::ports::TwoFactor,
    ) -> Result<bool, kemlock_app::ports::StoreError> {
        kemlock_app::ports::TwoFactorRepo::replace_if_sealed(&self.0, from, to).await
    }
}

#[tokio::test]
async fn confirming_does_not_bring_back_an_authenticator_removed_in_the_meantime() {
    let world = World::new().with_signups();
    let user = make_user(&world, "sam@example.org").await;
    world
        .enrol_totp()
        .execute(user)
        .await
        .expect("enrolment works");
    let code = totp_code(&world, user);

    let racing = kemlock_app::ConfirmTotp {
        two_factor: RemovesAfterReading(world.store.clone()),
        seal: world.seal.clone(),
        totp: world.totp.clone(),
        env: world.env.clone(),
    };
    assert!(matches!(
        racing.execute(user, &code).await,
        Err(AppError::Invalid(_))
    ));
    assert!(
        world.store.two_factor_of(user).is_empty(),
        "the removal stands"
    );
}
