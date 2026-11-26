mod fakes;

use fakes::unlock::sign_out_device;
use fakes::*;
use kemlock_app::{AppError, SignedIn, TokenPair};
use kemlock_domain::{Role, UserId};
use time::Duration;

const EMAIL: &str = "sam@example.org";
const JKT: &str = "jkt-1";

async fn signed_in() -> (World, UserId, TokenPair) {
    let world = World::new().with_signups();
    let user = make_user(&world, EMAIL).await;
    let SignedIn::Tokens(tokens) = sign_in_with(&world, EMAIL, &PASSWORD, device("Pixel"), JKT)
        .await
        .expect("signs in")
    else {
        panic!("tokens expected");
    };
    (world, user, tokens)
}

#[tokio::test]
async fn a_token_and_its_key_make_an_actor() {
    let (world, user, tokens) = signed_in().await;
    let actor = world
        .authenticate()
        .execute(&tokens.access_token, JKT)
        .await
        .expect("authenticates");
    assert_eq!(actor.user, user);
    assert_eq!(actor.device, tokens.device);
    assert!(!actor.admin);
}

#[tokio::test]
async fn a_token_used_with_another_key_is_refused() {
    let (world, _user, tokens) = signed_in().await;
    assert_eq!(
        world
            .authenticate()
            .execute(&tokens.access_token, "jkt-thief")
            .await,
        Err(AppError::Unauthorized)
    );
}

#[tokio::test]
async fn an_expired_or_unknown_token_is_refused() {
    let (world, _user, tokens) = signed_in().await;
    assert_eq!(
        world.authenticate().execute("garbage", JKT).await,
        Err(AppError::Unauthorized)
    );
    world.env.clock.advance(Duration::minutes(10));
    assert_eq!(
        world
            .authenticate()
            .execute(&tokens.access_token, JKT)
            .await,
        Err(AppError::Unauthorized)
    );
}

#[tokio::test]
async fn a_changed_security_stamp_ends_every_session() {
    let (world, user, tokens) = signed_in().await;
    let mut account = world.store.user(user).expect("user");
    account.security_stamp = uuid::Uuid::from_u128(99);
    world.store.put_user(account);
    assert_eq!(
        world
            .authenticate()
            .execute(&tokens.access_token, JKT)
            .await,
        Err(AppError::SessionEnded("security-stamp-changed"))
    );
}

#[tokio::test]
async fn a_token_of_a_device_that_was_signed_out_is_refused_at_once() {
    let (world, user, tokens) = signed_in().await;
    let SignedIn::Tokens(other) = sign_in_with(&world, EMAIL, &PASSWORD, device("Laptop"), "jkt-2")
        .await
        .expect("signs in")
    else {
        panic!("tokens expected");
    };
    let me = world
        .authenticate()
        .execute(&tokens.access_token, JKT)
        .await
        .expect("authenticates");

    sign_out_device(&world)
        .execute(&me, other.device)
        .await
        .expect("signs the other device out");

    // Its access token is still unexpired and still carries the account's stamp, and no longer
    // opens anything; the device that signed it out is untouched.
    assert_eq!(
        world
            .authenticate()
            .execute(&other.access_token, "jkt-2")
            .await,
        Err(AppError::SessionEnded("signed-out"))
    );
    assert_eq!(
        world
            .authenticate()
            .execute(&tokens.access_token, JKT)
            .await,
        Ok(me)
    );
    assert_eq!(user, me.user);
}

#[tokio::test]
async fn a_token_naming_a_device_of_another_account_is_refused() {
    let (world, user, tokens) = signed_in().await;
    let stranger = make_user(&world, "kim@example.org").await;
    // The device row now belongs to someone else, as a token minted for another account's device
    // id would find it.
    let mut device_row = world
        .store
        .devices_of(user)
        .into_iter()
        .next()
        .expect("a device");
    device_row.user = stranger;
    kemlock_app::ports::DeviceRepo::upsert(&world.store, &device_row)
        .await
        .expect("moves the device");
    assert_eq!(
        world
            .authenticate()
            .execute(&tokens.access_token, JKT)
            .await,
        Err(AppError::SessionEnded("signed-out"))
    );
}

#[tokio::test]
async fn the_admin_flag_is_the_accounts_role_now() {
    let (world, user, tokens) = signed_in().await;
    let mut account = world.store.user(user).expect("user");
    account.role = Role::Admin;
    world.store.put_user(account);

    // An admin role alone is not enough: without a confirmed two-step method the account acts
    // as an ordinary user.
    let actor = world
        .authenticate()
        .execute(&tokens.access_token, JKT)
        .await
        .expect("authenticates");
    assert!(!actor.admin, "no two-step method, no admin access");

    world.enrol_totp().execute(user).await.expect("enrolment");
    let enrolled_only = world
        .authenticate()
        .execute(&tokens.access_token, JKT)
        .await
        .expect("authenticates");
    assert!(!enrolled_only.admin, "an unconfirmed method doesn't count");

    let code = totp_code(&world, user);
    world
        .confirm_totp()
        .execute(user, &code)
        .await
        .expect("confirmed");
    let actor = world
        .authenticate()
        .execute(&tokens.access_token, JKT)
        .await
        .expect("authenticates");
    assert!(actor.admin, "the token was issued before the promotion");
}

#[tokio::test]
async fn an_admin_without_two_step_login_gets_no_admin_token_either() {
    let (world, user, _tokens) = signed_in().await;
    let mut account = world.store.user(user).expect("user");
    account.role = Role::Admin;
    world.store.put_user(account);
    // Signing in again, as an admin role with no second factor: tokens say user.
    let SignedIn::Tokens(again) = sign_in_with(&world, EMAIL, &PASSWORD, device("Pixel"), JKT)
        .await
        .expect("signs in")
    else {
        panic!("tokens expected");
    };
    assert!(!again.admin);
    let claims = kemlock_app::ports::TokenSigner::verify(
        &world.signer,
        &again.access_token,
        kemlock_app::ports::Clock::now(&world.env),
    )
    .expect("verifies");
    assert!(!claims.admin);
}

#[tokio::test]
async fn an_access_token_dies_with_a_refresh_token_used_twice() {
    let (world, _user, first) = signed_in().await;
    let second = world
        .refresh()
        .execute(&first.refresh_token, JKT)
        .await
        .expect("the first use works");
    world
        .authenticate()
        .execute(&second.access_token, JKT)
        .await
        .expect("the rotated token's access token works");

    // A copy of the first refresh token comes back: the family is revoked and the device's key no
    // longer vouches for it, so the access token the device holds stops at once as well.
    let reuse = world.refresh().execute(&first.refresh_token, JKT).await;
    assert_eq!(reuse, Err(AppError::SessionEnded("refresh-token-reuse")));
    assert_eq!(
        world
            .authenticate()
            .execute(&second.access_token, JKT)
            .await,
        Err(AppError::SessionEnded("signed-out"))
    );
}
