mod fakes;

use fakes::*;
use kemlock_app::ports::{Clock, DeviceRepo, RefreshToken, TokenRepo, TokenSigner};
use kemlock_app::{AppError, SignedIn, TokenPair};
use kemlock_domain::UserId;
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
async fn a_refresh_rotates_the_token_and_keeps_the_family() {
    let (world, user, first) = signed_in().await;
    world.env.clock.advance(Duration::minutes(9));

    let second = world
        .refresh()
        .execute(&first.refresh_token, JKT)
        .await
        .expect("the refresh works");
    assert_ne!(second.refresh_token, first.refresh_token);
    assert_ne!(second.access_token, first.access_token);
    assert_eq!(second.user, user);
    assert_eq!(second.device, first.device);
    assert!(second.access_expires_at > first.access_expires_at);

    // The old token is kept as used; the new one is of the same family.
    let rows = world.store.refresh_tokens();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].family, rows[1].family);
    assert_eq!(rows.iter().filter(|t| t.used_at.is_some()).count(), 1);

    // And the new token rotates again.
    world
        .refresh()
        .execute(&second.refresh_token, JKT)
        .await
        .expect("the next refresh works");
}

#[tokio::test]
async fn a_refresh_token_used_twice_revokes_the_whole_family_and_the_device() {
    let (world, user, first) = signed_in().await;
    let second = world
        .refresh()
        .execute(&first.refresh_token, JKT)
        .await
        .expect("the first use works");

    // The copy of the first token is used again.
    let reuse = world.refresh().execute(&first.refresh_token, JKT).await;
    assert_eq!(reuse, Err(AppError::SessionEnded("refresh-token-reuse")));
    assert!(world.store.refresh_tokens().is_empty());
    // The device is no longer bound to its key, which open live sockets notice.
    let device = DeviceRepo::get(&world.store, first.device)
        .await
        .expect("get")
        .expect("the device is kept");
    assert_eq!(device.dpop_jkt, None);

    // The rotated token, which the legitimate device holds, is dead too.
    let after = world.refresh().execute(&second.refresh_token, JKT).await;
    assert_eq!(after, Err(AppError::Unauthorized));
    assert!(
        world
            .store
            .events()
            .iter()
            .any(|e| e.action == "auth.refresh_reuse" && e.actor == Some(user))
    );
}

#[tokio::test]
async fn a_refresh_token_from_another_key_is_refused_and_ends_the_family() {
    let (world, _user, first) = signed_in().await;
    let stolen = world
        .refresh()
        .execute(&first.refresh_token, "jkt-thief")
        .await;
    assert_eq!(stolen, Err(AppError::SessionEnded("dpop-key-mismatch")));
    assert!(world.store.refresh_tokens().is_empty());
}

#[tokio::test]
async fn a_refresh_token_expires_after_thirty_days() {
    let (world, _user, first) = signed_in().await;
    world.env.clock.advance(Duration::days(30));
    assert_eq!(
        world.refresh().execute(&first.refresh_token, JKT).await,
        Err(AppError::SessionEnded("expired"))
    );
}

#[tokio::test]
async fn a_token_that_isnt_one_is_unauthorized() {
    let (world, _user, _first) = signed_in().await;
    let unknown = kemlock_app::b64url::encode(&[7u8; 32]);
    for garbage in ["", "not base64!", "AAAA", unknown.as_str()] {
        assert_eq!(
            world.refresh().execute(garbage, JKT).await,
            Err(AppError::Unauthorized),
            "{garbage:?}"
        );
    }
}

#[tokio::test]
async fn a_token_whose_device_is_gone_ends_the_session() {
    let (world, user, _first) = signed_in().await;
    let raw = [3u8; 32];
    let now = world.env.now();
    TokenRepo::insert(
        &world.store,
        &RefreshToken {
            hash: kemlock_crypto::hash::sha256(&raw),
            family: uuid::Uuid::from_u128(1),
            user,
            device: kemlock_domain::DeviceId::random(),
            security_stamp: world
                .store
                .user(user)
                .expect("the user exists")
                .security_stamp,
            created_at: now,
            expires_at: now + Duration::days(1),
            used_at: None,
        },
    )
    .await
    .expect("inserts");
    assert_eq!(
        world
            .refresh()
            .execute(&kemlock_app::b64url::encode(&raw), JKT)
            .await,
        Err(AppError::SessionEnded("signed-out"))
    );
}

#[tokio::test]
async fn the_new_access_token_authenticates_with_the_same_key() {
    let (world, user, first) = signed_in().await;
    let second = world
        .refresh()
        .execute(&first.refresh_token, JKT)
        .await
        .expect("the refresh works");
    let actor = world
        .authenticate()
        .execute(&second.access_token, JKT)
        .await
        .expect("authenticates");
    assert_eq!(actor.user, user);
    assert_eq!(actor.device, first.device);
}

#[tokio::test]
async fn a_rotation_that_loses_the_race_with_a_revocation_leaves_no_live_token() {
    let (world, user, first) = signed_in().await;
    let raw = kemlock_app::b64url::decode(&first.refresh_token).expect("base64url");

    // Two requests carry the same refresh token. The first one's take wins: the token is used.
    let winner = TokenRepo::take(
        &world.store,
        kemlock_crypto::hash::sha256(&raw),
        world.env.now(),
    )
    .await
    .expect("take")
    .expect("the token exists");
    assert_eq!(winner.used_at, None, "the winner sees it unused");

    // The second sees it used, and revokes the whole family.
    assert_eq!(
        world.refresh().execute(&first.refresh_token, JKT).await,
        Err(AppError::SessionEnded("refresh-token-reuse"))
    );

    // Only now does the winner issue its successor, in the family that was just revoked. It
    // must not leave a usable token behind, or reuse detection would have been defeated.
    let account = world.store.user(user).expect("the user exists");
    let device = DeviceRepo::get(&world.store, first.device)
        .await
        .expect("get")
        .expect("the device exists");
    let issued = world
        .sessions()
        .issue(
            &account,
            &device,
            JKT,
            Some(kemlock_app::Continued {
                family: winner.family,
                signed_in_at: world.env.now(),
            }),
        )
        .await;
    assert_eq!(
        issued.map(|_| ()),
        Err(AppError::SessionEnded("refresh-token-reuse"))
    );
    assert!(world.store.refresh_tokens().is_empty());
}

#[tokio::test]
async fn a_refresh_after_a_security_stamp_change_is_refused_and_ends_the_family() {
    let (world, user, first) = signed_in().await;
    // A password change: the account's stamp moves on.
    let mut account = world.store.user(user).expect("the user exists");
    account.security_stamp = uuid::Uuid::from_u128(0xc0ffee);
    world.store.put_user(account);

    // The access token is already refused by `authenticate`; the refresh token must not carry
    // the session over the change either, or the old session would renew itself for 30 days.
    assert_eq!(
        world.refresh().execute(&first.refresh_token, JKT).await,
        Err(AppError::SessionEnded("security-stamp-changed"))
    );
    assert!(world.store.refresh_tokens().is_empty());
    assert!(
        world
            .store
            .events()
            .iter()
            .any(|e| e.action == "auth.refresh_stamp_changed" && e.actor == Some(user))
    );

    // Signing in again after the change works, with a token of the new stamp.
    let SignedIn::Tokens(again) = sign_in_with(&world, EMAIL, &PASSWORD, device("Pixel"), JKT)
        .await
        .expect("signs in")
    else {
        panic!("tokens expected");
    };
    world
        .refresh()
        .execute(&again.refresh_token, JKT)
        .await
        .expect("a token of the new stamp refreshes");
}

#[tokio::test]
async fn every_refresh_token_carries_the_stamp_of_its_account() {
    let (world, user, first) = signed_in().await;
    let stamp = world
        .store
        .user(user)
        .expect("the user exists")
        .security_stamp;
    let second = world
        .refresh()
        .execute(&first.refresh_token, JKT)
        .await
        .expect("the refresh works");
    assert!(
        world
            .store
            .refresh_tokens()
            .iter()
            .all(|t| t.security_stamp == stamp)
    );
    assert_eq!(world.store.refresh_tokens().len(), 2);
    assert_ne!(second.refresh_token, first.refresh_token);
}

#[tokio::test]
async fn a_disabled_account_cannot_refresh_even_with_its_stamp_unchanged() {
    let (world, user, first) = signed_in().await;
    // The stamp stays what it was: the flag alone must stop the refresh, as it does for an
    // account Vaultwarden had disabled.
    world.store.set_account_disabled(user, true);

    let result = world.refresh().execute(&first.refresh_token, JKT).await;
    assert_eq!(result, Err(AppError::SessionEnded("account-disabled")));
    assert!(
        world.store.refresh_tokens().is_empty(),
        "the family is revoked"
    );
    assert!(
        world
            .store
            .events()
            .iter()
            .any(|e| e.action == "auth.refresh_disabled" && e.actor == Some(user))
    );

    // Enabling the account doesn't bring the session back: the device signs in again.
    world.store.set_account_disabled(user, false);
    let again = world.refresh().execute(&first.refresh_token, JKT).await;
    assert_eq!(again, Err(AppError::Unauthorized));
}

#[tokio::test]
async fn an_account_whose_deletion_is_pending_cannot_refresh() {
    let (world, user, first) = signed_in().await;
    world.store.set_erasure_pending(user, true);

    let result = world.refresh().execute(&first.refresh_token, JKT).await;
    assert_eq!(result, Err(AppError::SessionEnded("account-being-deleted")));
    assert!(
        world.store.refresh_tokens().is_empty(),
        "the family is revoked"
    );
}

#[tokio::test]
async fn a_refresh_keeps_the_time_of_the_sign_in_it_descends_from() {
    let (world, _user, first) = signed_in().await;
    let signed_in_at = world.env.now();
    let claims = world
        .signer
        .verify(&first.access_token, world.env.now())
        .expect("the access token verifies");
    assert_eq!(claims.auth_time, signed_in_at);

    // Two refreshes, 9 minutes apart: each token is young, the sign-in is not.
    world.env.clock.advance(Duration::minutes(9));
    let second = world
        .refresh()
        .execute(&first.refresh_token, JKT)
        .await
        .expect("the first refresh works");
    world.env.clock.advance(Duration::minutes(9));
    let third = world
        .refresh()
        .execute(&second.refresh_token, JKT)
        .await
        .expect("the second refresh works");
    let claims = world
        .signer
        .verify(&third.access_token, world.env.now())
        .expect("the access token verifies");
    assert_eq!(claims.issued_at, world.env.now());
    assert_eq!(claims.auth_time, signed_in_at);
}
