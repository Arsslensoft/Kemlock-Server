//! The policy routes and the join guard in-process: a device signs in with real OPAQUE and DPoP,
//! then reads and sets a space's policies, and accepts or confirms against them.

mod common;
/// `space_fakes` names the fakes by their path at a test crate's root.
mod fakes {
    pub(crate) use super::common::fakes::*;
}
#[path = "../../kemlock-app/tests/send_fakes/mod.rs"]
mod send_fakes;
#[path = "../../kemlock-app/tests/space_fakes/mod.rs"]
mod space_fakes;

use axum::Router;
use axum::http::StatusCode;
use common::{App, Client, Reply, Req, Session, b64, register_and_sign_in_with};
use kemlock_api_kem::testing::DpopSigner;
use kemlock_api_kem::{policies_router, spaces_router, with_join_guard};
use kemlock_app::ports::{TwoFactor, TwoFactorMethod, TwoFactorRepo};
use kemlock_domain::UserId;
use send_fakes::FakePolicies;
use serde_json::{Value, json};
use space_fakes::{FakeSpaces, name, sealed_key};
use time::macros::datetime;
use uuid::Uuid;

struct Person {
    client: Client,
    session: Session,
    id: UserId,
    email: String,
    /// The key this person signs confirmations with.
    signing: kemlock_crypto::sig1::SigningKey,
    /// The public-key bundle they registered, which carries that key's public half.
    bundle: Vec<u8>,
}

impl Person {
    async fn call(&self, method: &str, uri: &str, body: Option<Value>) -> Reply {
        self.client
            .send(
                method,
                uri,
                Req {
                    access_token: Some(self.session.access_token.as_str()),
                    body,
                    ..Req::default()
                },
            )
            .await
    }

    fn fingerprint(&self) -> Vec<u8> {
        kemlock_crypto::bundle::Bundle::from_bytes(&self.bundle)
            .expect("the bundle parses")
            .fingerprint()
            .to_vec()
    }
}

struct Rig {
    app: App,
    router: Router,
}

impl Rig {
    fn new() -> Rig {
        let app = App::new(true);
        let spaces = FakeSpaces::new(app.store.clone());
        let policies = FakePolicies::new();
        let guarded = with_join_guard(
            spaces_router(app.api.clone(), spaces.clone()),
            app.api.clone(),
            spaces.clone(),
            policies.clone(),
        );
        let router = app.router.clone().merge(guarded).merge(policies_router(
            app.api.clone(),
            spaces,
            policies,
        ));
        Rig { app, router }
    }

    async fn person(&self, email: &str) -> Person {
        let client = Client::new(
            self.router.clone(),
            self.app.clock.clone(),
            DpopSigner::es256(),
        );
        let signing = kemlock_crypto::sig1::SigningKey::generate();
        let session =
            register_and_sign_in_with(&client, email, |user| {
                common::fakes::signed_bundle(user, &signing)
            })
            .await;
        let id = UserId(session.user_id.parse().expect("a user id"));
        let bundle = real_bundle(id, &signing);
        Person {
            client,
            session,
            id,
            email: email.to_owned(),
            signing,
            bundle,
        }
    }

    /// Gives the person a confirmed two-step method.
    async fn enrol_two_step(&self, person: &Person) {
        TwoFactorRepo::put(
            &self.app.store,
            &TwoFactor {
                user: person.id,
                method: TwoFactorMethod::Totp,
                sealed_secret: vec![1; 40],
                enabled: true,
                created_at: datetime!(2026-03-01 12:00 UTC),
            },
        )
        .await
        .expect("enrolled");
    }
}

/// A public-key bundle for `user` with `signing`'s public key, which confirmations are checked
/// against. The exchange half is filler: the server only checks its length.
fn real_bundle(user: UserId, signing: &kemlock_crypto::sig1::SigningKey) -> Vec<u8> {
    kemlock_crypto::bundle::Bundle {
        account_id: *user.as_bytes(),
        key_version: 1,
        kx1_public: kemlock_crypto::kx1::PublicKey::from_bytes(&[0x42; 1600]).expect("a length"),
        sig1_public: signing.public_key().expect("a public key"),
    }
    .to_bytes()
}

fn sealed(fill: u8) -> String {
    b64(&sealed_key(fill))
}

async fn make_space(owner: &Person) -> (Uuid, Uuid) {
    let space = Uuid::new_v4();
    let collection = Uuid::new_v4();
    let reply = owner
        .call(
            "POST",
            "/kem/v1/spaces",
            Some(json!({
                "id": space.to_string(),
                "name": b64(&name(1)),
                "sealedSpaceKey": sealed(2),
                "collection": {
                    "id": collection.to_string(),
                    "name": b64(&name(3)),
                    "sealedKey": sealed(4),
                },
            })),
        )
        .await;
    assert_eq!(reply.status, StatusCode::CREATED, "{:?}", reply.json());
    (space, collection)
}

async fn invite(owner: &Person, member: &Person, space: Uuid) {
    let reply = owner
        .call(
            "POST",
            &format!("/kem/v1/spaces/{space}/members"),
            Some(json!({"email": member.email, "role": "member", "grants": []})),
        )
        .await;
    assert_eq!(reply.status, StatusCode::CREATED, "{:?}", reply.json());
}

async fn accept(member: &Person, space: Uuid) -> Reply {
    member
        .call(
            "POST",
            &format!("/kem/v1/spaces/{space}/members/me/accept"),
            Some(json!({})),
        )
        .await
}

/// Confirms `member`: `owner` signs, with their own key, that they compared the member's
/// fingerprint (docs/crypto.md, "Member confirmation"), which the server checks.
async fn confirm(owner: &Person, member: &Person, space: Uuid) -> Reply {
    let fingerprint: [u8; 64] = member
        .fingerprint()
        .try_into()
        .expect("a fingerprint is 64 bytes");
    let statement = kemlock_crypto::confirm::Statement {
        space: *space.as_bytes(),
        member: *member.id.as_bytes(),
        member_key_version: 1,
        fingerprint: &fingerprint,
        confirmer: *owner.id.as_bytes(),
    };
    let signature = statement
        .sign(&owner.signing)
        .expect("the confirmation signs");
    owner
        .call(
            "POST",
            &format!("/kem/v1/spaces/{space}/members/{}/confirm", member.id),
            Some(json!({
                "fingerprint": b64(&fingerprint),
                "statement": b64(&statement.to_bytes()),
                "signature": b64(&signature),
                "sealedSpaceKey": sealed(5),
                "collectionKeys": [],
            })),
        )
        .await
}

async fn set_policies(owner: &Person, space: Uuid, body: Value) -> Reply {
    owner
        .call(
            "PUT",
            &format!("/kem/v1/spaces/{space}/policies"),
            Some(body),
        )
        .await
}

#[tokio::test]
async fn the_policy_routes_need_a_signed_in_device() {
    let rig = Rig::new();
    let client = Client::new(
        rig.router.clone(),
        rig.app.clock.clone(),
        DpopSigner::es256(),
    );
    let reply = client.get("/kem/v1/policies").await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    assert!(reply.header("dpop-nonce").is_some());
}

#[tokio::test]
async fn an_owner_sets_policies_and_a_member_reads_them() {
    let rig = Rig::new();
    let sam = rig.person("sam@example.org").await;
    let ana = rig.person("ana@example.org").await;
    let (space, _) = make_space(&sam).await;

    // A space with none reads as everything off, with no date.
    let none = sam
        .call("GET", &format!("/kem/v1/spaces/{space}/policies"), None)
        .await;
    assert_eq!(none.status, StatusCode::OK);
    assert_eq!(none.json()["policies"]["twoStep"], false);
    assert_eq!(none.json()["updatedAt"], Value::Null);

    let set = set_policies(
        &sam,
        space,
        json!({
            "masterPassword": {"minLength": 14},
            "alwaysShowEmail": true,
            "sessionTimeoutMinutes": 30,
            "sessionTimeoutAction": "lock",
        }),
    )
    .await;
    assert_eq!(set.status, StatusCode::OK, "{:?}", set.json());
    let set = set.json();
    assert_eq!(set["policies"]["masterPassword"]["minLength"], 14);
    assert_eq!(set["policies"]["alwaysShowEmail"], true);
    assert_eq!(set["policies"]["requireSso"], false);
    assert_eq!(set["updatedBy"], sam.id.to_string());
    assert!(set["updatedAt"].is_i64());

    // Ana joins and reads them; she may not set them.
    invite(&sam, &ana, space).await;
    assert_eq!(accept(&ana, space).await.status, StatusCode::OK);
    assert_eq!(confirm(&sam, &ana, space).await.status, StatusCode::OK);
    let read = ana
        .call("GET", &format!("/kem/v1/spaces/{space}/policies"), None)
        .await;
    assert_eq!(read.status, StatusCode::OK);
    assert_eq!(read.json()["policies"]["sessionTimeoutAction"], "lock");
    let refused = set_policies(&ana, space, json!({})).await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN);

    // What binds Ana: the master password rules and the timeout, reported to her client.
    let mine = ana.call("GET", "/kem/v1/policies", None).await;
    assert_eq!(mine.status, StatusCode::OK);
    assert_eq!(mine.json()["masterPassword"]["minLength"], 14);
    assert_eq!(mine.json()["alwaysShowEmail"], true);
    assert_eq!(mine.json()["sessionTimeoutMinutes"], 30);
    // The owner is exempt from the Send policy of their own space.
    let sams = sam.call("GET", "/kem/v1/policies", None).await;
    assert_eq!(sams.json()["alwaysShowEmail"], false);
    assert_eq!(sams.json()["masterPassword"]["minLength"], 14);

    // Require SSO is one of the policies (there is no narrower route for it): the owner turns it
    // on, a member reads it, and a member can't turn it off.
    let sso = set_policies(&sam, space, json!({"requireSso": true})).await;
    assert_eq!(sso.status, StatusCode::OK, "{:?}", sso.json());
    assert_eq!(sso.json()["policies"]["requireSso"], true);
    let read = ana
        .call("GET", &format!("/kem/v1/spaces/{space}/policies"), None)
        .await;
    assert_eq!(read.json()["policies"]["requireSso"], true);
    let refused = set_policies(&ana, space, json!({"requireSso": false})).await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn outsiders_learn_nothing_and_bad_settings_are_refused() {
    let rig = Rig::new();
    let sam = rig.person("sam@example.org").await;
    let eve = rig.person("eve@example.org").await;
    let (space, _) = make_space(&sam).await;

    let uri = format!("/kem/v1/spaces/{space}/policies");
    assert_eq!(
        eve.call("GET", &uri, None).await.status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        eve.call("PUT", &uri, Some(json!({}))).await.status,
        StatusCode::NOT_FOUND
    );
    let missing = eve
        .call(
            "GET",
            &format!("/kem/v1/spaces/{}/policies", Uuid::new_v4()),
            None,
        )
        .await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);
    assert_eq!(
        sam.call("GET", "/kem/v1/spaces/nope/policies", None)
            .await
            .status,
        StatusCode::BAD_REQUEST
    );

    for bad in [
        json!({"masterPassword": {"minLength": 500}}),
        json!({"sessionTimeoutMinutes": 0}),
        json!({"sessionTimeoutAction": "lock"}),
        json!({"sessionTimeoutMinutes": 5, "sessionTimeoutAction": "sleep"}),
        json!({"surprise": true}),
    ] {
        let reply = set_policies(&sam, space, bad.clone()).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{bad}");
    }
    let still = sam.call("GET", &uri, None).await;
    assert_eq!(still.json()["updatedAt"], Value::Null);
}

#[tokio::test]
async fn a_space_requiring_two_step_refuses_an_accept_until_there_is_one() {
    let rig = Rig::new();
    let sam = rig.person("sam@example.org").await;
    let ana = rig.person("ana@example.org").await;
    let (space, _) = make_space(&sam).await;
    assert_eq!(
        set_policies(&sam, space, json!({"twoStep": true}))
            .await
            .status,
        StatusCode::OK
    );
    invite(&sam, &ana, space).await;

    let refused = accept(&ana, space).await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN);
    assert_eq!(refused.problem(), "policy-two-step-required");
    let view = ana
        .call("GET", &format!("/kem/v1/spaces/{space}"), None)
        .await
        .json();
    assert_eq!(view["me"]["state"], "invited", "she is still only invited");

    rig.enrol_two_step(&ana).await;
    assert_eq!(accept(&ana, space).await.status, StatusCode::OK);
}

#[tokio::test]
async fn confirming_is_checked_too() {
    let rig = Rig::new();
    let sam = rig.person("sam@example.org").await;
    let ana = rig.person("ana@example.org").await;
    let (space, _) = make_space(&sam).await;
    invite(&sam, &ana, space).await;
    assert_eq!(accept(&ana, space).await.status, StatusCode::OK);

    // The policy came on after she accepted; confirming her is refused until she has two-step.
    set_policies(&sam, space, json!({"twoStep": true})).await;
    let refused = confirm(&sam, &ana, space).await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN);
    assert_eq!(refused.problem(), "policy-two-step-required");
    rig.enrol_two_step(&ana).await;
    assert_eq!(confirm(&sam, &ana, space).await.status, StatusCode::OK);
}

#[tokio::test]
async fn one_space_per_member_is_checked_in_both_directions() {
    let rig = Rig::new();
    let sam = rig.person("sam@example.org").await;
    let zed = rig.person("zed@example.org").await;
    let ana = rig.person("ana@example.org").await;
    let (first, _) = make_space(&sam).await;
    let (second, _) = make_space(&zed).await;

    invite(&sam, &ana, first).await;
    assert_eq!(accept(&ana, first).await.status, StatusCode::OK);

    // The second space allows its members in no other space; Ana is in the first.
    set_policies(&zed, second, json!({"singleSpace": true})).await;
    invite(&zed, &ana, second).await;
    let refused = accept(&ana, second).await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN);
    assert_eq!(refused.problem(), "policy-single-space");

    // Without that policy there, but with it on the first, she is barred from the second.
    set_policies(&zed, second, json!({})).await;
    set_policies(&sam, first, json!({"singleSpace": true})).await;
    let barred = accept(&ana, second).await;
    assert_eq!(barred.status, StatusCode::FORBIDDEN);
    assert_eq!(barred.problem(), "policy-other-space-single");

    // With neither, she may.
    set_policies(&sam, first, json!({})).await;
    assert_eq!(accept(&ana, second).await.status, StatusCode::OK);
}

#[tokio::test]
async fn the_guard_leaves_everything_else_alone() {
    let rig = Rig::new();
    let sam = rig.person("sam@example.org").await;
    let (space, _) = make_space(&sam).await;
    // An accept for a space nobody invited her to is the handler's 404, not the guard's.
    let eve = rig.person("eve@example.org").await;
    assert_eq!(accept(&eve, space).await.status, StatusCode::NOT_FOUND);
    // The usual routes work through the guard.
    let list = sam.call("GET", "/kem/v1/spaces", None).await;
    assert_eq!(list.status, StatusCode::OK);
    assert_eq!(list.json().as_array().map(Vec::len), Some(1));
}
