//! The spaces routes, in-process: a device signs in with real OPAQUE and DPoP, then drives
//! `/kem/v1/spaces` against the in-memory fakes of `kemlock-app`.

mod common;
/// `space_fakes` names the fakes by their path at a test crate's root.
mod fakes {
    pub(crate) use super::common::fakes::*;
}
#[path = "../../kemlock-app/tests/space_fakes/mod.rs"]
mod space_fakes;

use axum::Router;
use axum::http::StatusCode;
use common::{App, Client, Reply, Req, Session, b64, register_and_sign_in_with};
use kemlock_api_kem::spaces_router;
use kemlock_api_kem::testing::DpopSigner;
use kemlock_app::notices::{BoxFuture, InvitationNotice, Notice, Outbox};
use kemlock_domain::UserId;
use serde_json::{Value, json};
use space_fakes::{FakeSpaces, name, sealed_key};
use uuid::Uuid;

/// A device signed in as one person.
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

    async fn get(&self, uri: &str) -> Reply {
        self.call("GET", uri, None).await
    }

    async fn post(&self, uri: &str, body: Value) -> Reply {
        self.call("POST", uri, Some(body)).await
    }

    async fn put(&self, uri: &str, body: Value) -> Reply {
        self.call("PUT", uri, Some(body)).await
    }

    async fn delete(&self, uri: &str) -> Reply {
        self.call("DELETE", uri, None).await
    }

    /// The fingerprint of this person's public-key bundle, as their app would show it.
    fn fingerprint(&self) -> Vec<u8> {
        kemlock_crypto::bundle::Bundle::from_bytes(&self.bundle)
            .expect("the bundle parses")
            .fingerprint()
            .to_vec()
    }
}

/// The main router with the spaces routes merged in, and the apps' clock to sign proofs by.
struct Rig {
    app: App,
    router: Router,
}

impl Rig {
    fn new() -> Rig {
        Rig::over(App::new(true))
    }

    /// A rig whose emails go to `outbox`.
    fn mailing(outbox: std::sync::Arc<dyn Outbox>) -> Rig {
        Rig::over(App::mailing(true, outbox))
    }

    fn over(app: App) -> Rig {
        let spaces = FakeSpaces::new(app.store.clone());
        let router = app
            .router_with(spaces.clone())
            .merge(spaces_router(app.api.clone(), spaces));
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
            register_and_sign_in_with(&client, email, |user| real_bundle(user, &signing)).await;
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

fn user_key(user: UserId, fill: u8) -> Value {
    json!({"user": user.to_string(), "sealed": sealed(fill)})
}

/// Sam makes a space with its first collection.
async fn make_space(sam: &Person) -> (Uuid, Uuid) {
    let space = Uuid::new_v4();
    let collection = Uuid::new_v4();
    let reply = sam
        .post(
            "/kem/v1/spaces",
            json!({
                "id": space.to_string(),
                "name": b64(&name(1)),
                "sealedSpaceKey": sealed(2),
                "collection": {
                    "id": collection.to_string(),
                    "name": b64(&name(3)),
                    "sealedKey": sealed(4),
                },
            }),
        )
        .await;
    assert_eq!(reply.status, StatusCode::CREATED, "{:?}", reply.json());
    (space, collection)
}

/// `owner` invites `member` with Edit on `collection`; the member accepts; `owner` confirms.
async fn join(owner: &Person, member: &Person, space: Uuid, collection: Uuid) {
    let invited = owner
        .post(
            &format!("/kem/v1/spaces/{space}/members"),
            json!({
                "email": member.email,
                "role": "member",
                "grants": [{"collection": collection.to_string(), "permission": "edit"}],
            }),
        )
        .await;
    assert_eq!(invited.status, StatusCode::CREATED, "{:?}", invited.json());
    let accepted = member
        .post(
            &format!("/kem/v1/spaces/{space}/members/me/accept"),
            json!({}),
        )
        .await;
    assert_eq!(accepted.status, StatusCode::OK, "{:?}", accepted.json());
    let confirmed = owner
        .post(
            &format!("/kem/v1/spaces/{space}/members/{}/confirm", member.id),
            confirm_body(owner, member, space, collection, 6),
        )
        .await;
    assert_eq!(confirmed.status, StatusCode::OK, "{:?}", confirmed.json());
}

/// The body that confirms `member` into `space`: `confirmer` signs, with their own key, that they
/// compared the member's fingerprint (docs/crypto.md, "Member confirmation").
fn confirm_body(
    confirmer: &Person,
    member: &Person,
    space: Uuid,
    collection: Uuid,
    fill: u8,
) -> Value {
    let fingerprint: [u8; 64] = member
        .fingerprint()
        .try_into()
        .expect("a fingerprint is 64 bytes");
    let statement = kemlock_crypto::confirm::Statement {
        space: *space.as_bytes(),
        member: *member.id.as_bytes(),
        member_key_version: 1,
        fingerprint: &fingerprint,
        confirmer: *confirmer.id.as_bytes(),
    };
    let signature = statement
        .sign(&confirmer.signing)
        .expect("the confirmation signs");
    json!({
        "fingerprint": b64(&fingerprint),
        "statement": b64(&statement.to_bytes()),
        "signature": b64(&signature),
        "sealedSpaceKey": sealed(5),
        "collectionKeys": [{"collection": collection.to_string(), "sealed": sealed(fill)}],
    })
}

#[tokio::test]
async fn the_spaces_routes_need_a_signed_in_device() {
    let rig = Rig::new();
    let client = Client::new(
        rig.router.clone(),
        rig.app.clock.clone(),
        DpopSigner::es256(),
    );
    let reply = client.get("/kem/v1/spaces").await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    assert_eq!(reply.problem(), "unauthorized");
    // Answers from the spaces routes carry the DPoP nonce too.
    assert!(reply.header("dpop-nonce").is_some());
}

#[tokio::test]
async fn a_space_is_made_listed_and_viewed() {
    let rig = Rig::new();
    let sam = rig.person("sam@example.org").await;
    let zed = rig.person("zed@example.org").await;
    let (space, collection) = make_space(&sam).await;

    let list = sam.get("/kem/v1/spaces").await;
    assert_eq!(list.status, StatusCode::OK);
    let list = list.json();
    assert_eq!(list.as_array().map(Vec::len), Some(1));
    assert_eq!(list[0]["space"]["id"], space.to_string());
    assert_eq!(list[0]["member"]["role"], "owner");
    assert_eq!(list[0]["member"]["state"], "confirmed");

    let view = sam.get(&format!("/kem/v1/spaces/{space}")).await;
    assert_eq!(view.status, StatusCode::OK);
    let view = view.json();
    assert_eq!(view["space"]["keyVersion"], 1);
    assert_eq!(view["space"]["keysPendingSince"], Value::Null);
    assert_eq!(view["me"]["sealedSpaceKey"], sealed(2));
    assert_eq!(view["collections"][0]["id"], collection.to_string());
    assert_eq!(view["grants"][0]["grantee"], format!("user:{}", sam.id));
    assert_eq!(view["grants"][0]["permission"], "manage");
    assert_eq!(view["collectionKeys"][0]["sealed"], sealed(4));

    // Someone outside the space sees nothing of it, and a missing space looks the same.
    assert!(
        zed.get("/kem/v1/spaces")
            .await
            .json()
            .as_array()
            .expect("a list")
            .is_empty()
    );
    let hidden = zed.get(&format!("/kem/v1/spaces/{space}")).await;
    assert_eq!(hidden.status, StatusCode::NOT_FOUND);
    let missing = zed.get(&format!("/kem/v1/spaces/{}", Uuid::new_v4())).await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);
    assert_eq!(hidden.problem(), missing.problem());
    let not_a_uuid = sam.get("/kem/v1/spaces/nope").await;
    assert_eq!(not_a_uuid.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn a_space_id_is_taken_once_and_values_must_be_base64url() {
    let rig = Rig::new();
    let sam = rig.person("sam@example.org").await;
    let (space, collection) = make_space(&sam).await;
    let body = |id: Uuid, name_field: &str| {
        json!({
            "id": id.to_string(),
            "name": name_field,
            "sealedSpaceKey": sealed(2),
            "collection": {
                "id": collection.to_string(),
                "name": b64(&name(3)),
                "sealedKey": sealed(4),
            },
        })
    };
    let again = sam
        .post("/kem/v1/spaces", body(space, &b64(&name(1))))
        .await;
    assert_eq!(again.status, StatusCode::CONFLICT);
    assert_eq!(again.problem(), "already-exists");
    let padded = sam
        .post("/kem/v1/spaces", body(Uuid::new_v4(), "not base64!"))
        .await;
    assert_eq!(padded.status, StatusCode::BAD_REQUEST);
    assert_eq!(padded.problem(), "invalid-request");
    // A body that isn't what the route takes is refused.
    let extra = sam
        .post(
            "/kem/v1/spaces",
            json!({"id": Uuid::new_v4().to_string(), "surprise": 1}),
        )
        .await;
    assert_eq!(extra.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn a_member_is_invited_accepts_and_is_confirmed_with_a_fingerprint() {
    let rig = Rig::new();
    let sam = rig.person("sam@example.org").await;
    let ana = rig.person("ana@example.org").await;
    let zed = rig.person("zed@example.org").await;
    let (space, collection) = make_space(&sam).await;

    let invited = sam
        .post(
            &format!("/kem/v1/spaces/{space}/members"),
            json!({
                "email": "ana@example.org",
                "role": "member",
                "grants": [{"collection": collection.to_string(), "permission": "edit"}],
            }),
        )
        .await;
    assert_eq!(invited.status, StatusCode::CREATED);
    let invited = invited.json();
    assert_eq!(invited["state"], "invited");
    assert_eq!(invited["sealedSpaceKey"], Value::Null);

    // Ana sees the invitation, and her own row of the space and nothing else of it.
    let mine = ana.get("/kem/v1/spaces").await.json();
    assert_eq!(mine[0]["member"]["state"], "invited");
    let view = ana.get(&format!("/kem/v1/spaces/{space}")).await.json();
    assert_eq!(view["me"]["state"], "invited");
    assert_eq!(view["collections"], json!([]));
    // Only the invitee accepts, for themselves.
    let other = ana
        .post(
            &format!("/kem/v1/spaces/{space}/members/{}/accept", sam.id),
            json!({}),
        )
        .await;
    assert_eq!(other.status, StatusCode::FORBIDDEN);
    let accepted = ana
        .post(
            &format!("/kem/v1/spaces/{space}/members/me/accept"),
            json!({}),
        )
        .await;
    assert_eq!(accepted.status, StatusCode::OK);
    assert_eq!(accepted.json()["state"], "accepted");

    // The owner sees the member list with what's needed to compare and seal.
    let members = sam
        .get(&format!("/kem/v1/spaces/{space}/members"))
        .await
        .json();
    let ana_row = members
        .as_array()
        .and_then(|rows| rows.iter().find(|m| m["user"] == ana.id.to_string()))
        .expect("Ana is listed");
    assert_eq!(ana_row["state"], "accepted");
    assert_eq!(ana_row["email"], "ana@example.org");
    assert_eq!(ana_row["publicBundle"], b64(&ana.bundle));
    assert_eq!(ana_row["needsReconfirmation"], false);

    // A fingerprint that isn't hers confirms nobody.
    let mut wrong = confirm_body(&sam, &ana, space, collection, 6);
    wrong["fingerprint"] = json!(b64(&zed.fingerprint()));
    let refused = sam
        .post(
            &format!("/kem/v1/spaces/{space}/members/{}/confirm", ana.id),
            wrong,
        )
        .await;
    assert_eq!(refused.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(refused.problem(), "fingerprint-mismatch");
    // A member can't confirm; a stranger can't tell the space exists.
    let by_member = ana
        .post(
            &format!("/kem/v1/spaces/{space}/members/{}/confirm", ana.id),
            confirm_body(&ana, &ana, space, collection, 6),
        )
        .await;
    assert_eq!(by_member.status, StatusCode::NOT_FOUND);
    let by_stranger = zed
        .post(
            &format!("/kem/v1/spaces/{space}/members/{}/confirm", ana.id),
            confirm_body(&zed, &ana, space, collection, 6),
        )
        .await;
    assert_eq!(by_stranger.status, StatusCode::NOT_FOUND);

    let body = confirm_body(&sam, &ana, space, collection, 6);
    let confirmed = sam
        .post(
            &format!("/kem/v1/spaces/{space}/members/{}/confirm", ana.id),
            body.clone(),
        )
        .await;
    assert_eq!(confirmed.status, StatusCode::OK, "{:?}", confirmed.json());
    let confirmed = confirmed.json();
    assert_eq!(confirmed["state"], "confirmed");
    assert_eq!(confirmed["confirmation"]["by"], sam.id.to_string());
    assert_eq!(
        confirmed["confirmation"]["fingerprint"],
        b64(&ana.fingerprint())
    );
    assert_eq!(confirmed["confirmation"]["signature"], body["signature"]);
    assert_eq!(confirmed["confirmation"]["statement"], body["statement"]);

    // Now Ana holds the keys and sees the collection; as a member she can't invite or confirm.
    let view = ana.get(&format!("/kem/v1/spaces/{space}")).await.json();
    assert_eq!(view["me"]["sealedSpaceKey"], sealed(5));
    assert_eq!(view["collections"][0]["id"], collection.to_string());
    assert_eq!(view["collectionKeys"][0]["sealed"], sealed(6));
    let forbidden = ana
        .post(
            &format!("/kem/v1/spaces/{space}/members"),
            json!({"email": "zed@example.org", "role": "member"}),
        )
        .await;
    assert_eq!(forbidden.status, StatusCode::FORBIDDEN);
    assert_eq!(forbidden.problem(), "forbidden");
}

#[tokio::test]
async fn roles_change_only_as_the_rules_allow() {
    let rig = Rig::new();
    let sam = rig.person("sam@example.org").await;
    let ana = rig.person("ana@example.org").await;
    let (space, collection) = make_space(&sam).await;
    join(&sam, &ana, space, collection).await;
    let role = |who: UserId, role: &str| {
        let uri = format!("/kem/v1/spaces/{space}/members/{who}/role");
        (uri, json!({"role": role, "custom": []}))
    };

    // Ana can't make anyone an owner, and the last owner can't step down.
    let (uri, body) = role(ana.id, "owner");
    assert_eq!(ana.put(&uri, body).await.status, StatusCode::FORBIDDEN);
    let (uri, body) = role(sam.id, "admin");
    let last = sam.put(&uri, body).await;
    assert_eq!(last.status, StatusCode::CONFLICT);
    assert_eq!(last.problem(), "last-owner");
    // Sam makes Ana an owner, a Custom role carries permissions by name, and an unknown one fails.
    let (uri, body) = role(ana.id, "owner");
    let made = sam.put(&uri, body).await;
    assert_eq!(made.status, StatusCode::OK, "{:?}", made.json());
    assert_eq!(made.json()["role"], "owner");
    let custom = sam
        .put(
            &format!("/kem/v1/spaces/{space}/members/{}/role", ana.id),
            json!({"role": "custom", "custom": ["manage-users", "create-collections"]}),
        )
        .await;
    assert_eq!(custom.status, StatusCode::OK, "{:?}", custom.json());
    assert_eq!(
        custom.json()["custom"],
        json!(["manage-users", "create-collections"])
    );
    let unknown = sam
        .put(
            &format!("/kem/v1/spaces/{space}/members/{}/role", ana.id),
            json!({"role": "custom", "custom": ["fly"]}),
        )
        .await;
    assert_eq!(unknown.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn revoking_pauses_the_space_until_the_keys_are_replaced() {
    let rig = Rig::new();
    let sam = rig.person("sam@example.org").await;
    let ana = rig.person("ana@example.org").await;
    let (space, collection) = make_space(&sam).await;
    join(&sam, &ana, space, collection).await;

    let revoked = sam
        .post(
            &format!("/kem/v1/spaces/{space}/members/{}/revoke", ana.id),
            json!({}),
        )
        .await;
    assert_eq!(revoked.status, StatusCode::OK, "{:?}", revoked.json());
    let revoked = revoked.json();
    assert_eq!(revoked["keysPending"], true);
    assert_eq!(revoked["exposed"][0]["collection"], collection.to_string());
    assert_eq!(revoked["exposed"][0]["liveItems"], 0);

    // Ana no longer sees the space; Sam sees it paused, and key-bearing changes are 423.
    assert_eq!(
        ana.get(&format!("/kem/v1/spaces/{space}")).await.status,
        StatusCode::NOT_FOUND
    );
    let view = sam.get(&format!("/kem/v1/spaces/{space}")).await.json();
    assert!(view["space"]["keysPendingSince"].is_number());
    assert!(view["collections"][0]["staleSince"].is_number());
    let paused = sam
        .post(
            &format!("/kem/v1/spaces/{space}/collections"),
            json!({"id": Uuid::new_v4().to_string(), "name": b64(&name(9)),
                   "keys": [user_key(sam.id, 7)]}),
        )
        .await;
    assert_eq!(paused.status, StatusCode::LOCKED);
    assert_eq!(paused.problem(), "space-keys-pending");

    // An incomplete replacement is refused and changes nothing; a complete one lands.
    let incomplete = sam
        .post(
            &format!("/kem/v1/spaces/{space}/key-replacement"),
            json!({"spaceKeyVersion": 2}),
        )
        .await;
    assert_eq!(incomplete.status, StatusCode::BAD_REQUEST);
    let still = sam.get(&format!("/kem/v1/spaces/{space}")).await.json();
    assert_eq!(still["space"]["keyVersion"], 1);

    let landed = sam
        .post(
            &format!("/kem/v1/spaces/{space}/key-replacement"),
            json!({
                "spaceKeyVersion": 2,
                "spaceName": b64(&name(40)),
                "sealedSpaceKeys": [user_key(sam.id, 20)],
                "collectionNames": [{"id": collection.to_string(), "name": b64(&name(41))}],
                "groupNames": [],
                "collections": [{
                    "collection": collection.to_string(),
                    "keyVersion": 2,
                    "keys": [user_key(sam.id, 21)],
                }],
                "writes": [],
            }),
        )
        .await;
    assert_eq!(landed.status, StatusCode::OK, "{:?}", landed.json());
    assert_eq!(landed.json()["items"], json!([]));
    let after = sam.get(&format!("/kem/v1/spaces/{space}")).await.json();
    assert_eq!(after["space"]["keyVersion"], 2);
    assert_eq!(after["space"]["keysPendingSince"], Value::Null);
    assert_eq!(after["collections"][0]["keyVersion"], 2);
    assert_eq!(after["me"]["sealedSpaceKey"], sealed(20));
    assert_eq!(after["collectionKeys"][0]["sealed"], sealed(21));

    // Nothing waits any more; a second replacement is a conflict of state, and Ana, revoked, can
    // be restored to wait for confirmation.
    let nothing = sam
        .post(
            &format!("/kem/v1/spaces/{space}/key-replacement"),
            json!({"spaceKeyVersion": 3}),
        )
        .await;
    assert_eq!(nothing.status, StatusCode::CONFLICT);
    let again = sam
        .post(
            &format!("/kem/v1/spaces/{space}/members/{}/revoke", ana.id),
            json!({}),
        )
        .await;
    assert_eq!(again.status, StatusCode::CONFLICT);
    assert_eq!(again.problem(), "wrong-state");
    let restored = sam
        .post(
            &format!("/kem/v1/spaces/{space}/members/{}/restore", ana.id),
            json!({}),
        )
        .await;
    assert_eq!(restored.status, StatusCode::OK);
    assert_eq!(restored.json()["state"], "accepted");
}

#[tokio::test]
async fn a_member_who_leaves_is_removed() {
    let rig = Rig::new();
    let sam = rig.person("sam@example.org").await;
    let ana = rig.person("ana@example.org").await;
    let (space, collection) = make_space(&sam).await;
    join(&sam, &ana, space, collection).await;

    let left = ana
        .delete(&format!("/kem/v1/spaces/{space}/members/me"))
        .await;
    assert_eq!(left.status, StatusCode::OK, "{:?}", left.json());
    assert_eq!(left.json()["keysPending"], true);
    assert!(
        ana.get("/kem/v1/spaces")
            .await
            .json()
            .as_array()
            .expect("a list")
            .is_empty()
    );
    // The only owner can't leave.
    let owner = sam
        .delete(&format!("/kem/v1/spaces/{space}/members/me"))
        .await;
    assert_eq!(owner.status, StatusCode::CONFLICT);
    assert_eq!(owner.problem(), "last-owner");
}

#[tokio::test]
async fn collections_groups_and_grants_are_shaped_over_http() {
    let rig = Rig::new();
    let sam = rig.person("sam@example.org").await;
    let ana = rig.person("ana@example.org").await;
    let (space, everyone) = make_space(&sam).await;
    join(&sam, &ana, space, everyone).await;

    // A collection made with keys for exactly its grantees: Sam alone here.
    let finance = Uuid::new_v4();
    let missing_key = sam
        .post(
            &format!("/kem/v1/spaces/{space}/collections"),
            json!({"id": finance.to_string(), "name": b64(&name(10)), "keys": []}),
        )
        .await;
    assert_eq!(missing_key.status, StatusCode::BAD_REQUEST);
    let made = sam
        .post(
            &format!("/kem/v1/spaces/{space}/collections"),
            json!({"id": finance.to_string(), "name": b64(&name(10)),
                   "keys": [user_key(sam.id, 11)]}),
        )
        .await;
    assert_eq!(made.status, StatusCode::CREATED, "{:?}", made.json());
    assert_eq!(made.json()["keyVersion"], 1);
    // Ana, an editor of Everyone only, can't see Finance.
    let ana_collections = ana
        .get(&format!("/kem/v1/spaces/{space}/collections"))
        .await
        .json();
    assert_eq!(ana_collections.as_array().map(Vec::len), Some(1));

    // Granting needs the key sealed to Ana; with it, she sees the collection.
    let no_key = sam
        .put(
            &format!("/kem/v1/spaces/{space}/grants"),
            json!({"collection": finance.to_string(), "grantee": format!("user:{}", ana.id),
                   "permission": "view", "keys": []}),
        )
        .await;
    assert_eq!(no_key.status, StatusCode::BAD_REQUEST);
    let granted = sam
        .put(
            &format!("/kem/v1/spaces/{space}/grants"),
            json!({"collection": finance.to_string(), "grantee": format!("user:{}", ana.id),
                   "permission": "view", "keys": [user_key(ana.id, 12)]}),
        )
        .await;
    assert_eq!(granted.status, StatusCode::OK, "{:?}", granted.json());
    assert_eq!(granted.json()["permission"], "view");
    assert_eq!(
        ana.get(&format!("/kem/v1/spaces/{space}/collections"))
            .await
            .json()
            .as_array()
            .map(Vec::len),
        Some(2)
    );
    let grants = sam
        .get(&format!("/kem/v1/spaces/{space}/grants"))
        .await
        .json();
    assert!(grants.as_array().expect("a list").len() >= 4);

    // A bad permission or grantee is a bad request.
    let bad_permission = sam
        .put(
            &format!("/kem/v1/spaces/{space}/grants"),
            json!({"collection": finance.to_string(), "grantee": format!("user:{}", ana.id),
                   "permission": "own", "keys": []}),
        )
        .await;
    assert_eq!(bad_permission.status, StatusCode::BAD_REQUEST);
    let bad_grantee = sam
        .put(
            &format!("/kem/v1/spaces/{space}/grants"),
            json!({"collection": finance.to_string(), "grantee": "team:x",
                   "permission": "view", "keys": []}),
        )
        .await;
    assert_eq!(bad_grantee.status, StatusCode::BAD_REQUEST);

    // Revoking the grant takes it away once.
    let grant_uri = format!("/kem/v1/spaces/{space}/grants/{finance}/user:{}", ana.id);
    assert_eq!(sam.delete(&grant_uri).await.status, StatusCode::NO_CONTENT);
    assert_eq!(sam.delete(&grant_uri).await.status, StatusCode::NOT_FOUND);

    // A group: made, renamed, deleted.
    let ops = Uuid::new_v4();
    let group = sam
        .post(
            &format!("/kem/v1/spaces/{space}/groups"),
            json!({"id": ops.to_string(), "name": b64(&name(20)), "members": [ana.id.to_string()]}),
        )
        .await;
    assert_eq!(group.status, StatusCode::CREATED, "{:?}", group.json());
    assert_eq!(group.json()["members"], json!([ana.id.to_string()]));
    let renamed = sam
        .put(
            &format!("/kem/v1/spaces/{space}/groups/{ops}"),
            json!({"name": b64(&name(21))}),
        )
        .await;
    assert_eq!(renamed.status, StatusCode::OK, "{:?}", renamed.json());
    assert_eq!(renamed.json()["name"], b64(&name(21)));
    let groups = sam
        .get(&format!("/kem/v1/spaces/{space}/groups"))
        .await
        .json();
    assert_eq!(groups.as_array().map(Vec::len), Some(1));
    assert_eq!(
        sam.delete(&format!("/kem/v1/spaces/{space}/groups/{ops}"))
            .await
            .status,
        StatusCode::NO_CONTENT
    );

    // A collection: renamed and moved to the top, then deleted while empty.
    let moved = sam
        .put(
            &format!("/kem/v1/spaces/{space}/collections/{finance}"),
            json!({"name": b64(&name(30)), "moveToTop": true}),
        )
        .await;
    assert_eq!(moved.status, StatusCode::OK, "{:?}", moved.json());
    assert_eq!(moved.json()["parent"], Value::Null);
    let both = sam
        .put(
            &format!("/kem/v1/spaces/{space}/collections/{finance}"),
            json!({"parent": everyone.to_string(), "moveToTop": true}),
        )
        .await;
    assert_eq!(both.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        sam.delete(&format!("/kem/v1/spaces/{space}/collections/{finance}"))
            .await
            .status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        sam.delete(&format!("/kem/v1/spaces/{space}/collections/{finance}"))
            .await
            .status,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn the_spaces_openapi_names_every_route() {
    let doc = serde_json::to_value(kemlock_api_kem::spaces_openapi()).expect("the document");
    for (path, method) in [
        ("/kem/v1/spaces", "get"),
        ("/kem/v1/spaces", "post"),
        ("/kem/v1/spaces/{id}", "get"),
        ("/kem/v1/spaces/{id}/members", "get"),
        ("/kem/v1/spaces/{id}/members", "post"),
        ("/kem/v1/spaces/{id}/members/{user}/accept", "post"),
        ("/kem/v1/spaces/{id}/members/{user}/confirm", "post"),
        ("/kem/v1/spaces/{id}/members/{user}/role", "put"),
        ("/kem/v1/spaces/{id}/members/{user}/revoke", "post"),
        ("/kem/v1/spaces/{id}/members/{user}/restore", "post"),
        ("/kem/v1/spaces/{id}/members/{user}", "delete"),
        ("/kem/v1/spaces/{id}/collections", "get"),
        ("/kem/v1/spaces/{id}/collections", "post"),
        ("/kem/v1/spaces/{id}/collections/{collection}", "put"),
        ("/kem/v1/spaces/{id}/collections/{collection}", "delete"),
        ("/kem/v1/spaces/{id}/groups", "get"),
        ("/kem/v1/spaces/{id}/groups", "post"),
        ("/kem/v1/spaces/{id}/groups/{group}", "put"),
        ("/kem/v1/spaces/{id}/groups/{group}", "delete"),
        ("/kem/v1/spaces/{id}/grants", "get"),
        ("/kem/v1/spaces/{id}/grants", "put"),
        (
            "/kem/v1/spaces/{id}/grants/{collection}/{grantee}",
            "delete",
        ),
        ("/kem/v1/spaces/{id}/key-replacement", "post"),
    ] {
        assert!(
            doc["paths"][path][method].is_object(),
            "{method} {path} is documented"
        );
    }
}

// ---- items of a space ----

/// An item of `space` in `collection`, in docs/crypto.md's wire shape with random sealed bytes.
fn space_item(space: Uuid, collection: Option<Uuid>, id: Uuid, revision: u64) -> Value {
    let mut item = json!({
        "id": id.to_string(),
        "owner": format!("space:{space}"),
        "kind": "login",
        "format": "kem1",
        "revision": revision,
        "keyVersion": 1,
        "ciphertext": b64(&kemlock_crypto::rand::bytes::<64>()),
        "itemKey": b64(&kemlock_crypto::rand::bytes::<60>()),
        "deleted": false,
    });
    if let Some(collection) = collection {
        item["collectionId"] = json!(collection.to_string());
    }
    item
}

impl Person {
    /// A write with a precondition header, as the item routes take.
    async fn write(
        &self,
        method: &str,
        uri: &str,
        header: (&'static str, &str),
        body: Value,
    ) -> Reply {
        self.client
            .send(
                method,
                uri,
                Req {
                    access_token: Some(self.session.access_token.as_str()),
                    headers: vec![(header.0, header.1.to_owned())],
                    body: Some(body),
                    ..Req::default()
                },
            )
            .await
    }

    async fn put_new(&self, id: Uuid, body: Value) -> Reply {
        self.write(
            "PUT",
            &format!("/kem/v1/items/{id}"),
            ("if-none-match", "*"),
            body,
        )
        .await
    }
}

#[tokio::test]
async fn a_member_with_edit_writes_a_space_item_and_syncs_it_with_its_collection() {
    let rig = Rig::new();
    let sam = rig.person("sam@example.org").await;
    let ana = rig.person("ana@example.org").await;
    let (space, collection) = make_space(&sam).await;
    join(&sam, &ana, space, collection).await;

    let id = Uuid::new_v4();
    let created = ana
        .put_new(id, space_item(space, Some(collection), id, 1))
        .await;
    assert_eq!(created.status, StatusCode::CREATED, "{:?}", created.json());
    assert_eq!(created.json()["collectionId"], collection.to_string());
    assert_eq!(created.json()["owner"], format!("space:{space}"));

    // Sam, a member too, receives it in his sync, with the collection that holds its key.
    let synced = sam.get("/kem/v1/sync").await;
    assert_eq!(synced.status, StatusCode::OK);
    let items = synced.json()["items"].clone();
    assert_eq!(items.as_array().map(Vec::len), Some(1));
    assert_eq!(items[0]["id"], id.to_string());
    assert_eq!(items[0]["collectionId"], collection.to_string());

    // A replacement names the revision it replaces, as for a vault item.
    let replaced = ana
        .write(
            "PUT",
            &format!("/kem/v1/items/{id}"),
            ("if-match", "1"),
            space_item(space, Some(collection), id, 2),
        )
        .await;
    assert_eq!(replaced.status, StatusCode::OK, "{:?}", replaced.json());
    let stale = ana
        .write(
            "PUT",
            &format!("/kem/v1/items/{id}"),
            ("if-match", "1"),
            space_item(space, Some(collection), id, 2),
        )
        .await;
    assert_eq!(stale.status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn a_space_item_is_refused_without_a_collection_or_to_an_outsider() {
    let rig = Rig::new();
    let sam = rig.person("sam@example.org").await;
    let zed = rig.person("zed@example.org").await;
    let (space, collection) = make_space(&sam).await;

    let id = Uuid::new_v4();
    let no_collection = sam.put_new(id, space_item(space, None, id, 1)).await;
    assert_eq!(no_collection.status, StatusCode::BAD_REQUEST);
    // Someone outside the space learns nothing of it, as for its other routes.
    let outsider = zed
        .put_new(id, space_item(space, Some(collection), id, 1))
        .await;
    assert_eq!(outsider.status, StatusCode::NOT_FOUND);
    // A vault item has no collection.
    let mut vault = common::item_json(&zed.id.to_string(), &id.to_string(), 1);
    vault["collectionId"] = json!(collection.to_string());
    let stray = zed.put_new(id, vault).await;
    assert_eq!(stray.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn a_member_with_only_a_view_cannot_write() {
    let rig = Rig::new();
    let sam = rig.person("sam@example.org").await;
    let lee = rig.person("lee@example.org").await;
    let (space, collection) = make_space(&sam).await;
    let invited = sam
        .post(
            &format!("/kem/v1/spaces/{space}/members"),
            json!({
                "email": "lee@example.org",
                "role": "member",
                "grants": [{"collection": collection.to_string(), "permission": "view"}],
            }),
        )
        .await;
    assert_eq!(invited.status, StatusCode::CREATED, "{:?}", invited.json());
    lee.post(
        &format!("/kem/v1/spaces/{space}/members/me/accept"),
        json!({}),
    )
    .await;
    let confirmed = sam
        .post(
            &format!("/kem/v1/spaces/{space}/members/{}/confirm", lee.id),
            confirm_body(&sam, &lee, space, collection, 6),
        )
        .await;
    assert_eq!(confirmed.status, StatusCode::OK, "{:?}", confirmed.json());

    let id = Uuid::new_v4();
    let refused = lee
        .put_new(id, space_item(space, Some(collection), id, 1))
        .await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn a_batch_stores_vault_and_space_items_together() {
    let rig = Rig::new();
    let sam = rig.person("sam@example.org").await;
    let (space, collection) = make_space(&sam).await;

    let (own, shared) = (Uuid::new_v4(), Uuid::new_v4());
    let batch = sam
        .post(
            "/kem/v1/items:batch",
            json!({"writes": [
                {"item": common::item_json(&sam.id.to_string(), &own.to_string(), 1)},
                {"item": space_item(space, Some(collection), shared, 1)},
            ]}),
        )
        .await;
    assert_eq!(batch.status, StatusCode::OK, "{:?}", batch.json());
    let items = batch.json()["items"].clone();
    assert_eq!(items.as_array().map(Vec::len), Some(2));
    assert!(items[0].get("collectionId").is_none());
    assert_eq!(items[1]["collectionId"], collection.to_string());

    // One bad write stores none of them: the second names no collection.
    let (first, second) = (Uuid::new_v4(), Uuid::new_v4());
    let refused = sam
        .post(
            "/kem/v1/items:batch",
            json!({"writes": [
                {"item": common::item_json(&sam.id.to_string(), &first.to_string(), 1)},
                {"item": space_item(space, None, second, 1)},
            ]}),
        )
        .await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST);
    let synced = sam.get("/kem/v1/sync").await.json();
    let ids: Vec<&str> = synced["items"]
        .as_array()
        .expect("a list")
        .iter()
        .filter_map(|i| i["id"].as_str())
        .collect();
    assert!(ids.contains(&own.to_string().as_str()));
    assert!(!ids.contains(&first.to_string().as_str()));
}

#[tokio::test]
async fn a_confirmation_must_be_the_confirmers_signature_over_this_members_fingerprint() {
    let rig = Rig::new();
    let sam = rig.person("sam@example.org").await;
    let ana = rig.person("ana@example.org").await;
    let zed = rig.person("zed@example.org").await;
    let (space, collection) = make_space(&sam).await;
    let invited = sam
        .post(
            &format!("/kem/v1/spaces/{space}/members"),
            json!({
                "email": "ana@example.org",
                "role": "member",
                "grants": [{"collection": collection.to_string(), "permission": "edit"}],
            }),
        )
        .await;
    assert_eq!(invited.status, StatusCode::CREATED, "{:?}", invited.json());
    ana.post(
        &format!("/kem/v1/spaces/{space}/members/me/accept"),
        json!({}),
    )
    .await;
    let uri = format!("/kem/v1/spaces/{space}/members/{}/confirm", ana.id);

    // A signature with another key (here Zed's) is no confirmation by Sam.
    let mut forged = confirm_body(&sam, &ana, space, collection, 6);
    forged["signature"] = confirm_body(&zed, &ana, space, collection, 6)["signature"].clone();
    let refused = sam.post(&uri, forged).await;
    assert_eq!(
        refused.status,
        StatusCode::BAD_REQUEST,
        "{:?}",
        refused.json()
    );

    // A statement about another member, signed by Sam, doesn't confirm Ana.
    let mut about_zed = confirm_body(&sam, &zed, space, collection, 6);
    about_zed["fingerprint"] =
        confirm_body(&sam, &ana, space, collection, 6)["fingerprint"].clone();
    let refused = sam.post(&uri, about_zed).await;
    assert_eq!(
        refused.status,
        StatusCode::BAD_REQUEST,
        "{:?}",
        refused.json()
    );

    // The signature is over the statement's bytes: a flipped byte breaks it.
    let mut flipped = confirm_body(&sam, &ana, space, collection, 6);
    let mut statement = common::unb64(flipped["statement"].as_str().expect("a statement"));
    statement[60] ^= 1;
    flipped["statement"] = json!(b64(&statement));
    let refused = sam.post(&uri, flipped).await;
    assert_eq!(
        refused.status,
        StatusCode::BAD_REQUEST,
        "{:?}",
        refused.json()
    );

    // None of those left Ana half confirmed.
    let view = ana.get(&format!("/kem/v1/spaces/{space}")).await.json();
    assert_eq!(view["me"]["state"], "accepted");

    let confirmed = sam
        .post(&uri, confirm_body(&sam, &ana, space, collection, 6))
        .await;
    assert_eq!(confirmed.status, StatusCode::OK, "{:?}", confirmed.json());
}

// ---------------------------------------------------------------------------------------------
// Space manifests.

/// A manifest of `space`'s items at `counter`, signed with `person`'s key.
fn space_manifest(person: &Person, space: Uuid, counter: u64) -> Value {
    use kemlock_crypto::manifest::{Entry, Manifest};
    use kemlock_crypto::owner::Owner;
    let manifest = Manifest {
        owner: Owner::space(*space.as_bytes()),
        counter,
        entries: vec![Entry::live([2; 16], 3, b"cipher two")],
    };
    json!({
        "manifest": b64(&manifest.to_bytes().expect("encodes")),
        "signature": b64(&manifest.sign(&person.signing).expect("signs")),
    })
}

/// A manifest of `person`'s own items at `counter`.
fn own_manifest(person: &Person, counter: u64) -> Value {
    use kemlock_crypto::manifest::{Entry, Manifest};
    use kemlock_crypto::owner::Owner;
    let manifest = Manifest {
        owner: Owner::user(*person.id.as_bytes()),
        counter,
        entries: vec![Entry::live([1; 16], 1, b"cipher one")],
    };
    json!({
        "manifest": b64(&manifest.to_bytes().expect("encodes")),
        "signature": b64(&manifest.sign(&person.signing).expect("signs")),
    })
}

#[tokio::test]
async fn a_member_with_edit_stores_the_spaces_manifest_and_members_read_it() {
    let rig = Rig::new();
    let sam = rig.person("sam@example.org").await;
    let ana = rig.person("ana@example.org").await;
    let (space, collection) = make_space(&sam).await;
    join(&sam, &ana, space, collection).await;
    let uri = format!("/kem/v1/manifests/space:{space}");

    assert_eq!(sam.get(&uri).await.status, StatusCode::NOT_FOUND);
    let body = space_manifest(&ana, space, 3);
    let put = ana.put(&uri, body.clone()).await;
    assert_eq!(put.status, StatusCode::OK, "{:?}", put.json());
    assert_eq!(put.json()["owner"], format!("space:{space}"));
    assert_eq!(put.json()["counter"], 3);
    assert_eq!(put.json()["signer"], ana.id.to_string());

    // Every confirmed member reads what any member stored, signer named.
    let read = sam.get(&uri).await;
    assert_eq!(read.status, StatusCode::OK, "{:?}", read.json());
    assert_eq!(read.json()["manifest"], body["manifest"]);
    assert_eq!(read.json()["signer"], ana.id.to_string());

    // The counter only goes up, per space: the account's own counter is another one.
    let stale = sam.put(&uri, space_manifest(&sam, space, 3)).await;
    assert_eq!(stale.status, StatusCode::CONFLICT);
    assert_eq!(stale.json()["currentCounter"], 3);
    let next = sam.put(&uri, space_manifest(&sam, space, 4)).await;
    assert_eq!(next.status, StatusCode::OK, "{:?}", next.json());
    assert_eq!(next.json()["signer"], sam.id.to_string());
    let own = sam
        .put(
            &format!("/kem/v1/manifests/user:{}", sam.id),
            own_manifest(&sam, 1),
        )
        .await;
    assert_eq!(own.status, StatusCode::OK, "{:?}", own.json());
    let (second, _) = make_space(&sam).await;
    let elsewhere = sam
        .put(
            &format!("/kem/v1/manifests/space:{second}"),
            space_manifest(&sam, second, 1),
        )
        .await;
    assert_eq!(elsewhere.status, StatusCode::OK, "{:?}", elsewhere.json());
}

#[tokio::test]
async fn a_spaces_manifest_is_refused_to_outsiders_viewers_and_forgeries() {
    let rig = Rig::new();
    let sam = rig.person("sam@example.org").await;
    let lee = rig.person("lee@example.org").await;
    let zed = rig.person("zed@example.org").await;
    let (space, collection) = make_space(&sam).await;
    let uri = format!("/kem/v1/manifests/space:{space}");

    // Lee is a confirmed member with view only.
    let invited = sam
        .post(
            &format!("/kem/v1/spaces/{space}/members"),
            json!({
                "email": "lee@example.org",
                "role": "member",
                "grants": [{"collection": collection.to_string(), "permission": "view"}],
            }),
        )
        .await;
    assert_eq!(invited.status, StatusCode::CREATED, "{:?}", invited.json());
    lee.post(
        &format!("/kem/v1/spaces/{space}/members/me/accept"),
        json!({}),
    )
    .await;
    let confirmed = sam
        .post(
            &format!("/kem/v1/spaces/{space}/members/{}/confirm", lee.id),
            confirm_body(&sam, &lee, space, collection, 6),
        )
        .await;
    assert_eq!(confirmed.status, StatusCode::OK, "{:?}", confirmed.json());

    let viewer = lee.put(&uri, space_manifest(&lee, space, 1)).await;
    assert_eq!(viewer.status, StatusCode::FORBIDDEN);
    // A viewer reads, a stranger can't tell the space is there.
    let stored = sam.put(&uri, space_manifest(&sam, space, 1)).await;
    assert_eq!(stored.status, StatusCode::OK, "{:?}", stored.json());
    assert_eq!(lee.get(&uri).await.status, StatusCode::OK);
    let stranger_put = zed.put(&uri, space_manifest(&zed, space, 2)).await;
    let stranger_get = zed.get(&uri).await;
    let missing = zed
        .get(&format!("/kem/v1/manifests/space:{}", Uuid::new_v4()))
        .await;
    assert_eq!(stranger_put.status, StatusCode::NOT_FOUND);
    assert_eq!(stranger_get.status, StatusCode::NOT_FOUND);
    assert_eq!(stranger_get.problem(), missing.problem());

    // The signature must be the signer's own, and the bytes must name this space.
    let forged = sam.put(&uri, space_manifest(&zed, space, 2)).await;
    assert_eq!(
        forged.status,
        StatusCode::BAD_REQUEST,
        "{:?}",
        forged.json()
    );
    let (other, _) = make_space(&sam).await;
    let mismatched = sam.put(&uri, space_manifest(&sam, other, 2)).await;
    assert_eq!(mismatched.status, StatusCode::BAD_REQUEST);
    assert_eq!(sam.get(&uri).await.json()["counter"], 1);
}

#[tokio::test]
async fn a_space_waiting_for_new_keys_takes_no_manifest() {
    let rig = Rig::new();
    let sam = rig.person("sam@example.org").await;
    let ana = rig.person("ana@example.org").await;
    let (space, collection) = make_space(&sam).await;
    join(&sam, &ana, space, collection).await;
    let uri = format!("/kem/v1/manifests/space:{space}");
    let revoked = sam
        .post(
            &format!("/kem/v1/spaces/{space}/members/{}/revoke", ana.id),
            json!({}),
        )
        .await;
    assert_eq!(revoked.status, StatusCode::OK, "{:?}", revoked.json());

    let paused = sam.put(&uri, space_manifest(&sam, space, 1)).await;
    assert_eq!(paused.status, StatusCode::LOCKED, "{:?}", paused.json());
    // The revoked member is out of the space entirely.
    assert_eq!(ana.get(&uri).await.status, StatusCode::NOT_FOUND);
    assert_eq!(
        ana.put(&uri, space_manifest(&ana, space, 1)).await.status,
        StatusCode::NOT_FOUND
    );
}

/// Keeps the invitations that are mailed.
#[derive(Default)]
struct Invitations(std::sync::Mutex<Vec<InvitationNotice>>);

impl Outbox for Invitations {
    fn deliver(&self, notice: Notice) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            if let Notice::Invitation(invitation) = notice {
                self.0.lock().expect("the lock").push(invitation);
            }
        })
    }
}

#[tokio::test]
async fn an_invitation_is_mailed_with_the_link_to_its_space() {
    let mailbox = std::sync::Arc::new(Invitations::default());
    let rig = Rig::mailing(mailbox.clone());
    let sam = rig.person("sam@example.org").await;
    let _ana = rig.person("ana@example.org").await;
    let (space, collection) = make_space(&sam).await;

    let invited = sam
        .post(
            &format!("/kem/v1/spaces/{space}/members"),
            json!({
                "email": "ana@example.org",
                "role": "member",
                "grants": [{"collection": collection.to_string(), "permission": "edit"}],
            }),
        )
        .await;
    assert_eq!(invited.status, StatusCode::CREATED);
    for _ in 0..200 {
        if !mailbox.0.lock().expect("the lock").is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    let sent = mailbox.0.lock().expect("the lock").clone();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].to.as_str(), "ana@example.org");
    assert_eq!(sent[0].space_id, Some(kemlock_domain::SpaceId(space)));
    // The server can't read the space's sealed name, so the mail has none; it names the inviter by
    // the email of their account.
    assert_eq!(sent[0].space, None);
    assert_eq!(sent[0].inviter.as_deref(), Some("sam@example.org"));
}

#[tokio::test]
async fn a_refused_invitation_mails_nobody() {
    let mailbox = std::sync::Arc::new(Invitations::default());
    let rig = Rig::mailing(mailbox.clone());
    let sam = rig.person("sam@example.org").await;
    let (space, _collection) = make_space(&sam).await;
    // No such account.
    let refused = sam
        .post(
            &format!("/kem/v1/spaces/{space}/members"),
            json!({"email": "nobody@example.org", "role": "member"}),
        )
        .await;
    assert_ne!(refused.status, StatusCode::CREATED);
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert!(mailbox.0.lock().expect("the lock").is_empty());
}

fn lookup_uri(space: Uuid, email: &str) -> String {
    format!("/kem/v1/spaces/{space}/lookup?email={email}")
}

#[tokio::test]
async fn an_admin_looks_an_account_up_by_email_and_gets_its_id_and_bundle() {
    let rig = Rig::new();
    let sam = rig.person("sam@example.org").await;
    let ana = rig.person("ana@example.org").await;
    let (space, _collection) = make_space(&sam).await;

    let found = sam.get(&lookup_uri(space, "ana@example.org")).await;
    assert_eq!(found.status, StatusCode::OK, "{:?}", found.json());
    let found = found.json();
    assert_eq!(found["account"], ana.id.to_string());
    assert_eq!(found["bundle"], b64(&ana.bundle));
    // The signature and key version come with it, so the inviter can check the bundle first.
    assert!(
        found["bundleSignature"]
            .as_str()
            .is_some_and(|s| !s.is_empty()),
        "{found}"
    );
    assert!(found["keyVersion"].is_u64(), "{found}");
}

#[tokio::test]
async fn a_custom_member_with_manage_users_looks_up_and_a_plain_member_may_not() {
    let rig = Rig::new();
    let sam = rig.person("sam@example.org").await;
    let ana = rig.person("ana@example.org").await;
    let bob = rig.person("bob@example.org").await;
    let zed = rig.person("zed@example.org").await;
    let (space, collection) = make_space(&sam).await;
    join(&sam, &ana, space, collection).await;
    join(&sam, &bob, space, collection).await;

    // A plain member is refused; someone outside the space finds no such space.
    let member = bob.get(&lookup_uri(space, "zed@example.org")).await;
    assert_eq!(member.status, StatusCode::FORBIDDEN);
    assert_eq!(member.problem(), "forbidden");
    let outsider = zed.get(&lookup_uri(space, "ana@example.org")).await;
    assert_eq!(outsider.status, StatusCode::NOT_FOUND);
    assert_eq!(outsider.problem(), "not-found");

    // Custom without Manage users is refused too; with it, the lookup answers.
    let role_uri = format!("/kem/v1/spaces/{space}/members/{}/role", ana.id);
    let role = |custom: Value| sam.put(&role_uri, json!({"role": "custom", "custom": custom}));
    let made = role(json!(["create-collections"])).await;
    assert_eq!(made.status, StatusCode::OK, "{:?}", made.json());
    assert_eq!(
        ana.get(&lookup_uri(space, "zed@example.org")).await.status,
        StatusCode::FORBIDDEN
    );
    let made = role(json!(["manage-users"])).await;
    assert_eq!(made.status, StatusCode::OK, "{:?}", made.json());
    let found = ana.get(&lookup_uri(space, "zed@example.org")).await;
    assert_eq!(found.status, StatusCode::OK, "{:?}", found.json());
    assert_eq!(found.json()["account"], zed.id.to_string());
}

#[tokio::test]
async fn looking_up_an_unknown_email_is_404_no_account() {
    let rig = Rig::new();
    let sam = rig.person("sam@example.org").await;
    let (space, _collection) = make_space(&sam).await;

    let unknown = sam.get(&lookup_uri(space, "nobody@example.org")).await;
    assert_eq!(unknown.status, StatusCode::NOT_FOUND);
    assert_eq!(unknown.problem(), "no-account");
    let not_an_email = sam.get(&lookup_uri(space, "nope")).await;
    assert_eq!(not_an_email.status, StatusCode::BAD_REQUEST);
    let missing = sam.get(&format!("/kem/v1/spaces/{space}/lookup")).await;
    assert_eq!(missing.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn lookups_are_limited_per_caller() {
    let rig = Rig::new();
    let sam = rig.person("sam@example.org").await;
    let ana = rig.person("ana@example.org").await;
    let (space, collection) = make_space(&sam).await;
    join(&sam, &ana, space, collection).await;
    let role = ana_as_admin(&sam, space, ana.id).await;
    assert_eq!(role, StatusCode::OK);

    for _ in 0..10 {
        let reply = sam.get(&lookup_uri(space, "ana@example.org")).await;
        assert_eq!(reply.status, StatusCode::OK);
    }
    let over = sam.get(&lookup_uri(space, "ana@example.org")).await;
    assert_eq!(over.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(over.problem(), "rate-limited");
    // The limit is the caller's own: another admin is not slowed down by it.
    let other = ana.get(&lookup_uri(space, "sam@example.org")).await;
    assert_eq!(other.status, StatusCode::OK, "{:?}", other.json());
}

async fn ana_as_admin(sam: &Person, space: Uuid, ana: UserId) -> StatusCode {
    sam.put(
        &format!("/kem/v1/spaces/{space}/members/{ana}/role"),
        json!({"role": "admin", "custom": []}),
    )
    .await
    .status
}

async fn invite_plain(inviter: &Person, space: Uuid, email: &str) {
    let invited = inviter
        .post(
            &format!("/kem/v1/spaces/{space}/members"),
            json!({"email": email, "role": "member"}),
        )
        .await;
    assert_eq!(invited.status, StatusCode::CREATED, "{:?}", invited.json());
}

fn resend_uri(space: Uuid, member: UserId) -> String {
    format!("/kem/v1/spaces/{space}/members/{member}/resend")
}

#[tokio::test]
async fn an_invitation_is_mailed_again_once_in_ten_minutes_per_member() {
    let mailbox = std::sync::Arc::new(Invitations::default());
    let rig = Rig::mailing(mailbox.clone());
    let sam = rig.person("sam@example.org").await;
    let ana = rig.person("ana@example.org").await;
    let zed = rig.person("zed@example.org").await;
    let (space, _collection) = make_space(&sam).await;
    invite_plain(&sam, space, "ana@example.org").await;
    invite_plain(&sam, space, "zed@example.org").await;

    let again = sam.post(&resend_uri(space, ana.id), json!({})).await;
    assert_eq!(again.status, StatusCode::NO_CONTENT);
    // The second try inside the window waits; another member's turn is their own.
    let soon = sam.post(&resend_uri(space, ana.id), json!({})).await;
    assert_eq!(soon.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(soon.problem(), "rate-limited");
    assert_eq!(soon.header("retry-after"), Some("600"));
    let other = sam.post(&resend_uri(space, zed.id), json!({})).await;
    assert_eq!(other.status, StatusCode::NO_CONTENT);

    for _ in 0..200 {
        if mailbox.0.lock().expect("the lock").len() >= 4 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    tokio::time::sleep(std::time::Duration::from_millis(30)).await;
    let sent = mailbox.0.lock().expect("the lock").clone();
    // Two invitations, then two resends: one each, the refused try mailed nothing.
    let to: Vec<&str> = sent.iter().map(|n| n.to.as_str()).collect();
    assert_eq!(sent.len(), 4, "{to:?}");
    assert_eq!(to.iter().filter(|t| **t == "ana@example.org").count(), 2);
    assert_eq!(to.iter().filter(|t| **t == "zed@example.org").count(), 2);
    assert!(
        sent.iter()
            .all(|n| n.inviter.as_deref() == Some("sam@example.org"))
    );
}

#[tokio::test]
async fn only_a_manager_resends_and_only_while_the_member_is_invited() {
    let mailbox = std::sync::Arc::new(Invitations::default());
    let rig = Rig::mailing(mailbox.clone());
    let sam = rig.person("sam@example.org").await;
    let ana = rig.person("ana@example.org").await;
    let bob = rig.person("bob@example.org").await;
    let zed = rig.person("zed@example.org").await;
    let (space, collection) = make_space(&sam).await;
    join(&sam, &bob, space, collection).await;
    invite_plain(&sam, space, "ana@example.org").await;

    // A plain member can't; someone outside the space finds nothing.
    let member = bob.post(&resend_uri(space, ana.id), json!({})).await;
    assert_eq!(member.status, StatusCode::FORBIDDEN);
    let outsider = zed.post(&resend_uri(space, ana.id), json!({})).await;
    assert_eq!(outsider.status, StatusCode::NOT_FOUND);
    // Nobody is invited who isn't in the space, and a confirmed member has no invitation to send.
    let stranger = sam.post(&resend_uri(space, zed.id), json!({})).await;
    assert_eq!(stranger.status, StatusCode::CONFLICT);
    assert_eq!(stranger.problem(), "wrong-state");
    let confirmed = sam.post(&resend_uri(space, bob.id), json!({})).await;
    assert_eq!(confirmed.status, StatusCode::CONFLICT);
    // Once Ana accepts, there is nothing to resend.
    let accepted = ana
        .post(
            &format!("/kem/v1/spaces/{space}/members/me/accept"),
            json!({}),
        )
        .await;
    assert_eq!(accepted.status, StatusCode::OK);
    let late = sam.post(&resend_uri(space, ana.id), json!({})).await;
    assert_eq!(late.status, StatusCode::CONFLICT);

    // Refused tries mailed nobody and used no turn: only the first invitation and the confirmed
    // member's earlier one were sent.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(mailbox.0.lock().expect("the lock").len(), 2);
}

#[tokio::test]
async fn a_refused_resend_does_not_use_the_members_turn() {
    let rig = Rig::new();
    let sam = rig.person("sam@example.org").await;
    let ana = rig.person("ana@example.org").await;
    let bob = rig.person("bob@example.org").await;
    let (space, collection) = make_space(&sam).await;
    join(&sam, &bob, space, collection).await;
    invite_plain(&sam, space, "ana@example.org").await;

    // Bob is refused (and not counted), so Sam's resend is the first of the window.
    let refused = bob.post(&resend_uri(space, ana.id), json!({})).await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN);
    let sent = sam.post(&resend_uri(space, ana.id), json!({})).await;
    assert_eq!(sent.status, StatusCode::NO_CONTENT);
}
