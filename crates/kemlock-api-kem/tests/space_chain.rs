//! The space chain routes, in-process: devices sign in with real OPAQUE and DPoP, then append
//! signed records, read the chain back and meet every refusal, against the in-memory fakes of
//! `kemlock-app`.

mod common;
/// `space_fakes` names the fakes by their path at a test crate's root.
mod fakes {
    pub(crate) use super::common::fakes::*;
}
#[path = "../../kemlock-app/tests/chain_kit/mod.rs"]
mod chain_kit;
#[path = "../../kemlock-app/tests/space_fakes/mod.rs"]
mod space_fakes;

use axum::Router;
use axum::http::StatusCode;
use chain_kit::{Chain, Person, Step, request};
use common::{App, Client, Reply, Req, Session, b64, register_and_sign_in_with};
use kemlock_api_kem::testing::DpopSigner;
use kemlock_api_kem::{
    ChainLargeBodies, space_chain_router_with, space_recovery_router, spaces_router,
};
use kemlock_app::notices::{BoxFuture, InvitationNotice, Notice, Outbox};
use kemlock_app::ports::Clock as _;
use kemlock_app::ports::ItemStore;
use kemlock_app::spaces::{SpaceRecoveryRepo, SpaceRepo};
use kemlock_crypto::space_chain::{
    Body, CollectionPerm, Grantee, KeyRef, Policies, Role, b64 as chain_b64, link,
};
use kemlock_domain::spaces::MemberState;
use kemlock_domain::{ItemId, SpaceId, UserId};
use serde_json::{Value, json};
use space_fakes::FakeSpaces;
use uuid::Uuid;

struct Who {
    client: Client,
    session: Session,
    id: UserId,
    person: Person,
}

impl Who {
    /// Accepts the invitation to `space`: the invitee's own step, which isn't in the chain and
    /// comes before a confirm.
    async fn accept(&self, space: Uuid) {
        let reply = self
            .post(
                &format!("/kem/v1/spaces/{space}/members/me/accept"),
                json!({}),
            )
            .await;
        assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.json());
    }
}

impl Who {
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

    async fn post(&self, uri: &str, body: Value) -> Reply {
        self.call("POST", uri, Some(body)).await
    }

    async fn get(&self, uri: &str) -> Reply {
        self.call("GET", uri, None).await
    }
}

struct Rig {
    app: App,
    router: Router,
    spaces: FakeSpaces<common::fakes::FakeStore>,
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
        Rig::over_with(app, ChainLargeBodies::default())
    }

    /// A rig whose router keeps the places for large bodies in `places`, which a test may fill.
    fn over_with(app: App, places: ChainLargeBodies) -> Rig {
        let spaces = FakeSpaces::new(app.store.clone());
        let router = app
            .router_with(spaces.clone())
            .merge(spaces_router(app.api.clone(), spaces.clone()))
            .merge(space_chain_router_with(
                app.api.clone(),
                spaces.clone(),
                places,
            ))
            .merge(space_recovery_router(app.api.clone(), spaces.clone()));
        Rig {
            app,
            router,
            spaces,
        }
    }

    /// A person whose registered bundle has real keys, so boxes can be sealed to it.
    async fn person(&self, email: &str, seed: u8) -> Who {
        let client = Client::new(
            self.router.clone(),
            self.app.clock.clone(),
            DpopSigner::es256(),
        );
        let session = register_and_sign_in_with(&client, email, |user| {
            let person = Person::new(*user.as_bytes(), seed);
            (person.bytes(), person.self_signature())
        })
        .await;
        let id = UserId(session.user_id.parse().expect("a user id"));
        let person = Person::new(*id.as_bytes(), seed);
        Who {
            client,
            session,
            id,
            person,
        }
    }

    fn chain(&self, space: Uuid) -> Chain {
        Chain::new(
            *space.as_bytes(),
            u64::try_from(self.app.now()).expect("a time"),
        )
    }
}

fn uri(space: Uuid) -> String {
    format!("/kem/v1/spaces/{space}/chain")
}

/// Sam makes a chained space with its first collection.
async fn make(rig: &Rig, sam: &Who) -> (Uuid, Uuid, Chain, Step) {
    let space = Uuid::new_v4();
    let collection = Uuid::new_v4();
    let mut chain = rig.chain(space);
    let create = chain.create(&sam.person, *collection.as_bytes());
    let reply = sam.post(&uri(space), request(&[&create])).await;
    assert_eq!(reply.status, StatusCode::CREATED, "{:?}", reply.json());
    (space, collection, chain, create)
}

#[tokio::test]
async fn a_recovery_box_for_another_key_version_is_a_409_with_the_current_one() {
    let rig = Rig::new();
    let sam = rig.person("sam@example.org", 1).await;
    let (space, _collection, mut chain, _create) = make(&rig, &sam).await;
    // The chain sets a recovery key (seq 1) and turns account recovery on (seq 2).
    let key = sam.person.bundle.kx1_public.as_bytes().to_vec();
    let set_key = chain.record(&sam.person, Body::RecoveryKey { key });
    let reply = sam.post(&uri(space), request(&[&set_key])).await;
    assert_eq!(reply.status, StatusCode::CREATED, "{:?}", reply.json());
    let policies = Policies {
        account_recovery: true,
        ..Policies::default()
    };
    let turn_on = chain.record(&sam.person, Body::Policies { policies });
    let reply = sam.post(&uri(space), request(&[&turn_on])).await;
    assert_eq!(reply.status, StatusCode::CREATED, "{:?}", reply.json());

    // The store says the account is at key version 2.
    rig.spaces.set_account_key_version(2);
    let enrol_uri = format!("/kem/v1/spaces/{space}/members/me/recovery");
    let enrol = |key_version: Option<u32>| {
        let mut body = json!({"box": b64(&[1u8; 1693]), "keySeq": 1});
        if let Some(version) = key_version {
            body["keyVersion"] = json!(version);
        }
        sam.call("PUT", &enrol_uri, Some(body))
    };
    let stale = enrol(Some(1)).await;
    assert_eq!(stale.status, StatusCode::CONFLICT, "{:?}", stale.json());
    assert_eq!(
        stale.json()["type"],
        "urn:kemlock:problem:key-version-stale"
    );
    assert_eq!(stale.json()["currentKeyVersion"], 2);
    // Nothing was stored, so the member has no box to read back.
    assert_eq!(
        SpaceRecoveryRepo::recovery_box(&rig.spaces, SpaceId(space), sam.id).await,
        Ok(None)
    );
    assert_eq!(enrol(Some(2)).await.status, StatusCode::NO_CONTENT);
    // An old client sends no version, and is accepted.
    assert_eq!(enrol(None).await.status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn a_create_record_makes_the_space_and_the_chain_serves_it_back() {
    let rig = Rig::new();
    let sam = rig.person("sam@example.org", 1).await;
    let space = Uuid::new_v4();
    let collection = Uuid::new_v4();
    let mut chain = rig.chain(space);
    let create = chain.create(&sam.person, *collection.as_bytes());
    let reply = sam.post(&uri(space), request(&[&create])).await;
    assert_eq!(reply.status, StatusCode::CREATED, "{:?}", reply.json());
    let head = reply.json();
    assert_eq!(head["seq"], 0);
    assert_eq!(head["link"], chain_b64::encode(&link(&create.record.entry)));

    // The server's own tables are derived from the record: Sam is its confirmed owner.
    let view = sam.get(&format!("/kem/v1/spaces/{space}")).await;
    assert_eq!(view.status, StatusCode::OK, "{:?}", view.json());
    assert_eq!(view.json()["me"]["role"], "owner");
    assert_eq!(view.json()["me"]["state"], "confirmed");
    assert_eq!(view.json()["collections"].as_array().map(Vec::len), Some(1));

    // The chain comes back as the exact bytes.
    let chain_reply = sam.get(&uri(space)).await;
    assert_eq!(chain_reply.status, StatusCode::OK);
    let records = chain_reply.json();
    assert_eq!(records.as_array().map(Vec::len), Some(1));
    assert_eq!(records[0]["entry"], chain_b64::encode(&create.record.entry));
    assert_eq!(
        records[0]["signature"],
        chain_b64::encode(&create.record.signature)
    );
    assert!(records[0].get("cosignature").is_none());
    // From a seq past the head: nothing. From a bad value: 400.
    let later = sam.get(&format!("{}?from=1", uri(space))).await;
    assert_eq!(later.json(), json!([]));
    let bad = sam.get(&format!("{}?from=-1", uri(space))).await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn confirm_and_seal_after_the_invitee_accepted_make_a_member_with_a_key() {
    let rig = Rig::new();
    let sam = rig.person("sam@example.org", 1).await;
    let ana = rig.person("ana@example.org", 2).await;
    let (space, _, mut chain, _) = make(&rig, &sam).await;
    let invite = chain.invite(&sam.person, ana.person.id, Role::Member);
    let confirm = chain.confirm(&sam.person, &ana.person);
    let seal = chain.seal_space_key(&sam.person, &ana.person);
    let reply = sam.post(&uri(space), request(&[&invite])).await;
    assert_eq!(reply.status, StatusCode::CREATED, "{:?}", reply.json());
    ana.accept(space).await;
    let reply = sam.post(&uri(space), request(&[&confirm, &seal])).await;
    assert_eq!(reply.status, StatusCode::CREATED, "{:?}", reply.json());
    assert_eq!(reply.json()["seq"], 3);

    // Ana is a confirmed member now, and reads the chain.
    let view = ana.get(&format!("/kem/v1/spaces/{space}")).await;
    assert_eq!(view.status, StatusCode::OK, "{:?}", view.json());
    assert_eq!(view.json()["me"]["state"], "confirmed");
    let from = ana.get(&format!("{}?from=2", uri(space))).await;
    assert_eq!(from.json().as_array().map(Vec::len), Some(2));

    // The seal hashes record 3 committed: one, for Ana, whose hash is the box's.
    let seals = ana.get(&format!("{}/3/seals", uri(space))).await;
    assert_eq!(seals.status, StatusCode::OK, "{:?}", seals.json());
    let list = seals.json();
    assert_eq!(list.as_array().map(Vec::len), Some(1));
    assert_eq!(list[0]["key"], "space");
    assert_eq!(list[0]["version"], 1);
    assert_eq!(list[0]["bundleVersion"], 1);
    assert_eq!(
        list[0]["member"],
        Uuid::from_bytes(ana.person.id).to_string()
    );
    let boxed = &seal.seals[0].sealed;
    assert_eq!(
        list[0]["sealHash"],
        chain_b64::encode(&kemlock_crypto::space_chain::seal_hash(boxed))
    );
    // A record that isn't there has no seals.
    assert_eq!(
        ana.get(&format!("{}/9/seals", uri(space))).await.status,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn a_second_append_at_the_same_seq_is_a_conflict_with_the_head() {
    let rig = Rig::new();
    let sam = rig.person("sam@example.org", 1).await;
    let (space, collection, _, create) = make(&rig, &sam).await;
    // The same create again, or another record at seq 0.
    let again = sam.post(&uri(space), request(&[&create])).await;
    assert_eq!(again.status, StatusCode::CONFLICT, "{:?}", again.json());
    assert_eq!(again.json()["head"]["seq"], 0);
    assert_eq!(
        again.json()["head"]["link"],
        chain_b64::encode(&link(&create.record.entry))
    );
    let other = rig.chain(space).create(&sam.person, *collection.as_bytes());
    assert_eq!(
        sam.post(&uri(space), request(&[&other])).await.status,
        StatusCode::CONFLICT
    );
}

#[tokio::test]
async fn a_chain_that_names_another_spaces_collection_is_refused_not_retried() {
    let rig = Rig::new();
    let sam = rig.person("sam@example.org", 1).await;
    let zoe = rig.person("zoe@example.org", 3).await;
    let (space, collection, _, _) = make(&rig, &sam).await;

    // Zoe makes a space whose first collection has the id of Sam's: a 400, not a 409 with a head
    // that would send her client to try again.
    let other = Uuid::new_v4();
    let mut chain = rig.chain(other);
    let create = chain.create(&zoe.person, *collection.as_bytes());
    let reply = zoe.post(&uri(other), request(&[&create])).await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{:?}", reply.json());
    assert!(reply.json().get("head").is_none(), "{:?}", reply.json());
    assert_eq!(
        zoe.get(&format!("/kem/v1/spaces/{other}")).await.status,
        StatusCode::NOT_FOUND
    );

    // Sam's space still has its collection.
    let view = sam.get(&format!("/kem/v1/spaces/{space}")).await;
    assert_eq!(view.json()["collections"].as_array().map(Vec::len), Some(1));
}

#[tokio::test]
async fn an_outsider_is_not_told_the_head_of_a_chain() {
    let rig = Rig::new();
    let sam = rig.person("sam@example.org", 1).await;
    let ana = rig.person("ana@example.org", 2).await;
    let zoe = rig.person("zoe@example.org", 3).await;
    let (space, _, mut chain, create) = make(&rig, &sam).await;
    // A record at seq 0 from someone outside the space: a 404 like every other space route, with
    // no head in it.
    let reply = zoe.post(&uri(space), request(&[&create])).await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND, "{:?}", reply.json());
    assert!(reply.json().get("head").is_none(), "{:?}", reply.json());

    // An invited member is in the space: she gets the conflict and the head.
    let invite = chain.invite(&sam.person, ana.person.id, Role::Member);
    let reply = sam.post(&uri(space), request(&[&invite])).await;
    assert_eq!(reply.status, StatusCode::CREATED, "{:?}", reply.json());
    let reply = ana.post(&uri(space), request(&[&create])).await;
    assert_eq!(reply.status, StatusCode::CONFLICT, "{:?}", reply.json());
    assert_eq!(reply.json()["head"]["seq"], 1);
    // And a record Sam signed but she sent is refused for it (A5), not hidden.
    let next = chain.invite(&sam.person, zoe.person.id, Role::Member);
    let reply = ana.post(&uri(space), request(&[&next])).await;
    assert_eq!(
        reply.status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "{:?}",
        reply.json()
    );
    assert_eq!(reply.json()["reason"], "not allowed");
}

#[tokio::test]
async fn a_confirm_before_the_invitee_accepted_is_refused() {
    let rig = Rig::new();
    let sam = rig.person("sam@example.org", 1).await;
    let zoe = rig.person("zoe@example.org", 3).await;
    let (space, _, mut chain, create) = make(&rig, &sam).await;

    // Invite and confirm in one request: she never had the chance to accept.
    let invite = chain.invite(&sam.person, zoe.person.id, Role::Member);
    let confirm = chain.confirm(&sam.person, &zoe.person);
    let seal = chain.seal_space_key(&sam.person, &zoe.person);
    let reply = sam
        .post(&uri(space), request(&[&invite, &confirm, &seal]))
        .await;
    assert_eq!(
        reply.status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "{:?}",
        reply.json()
    );
    assert_eq!(reply.json()["reason"], "not allowed");
    assert!(rig.spaces.member(SpaceId(space), zoe.id).is_none());

    // Invited but not accepted: the same.
    let mut chain = rig.chain(space);
    chain.head = Some((0, link(&create.record.entry)));
    let invite = chain.invite(&sam.person, zoe.person.id, Role::Member);
    let confirm = chain.confirm(&sam.person, &zoe.person);
    let seal = chain.seal_space_key(&sam.person, &zoe.person);
    let reply = sam.post(&uri(space), request(&[&invite])).await;
    assert_eq!(reply.status, StatusCode::CREATED, "{:?}", reply.json());
    let reply = sam.post(&uri(space), request(&[&confirm, &seal])).await;
    assert_eq!(
        reply.status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "{:?}",
        reply.json()
    );
    assert_eq!(reply.json()["reason"], "not allowed");
    let state = rig.spaces.member(SpaceId(space), zoe.id).map(|m| m.state);
    assert_eq!(state, Some(MemberState::Invited));

    // Once she accepts, the same records go in and she is confirmed.
    zoe.accept(space).await;
    let reply = sam.post(&uri(space), request(&[&confirm, &seal])).await;
    assert_eq!(reply.status, StatusCode::CREATED, "{:?}", reply.json());
    let state = rig.spaces.member(SpaceId(space), zoe.id).map(|m| m.state);
    assert_eq!(state, Some(MemberState::Confirmed));
}

#[tokio::test]
async fn refusals_name_their_reason_and_seq() {
    let rig = Rig::new();
    let sam = rig.person("sam@example.org", 1).await;
    let ana = rig.person("ana@example.org", 2).await;
    let (space, _, mut chain, _) = make(&rig, &sam).await;

    // A flipped byte of the signature.
    let mut invite = chain.invite(&sam.person, ana.person.id, Role::Member);
    let good = invite.clone();
    invite.record.signature[10] ^= 1;
    let reply = sam.post(&uri(space), request(&[&invite])).await;
    assert_eq!(
        reply.status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "{:?}",
        reply.json()
    );
    assert_eq!(reply.json()["reason"], "bad signature");
    assert_eq!(reply.json()["seq"], 1);

    // A record signed by Sam but sent by Ana, who isn't in the space: she learns nothing of it.
    let reply = ana.post(&uri(space), request(&[&good])).await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND, "{:?}", reply.json());

    // A cosignature on a record that isn't a rekey is malformed.
    let mut body = request(&[&good]);
    body["records"][0]["cosignature"] = body["records"][0]["signature"].clone();
    let reply = sam.post(&uri(space), body).await;
    assert_eq!(reply.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(reply.json()["reason"], "malformed");

    // A record whose bundle isn't the account's registered one: Ana confirmed with Sam's keys.
    let impostor = Person::new(ana.person.id, 99);
    let mut forged = Chain::new(chain.space, chain.at);
    forged.head = chain.head;
    let invite_ok = good.clone();
    let confirm = forged.confirm(&sam.person, &impostor);
    let reply = sam
        .post(&uri(space), request(&[&invite_ok, &confirm]))
        .await;
    assert_eq!(
        reply.status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "{:?}",
        reply.json()
    );
    assert_eq!(reply.json()["reason"], "bad bundle");

    // Nothing was appended by any of these.
    let head = sam.get(&format!("{}?from=1", uri(space))).await;
    assert_eq!(head.json(), json!([]));

    // Ana is invited and accepts, as a confirm needs.
    let reply = sam.post(&uri(space), request(&[&good])).await;
    assert_eq!(reply.status, StatusCode::CREATED, "{:?}", reply.json());
    ana.accept(space).await;

    // A box missing for a commitment's recipient, and one nobody committed.
    let confirm = chain.confirm(&sam.person, &ana.person);
    let seal = chain.seal_space_key(&sam.person, &ana.person);
    let mut without = request(&[&confirm, &seal]);
    without["seals"] = json!([]);
    let reply = sam.post(&uri(space), without).await;
    assert_eq!(
        reply.status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "{:?}",
        reply.json()
    );
    assert_eq!(reply.json()["reason"], "invalid");
    let mut extra = request(&[&confirm, &seal]);
    let first = extra["seals"][0].clone();
    extra["seals"].as_array_mut().expect("seals").push(first);
    let reply = sam.post(&uri(space), extra).await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{:?}", reply.json());
    // The same request, whole, is accepted.
    let reply = sam.post(&uri(space), request(&[&confirm, &seal])).await;
    assert_eq!(reply.status, StatusCode::CREATED, "{:?}", reply.json());

    // A create for a space that already exists is refused.
    let mut again = Chain::new(chain.space, chain.at);
    let create = again.create(&sam.person, [9; 16]);
    let reply = sam.post(&uri(space), request(&[&create])).await;
    assert_eq!(reply.status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn only_members_read_the_chain_and_a_removed_member_is_a_stranger() {
    let rig = Rig::new();
    let sam = rig.person("sam@example.org", 1).await;
    let ana = rig.person("ana@example.org", 2).await;
    let zoe = rig.person("zoe@example.org", 3).await;
    let (space, _, mut chain, _) = make(&rig, &sam).await;
    assert_eq!(zoe.get(&uri(space)).await.status, StatusCode::NOT_FOUND);
    assert_eq!(
        zoe.get(&format!("{}/0/seals", uri(space))).await.status,
        StatusCode::NOT_FOUND
    );

    // An invited member reads it too.
    let invite = chain.invite(&sam.person, ana.person.id, Role::Member);
    let reply = sam.post(&uri(space), request(&[&invite])).await;
    assert_eq!(reply.status, StatusCode::CREATED, "{:?}", reply.json());
    assert_eq!(ana.get(&uri(space)).await.status, StatusCode::OK);

    // Removed, she gets a 404 like anyone else.
    let remove = chain.remove(&sam.person, ana.person.id, Vec::new());
    let reply = sam.post(&uri(space), request(&[&remove])).await;
    assert_eq!(reply.status, StatusCode::CREATED, "{:?}", reply.json());
    assert_eq!(ana.get(&uri(space)).await.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_chained_space_refuses_the_plain_member_routes() {
    let rig = Rig::new();
    let sam = rig.person("sam@example.org", 1).await;
    let _ana = rig.person("ana@example.org", 2).await;
    let (space, _, _, _) = make(&rig, &sam).await;
    let reply = sam
        .post(
            &format!("/kem/v1/spaces/{space}/members"),
            json!({"email": "ana@example.org", "role": "member", "grants": []}),
        )
        .await;
    assert_eq!(reply.status, StatusCode::CONFLICT, "{:?}", reply.json());
    assert_eq!(
        reply.json()["type"]
            .as_str()
            .map(|t| t.ends_with("wrong-state")),
        Some(true)
    );
}

#[tokio::test]
async fn an_outside_change_is_listed_answered_and_dropped_by_an_admin() {
    use kemlock_app::spaces::{ExternalSource, PendingChange, PendingExternal, SpaceRepo};
    use kemlock_domain::SpaceId;
    use kemlock_domain::spaces::CustomPermissions;

    let rig = Rig::new();
    let sam = rig.person("sam@example.org", 1).await;
    let ana = rig.person("ana@example.org", 2).await;
    let zoe = rig.person("zoe@example.org", 3).await;
    let (space, _, mut chain, create) = make(&rig, &sam).await;
    let queue = |change: PendingChange| PendingExternal {
        id: Uuid::new_v4(),
        space: SpaceId(space),
        source: ExternalSource::Bitwarden,
        queued_at: rig.app.clock.now(),
        requested_by: None,
        via: "Bitwarden-compatible API".to_owned(),
        account: ana.id,
        email: None,
        change,
    };
    let add = queue(PendingChange::AddMember {
        role: kemlock_domain::spaces::SpaceRole::Member,
        custom: CustomPermissions::NONE,
        grants: Vec::new(),
    });
    rig.spaces
        .queue_external(add.clone())
        .await
        .expect("queued");

    // Only the space's admins see it.
    let pending = format!("{}/pending", uri(space));
    assert_eq!(ana.get(&pending).await.status, StatusCode::NOT_FOUND);
    assert_eq!(zoe.get(&pending).await.status, StatusCode::NOT_FOUND);
    let listed = sam.get(&pending).await;
    assert_eq!(listed.status, StatusCode::OK, "{:?}", listed.json());
    let list = listed.json();
    assert_eq!(list.as_array().map(Vec::len), Some(1));
    let item = &list[0];
    assert_eq!(item["id"], add.id.to_string());
    assert_eq!(item["source"], "bitwarden");
    assert!(item["queuedAt"].is_i64());
    assert_eq!(item["requestedBy"]["via"], "Bitwarden-compatible API");
    assert_eq!(item["change"]["kind"], "add-member");
    assert_eq!(item["change"]["account"], ana.id.to_string());
    assert_eq!(item["change"]["email"], "ana@example.org");
    assert_eq!(item["change"]["role"], "member");

    // An answer that isn't that change is refused, and nothing is appended.
    let one = format!("{pending}/{}", add.id);
    let wrong = chain.invite(&sam.person, ana.person.id, Role::Admin);
    let reply = sam.post(&one, request(&[&wrong])).await;
    assert_eq!(
        reply.status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "{:?}",
        reply.json()
    );
    assert_eq!(
        reply.json()["type"]
            .as_str()
            .map(|t| t.ends_with("pending-change-mismatch")),
        Some(true)
    );
    assert_eq!(
        sam.get(&format!("{}?from=1", uri(space))).await.json(),
        json!([])
    );
    // Another person can't answer.
    assert_eq!(
        zoe.post(&one, request(&[&wrong])).await.status,
        StatusCode::NOT_FOUND
    );

    // The matching record is appended, applied, and the entry is done.
    let mut right_chain = Chain::new(chain.space, chain.at);
    right_chain.head = Some((0, link(&create.record.entry)));
    let right = right_chain.invite(&sam.person, ana.person.id, Role::Member);
    let reply = sam.post(&one, request(&[&right])).await;
    assert_eq!(reply.status, StatusCode::CREATED, "{:?}", reply.json());
    assert_eq!(reply.json()["seq"], 1);
    assert_eq!(sam.get(&pending).await.json(), json!([]));
    assert_eq!(ana.get(&uri(space)).await.status, StatusCode::OK);

    // A change can be dropped, once.
    let removal = queue(PendingChange::RemoveMember);
    rig.spaces
        .queue_external(removal.clone())
        .await
        .expect("queued");
    let drop_uri = format!("{pending}/{}", removal.id);
    assert_eq!(
        sam.call("DELETE", &drop_uri, None).await.status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(sam.get(&pending).await.json(), json!([]));
    assert_eq!(
        sam.call("DELETE", &drop_uri, None).await.status,
        StatusCode::NOT_FOUND
    );
}

// ---- items under an old key version (spec case 7) ----

impl Who {
    /// Writes a new space item in `collection` under `key_version`.
    async fn put_item(&self, space: Uuid, collection: Uuid, key_version: u32) -> Reply {
        let id = Uuid::new_v4();
        self.client
            .send(
                "PUT",
                &format!("/kem/v1/items/{id}"),
                Req {
                    access_token: Some(self.session.access_token.as_str()),
                    headers: vec![("if-none-match", "*".to_owned())],
                    body: Some(json!({
                        "id": id.to_string(),
                        "owner": format!("space:{space}"),
                        "kind": "login",
                        "format": "kem1",
                        "revision": 1,
                        "keyVersion": key_version,
                        "ciphertext": b64(&kemlock_crypto::rand::bytes::<64>()),
                        "itemKey": b64(&kemlock_crypto::rand::bytes::<60>()),
                        "deleted": false,
                        "collectionId": collection.to_string(),
                    })),
                    ..Req::default()
                },
            )
            .await
    }
}

fn problem_type(reply: &Reply) -> String {
    reply.json()["type"].as_str().unwrap_or_default().to_owned()
}

#[tokio::test]
async fn an_item_under_a_replaced_collection_key_version_is_refused() {
    let rig = Rig::new();
    let sam = rig.person("sam@example.org", 1).await;
    let (space, collection, mut chain, _) = make(&rig, &sam).await;

    // Under the collection's version 1 a write works.
    let first = sam.put_item(space, collection, 1).await;
    assert_eq!(first.status, StatusCode::CREATED, "{:?}", first.json());

    // Its key moves to version 2 by a `keys` record. Version 1 is stale now, 2 is accepted, and 3
    // names a key the chain hasn't made.
    let keys = chain.rotate_collection(&sam.person, *collection.as_bytes(), 2, &[&sam.person]);
    let reply = sam.post(&uri(space), request(&[&keys])).await;
    assert_eq!(reply.status, StatusCode::CREATED, "{:?}", reply.json());
    let old = sam.put_item(space, collection, 1).await;
    assert_eq!(old.status, StatusCode::CONFLICT, "{:?}", old.json());
    assert!(problem_type(&old).ends_with("stale-key-version"));
    assert_eq!(old.json()["currentKeyVersion"], 2);
    let newer = sam.put_item(space, collection, 3).await;
    assert_eq!(newer.status, StatusCode::CONFLICT, "{:?}", newer.json());
    let current = sam.put_item(space, collection, 2).await;
    assert_eq!(current.status, StatusCode::CREATED, "{:?}", current.json());
}

#[tokio::test]
async fn an_item_between_a_removal_and_the_keys_record_is_refused() {
    let rig = Rig::new();
    let sam = rig.person("sam@example.org", 1).await;
    let ana = rig.person("ana@example.org", 2).await;
    let (space, collection, mut chain, _) = make(&rig, &sam).await;
    let invite = chain.invite(&sam.person, ana.person.id, Role::Member);
    let confirm = chain.confirm(&sam.person, &ana.person);
    let seal = chain.seal_space_key(&sam.person, &ana.person);
    let reply = sam.post(&uri(space), request(&[&invite])).await;
    assert_eq!(reply.status, StatusCode::CREATED, "{:?}", reply.json());
    ana.accept(space).await;
    let reply = sam.post(&uri(space), request(&[&confirm, &seal])).await;
    assert_eq!(reply.status, StatusCode::CREATED, "{:?}", reply.json());

    // Ana held the space key, so removing her marks it, and writes wait for the replacement.
    let remove = chain.remove(&sam.person, ana.person.id, vec![KeyRef::Space]);
    let reply = sam.post(&uri(space), request(&[&remove])).await;
    assert_eq!(reply.status, StatusCode::CREATED, "{:?}", reply.json());
    let held = sam.put_item(space, collection, 1).await;
    assert_eq!(held.status, StatusCode::LOCKED, "{:?}", held.json());
    assert!(problem_type(&held).ends_with("space-keys-pending"));
}

// ---- held items (I4) ----

impl Who {
    /// Replaces revision `revision - 1` of an item of `space` with a live revision under
    /// `key_version`, or with a tombstone when `deleted`.
    async fn write_item(
        &self,
        space: Uuid,
        collection: Uuid,
        id: Uuid,
        revision: u64,
        key_version: u32,
        deleted: bool,
    ) -> Reply {
        let mut body = json!({
            "id": id.to_string(),
            "owner": format!("space:{space}"),
            "kind": "login",
            "format": "kem1",
            "revision": revision,
            "keyVersion": key_version,
            "deleted": deleted,
            "collectionId": collection.to_string(),
        });
        if !deleted {
            body["ciphertext"] = json!(b64(&kemlock_crypto::rand::bytes::<64>()));
            body["itemKey"] = json!(b64(&kemlock_crypto::rand::bytes::<60>()));
        }
        self.client
            .send(
                "PUT",
                &format!("/kem/v1/items/{id}"),
                Req {
                    access_token: Some(self.session.access_token.as_str()),
                    headers: vec![("if-match", (revision - 1).to_string())],
                    body: Some(body),
                    ..Req::default()
                },
            )
            .await
    }
}

/// Sam's space with one live item under Finance's version 1, which a `keys` record then moves to
/// version 2, naming that item held.
async fn a_held_item(rig: &Rig, sam: &Who) -> (Uuid, Uuid, Uuid) {
    a_held_item_with(rig, sam, None).await
}

/// As [`a_held_item`], with `member` a confirmed member of the space who has no grant on Finance,
/// so no edit on it, and no seal of its key.
async fn a_held_item_with(rig: &Rig, sam: &Who, member: Option<&Who>) -> (Uuid, Uuid, Uuid) {
    let (space, collection, mut chain, _) = make(rig, sam).await;
    if let Some(member) = member {
        let invite = chain.invite(&sam.person, member.person.id, Role::Member);
        let confirm = chain.confirm(&sam.person, &member.person);
        let seal = chain.seal_space_key(&sam.person, &member.person);
        let reply = sam.post(&uri(space), request(&[&invite])).await;
        assert_eq!(reply.status, StatusCode::CREATED, "{:?}", reply.json());
        member.accept(space).await;
        let reply = sam.post(&uri(space), request(&[&confirm, &seal])).await;
        assert_eq!(reply.status, StatusCode::CREATED, "{:?}", reply.json());
    }
    let made = sam.put_item(space, collection, 1).await;
    assert_eq!(made.status, StatusCode::CREATED, "{:?}", made.json());
    let id: Uuid = made.json()["id"]
        .as_str()
        .and_then(|id| id.parse().ok())
        .expect("an item id");
    let keys = chain.rotate_collection(&sam.person, *collection.as_bytes(), 2, &[&sam.person]);
    let mut body = request(&[&keys]);
    body["held"] = json!([id.to_string()]);
    let reply = sam.post(&uri(space), body).await;
    assert_eq!(reply.status, StatusCode::CREATED, "{:?}", reply.json());
    let held = SpaceRepo::held_items(&rig.spaces, SpaceId(space))
        .await
        .expect("held items");
    assert_eq!(held, vec![ItemId(id)]);
    (space, collection, id)
}

async fn held_ids(rig: &Rig, space: Uuid) -> Vec<ItemId> {
    SpaceRepo::held_items(&rig.spaces, SpaceId(space))
        .await
        .expect("held items")
}

#[tokio::test]
async fn a_held_item_is_released_by_a_write_under_the_new_key_version() {
    let rig = Rig::new();
    let sam = rig.person("sam@example.org", 1).await;
    let (space, collection, id) = a_held_item(&rig, &sam).await;

    let reply = sam.write_item(space, collection, id, 2, 2, false).await;
    assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.json());
    assert_eq!(reply.json()["keyVersion"], 2);
    assert!(held_ids(&rig, space).await.is_empty());
    let stored = ItemStore::get(&rig.app.store, ItemId(id))
        .await
        .expect("read")
        .expect("the item");
    assert_eq!((stored.revision.0, stored.key_version), (2, 2));
}

#[tokio::test]
async fn a_write_under_the_old_key_version_is_refused_and_the_item_stays_held() {
    let rig = Rig::new();
    let sam = rig.person("sam@example.org", 1).await;
    let (space, collection, id) = a_held_item(&rig, &sam).await;

    let old = sam.write_item(space, collection, id, 2, 1, false).await;
    assert_eq!(old.status, StatusCode::CONFLICT, "{:?}", old.json());
    assert!(problem_type(&old).ends_with("stale-key-version"));
    assert_eq!(old.json()["currentKeyVersion"], 2);
    assert_eq!(held_ids(&rig, space).await, vec![ItemId(id)]);
    // Nothing was stored: the held revision is the one there.
    let stored = ItemStore::get(&rig.app.store, ItemId(id))
        .await
        .expect("read")
        .expect("the item");
    assert_eq!((stored.revision.0, stored.key_version), (1, 1));
}

#[tokio::test]
async fn a_held_item_deleted_by_a_tombstone_is_released() {
    let rig = Rig::new();
    let sam = rig.person("sam@example.org", 1).await;
    let (space, collection, id) = a_held_item(&rig, &sam).await;

    // A delete seals nothing: the key version it names isn't compared.
    let reply = sam.write_item(space, collection, id, 2, 1, true).await;
    assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.json());
    assert_eq!(reply.json()["deleted"], true);
    assert!(held_ids(&rig, space).await.is_empty());
    let stored = ItemStore::get(&rig.app.store, ItemId(id))
        .await
        .expect("read")
        .expect("the tombstone");
    assert!(stored.is_tombstone());
}

#[tokio::test]
async fn a_member_without_edit_cannot_release_a_held_item() {
    let rig = Rig::new();
    let sam = rig.person("sam@example.org", 1).await;
    let ana = rig.person("ana@example.org", 2).await;
    let (space, collection, id) = a_held_item_with(&rig, &sam, Some(&ana)).await;

    // Neither a write under the current key version nor a tombstone is hers to make.
    let write = ana.write_item(space, collection, id, 2, 2, false).await;
    assert_eq!(write.status, StatusCode::FORBIDDEN, "{:?}", write.json());
    let delete = ana.write_item(space, collection, id, 2, 1, true).await;
    assert_eq!(delete.status, StatusCode::FORBIDDEN, "{:?}", delete.json());

    // Nothing was stored, and the item is still held.
    assert_eq!(held_ids(&rig, space).await, vec![ItemId(id)]);
    let stored = ItemStore::get(&rig.app.store, ItemId(id))
        .await
        .expect("read")
        .expect("the item");
    assert_eq!((stored.revision.0, stored.key_version), (1, 1));
    assert!(!stored.is_tombstone());

    // Sam, who has edit, still can.
    let reply = sam.write_item(space, collection, id, 2, 2, false).await;
    assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.json());
    assert!(held_ids(&rig, space).await.is_empty());
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

impl Invitations {
    /// The invitations mailed so far, after giving the mail tasks a moment to run.
    async fn sent(&self, at_least: usize) -> Vec<InvitationNotice> {
        for _ in 0..200 {
            if self.0.lock().expect("the lock").len() >= at_least {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        self.0.lock().expect("the lock").clone()
    }
}

#[tokio::test]
async fn an_invite_record_mails_the_invitee_once_it_lands() {
    let mailbox = std::sync::Arc::new(Invitations::default());
    let rig = Rig::mailing(mailbox.clone());
    let sam = rig.person("sam@example.org", 1).await;
    let ana = rig.person("ana@example.org", 2).await;
    let (space, _, mut chain, _) = make(&rig, &sam).await;
    // Making the space invites no one.
    assert!(mailbox.sent(0).await.is_empty());

    let invite = chain.invite(&sam.person, ana.person.id, Role::Member);
    let reply = sam.post(&uri(space), request(&[&invite])).await;
    assert_eq!(reply.status, StatusCode::CREATED, "{:?}", reply.json());
    let sent = mailbox.sent(1).await;
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].to.as_str(), "ana@example.org");
    assert_eq!(sent[0].space_id, Some(SpaceId(space)));
    assert_eq!(sent[0].space, None);
    assert_eq!(sent[0].inviter.as_deref(), Some("sam@example.org"));

    // The same record again is a conflict, and mails nobody.
    let again = sam.post(&uri(space), request(&[&invite])).await;
    assert_eq!(again.status, StatusCode::CONFLICT);
    assert_eq!(mailbox.sent(2).await.len(), 1);
}

#[tokio::test]
async fn a_key_replacement_cannot_hold_an_item_of_a_collection_it_does_not_rotate() {
    let rig = Rig::new();
    let sam = rig.person("sam@example.org", 1).await;
    let (space, general, mut chain, _) = make(&rig, &sam).await;
    let finance = Uuid::new_v4();
    let added = chain.collection(&sam.person, *finance.as_bytes());
    let reply = sam.post(&uri(space), request(&[&added])).await;
    assert_eq!(reply.status, StatusCode::CREATED, "{:?}", reply.json());
    let made = sam.put_item(space, finance, 1).await;
    assert_eq!(made.status, StatusCode::CREATED, "{:?}", made.json());
    let id: Uuid = made.json()["id"]
        .as_str()
        .and_then(|id| id.parse().ok())
        .expect("an item id");

    // The record replaces General's key, so it can't hold an item of Finance.
    let keys = chain.rotate_collection(&sam.person, *general.as_bytes(), 2, &[&sam.person]);
    let mut body = request(&[&keys]);
    body["held"] = json!([id.to_string()]);
    let refused = sam.post(&uri(space), body).await;
    assert_eq!(
        refused.status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "{:?}",
        refused.json()
    );
    assert!(problem_type(&refused).ends_with("held-not-rotated"));
    assert!(held_ids(&rig, space).await.is_empty());

    // Nothing was appended: the same record, without the hold, is still the next one.
    let ok = sam.post(&uri(space), request(&[&keys])).await;
    assert_eq!(ok.status, StatusCode::CREATED, "{:?}", ok.json());
}

// ---- a key replacement carries its re-written items ----

/// The body of a re-written item, as the key-replacement route takes it.
fn rewrite(space: Uuid, collection: Uuid, id: Uuid, expected: u64, key_version: u32) -> Value {
    json!({
        "collection": collection.to_string(),
        "expectedRevision": expected,
        "item": {
            "id": id.to_string(),
            "owner": format!("space:{space}"),
            "kind": "login",
            "format": "kem1",
            "revision": expected + 1,
            "keyVersion": key_version,
            "ciphertext": b64(&kemlock_crypto::rand::bytes::<64>()),
            "itemKey": b64(&kemlock_crypto::rand::bytes::<60>()),
            "deleted": false,
            "collectionId": collection.to_string(),
        },
    })
}

async fn made_item(sam: &Who, space: Uuid, collection: Uuid) -> Uuid {
    let made = sam.put_item(space, collection, 1).await;
    assert_eq!(made.status, StatusCode::CREATED, "{:?}", made.json());
    made.json()["id"]
        .as_str()
        .and_then(|id| id.parse().ok())
        .expect("an item id")
}

#[tokio::test]
async fn a_keys_record_is_appended_with_the_items_it_rewrites_in_one_transaction() {
    let rig = Rig::new();
    let sam = rig.person("sam@example.org", 1).await;
    let (space, collection, mut chain, _) = make(&rig, &sam).await;
    let id = made_item(&sam, space, collection).await;

    let keys = chain.rotate_collection(&sam.person, *collection.as_bytes(), 2, &[&sam.person]);
    let mut body = request(&[&keys]);
    body["writes"] = json!([rewrite(space, collection, id, 1, 2)]);
    let reply = sam.post(&uri(space), body).await;
    assert_eq!(reply.status, StatusCode::CREATED, "{:?}", reply.json());

    // The item is the next revision, under the new key version, live and in its collection.
    let stored = ItemStore::get(&rig.app.store, ItemId(id))
        .await
        .expect("read")
        .expect("the item");
    assert_eq!((stored.revision.0, stored.key_version), (2, 2));
    assert!(!stored.is_tombstone());
    assert!(held_ids(&rig, space).await.is_empty());
    // And the collection's writes continue under version 2.
    let next = sam.put_item(space, collection, 2).await;
    assert_eq!(next.status, StatusCode::CREATED, "{:?}", next.json());
}

#[tokio::test]
async fn a_rewrite_under_another_key_version_than_the_new_one_appends_nothing() {
    let rig = Rig::new();
    let sam = rig.person("sam@example.org", 1).await;
    let (space, collection, mut chain, _) = make(&rig, &sam).await;
    let id = made_item(&sam, space, collection).await;

    let keys = chain.rotate_collection(&sam.person, *collection.as_bytes(), 2, &[&sam.person]);
    let mut body = request(&[&keys]);
    body["writes"] = json!([rewrite(space, collection, id, 1, 1)]);
    let refused = sam.post(&uri(space), body).await;
    assert_eq!(
        refused.status,
        StatusCode::BAD_REQUEST,
        "{:?}",
        refused.json()
    );
    let stored = ItemStore::get(&rig.app.store, ItemId(id))
        .await
        .expect("read")
        .expect("the item");
    assert_eq!((stored.revision.0, stored.key_version), (1, 1));

    // Nothing was appended: the same record, without the writes, is still the next one.
    let ok = sam.post(&uri(space), request(&[&keys])).await;
    assert_eq!(ok.status, StatusCode::CREATED, "{:?}", ok.json());
}

/// `write` (an entry of a request's `writes`) signed by `by` with their own key at key version 1,
/// the statement binding `bound` as the collection (docs/crypto.md, "Signed item writes").
fn signed_rewrite(by: &Who, space: Uuid, bound: Uuid, mut write: Value) -> Value {
    use kemlock_crypto::{item_write, owner::Owner};
    let item = &write["item"];
    let ciphertext = common::unb64(item["ciphertext"].as_str().expect("a ciphertext"));
    let item_key = common::unb64(item["itemKey"].as_str().expect("an item key"));
    let id: Uuid = item["id"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .expect("an item id");
    let key_version = u32::try_from(item["keyVersion"].as_u64().expect("a key version"))
        .expect("a key version fits");
    let statement = item_write::Statement {
        owner: Owner::space(*space.as_bytes()),
        item_id: *id.as_bytes(),
        kind: "login",
        revision: item["revision"].as_u64().expect("a revision"),
        deleted: false,
        envelope: item_write::envelope_hash(
            key_version,
            Some((ciphertext.as_slice(), item_key.as_slice())),
        )
        .expect("the hash"),
        writer: *by.id.as_bytes(),
        writer_key_version: 1,
        collection: Some(*bound.as_bytes()),
    };
    let signature = b64(&statement.sign(&by.person.sig).expect("signs"));
    write["item"]["writer"] = json!(by.id.to_string());
    write["item"]["writerKeyVersion"] = json!(1);
    write["item"]["writeSignature"] = json!(signature);
    write
}

/// An append body of `mib` MiB that is no append: whitespace, which the route reads before it
/// parses anything.
fn padding(mib: usize) -> Req<'static> {
    Req {
        raw_body: Some(vec![b' '; mib * 1024 * 1024]),
        ..Req::default()
    }
}

/// `request` posted to the chain of `space` as `who`.
async fn post_as(who: &Who, space: Uuid, request: Req<'static>) -> Reply {
    who.client
        .send(
            "POST",
            &uri(space),
            Req {
                access_token: Some(who.session.access_token.as_str()),
                ..request
            },
        )
        .await
}

/// A space in which Ana, who could edit General, lost her grant, so General's key is marked and
/// Sam (an owner, with manage on it) may replace it, and Lee, a member with view only, may not.
/// General holds `items` live items by then (nothing is written once its key is marked).
async fn a_marked_collection_key(
    rig: &Rig,
    sam: &Who,
    ana: &Who,
    lee: &Who,
    items: usize,
) -> (Uuid, Uuid, Chain, Vec<Uuid>) {
    let (space, collection, mut chain, _) = make(rig, sam).await;
    let general = *collection.as_bytes();
    let invite_ana = chain.invite(&sam.person, ana.person.id, Role::Member);
    let invite_lee = chain.invite(&sam.person, lee.person.id, Role::Member);
    let reply = sam
        .post(&uri(space), request(&[&invite_ana, &invite_lee]))
        .await;
    assert_eq!(reply.status, StatusCode::CREATED, "{:?}", reply.json());
    ana.accept(space).await;
    lee.accept(space).await;
    let grant = |chain: &mut Chain, who: &Who, permission| {
        chain.record(
            &sam.person,
            Body::Grant {
                collection: general,
                grantee: Grantee::User(who.person.id),
                permission,
            },
        )
    };
    let grant_ana = grant(&mut chain, ana, CollectionPerm::Edit);
    let confirm_ana = chain.confirm(&sam.person, &ana.person);
    let seal_ana = chain.seal_collection_key(&sam.person, general, &ana.person);
    let grant_lee = grant(&mut chain, lee, CollectionPerm::View);
    let confirm_lee = chain.confirm(&sam.person, &lee.person);
    let seal_lee = chain.seal_collection_key(&sam.person, general, &lee.person);
    let reply = sam
        .post(
            &uri(space),
            request(&[
                &grant_ana,
                &confirm_ana,
                &seal_ana,
                &grant_lee,
                &confirm_lee,
                &seal_lee,
            ]),
        )
        .await;
    assert_eq!(reply.status, StatusCode::CREATED, "{:?}", reply.json());
    let mut ids = Vec::new();
    for _ in 0..items {
        ids.push(made_item(sam, space, collection).await);
    }
    let ungrant = chain.record(
        &sam.person,
        Body::Ungrant {
            collection: general,
            grantee: Grantee::User(ana.person.id),
            replace: vec![KeyRef::Collection(general)],
        },
    );
    let reply = sam.post(&uri(space), request(&[&ungrant])).await;
    assert_eq!(reply.status, StatusCode::CREATED, "{:?}", reply.json());
    (space, collection, chain, ids)
}

#[tokio::test]
async fn a_body_over_8_mib_is_read_only_for_a_member_who_may_replace_a_marked_key() {
    // No wait after a refusal here: that is the next test's.
    let rig = Rig::over_with(App::new(true), ChainLargeBodies::new(2, 0));
    let sam = rig.person("sam@example.org", 1).await;
    let zed = rig.person("zed@example.org", 2).await;
    let ana = rig.person("ana@example.org", 3).await;
    let lee = rig.person("lee@example.org", 4).await;
    let (quiet, _, _, _) = make(&rig, &sam).await;
    let (space, _, _, _) = a_marked_collection_key(&rig, &sam, &ana, &lee, 0).await;

    // Nobody signed in is refused before the body is read.
    let anon = Client::new(
        rig.router.clone(),
        rig.app.clock.clone(),
        DpopSigner::es256(),
    );
    let reply = anon.send("POST", &uri(space), padding(9)).await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);

    // A stranger gets the ordinary limit: 413 past 8 MiB, with nothing said of the space.
    let reply = post_as(&zed, space, padding(9)).await;
    assert_eq!(reply.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(reply.problem(), "payload-too-large");

    // So does a confirmed member who may only view the collection whose key is marked.
    let reply = post_as(&lee, space, padding(9)).await;
    assert_eq!(reply.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(reply.problem(), "payload-too-large");

    // And an owner of a space in which no key waits to be replaced: nothing needs a body that large.
    let reply = post_as(&sam, quiet, padding(9)).await;
    assert_eq!(reply.status, StatusCode::PAYLOAD_TOO_LARGE);

    // The owner who may replace the marked key is read to 32 MiB: 9 MiB passes the size check and
    // fails as the JSON it isn't, and 33 MiB is too large.
    let reply = post_as(&sam, space, padding(9)).await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    let reply = post_as(&sam, space, padding(33)).await;
    assert_eq!(reply.status, StatusCode::PAYLOAD_TOO_LARGE);

    // The pending-answer route reads 8 MiB from anyone.
    let pending = Uuid::new_v4();
    let reply = sam
        .client
        .send(
            "POST",
            &format!("{}/pending/{pending}", uri(space)),
            Req {
                access_token: Some(sam.session.access_token.as_str()),
                ..padding(9)
            },
        )
        .await;
    assert_eq!(reply.status, StatusCode::PAYLOAD_TOO_LARGE);

    // Nobody's place was kept: Sam's next large body is read as well.
    let reply = post_as(&sam, space, padding(9)).await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn large_bodies_are_limited_for_the_server_each_space_and_each_account_and_wait_after_a_refusal()
 {
    // A request that finds no place waits for one; here, not long.
    let places = ChainLargeBodies::new(2, 60).with_wait(std::time::Duration::from_millis(100));
    let rig = Rig::over_with(App::new(true), places.clone());
    let sam = rig.person("sam@example.org", 1).await;
    let ana = rig.person("ana@example.org", 3).await;
    let lee = rig.person("lee@example.org", 4).await;
    let (space, _, _, _) = a_marked_collection_key(&rig, &sam, &ana, &lee, 0).await;
    let (other_space, other_account) = ([0x51u8; 16], [0x52u8; 16]);

    // The space has a large body in hand already: 429, and Sam's own turn is not spent.
    let busy = places
        .occupy(other_account, *space.as_bytes())
        .await
        .expect("a place");
    let reply = post_as(&sam, space, padding(9)).await;
    assert_eq!(reply.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(reply.problem(), "rate-limited");
    drop(busy);

    // So has the account, in another space.
    let busy = places
        .occupy(*sam.id.as_bytes(), other_space)
        .await
        .expect("a place");
    let reply = post_as(&sam, space, padding(9)).await;
    assert_eq!(reply.status, StatusCode::TOO_MANY_REQUESTS);
    drop(busy);

    // And so has the server: both of its places are taken by others, and Sam waits for one in
    // vain.
    let one = places
        .occupy([0x61; 16], [0x62; 16])
        .await
        .expect("a place");
    let two = places
        .occupy([0x63; 16], [0x64; 16])
        .await
        .expect("a place");
    let reply = post_as(&sam, space, padding(9)).await;
    assert_eq!(reply.status, StatusCode::TOO_MANY_REQUESTS);
    drop((one, two));

    // With the places free, the body is read, and it ends in a refusal (it is no JSON)...
    let reply = post_as(&sam, space, padding(9)).await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    // ...so the account waits before another: 429 with a Retry-After, whatever the body.
    let reply = post_as(&sam, space, padding(9)).await;
    assert_eq!(reply.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(reply.header("retry-after").is_some());
    // The wait is the account's: Ana, who may not send a large body, is still told 413, not 429.
    let reply = post_as(&ana, space, padding(9)).await;
    assert_eq!(reply.status, StatusCode::PAYLOAD_TOO_LARGE);
    // A small request is not held up by it.
    let reply = sam.get(&uri(space)).await;
    assert_eq!(reply.status, StatusCode::OK);
}

#[tokio::test]
async fn an_account_has_a_budget_of_large_bodies_an_hour() {
    let places = ChainLargeBodies::new(2, 0).with_budget(1);
    let rig = Rig::over_with(App::new(true), places);
    let sam = rig.person("sam@example.org", 1).await;
    let ana = rig.person("ana@example.org", 3).await;
    let lee = rig.person("lee@example.org", 4).await;
    let (space, _, _, _) = a_marked_collection_key(&rig, &sam, &ana, &lee, 0).await;

    // The one of the hour is read (it is no JSON), and counts, though nothing waits after it...
    let reply = post_as(&sam, space, padding(9)).await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    // ...so the next is refused with a time to wait, before its body is read past 8 MiB.
    let reply = post_as(&sam, space, padding(9)).await;
    assert_eq!(reply.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(reply.header("retry-after").is_some());
}

#[tokio::test]
async fn a_key_replacement_that_lands_makes_the_account_no_wait() {
    let places = ChainLargeBodies::new(2, 60).with_budget(2);
    let rig = Rig::over_with(App::new(true), places.clone());
    let sam = rig.person("sam@example.org", 1).await;
    let ana = rig.person("ana@example.org", 3).await;
    let lee = rig.person("lee@example.org", 4).await;
    // Seven items of 1 MB make the request more than 8 MiB.
    let (space, general, mut chain, ids) = a_marked_collection_key(&rig, &sam, &ana, &lee, 7).await;
    let keys = chain.rotate_collection(
        &sam.person,
        *general.as_bytes(),
        2,
        &[&sam.person, &lee.person],
    );
    let mut body = request(&[&keys]);
    body["writes"] = json!(
        ids.iter()
            .map(|id| {
                let mut write = rewrite(space, general, *id, 1, 2);
                write["item"]["ciphertext"] = json!(b64(&vec![0xAB_u8; 1_000_000]));
                write
            })
            .collect::<Vec<_>>()
    );
    assert!(body.to_string().len() > 8 * 1024 * 1024);
    let reply = sam.post(&uri(space), body).await;
    assert_eq!(reply.status, StatusCode::CREATED, "{:?}", reply.json());

    // It was what the places are for: no wait of a minute (it spent one of the two of the hour).
    places
        .occupy(*sam.id.as_bytes(), [0x71; 16])
        .await
        .expect("the account doesn't wait");
}

#[tokio::test]
async fn a_signed_rewrite_is_stored_with_its_signature_and_one_that_binds_another_collection_is_refused()
 {
    let rig = Rig::new();
    let sam = rig.person("sam@example.org", 1).await;
    let (space, collection, mut chain, _) = make(&rig, &sam).await;
    let id = made_item(&sam, space, collection).await;

    let keys = chain.rotate_collection(&sam.person, *collection.as_bytes(), 2, &[&sam.person]);
    let bare = rewrite(space, collection, id, 1, 2);

    // A signature that binds another collection is no signature of this write: nothing is stored.
    let mut body = request(&[&keys]);
    body["writes"] = json!([signed_rewrite(&sam, space, Uuid::new_v4(), bare.clone())]);
    let refused = sam.post(&uri(space), body).await;
    assert_eq!(
        refused.status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "{:?}",
        refused.json()
    );
    assert!(problem_type(&refused).ends_with("invalid-signature"));
    let stored = ItemStore::get(&rig.app.store, ItemId(id))
        .await
        .expect("read")
        .expect("the item");
    assert_eq!((stored.revision.0, stored.key_version), (1, 1));

    // The one that binds the collection it is written into is stored, with the signature.
    let mut body = request(&[&keys]);
    body["writes"] = json!([signed_rewrite(&sam, space, collection, bare)]);
    let reply = sam.post(&uri(space), body).await;
    assert_eq!(reply.status, StatusCode::CREATED, "{:?}", reply.json());
    let stored = ItemStore::get(&rig.app.store, ItemId(id))
        .await
        .expect("read")
        .expect("the item");
    assert_eq!((stored.revision.0, stored.key_version), (2, 2));
    let signature = stored.signature.expect("the signature is stored");
    assert_eq!((signature.writer, signature.key_version), (sam.id, 1));
}

#[tokio::test]
async fn a_space_that_takes_signed_writes_only_refuses_an_unsigned_rewrite() {
    let rig = Rig::new();
    let sam = rig.person("sam@example.org", 1).await;
    let (space, collection, mut chain, _) = make(&rig, &sam).await;
    let id = made_item(&sam, space, collection).await;
    let asked = sam
        .call(
            "PUT",
            &format!("/kem/v1/owners/space:{space}/signed-writes"),
            None,
        )
        .await;
    assert_eq!(asked.status, StatusCode::NO_CONTENT, "{:?}", asked.json());

    let keys = chain.rotate_collection(&sam.person, *collection.as_bytes(), 2, &[&sam.person]);
    let bare = rewrite(space, collection, id, 1, 2);
    let mut body = request(&[&keys]);
    body["writes"] = json!([bare.clone()]);
    let refused = sam.post(&uri(space), body).await;
    assert_eq!(
        refused.status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "{:?}",
        refused.json()
    );
    assert!(problem_type(&refused).ends_with("signature-required"));

    // Nothing was appended or written: the same record with the signed write is the next one.
    let mut body = request(&[&keys]);
    body["writes"] = json!([signed_rewrite(&sam, space, collection, bare)]);
    let reply = sam.post(&uri(space), body).await;
    assert_eq!(reply.status, StatusCode::CREATED, "{:?}", reply.json());
}

#[tokio::test]
async fn only_items_of_a_replaced_collection_are_rewritten_and_none_that_is_also_held() {
    let rig = Rig::new();
    let sam = rig.person("sam@example.org", 1).await;
    let (space, general, mut chain, _) = make(&rig, &sam).await;
    let finance = Uuid::new_v4();
    let added = chain.collection(&sam.person, *finance.as_bytes());
    let reply = sam.post(&uri(space), request(&[&added])).await;
    assert_eq!(reply.status, StatusCode::CREATED, "{:?}", reply.json());
    let of_finance = made_item(&sam, space, finance).await;
    let of_general = made_item(&sam, space, general).await;

    // The record replaces General's key: it can't re-write an item of Finance.
    let keys = chain.rotate_collection(&sam.person, *general.as_bytes(), 2, &[&sam.person]);
    let mut body = request(&[&keys]);
    body["writes"] = json!([rewrite(space, finance, of_finance, 1, 2)]);
    let refused = sam.post(&uri(space), body).await;
    assert_eq!(
        refused.status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "{:?}",
        refused.json()
    );
    assert!(problem_type(&refused).ends_with("held-not-rotated"));

    // Nor one it also holds, nor one twice, nor an item that isn't there.
    for writes in [
        json!([rewrite(space, general, of_general, 1, 2)]),
        json!([
            rewrite(space, general, of_general, 1, 2),
            rewrite(space, general, of_general, 1, 2)
        ]),
        json!([rewrite(space, general, Uuid::new_v4(), 1, 2)]),
    ] {
        let mut body = request(&[&keys]);
        body["writes"] = writes.clone();
        if writes.as_array().is_some_and(|w| w.len() == 1) {
            body["held"] = json!([of_general.to_string()]);
        }
        let refused = sam.post(&uri(space), body).await;
        assert_eq!(
            refused.status,
            StatusCode::BAD_REQUEST,
            "{:?}",
            refused.json()
        );
    }

    // Nothing of any of it landed: the record goes in alone.
    let ok = sam.post(&uri(space), request(&[&keys])).await;
    assert_eq!(ok.status, StatusCode::CREATED, "{:?}", ok.json());
}

#[tokio::test]
async fn a_chain_write_releases_an_item_an_earlier_replacement_held() {
    let rig = Rig::new();
    let sam = rig.person("sam@example.org", 1).await;
    let (space, collection, mut chain, _) = make(&rig, &sam).await;
    let id = made_item(&sam, space, collection).await;

    // The first replacement holds the item, under version 1.
    let keys = chain.rotate_collection(&sam.person, *collection.as_bytes(), 2, &[&sam.person]);
    let mut body = request(&[&keys]);
    body["held"] = json!([id.to_string()]);
    let reply = sam.post(&uri(space), body).await;
    assert_eq!(reply.status, StatusCode::CREATED, "{:?}", reply.json());
    assert_eq!(held_ids(&rig, space).await, vec![ItemId(id)]);

    // The next one re-writes it under version 3: it is live again.
    let keys = chain.rotate_collection(&sam.person, *collection.as_bytes(), 3, &[&sam.person]);
    let mut body = request(&[&keys]);
    body["writes"] = json!([rewrite(space, collection, id, 1, 3)]);
    let reply = sam.post(&uri(space), body).await;
    assert_eq!(reply.status, StatusCode::CREATED, "{:?}", reply.json());
    assert!(held_ids(&rig, space).await.is_empty());
    let stored = ItemStore::get(&rig.app.store, ItemId(id))
        .await
        .expect("read")
        .expect("the item");
    assert_eq!((stored.revision.0, stored.key_version), (2, 3));
}

#[tokio::test]
async fn no_item_is_written_while_the_space_key_waits_to_be_replaced() {
    let rig = Rig::new();
    let sam = rig.person("sam@example.org", 1).await;
    let ana = rig.person("ana@example.org", 2).await;
    let (space, collection, mut chain, _) = make(&rig, &sam).await;
    let invite = chain.invite(&sam.person, ana.person.id, Role::Member);
    let confirm = chain.confirm(&sam.person, &ana.person);
    let seal = chain.seal_space_key(&sam.person, &ana.person);
    let remove = chain.remove(&sam.person, ana.person.id, vec![KeyRef::Space]);
    let reply = sam.post(&uri(space), request(&[&invite])).await;
    assert_eq!(reply.status, StatusCode::CREATED, "{:?}", reply.json());
    ana.accept(space).await;
    let reply = sam.post(&uri(space), request(&[&confirm, &seal])).await;
    assert_eq!(reply.status, StatusCode::CREATED, "{:?}", reply.json());
    let id = made_item(&sam, space, collection).await;
    let reply = sam.post(&uri(space), request(&[&remove])).await;
    assert_eq!(reply.status, StatusCode::CREATED, "{:?}", reply.json());

    // The space key is marked: a collection's key may be replaced, but no item is written (I1).
    let keys = chain.rotate_collection(&sam.person, *collection.as_bytes(), 2, &[&sam.person]);
    let mut body = request(&[&keys]);
    body["writes"] = json!([rewrite(space, collection, id, 1, 2)]);
    let refused = sam.post(&uri(space), body).await;
    assert_eq!(
        refused.status,
        StatusCode::BAD_REQUEST,
        "{:?}",
        refused.json()
    );
    let stored = ItemStore::get(&rig.app.store, ItemId(id))
        .await
        .expect("read")
        .expect("the item");
    assert_eq!((stored.revision.0, stored.key_version), (1, 1));

    // Nothing was appended: the record, naming the item held, is still the next one.
    let mut body = request(&[&keys]);
    body["held"] = json!([id.to_string()]);
    let ok = sam.post(&uri(space), body).await;
    assert_eq!(ok.status, StatusCode::CREATED, "{:?}", ok.json());
}

#[tokio::test]
async fn an_account_past_its_record_quota_is_told_to_wait() {
    use kemlock_app::spaces::ChainUsage;

    let rig = Rig::new();
    let sam = rig.person("sam@example.org", 1).await;
    let ana = rig.person("ana@example.org", 2).await;
    let (space, _, mut chain, _) = make(&rig, &sam).await;
    let invite = chain.invite(&sam.person, ana.person.id, Role::Member);

    // The day is asked of everyone, an Owner included: 429, and nothing is stored.
    rig.spaces.set_usage(ChainUsage {
        by_member_hour: 0,
        by_member_day: 4_096,
    });
    let reply = sam.post(&uri(space), request(&[&invite])).await;
    assert_eq!(
        reply.status,
        StatusCode::TOO_MANY_REQUESTS,
        "{:?}",
        reply.json()
    );
    assert!(problem_type(&reply).ends_with("space-chain-quota"));
    assert_eq!(
        sam.get(&uri(space)).await.json().as_array().map(Vec::len),
        Some(1)
    );

    // The hour is not asked of a space's Owners and Admins: the same record goes in.
    rig.spaces.set_usage(ChainUsage {
        by_member_hour: 1_024,
        by_member_day: 0,
    });
    let reply = sam.post(&uri(space), request(&[&invite])).await;
    assert_eq!(reply.status, StatusCode::CREATED, "{:?}", reply.json());
}

#[tokio::test]
async fn a_role_record_that_demotes_an_admin_meets_the_join_policies() {
    use kemlock_crypto::space_chain::Body;
    use kemlock_domain::policies::SpacePolicies;

    let rig = Rig::new();
    let sam = rig.person("sam@example.org", 1).await;
    let ana = rig.person("ana@example.org", 2).await;
    let (space, _, mut chain, _) = make(&rig, &sam).await;
    // Ana joins as an Admin, whom the join policies do not bind.
    let invite = chain.invite(&sam.person, ana.person.id, Role::Admin);
    let confirm = chain.confirm(&sam.person, &ana.person);
    let seal = chain.seal_space_key(&sam.person, &ana.person);
    let reply = sam.post(&uri(space), request(&[&invite])).await;
    assert_eq!(reply.status, StatusCode::CREATED, "{:?}", reply.json());
    ana.accept(space).await;
    let reply = sam.post(&uri(space), request(&[&confirm, &seal])).await;
    assert_eq!(reply.status, StatusCode::CREATED, "{:?}", reply.json());

    // The space asks for two-step login, which Ana has not set up. A record that makes her a member
    // is refused, with the problem type of the join guard on the routes; nothing is stored.
    rig.spaces.set_policies(
        SpaceId(space),
        SpacePolicies {
            two_step: true,
            ..SpacePolicies::default()
        },
    );
    let demote = chain.record(
        &sam.person,
        Body::Role {
            custom: Vec::new(),
            member: ana.person.id,
            role: Role::Member,
        },
    );
    let reply = sam.post(&uri(space), request(&[&demote])).await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN, "{:?}", reply.json());
    assert!(problem_type(&reply).ends_with("policy-two-step-required"));
    assert_eq!(
        sam.get(&uri(space)).await.json().as_array().map(Vec::len),
        Some(4)
    );
}
