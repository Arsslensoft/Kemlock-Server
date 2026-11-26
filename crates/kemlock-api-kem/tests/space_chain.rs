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
use kemlock_api_kem::{space_chain_router, spaces_router};
use kemlock_app::notices::{BoxFuture, InvitationNotice, Notice, Outbox};
use kemlock_app::ports::Clock as _;
use kemlock_app::ports::ItemStore;
use kemlock_app::spaces::SpaceRepo;
use kemlock_crypto::space_chain::{KeyRef, Role, b64 as chain_b64, link};
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
        let spaces = FakeSpaces::new(app.store.clone());
        let router = app
            .router_with(spaces.clone())
            .merge(spaces_router(app.api.clone(), spaces.clone()))
            .merge(space_chain_router(app.api.clone(), spaces.clone()));
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
    assert_eq!(refused.status, StatusCode::BAD_REQUEST, "{:?}", refused.json());
    let stored = ItemStore::get(&rig.app.store, ItemId(id))
        .await
        .expect("read")
        .expect("the item");
    assert_eq!((stored.revision.0, stored.key_version), (1, 1));

    // Nothing was appended: the same record, without the writes, is still the next one.
    let ok = sam.post(&uri(space), request(&[&keys])).await;
    assert_eq!(ok.status, StatusCode::CREATED, "{:?}", ok.json());
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
        assert_eq!(refused.status, StatusCode::BAD_REQUEST, "{:?}", refused.json());
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
    assert_eq!(refused.status, StatusCode::BAD_REQUEST, "{:?}", refused.json());
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
