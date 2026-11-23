//! The duplicate cleaner's routes, in-process: a device signs in with real OPAQUE and DPoP, then
//! drives `/kem/v1/duplicates`, `PUT /kem/v1/items/{id}/tags` and the tags on item writes against
//! the in-memory fakes of `kemlock-app`.

mod common;
/// `space_fakes` names the fakes by their path at a test crate's root.
mod fakes {
    pub(crate) use super::common::fakes::*;
}
#[path = "../../kemlock-app/tests/space_fakes/mod.rs"]
mod space_fakes;

use axum::Router;
use axum::http::StatusCode;
use common::{App, Client, Reply, Req, Session, b64, item_json, new_item_id, register_and_sign_in};
use kemlock_api_kem::duplicates_router;
use kemlock_api_kem::testing::DpopSigner;
use serde_json::{Value, json};
use space_fakes::FakeSpaces;

struct Person {
    client: Client,
    session: Session,
    id: String,
}

impl Person {
    async fn send(
        &self,
        method: &str,
        uri: &str,
        body: Option<Value>,
        headers: Vec<(&str, String)>,
    ) -> Reply {
        self.client
            .send(
                method,
                uri,
                Req {
                    access_token: Some(self.session.access_token.as_str()),
                    body,
                    headers,
                    ..Req::default()
                },
            )
            .await
    }

    async fn get(&self, uri: &str) -> Reply {
        self.send("GET", uri, None, Vec::new()).await
    }

    async fn put(&self, uri: &str, body: Value) -> Reply {
        self.send("PUT", uri, Some(body), Vec::new()).await
    }

    async fn post(&self, uri: &str, body: Value) -> Reply {
        self.send("POST", uri, Some(body), Vec::new()).await
    }

    async fn delete(&self, uri: &str) -> Reply {
        self.send("DELETE", uri, None, Vec::new()).await
    }

    fn owner(&self) -> String {
        format!("user:{}", self.id)
    }

    /// A new item (`If-None-Match: *`), with these tags when there are any.
    async fn create(&self, id: &str, tags: Option<(&[u8], u32)>) -> Reply {
        let mut item = item_json(&self.id, id, 1);
        add_tags(&mut item, tags);
        self.send(
            "PUT",
            &format!("/kem/v1/items/{id}"),
            Some(item),
            vec![("if-none-match", "*".to_owned())],
        )
        .await
    }

    /// The next revision of an item (`If-Match: revision - 1`).
    async fn replace(&self, id: &str, revision: u64, tags: Option<(&[u8], u32)>) -> Reply {
        let mut item = item_json(&self.id, id, revision);
        add_tags(&mut item, tags);
        self.send(
            "PUT",
            &format!("/kem/v1/items/{id}"),
            Some(item),
            vec![("if-match", (revision - 1).to_string())],
        )
        .await
    }

    async fn matching(&self, enabled: bool) -> Reply {
        self.put(
            &format!("/kem/v1/duplicates/settings?owner={}", self.owner()),
            json!({ "enabled": enabled }),
        )
        .await
    }

    async fn groups(&self) -> Value {
        let reply = self
            .get(&format!("/kem/v1/duplicates?owner={}", self.owner()))
            .await;
        assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.json());
        reply.json()
    }
}

/// A tag whose bytes are all `n`.
fn tag(n: u8) -> String {
    b64(&[n; 32])
}

fn add_tags(item: &mut Value, tags: Option<(&[u8], u32)>) {
    if let Some((tags, version)) = tags {
        item["tags"] = json!(tags.iter().map(|n| tag(*n)).collect::<Vec<_>>());
        item["tagVersion"] = json!(version);
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
        let router = app.router.clone().merge(duplicates_router(
            app.api.clone(),
            app.store.clone(),
            spaces,
        ));
        Rig { app, router }
    }

    async fn person(&self, email: &str) -> Person {
        let client = Client::new(
            self.router.clone(),
            self.app.clock.clone(),
            DpopSigner::es256(),
        );
        let session = register_and_sign_in(&client, email).await;
        let id = session.user_id.clone();
        Person {
            client,
            session,
            id,
        }
    }
}

fn ids(value: &Value) -> Vec<String> {
    let mut ids: Vec<String> = value
        .as_array()
        .expect("a list")
        .iter()
        .map(|v| v.as_str().expect("an id").to_owned())
        .collect();
    ids.sort();
    ids
}

fn sorted(mut ids: Vec<String>) -> Vec<String> {
    ids.sort();
    ids
}

#[tokio::test]
async fn the_routes_need_a_signed_in_device() {
    let rig = Rig::new();
    let client = Client::new(
        rig.router.clone(),
        rig.app.clock.clone(),
        DpopSigner::es256(),
    );
    let reply = client
        .get("/kem/v1/duplicates?owner=user:00000000-0000-0000-0000-000000000000")
        .await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    assert_eq!(reply.problem(), "unauthorized");
    // Answers from these routes carry the DPoP nonce too.
    assert!(reply.header("dpop-nonce").is_some());
}

#[tokio::test]
async fn matching_is_off_until_it_is_turned_on() {
    let rig = Rig::new();
    let sam = rig.person("sam@example.org").await;
    let a = new_item_id();

    let settings = sam
        .get(&format!(
            "/kem/v1/duplicates/settings?owner={}",
            sam.owner()
        ))
        .await
        .json();
    assert_eq!(settings["enabled"], false);
    assert_eq!(settings["tagVersion"], 1);
    assert_eq!(settings["changedBy"], Value::Null);

    // Tags that come with a write are ignored, not refused: the item is written.
    let created = sam.create(&a, Some((&[1], 1))).await;
    assert_eq!(created.status, StatusCode::CREATED, "{:?}", created.json());
    assert_eq!(created.json()["tagsStored"], false);
    assert!(created.json().get("matches").is_none());

    let backfill = sam
        .send(
            "PUT",
            &format!("/kem/v1/items/{a}/tags"),
            Some(json!({ "tags": [tag(1)], "tagVersion": 1 })),
            vec![("if-match", "1".to_owned())],
        )
        .await;
    assert_eq!(backfill.status, StatusCode::CONFLICT);
    assert_eq!(backfill.problem(), "server-matching-off");

    let groups = sam.groups().await;
    assert_eq!(groups["enabled"], false);
    assert_eq!(groups["groups"], json!([]));

    let on = sam.matching(true).await;
    assert_eq!(on.status, StatusCode::OK, "{:?}", on.json());
    let on = on.json();
    assert_eq!(on["enabled"], true);
    assert_eq!(on["changedBy"], sam.id.as_str());
    assert!(on["changedAt"].as_i64().is_some());
}

#[tokio::test]
async fn tags_on_item_writes_make_groups_and_a_write_without_them_clears() {
    let rig = Rig::new();
    let sam = rig.person("sam@example.org").await;
    assert_eq!(sam.matching(true).await.status, StatusCode::OK);
    let (a, b, c) = (new_item_id(), new_item_id(), new_item_id());

    let first = sam.create(&a, Some((&[1, 2], 1))).await;
    assert_eq!(first.status, StatusCode::CREATED, "{:?}", first.json());
    assert_eq!(first.json()["tagsStored"], true);
    assert_eq!(first.json()["matches"], json!([]));
    // The item itself comes back as it always did.
    assert_eq!(first.json()["id"], a.as_str());
    assert_eq!(first.header("etag"), Some("\"1\""));

    let second = sam.create(&b, Some((&[2, 3], 1))).await.json();
    assert_eq!(second["matches"], json!([a]));

    // A batch carries tags per write and answers with each item's matches.
    let batch = sam
        .post(
            "/kem/v1/items:batch",
            json!({ "writes": [{
                "item": {
                    "id": c, "owner": sam.owner(), "kind": "login", "format": "kem1",
                    "revision": 1, "keyVersion": 1,
                    "ciphertext": b64(&[7u8; 64]), "itemKey": b64(&[8u8; 60]),
                    "deleted": false,
                    "tags": [tag(2)], "tagVersion": 1,
                },
            }] }),
        )
        .await;
    assert_eq!(batch.status, StatusCode::OK, "{:?}", batch.json());
    let batch = batch.json();
    assert_eq!(batch["items"].as_array().map(Vec::len), Some(1));
    assert_eq!(batch["tags"][0]["item"], c.as_str());
    assert_eq!(batch["tags"][0]["stored"], true);
    assert_eq!(
        ids(&batch["tags"][0]["matches"]),
        sorted(vec![a.clone(), b.clone()])
    );

    let report = sam.groups().await;
    assert_eq!(report["enabled"], true);
    assert_eq!(report["tagVersion"], 1);
    assert_eq!(report["waiting"], 0);
    let groups = report["groups"].as_array().expect("groups");
    assert_eq!(groups.len(), 1);
    assert_eq!(
        ids(&groups[0]["items"]),
        sorted(vec![a.clone(), b.clone(), c.clone()])
    );

    // A write without tags clears that item's, and the answer is the item alone.
    let replaced = sam.replace(&a, 2, None).await;
    assert_eq!(replaced.status, StatusCode::OK, "{:?}", replaced.json());
    assert!(replaced.json().get("tagsStored").is_none());
    let report = sam.groups().await;
    assert_eq!(report["waiting"], 1);
    assert_eq!(
        ids(&report["groups"][0]["items"]),
        sorted(vec![b.clone(), c.clone()])
    );
}

#[tokio::test]
async fn a_backfill_needs_the_revision_and_the_key_version() {
    let rig = Rig::new();
    let sam = rig.person("sam@example.org").await;
    assert_eq!(sam.matching(true).await.status, StatusCode::OK);
    let (a, b) = (new_item_id(), new_item_id());
    assert_eq!(sam.create(&a, None).await.status, StatusCode::CREATED);
    assert_eq!(
        sam.create(&b, Some((&[5], 1))).await.status,
        StatusCode::CREATED
    );
    let uri = format!("/kem/v1/items/{a}/tags");
    let body = json!({ "tags": [tag(5)], "tagVersion": 1 });

    let ok = sam
        .send(
            "PUT",
            &uri,
            Some(body.clone()),
            vec![("if-match", "1".to_owned())],
        )
        .await;
    assert_eq!(ok.status, StatusCode::OK, "{:?}", ok.json());
    assert_eq!(ok.json()["matches"], json!([b]));

    let stale = sam
        .send(
            "PUT",
            &uri,
            Some(body.clone()),
            vec![("if-match", "9".to_owned())],
        )
        .await;
    assert_eq!(stale.status, StatusCode::CONFLICT);
    assert_eq!(stale.problem(), "stale-revision");
    assert_eq!(stale.json()["currentRevision"], 1);

    let old_key = sam
        .send(
            "PUT",
            &uri,
            Some(json!({ "tags": [tag(5)], "tagVersion": 4 })),
            vec![("if-match", "1".to_owned())],
        )
        .await;
    assert_eq!(old_key.status, StatusCode::CONFLICT);
    assert_eq!(old_key.problem(), "stale-dedup-version");
    assert_eq!(old_key.json()["currentTagVersion"], 1);

    let no_header = sam.put(&uri, body.clone()).await;
    assert_eq!(no_header.status, StatusCode::PRECONDITION_REQUIRED);

    for bad in [
        json!({ "tags": ["AAAA"], "tagVersion": 1 }),
        json!({ "tags": [tag(1)] }),
        json!({ "tags": [tag(1)], "tagVersion": 1, "extra": true }),
        json!({ "tags": ["not base64!"], "tagVersion": 1 }),
    ] {
        let reply = sam
            .send("PUT", &uri, Some(bad), vec![("if-match", "1".to_owned())])
            .await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{:?}", reply.json());
    }
    let one_without_the_other = sam
        .send(
            "PUT",
            &format!("/kem/v1/items/{}", new_item_id()),
            Some({
                let mut item = item_json(&sam.id, &new_item_id(), 1);
                item["tags"] = json!([tag(1)]);
                item
            }),
            vec![("if-none-match", "*".to_owned())],
        )
        .await;
    assert_eq!(one_without_the_other.status, StatusCode::BAD_REQUEST);

    let unknown = sam
        .send(
            "PUT",
            &format!("/kem/v1/items/{}/tags", new_item_id()),
            Some(body),
            vec![("if-match", "1".to_owned())],
        )
        .await;
    assert_eq!(unknown.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_not_duplicates_answer_hides_a_group_until_it_is_taken_back() {
    let rig = Rig::new();
    let sam = rig.person("sam@example.org").await;
    assert_eq!(sam.matching(true).await.status, StatusCode::OK);
    let (a, b) = (new_item_id(), new_item_id());
    sam.create(&a, Some((&[1], 1))).await;
    sam.create(&b, Some((&[1], 1))).await;
    assert_eq!(
        sam.groups().await["groups"].as_array().map(Vec::len),
        Some(1)
    );

    let saved = sam
        .post(
            "/kem/v1/duplicates/dismissals",
            json!({ "owner": sam.owner(), "items": [a, b] }),
        )
        .await;
    assert_eq!(saved.status, StatusCode::CREATED, "{:?}", saved.json());
    let saved = saved.json();
    assert_eq!(saved["by"], sam.id.as_str());
    assert_eq!(ids(&saved["items"]), sorted(vec![a.clone(), b.clone()]));
    assert_eq!(sam.groups().await["groups"], json!([]));

    let id = saved["id"].as_str().expect("an id").to_owned();
    let gone = sam
        .delete(&format!("/kem/v1/duplicates/dismissals/{id}"))
        .await;
    assert_eq!(gone.status, StatusCode::NO_CONTENT);
    assert_eq!(
        sam.groups().await["groups"].as_array().map(Vec::len),
        Some(1)
    );
    let again = sam
        .delete(&format!("/kem/v1/duplicates/dismissals/{id}"))
        .await;
    assert_eq!(again.status, StatusCode::NOT_FOUND);

    let too_few = sam
        .post(
            "/kem/v1/duplicates/dismissals",
            json!({ "owner": sam.owner(), "items": [a] }),
        )
        .await;
    assert_eq!(too_few.status, StatusCode::BAD_REQUEST);
    let bad_id = sam.delete("/kem/v1/duplicates/dismissals/not-a-uuid").await;
    assert_eq!(bad_id.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn deleting_the_tags_turns_matching_off() {
    let rig = Rig::new();
    let sam = rig.person("sam@example.org").await;
    assert_eq!(sam.matching(true).await.status, StatusCode::OK);
    sam.create(&new_item_id(), Some((&[1], 1))).await;
    sam.create(&new_item_id(), Some((&[1], 1))).await;
    assert_eq!(
        sam.groups().await["groups"].as_array().map(Vec::len),
        Some(1)
    );

    let off = sam
        .delete(&format!("/kem/v1/duplicates/tags?owner={}", sam.owner()))
        .await;
    assert_eq!(off.status, StatusCode::OK, "{:?}", off.json());
    assert_eq!(off.json()["enabled"], false);
    let report = sam.groups().await;
    assert_eq!(report["enabled"], false);
    assert_eq!(report["groups"], json!([]));

    // Turned on again, nothing was kept.
    assert_eq!(sam.matching(true).await.status, StatusCode::OK);
    assert_eq!(sam.groups().await["groups"], json!([]));
    assert_eq!(sam.groups().await["waiting"], 2);
}

#[tokio::test]
async fn nobody_else_reads_or_changes_a_vaults_duplicates() {
    let rig = Rig::new();
    let sam = rig.person("sam@example.org").await;
    let kim = rig.person("kim@example.org").await;
    assert_eq!(sam.matching(true).await.status, StatusCode::OK);
    let a = new_item_id();
    sam.create(&a, Some((&[1], 1))).await;

    let sams = sam.owner();
    for reply in [
        kim.get(&format!("/kem/v1/duplicates?owner={sams}")).await,
        kim.get(&format!("/kem/v1/duplicates/settings?owner={sams}"))
            .await,
        kim.put(
            &format!("/kem/v1/duplicates/settings?owner={sams}"),
            json!({ "enabled": false }),
        )
        .await,
        kim.delete(&format!("/kem/v1/duplicates/tags?owner={sams}"))
            .await,
        kim.get("/kem/v1/duplicates?owner=space:00000000-0000-0000-0000-000000000001")
            .await,
        kim.send(
            "PUT",
            &format!("/kem/v1/items/{a}/tags"),
            Some(json!({ "tags": [tag(9)], "tagVersion": 1 })),
            vec![("if-match", "1".to_owned())],
        )
        .await,
    ] {
        assert_eq!(reply.status, StatusCode::NOT_FOUND, "{:?}", reply.json());
    }
    assert_eq!(sam.groups().await["enabled"], true);

    for bad in ["", "?owner=sam", "?owner=user:nope", "?owner=group:1"] {
        let reply = kim.get(&format!("/kem/v1/duplicates{bad}")).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{bad}");
    }
}
