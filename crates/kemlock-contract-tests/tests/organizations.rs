//! `organizationId`: kept on items of an organization, never gained by a personal item.
//!
//! Kemlock "skips items with an `organizationId`" (design, "Item types"), Amethystora "counts
//! organization items and leaves them alone" (`spec-protocol.md` 5.6, "What a client must leave
//! alone": "`organizationId` non-null: encrypted under an org key this client never touches"), and
//! the design says: "Keep `organizationId` on space items; personal items never gain one". Neither
//! app calls organization routes (design, routes table), so these tests make one the way the web
//! vault does, only to have an item that belongs to it.

use kemlock_contract_tests::account::{as_write, login_cipher};
use kemlock_contract_tests::enc::{b64, enc, enc_bytes, random_bytes};
use kemlock_contract_tests::{Session, fresh_session};
use serde_json::json;

/// An organization of one, owned by the account, with its default collection. Returns the
/// organization's id and its collection's.
async fn organization(s: &Session) -> (String, String) {
    let reply = s
        .post(
            "/api/organizations",
            &json!({
                "name": "Contract organization",
                "billingEmail": s.account.email,
                "planType": 0,
                "key": format!("4.{}", b64(&random_bytes(256))),
                "keys": {
                    "publicKey": s.account.public_key,
                    "encryptedPrivateKey": s.account.private_key,
                },
                "collectionName": enc("Default collection"),
            }),
        )
        .await;
    let created = reply.ok_json("POST /api/organizations");
    let id = created["id"]
        .as_str()
        .unwrap_or_else(|| panic!("the organization has an id: {created}"))
        .to_owned();
    let sync = s.sync().await;
    let collection = sync["collections"]
        .as_array()
        .and_then(|all| all.iter().find(|c| c["organizationId"] == json!(id)))
        .unwrap_or_else(|| {
            panic!(
                "the organization has a collection in /api/sync: {}",
                sync["collections"]
            )
        });
    let collection_id = collection["id"]
        .as_str()
        .unwrap_or_else(|| panic!("the collection has an id: {collection}"))
        .to_owned();
    (id, collection_id)
}

#[tokio::test]
async fn an_item_of_an_organization_keeps_its_organization_id_through_a_put() {
    let s = fresh_session().await;
    let (org, collection) = organization(&s).await;

    let mut cipher = login_cipher(&s.user_id, "Shared login");
    cipher["organizationId"] = json!(org);
    cipher["key"] = json!(enc_bytes(&random_bytes(64)));
    let reply = s
        .post(
            "/api/ciphers/create",
            &json!({"cipher": cipher, "collectionIds": [collection]}),
        )
        .await;
    let made = reply.ok_json("POST /api/ciphers/create");
    assert_eq!(
        made["organizationId"],
        json!(org),
        "the item belongs to the organization: {made}"
    );
    let id = made["id"].as_str().expect("an id").to_owned();

    let synced = s.synced_cipher(&id).await.expect("in /api/sync");
    assert_eq!(
        synced["organizationId"],
        json!(org),
        "/api/sync shows the organizationId"
    );
    assert!(
        synced["collectionIds"]
            .as_array()
            .is_some_and(|ids| ids.contains(&json!(collection))),
        "and its collection: {synced}"
    );

    // The owner edits it, as an app that leaves organization items alone never does, and the
    // organizationId stays
    let mut update = as_write(&synced, &s.user_id);
    update["name"] = json!(enc("Shared login, renamed"));
    update["lastKnownRevisionDate"] = synced["revisionDate"].clone();
    let reply = s.update_cipher(&id, &update).await;
    let put = reply.ok_json("PUT an organization's item");
    assert_eq!(
        put["organizationId"],
        json!(org),
        "a PUT keeps the organizationId"
    );
    let after = s.synced_cipher(&id).await.expect("in /api/sync");
    assert_eq!(after["organizationId"], json!(org));
    assert_eq!(after["name"], update["name"]);
}

#[tokio::test]
async fn a_personal_item_never_gains_an_organization_id() {
    let s = fresh_session().await;
    let (org, _) = organization(&s).await;

    let made = s.create_cipher(&login_cipher(&s.user_id, "Personal")).await;
    assert!(
        made["organizationId"].is_null(),
        "a personal item has none: {made}"
    );
    let id = made["id"].as_str().expect("an id").to_owned();

    // An update that says the item is the organization's is refused, as Vaultwarden's
    // "Organization mismatch" is, and the item stays personal
    let mut update = as_write(&made, &s.user_id);
    update["organizationId"] = json!(org);
    update["lastKnownRevisionDate"] = made["revisionDate"].clone();
    let reply = s.update_cipher(&id, &update).await;
    assert!(
        !reply.is_success(),
        "a PUT can't move a personal item to an organization; got {} {}",
        reply.status,
        reply.text()
    );
    let synced = s.synced_cipher(&id).await.expect("in /api/sync");
    assert!(
        synced["organizationId"].is_null(),
        "still personal: {synced}"
    );

    // And an ordinary PUT leaves it null
    let mut plain = as_write(&synced, &s.user_id);
    plain["lastKnownRevisionDate"] = synced["revisionDate"].clone();
    let put = s.update_cipher(&id, &plain).await.ok_json("PUT");
    assert!(put["organizationId"].is_null(), "{put}");
}
