//! Attachments of organization ciphers through the router: the same slots, uploads, links and
//! deletes as a personal cipher's, with the organization's rules about who may.

mod common;

use axum::body::Body;
use axum::http::StatusCode;
use common::{DOMAIN, Harness, login_request};
use serde_json::{Value, json};
use time::Duration;

const ORG_KEY: &str = "4.orgkeywrappedforthefirstowner";
const RANGE: &str = "start=2026-11-01T00:00:00Z&end=2026-12-01T00:00:00Z";

fn multipart(boundary: &str, bytes: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"data\"; filename=\"2.encrypted-name\"\r\nContent-Type: application/octet-stream\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(bytes);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    body
}

async fn upload(
    h: &Harness,
    token: &str,
    cipher: &str,
    attachment: &str,
    bytes: &[u8],
) -> StatusCode {
    let boundary = "kemlockboundary";
    let content_type = format!("multipart/form-data; boundary={boundary}");
    let auth = format!("Bearer {token}");
    let (status, _, _) = h
        .send(
            "POST",
            &format!("/api/ciphers/{cipher}/attachment/{attachment}"),
            &[
                ("authorization", auth.as_str()),
                ("content-type", content_type.as_str()),
            ],
            Body::from(multipart(boundary, bytes)),
        )
        .await;
    status
}

async fn revision(h: &Harness, token: &str) -> i64 {
    h.json("GET", "/api/accounts/revision-date", Some(token), None)
        .await
        .1
        .as_i64()
        .expect("a number")
}

/// An organization with Ada as owner, Bob as a member who may only read its collection, and a
/// login Ada made in it. Returns the tokens, the organization, the collection and the cipher.
struct Fixture {
    h: Harness,
    ada: String,
    bob: String,
    eve: String,
    org: String,
    cipher: String,
}

async fn fixture() -> Fixture {
    let h = Harness::with(|settings| settings.org_events_enabled = true).await;
    let (ada, ada_id) = h.signed_in("ada@example.com").await;
    let (bob, bob_id) = h.signed_in("bob@example.com").await;
    let (eve, _) = h.signed_in("eve@example.com").await;
    let (status, org) = h
        .json(
            "POST",
            "/api/organizations",
            Some(&ada),
            Some(json!({
                "name": "Attachments organization",
                "billingEmail": "billing@example.com",
                "planType": 0,
                "key": ORG_KEY,
                "keys": {"publicKey": "MIIBIjANorg", "encryptedPrivateKey": "2.orgprivate|key|mac"},
                "collectionName": "2.defaultcollection|name|mac"
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{org}");
    let org = org["id"].as_str().expect("an id").to_owned();
    let (_, synced) = h.json("GET", "/api/sync", Some(&ada), None).await;
    let collection = synced["collections"][0]["id"]
        .as_str()
        .expect("a collection")
        .to_owned();

    let (status, body) = h
        .json(
            "POST",
            &format!("/api/organizations/{org}/users/invite"),
            Some(&ada),
            Some(json!({
                "emails": ["bob@example.com"],
                "type": 2,
                "collections": [{"id": collection, "readOnly": true, "hidePasswords": false}],
                "groups": []
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = h
        .json(
            "POST",
            &format!("/api/organizations/{org}/users/{bob_id}/confirm"),
            Some(&ada),
            Some(json!({"key": "4.memberkeywrappedbytheirpublickey"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let mut cipher = login_request(ada_id, "2.shared login");
    cipher["organizationId"] = json!(org);
    let (status, created) = h
        .json(
            "POST",
            "/api/ciphers/create",
            Some(&ada),
            Some(json!({"cipher": cipher, "collectionIds": [collection]})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{created}");
    let cipher = created["id"].as_str().expect("an id").to_owned();
    Fixture {
        h,
        ada,
        bob,
        eve,
        org,
        cipher,
    }
}

#[tokio::test]
async fn an_organization_cipher_takes_an_attachment_for_a_member_who_may_write_it() {
    let Fixture {
        h,
        ada,
        bob,
        org,
        cipher,
        ..
    } = fixture().await;
    let bob_before = revision(&h, &bob).await;

    h.env.advance(Duration::minutes(1));
    let (status, slot) = h
        .json(
            "POST",
            &format!("/api/ciphers/{cipher}/attachment/v2"),
            Some(&ada),
            Some(json!({"key": "2.attkey", "fileName": "2.file", "fileSize": 17, "adminRequest": false})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{slot}");
    assert_eq!(slot["object"], "attachment-fileUpload");
    let aid = slot["attachmentId"].as_str().expect("an id").to_owned();
    assert_eq!(slot["url"], format!("/ciphers/{cipher}/attachment/{aid}"));
    // The answer is the organization's cipher, with its organization.
    assert_eq!(slot["cipherResponse"]["id"], cipher.as_str());
    assert_eq!(slot["cipherResponse"]["organizationId"], org.as_str());
    assert_eq!(slot["cipherResponse"]["attachments"][0]["id"], aid.as_str());

    let file = b"0123456789abcdefg".to_vec();
    assert_eq!(upload(&h, &ada, &cipher, &aid, &file).await, StatusCode::OK);
    assert!(revision(&h, &bob).await > bob_before, "members sync");

    // A member who may only read the cipher reads the attachment and its link works.
    let (status, shown) = h
        .json(
            "GET",
            &format!("/api/ciphers/{cipher}/attachment/{aid}"),
            Some(&bob),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{shown}");
    assert_eq!(shown["object"], "attachment");
    assert_eq!(shown["size"], "17");
    let url = shown["url"].as_str().expect("a url").to_owned();
    assert!(
        url.starts_with(&format!("{DOMAIN}/attachments/{cipher}/{aid}?token=")),
        "{url}"
    );
    let path = url.trim_start_matches(DOMAIN).to_owned();
    let (status, _, bytes) = h.send("GET", &path, &[], Body::empty()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(bytes, file);

    // The cipher in the member's sync lists it.
    let (_, synced) = h.json("GET", "/api/sync", Some(&bob), None).await;
    assert_eq!(synced["ciphers"][0]["attachments"][0]["id"], aid.as_str());

    // Deleting removes the file, and answers the cipher without it.
    h.env.advance(Duration::minutes(1));
    let (status, deleted) = h
        .json(
            "DELETE",
            &format!("/api/ciphers/{cipher}/attachment/{aid}"),
            Some(&ada),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{deleted}");
    assert_eq!(deleted["cipher"]["attachments"], Value::Null);
    assert_eq!(deleted["cipher"]["organizationId"], org.as_str());
    assert!(h.blobs.is_empty());

    // Both are events of the organization.
    let (_, page) = h
        .json(
            "GET",
            &format!("/api/organizations/{org}/events?{RANGE}"),
            Some(&ada),
            None,
        )
        .await;
    let types: Vec<i64> = page["data"]
        .as_array()
        .expect("a list")
        .iter()
        .map(|e| e["type"].as_i64().expect("a type"))
        .collect();
    assert_eq!(&types[..2], [1104, 1103]);
    assert_eq!(page["data"][0]["cipherId"], cipher.as_str());
}

#[tokio::test]
async fn who_may_not_write_or_see_the_cipher_is_refused_with_vaultwardens_words() {
    let Fixture {
        h,
        ada,
        bob,
        eve,
        cipher,
        ..
    } = fixture().await;
    let (_, slot) = h
        .json(
            "POST",
            &format!("/api/ciphers/{cipher}/attachment/v2"),
            Some(&ada),
            Some(json!({"key": "2.k", "fileName": "2.f", "fileSize": 4})),
        )
        .await;
    let aid = slot["attachmentId"].as_str().expect("an id").to_owned();
    assert_eq!(
        upload(&h, &ada, &cipher, &aid, b"abcd").await,
        StatusCode::OK
    );

    // Bob's grant is read only: no new slot, no upload, no delete.
    let (status, body) = h
        .json(
            "POST",
            &format!("/api/ciphers/{cipher}/attachment/v2"),
            Some(&bob),
            Some(json!({"key": "2.k", "fileName": "2.f", "fileSize": 4})),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], "Cipher is not write accessible");
    assert_eq!(
        upload(&h, &bob, &cipher, &aid, b"abcd").await,
        StatusCode::BAD_REQUEST
    );
    let (status, body) = h
        .json(
            "DELETE",
            &format!("/api/ciphers/{cipher}/attachment/{aid}"),
            Some(&bob),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], "Cipher cannot be deleted by user");

    // Someone outside the organization can neither read nor change it.
    let (status, body) = h
        .json(
            "GET",
            &format!("/api/ciphers/{cipher}/attachment/{aid}"),
            Some(&eve),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], "Cipher is not accessible");
    let (status, body) = h
        .json(
            "DELETE",
            &format!("/api/ciphers/{cipher}/attachment/{aid}/admin"),
            Some(&eve),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], "Cipher cannot be deleted by user");

    // Nothing of that changed the attachment, and the admin form of the delete works for Ada.
    let (_, shown) = h
        .json(
            "GET",
            &format!("/api/ciphers/{cipher}/attachment/{aid}"),
            Some(&ada),
            None,
        )
        .await;
    assert_eq!(shown["size"], "4");
    let (status, body) = h
        .json(
            "POST",
            &format!("/api/ciphers/{cipher}/attachment/{aid}/delete-admin"),
            Some(&ada),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(h.blobs.is_empty());
}
