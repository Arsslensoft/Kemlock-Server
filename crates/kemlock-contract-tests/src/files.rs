//! Attachments, as the apps send them: the first step opens a slot with
//! `POST /api/ciphers/{id}/attachment/v2`, the second uploads the data as a multipart body with
//! one `data` part (`mobile/lib/features/sync/vaultwarden/vw_api.dart:386-448`).

use crate::enc::{enc, random_bytes};
use crate::http::{Reply, Session};
use serde_json::{Value, json};

const BOUNDARY: &str = "----kemlock-contract-boundary-7MA4YWxkTrZu0gW";

/// A multipart body of one part, `data`, as `uploadAttachment` builds it (`vw_api.dart:432-444`):
/// its content type and its bytes.
pub fn multipart(data: &[u8]) -> (String, Vec<u8>) {
    let mut body = format!(
        "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"data\"; filename=\"data\"\r\n\
         Content-Type: application/octet-stream\r\n\r\n"
    )
    .into_bytes();
    body.extend_from_slice(data);
    body.extend_from_slice(format!("\r\n--{BOUNDARY}--\r\n").as_bytes());
    (format!("multipart/form-data; boundary={BOUNDARY}"), body)
}

/// Some bytes standing for an encrypted attachment: not read by the server, only stored.
pub fn some_data(length: usize) -> Vec<u8> {
    random_bytes(length)
}

/// Step one: `POST /api/ciphers/{id}/attachment/v2` with an encrypted key and name and the size of
/// the data that will be uploaded. `last_known` is the cipher's `revisionDate`, which Amethystora
/// sends and the Kemlock app doesn't (`vaultwarden.rs:675`, `vw_api.dart:398`).
pub async fn open_slot(
    session: &Session,
    cipher_id: &str,
    file_size: usize,
    last_known: Option<&str>,
) -> Reply {
    let mut body = json!({
        "key": enc("attachment key"),
        "fileName": enc("a file.txt"),
        "fileSize": file_size,
        "adminRequest": false,
    });
    if let (Some(object), Some(date)) = (body.as_object_mut(), last_known) {
        object.insert(
            "lastKnownRevisionDate".to_owned(),
            Value::String(date.to_owned()),
        );
    }
    session
        .post(&format!("/api/ciphers/{cipher_id}/attachment/v2"), &body)
        .await
}

/// Step two: `POST /api/ciphers/{id}/attachment/{attachmentId}`, multipart with one `data` part.
pub async fn upload(session: &Session, cipher_id: &str, attachment_id: &str, data: &[u8]) -> Reply {
    let (content_type, body) = multipart(data);
    let call = session
        .call(
            "POST",
            &format!("/api/ciphers/{cipher_id}/attachment/{attachment_id}"),
        )
        .body(&content_type, body);
    session.send(call).await
}

/// Both steps for a cipher the session owns; returns the attachment's id. A refusal panics.
pub async fn attach(session: &Session, cipher_id: &str, data: &[u8]) -> String {
    let slot = open_slot(session, cipher_id, data.len(), None).await;
    let slot = slot.ok_json("attachment/v2");
    let id = slot["attachmentId"]
        .as_str()
        .unwrap_or_else(|| panic!("attachment/v2: no attachmentId in {slot}"))
        .to_owned();
    let uploaded = upload(session, cipher_id, &id, data).await;
    assert!(
        uploaded.is_success(),
        "uploading the data of attachment {id}: got {} {}",
        uploaded.status,
        uploaded.text()
    );
    id
}
