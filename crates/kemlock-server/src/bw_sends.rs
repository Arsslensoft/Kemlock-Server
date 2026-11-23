//! The Bitwarden API's Sends, kept in the database: [`SqlSends`] implements the Bitwarden layer's
//! `SendStore` over the same `sends` table the Kemlock API uses, so a Send made by a Bitwarden app
//! survives a restart (the layer's own default keeps them in memory).
//!
//! A Bitwarden Send is mapped onto the sealed parts of a [`kemlock_domain::sends::SendRecord`]:
//!
//! - `meta` holds the name and notes as the JSON `{"name": ..., "notes": ...}`, both the client's
//!   own encrypted strings, which the server never opens;
//! - `sealed_key` holds the client's encrypted key string as UTF-8 bytes;
//! - `payload` holds the text or file object (a JSON string) as UTF-8 bytes;
//! - the password keeps Bitwarden's PBKDF2 salt and hash, with the fixed round count
//!   [`SEND_PASSWORD_ITERATIONS`] the Bitwarden layer writes;
//! - a file Send's bytes sit at the blob named by the Send's own id, where the Send purge and an
//!   account's erasure delete them (see [`crate::files::BitwardenBlobs`]).
//!
//! A Send of the Kemlock API (sealed meta, an HMAC password) isn't one a Bitwarden app can show,
//! so the Bitwarden layer never sees it: it is skipped in lists and looks absent by id.

use kemlock_api_bw::sends::{SEND_PASSWORD_ITERATIONS, SendError, SendPassword, SendRecord};
use kemlock_api_bw::{BoxFuture, SendStore};
use kemlock_app::ports::StoreError;
use kemlock_app::sends::SendRepo;
use kemlock_domain::sends::{
    SendFile, SendFileFormat, SendId, SendKind, SendPassword as DomainPassword,
    SendRecord as DomainSend,
};
use kemlock_domain::{BlobId, UserId};
use kemlock_store_sql::SqlStore;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

/// How many due Sends one call of `past_deletion` returns.
const DUE_BATCH: u32 = 1000;

/// The Bitwarden layer's Send store over the SQL store.
#[derive(Clone, Debug)]
pub struct SqlSends {
    store: SqlStore,
}

impl SqlSends {
    pub fn new(store: SqlStore) -> Self {
        SqlSends { store }
    }
}

/// What `meta` holds for a Bitwarden Send. Anything else (a Kemlock Send's sealed bytes) fails to
/// parse, which is how the two are told apart.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Meta {
    name: String,
    notes: Option<String>,
}

fn failed(e: StoreError) -> SendError {
    SendError(e.to_string())
}

/// The domain's Send for a Bitwarden one.
fn to_domain(send: &SendRecord) -> Result<DomainSend, SendError> {
    let bad = |what: &str| SendError(format!("a Send can't be stored: {what}"));
    let owner = send.user.ok_or_else(|| bad("it has no owner account"))?;
    let kind = i16::try_from(send.kind)
        .ok()
        .and_then(SendKind::from_code)
        .ok_or_else(|| bad("its type is unknown"))?;
    let meta = serde_json::to_vec(&Meta {
        name: send.name.clone(),
        notes: send.notes.clone(),
    })
    .map_err(|e| SendError(e.to_string()))?;
    let file = if kind == SendKind::File {
        let data: serde_json::Value =
            serde_json::from_str(&send.data).map_err(|_| bad("a file Send's data isn't JSON"))?;
        let size = data
            .get("size")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| bad("a file Send's data has no size"))?;
        Some(SendFile {
            blob: BlobId::from_uuid(send.id),
            size,
            format: SendFileFormat::Opaque,
            // The Bitwarden layer doesn't tell the store when the bytes arrive; a file whose
            // bytes never came is removed with the Send at its deletion date, as Vaultwarden does.
            ready: true,
        })
    } else {
        None
    };
    let password = match &send.password {
        Some(p) if p.iterations == SEND_PASSWORD_ITERATIONS => Some(DomainPassword {
            salt: p.salt.clone(),
            hash: p.hash.clone(),
        }),
        Some(_) => return Err(bad("its password was hashed with another round count")),
        None => None,
    };
    Ok(DomainSend {
        id: SendId(send.id),
        owner,
        kind,
        meta,
        sealed_key: send.key.clone().into_bytes(),
        payload: send.data.clone().into_bytes(),
        file,
        password,
        max_access: send
            .max_access_count
            .map(u32::try_from)
            .transpose()
            .map_err(|_| bad("its view limit is negative"))?,
        access_count: u32::try_from(send.access_count).unwrap_or(0),
        hide_email: send.hide_email.unwrap_or(false),
        disabled: send.disabled,
        expires_at: send.expires_at,
        deletion_at: send.deleted_at,
        created_at: send.created_at,
        revised_at: send.revised_at,
    })
}

/// The Bitwarden Send for a stored one, or `None` when it isn't a Bitwarden-shaped Send.
fn from_domain(send: DomainSend) -> Option<SendRecord> {
    let meta: Meta = serde_json::from_slice(&send.meta).ok()?;
    let key = String::from_utf8(send.sealed_key).ok()?;
    let data = String::from_utf8(send.payload).ok()?;
    let max_access_count = match send.max_access {
        Some(n) => Some(i32::try_from(n).ok()?),
        None => None,
    };
    Some(SendRecord {
        id: send.id.0,
        user: Some(send.owner),
        organization: None,
        kind: i32::from(send.kind.code()),
        name: meta.name,
        notes: meta.notes,
        key,
        data,
        password: send.password.map(|p| SendPassword {
            hash: p.hash,
            salt: p.salt,
            iterations: SEND_PASSWORD_ITERATIONS,
        }),
        max_access_count,
        access_count: i32::try_from(send.access_count).unwrap_or(i32::MAX),
        created_at: send.created_at,
        revised_at: send.revised_at,
        expires_at: send.expires_at,
        deleted_at: send.deletion_at,
        disabled: send.disabled,
        hide_email: Some(send.hide_email),
    })
}

impl SendStore for SqlSends {
    fn get(&self, id: Uuid) -> BoxFuture<'_, Result<Option<SendRecord>, SendError>> {
        Box::pin(async move {
            Ok(SendRepo::send_by_id(&self.store, SendId(id))
                .await
                .map_err(failed)?
                .and_then(from_domain))
        })
    }

    fn list_by_user(&self, user: UserId) -> BoxFuture<'_, Result<Vec<SendRecord>, SendError>> {
        Box::pin(async move {
            let mut sends: Vec<SendRecord> = SendRepo::sends_of(&self.store, user)
                .await
                .map_err(failed)?
                .into_iter()
                .filter_map(from_domain)
                .collect();
            // The store lists newest first; the layer wants oldest first.
            sends.sort_by_key(|s| (s.created_at, s.id));
            Ok(sends)
        })
    }

    fn put(&self, send: SendRecord) -> BoxFuture<'_, Result<(), SendError>> {
        Box::pin(async move {
            let record = to_domain(&send)?;
            match self.store.overwrite_send(&record).await {
                Err(StoreError::NotFound) => SendRepo::add_send(&self.store, &record)
                    .await
                    .map_err(failed),
                other => other.map_err(failed),
            }
        })
    }

    fn delete(&self, id: Uuid) -> BoxFuture<'_, Result<bool, SendError>> {
        Box::pin(async move {
            let id = SendId(id);
            if SendRepo::send_by_id(&self.store, id)
                .await
                .map_err(failed)?
                .is_none()
            {
                return Ok(false);
            }
            SendRepo::remove_send(&self.store, id)
                .await
                .map_err(failed)?;
            Ok(true)
        })
    }

    fn register_access(
        &self,
        id: Uuid,
        at: OffsetDateTime,
    ) -> BoxFuture<'_, Result<Option<SendRecord>, SendError>> {
        Box::pin(async move {
            let id = SendId(id);
            if !SendRepo::count_send_view(&self.store, id, at)
                .await
                .map_err(failed)?
            {
                return Ok(None);
            }
            Ok(SendRepo::send_by_id(&self.store, id)
                .await
                .map_err(failed)?
                .and_then(from_domain))
        })
    }

    fn past_deletion(
        &self,
        before: OffsetDateTime,
    ) -> BoxFuture<'_, Result<Vec<SendRecord>, SendError>> {
        Box::pin(async move {
            // No file Send counts as abandoned here: only the deletion date decides.
            Ok(SendRepo::sends_to_delete(
                &self.store,
                before,
                OffsetDateTime::UNIX_EPOCH,
                DUE_BATCH,
            )
            .await
            .map_err(failed)?
            .into_iter()
            .filter(|s| s.deletion_at < before)
            .filter_map(from_domain)
            .collect())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kemlock_app::ports::UserRepo;
    use kemlock_domain::{AccountMode, Email, KdfParams, Role, User};
    use time::Duration;
    use time::macros::datetime;

    const MADE: OffsetDateTime = datetime!(2026-11-01 12:00:00 UTC);

    async fn store_with_user() -> (SqlSends, UserId) {
        let store = SqlStore::connect("sqlite::memory:")
            .await
            .expect("an in-memory store connects");
        let id = UserId::random();
        let user = User {
            id,
            email: Email::parse("sender@example.org").expect("an address"),
            name: None,
            mode: AccountMode::KemlockOnly,
            role: Role::User,
            kdf: KdfParams::new_account([3; 16]),
            opaque_record: Some(vec![1; 192]),
            wrapped_root_key: vec![2; 100],
            public_bundle: vec![3; 5000],
            bundle_signature: vec![4; 3400],
            sealed_private_keys: vec![5; 8000],
            key_version: 1,
            security_stamp: Uuid::new_v4(),
            created_at: MADE,
            updated_at: MADE,
        };
        UserRepo::insert(&store, &user).await.expect("a user");
        (SqlSends::new(store), id)
    }

    fn bw_send(user: UserId) -> SendRecord {
        SendRecord {
            id: Uuid::new_v4(),
            user: Some(user),
            organization: None,
            kind: 0,
            name: "2.name|iv|mac".to_owned(),
            notes: Some("2.notes|iv|mac".to_owned()),
            key: "2.key|iv|mac".to_owned(),
            data: r#"{"Text":"2.text|iv|mac","Hidden":false}"#.to_owned(),
            password: None,
            max_access_count: Some(2),
            access_count: 0,
            created_at: MADE,
            revised_at: MADE,
            expires_at: Some(MADE + Duration::days(1)),
            deleted_at: MADE + Duration::days(7),
            disabled: false,
            hide_email: Some(true),
        }
    }

    #[tokio::test]
    async fn a_send_put_is_still_there_in_a_fresh_store_over_the_same_database() {
        let (sends, user) = store_with_user().await;
        let mut send = bw_send(user);
        send.password = Some(SendPassword {
            hash: vec![7; 32],
            salt: vec![8; 64],
            iterations: SEND_PASSWORD_ITERATIONS,
        });
        sends.put(send.clone()).await.expect("stored");

        // What a restart does: a new adapter over the same database.
        let after_restart = SqlSends::new(sends.store.clone());
        assert_eq!(after_restart.get(send.id).await, Ok(Some(send.clone())));
        assert_eq!(after_restart.list_by_user(user).await, Ok(vec![send]));
    }

    #[tokio::test]
    async fn an_edit_replaces_the_key_and_data_and_keeps_the_view_count() {
        let (sends, user) = store_with_user().await;
        let send = bw_send(user);
        sends.put(send.clone()).await.expect("stored");
        let counted = sends
            .register_access(send.id, MADE + Duration::hours(1))
            .await
            .expect("counted")
            .expect("under the limit");
        assert_eq!(counted.access_count, 1);

        // The edit was read before the view: it carries the old count.
        let mut edited = send.clone();
        edited.key = "2.newkey|iv|mac".to_owned();
        edited.data = r#"{"Text":"2.other|iv|mac","Hidden":true}"#.to_owned();
        edited.revised_at = MADE + Duration::hours(2);
        sends.put(edited.clone()).await.expect("edited");

        let stored = sends.get(send.id).await.expect("read").expect("there");
        assert_eq!(stored.key, "2.newkey|iv|mac");
        assert_eq!(stored.data, edited.data);
        assert_eq!(stored.access_count, 1);
    }

    #[tokio::test]
    async fn views_stop_at_the_limit_and_deleting_says_whether_there_was_one() {
        let (sends, user) = store_with_user().await;
        let send = bw_send(user);
        sends.put(send.clone()).await.expect("stored");
        for _ in 0..2 {
            assert!(
                sends
                    .register_access(send.id, MADE)
                    .await
                    .expect("counted")
                    .is_some()
            );
        }
        assert_eq!(sends.register_access(send.id, MADE).await, Ok(None));
        assert_eq!(sends.delete(send.id).await, Ok(true));
        assert_eq!(sends.delete(send.id).await, Ok(false));
        assert_eq!(sends.get(send.id).await, Ok(None));
    }

    #[tokio::test]
    async fn a_file_send_keeps_its_bytes_at_the_blob_of_its_own_id() {
        let (sends, user) = store_with_user().await;
        let mut send = bw_send(user);
        send.kind = 1;
        send.data = r#"{"Id":"f1","Size":1234,"size":1234,"FileName":"2.n|i|m"}"#.to_owned();
        sends.put(send.clone()).await.expect("stored");
        let stored = SendRepo::send_by_id(&sends.store, SendId(send.id))
            .await
            .expect("read")
            .expect("there");
        let file = stored.file.expect("a file");
        assert_eq!(file.blob, BlobId::from_uuid(send.id));
        assert_eq!(file.size, 1234);
        assert_eq!(file.format, SendFileFormat::Opaque);
        assert!(file.ready);
        assert_eq!(sends.get(send.id).await, Ok(Some(send)));
    }

    #[tokio::test]
    async fn the_due_ones_are_those_past_their_deletion_date() {
        let (sends, user) = store_with_user().await;
        let soon = bw_send(user);
        let mut later = bw_send(user);
        later.deleted_at = MADE + Duration::days(20);
        sends.put(soon.clone()).await.expect("stored");
        sends.put(later).await.expect("stored");

        let due = sends
            .past_deletion(MADE + Duration::days(8))
            .await
            .expect("listed");
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].id, soon.id);
        assert!(sends.past_deletion(MADE).await.expect("listed").is_empty());
    }

    #[tokio::test]
    async fn a_kemlock_send_is_invisible_to_the_bitwarden_layer() {
        let (sends, user) = store_with_user().await;
        let kemlock = DomainSend {
            id: SendId::random(),
            owner: user,
            kind: SendKind::Text,
            meta: vec![0xA5; 40],
            sealed_key: vec![0xFF; 90],
            payload: vec![0xC3; 50],
            file: None,
            password: None,
            max_access: None,
            access_count: 0,
            hide_email: false,
            disabled: false,
            expires_at: None,
            deletion_at: MADE + Duration::days(7),
            created_at: MADE,
            revised_at: MADE,
        };
        SendRepo::add_send(&sends.store, &kemlock)
            .await
            .expect("stored");
        assert_eq!(sends.get(kemlock.id.0).await, Ok(None));
        assert_eq!(sends.list_by_user(user).await, Ok(Vec::new()));
    }

    #[tokio::test]
    async fn what_cannot_be_stored_is_refused() {
        let (sends, user) = store_with_user().await;
        let mut ownerless = bw_send(user);
        ownerless.user = None;
        assert!(sends.put(ownerless).await.is_err());
        let mut odd = bw_send(user);
        odd.password = Some(SendPassword {
            hash: vec![1; 32],
            salt: vec![2; 64],
            iterations: 5,
        });
        assert!(sends.put(odd).await.is_err());
        let mut negative = bw_send(user);
        negative.max_access_count = Some(-1);
        assert!(sends.put(negative).await.is_err());
    }
}
