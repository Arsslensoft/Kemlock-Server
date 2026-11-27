//! The Send use cases over in-memory fakes: making, changing, listing and deleting Sends, uploading
//! a file, opening one by its access id (password, view limit, dates, sender email) and the job that
//! deletes the ones whose date has come.

mod fakes;
mod file_fakes;
mod send_fakes;

use fakes::{FakeEnv, FakeStore, World, actor, make_user};
use file_fakes::{VecBody, kma1_bytes};
use futures_util::StreamExt;
use kemlock_app::Actor;
use kemlock_app::ports::Clock;
use kemlock_app::privacy::SendEraser;
use kemlock_app::quota::QuotaRefusal;
use kemlock_app::sends::{
    AccessSend, CreateSend, CreateSendInput, DeleteSend, EraseSends, GetSend, ListSends,
    PurgeSends, SendRules, SendsConfig, SendsError, UpdateSend, UpdateSendInput, UploadSendFile,
    access_id, parse_access_id,
};
use kemlock_domain::sends::{
    NewSend, SendFileFormat, SendId, SendKind, SendLimits, SendOptions, SendRecord,
};
use send_fakes::{FakeSendBlobs, FakeSends, FixedRules};
use time::Duration;

/// The use cases over one set of fakes.
struct Sends {
    world: World,
    sends: FakeSends,
    blobs: FakeSendBlobs,
    rules: FixedRules,
    config: SendsConfig,
}

impl Sends {
    fn new() -> Self {
        Sends {
            world: World::new().with_signups(),
            sends: FakeSends::new(),
            blobs: FakeSendBlobs::new(),
            rules: FixedRules::new(),
            config: SendsConfig::default(),
        }
    }

    fn with_file_limit(mut self, max_file_size: u64) -> Self {
        self.config.limits = SendLimits { max_file_size };
        self
    }

    fn create(&self) -> CreateSend<FakeSends, FixedRules, FakeStore, FakeEnv> {
        CreateSend {
            sends: self.sends.clone(),
            policies: self.rules.clone(),
            events: self.world.store.clone(),
            env: self.world.env.clone(),
            config: self.config,
        }
    }

    fn update(&self) -> UpdateSend<FakeSends, FixedRules, FakeStore, FakeEnv> {
        UpdateSend {
            sends: self.sends.clone(),
            policies: self.rules.clone(),
            events: self.world.store.clone(),
            env: self.world.env.clone(),
        }
    }

    fn list(&self) -> ListSends<FakeSends> {
        ListSends {
            sends: self.sends.clone(),
        }
    }

    fn get(&self) -> GetSend<FakeSends> {
        GetSend {
            sends: self.sends.clone(),
        }
    }

    fn delete(&self) -> DeleteSend<FakeSends, FakeSendBlobs, FakeStore, FakeEnv> {
        DeleteSend {
            sends: self.sends.clone(),
            blobs: self.blobs.clone(),
            events: self.world.store.clone(),
            clock: self.world.env.clone(),
        }
    }

    fn upload(&self) -> UploadSendFile<FakeSends, FakeSendBlobs, FakeStore, FakeEnv> {
        UploadSendFile {
            sends: self.sends.clone(),
            blobs: self.blobs.clone(),
            events: self.world.store.clone(),
            clock: self.world.env.clone(),
            config: self.config,
        }
    }

    fn access(&self) -> AccessSend<FakeSends, FakeStore, FakeSendBlobs, FakeEnv> {
        AccessSend {
            sends: self.sends.clone(),
            users: self.world.store.clone(),
            blobs: self.blobs.clone(),
            env: self.world.env.clone(),
        }
    }

    fn purge(&self) -> PurgeSends<FakeSends, FakeSendBlobs, FakeEnv> {
        PurgeSends {
            sends: self.sends.clone(),
            blobs: self.blobs.clone(),
            clock: self.world.env.clone(),
            config: self.config,
        }
    }

    fn advance(&self, by: Duration) {
        self.world.env.clock.advance(by);
    }

    fn options(&self) -> SendOptions {
        SendOptions {
            max_access: None,
            hide_email: false,
            disabled: false,
            expires_at: None,
            deletion_at: self.world.env.now() + Duration::days(7),
        }
    }

    fn note(&self) -> NewSend {
        NewSend {
            id: SendId::random(),
            kind: SendKind::Text,
            meta: vec![1; 40],
            sealed_key: vec![2; 100],
            payload: vec![3; 60],
            file: None,
            options: self.options(),
        }
    }

    fn file(&self, size: u64, format: SendFileFormat) -> NewSend {
        NewSend {
            kind: SendKind::File,
            file: Some((size, format)),
            ..self.note()
        }
    }

    async fn user(&self, email: &str) -> Actor {
        actor(make_user(&self.world, email).await)
    }

    async fn make(&self, who: &Actor, send: NewSend) -> SendRecord {
        self.create()
            .execute(
                who,
                CreateSendInput {
                    send,
                    password_proof: None,
                },
            )
            .await
            .expect("the Send is made")
    }

    async fn make_with_password(&self, who: &Actor, send: NewSend, proof: &[u8]) -> SendRecord {
        self.create()
            .execute(
                who,
                CreateSendInput {
                    send,
                    password_proof: Some(proof.to_vec()),
                },
            )
            .await
            .expect("the Send is made")
    }

    /// A file Send whose bytes have arrived.
    async fn uploaded_file(&self, who: &Actor, bytes: &[u8], format: SendFileFormat) -> SendRecord {
        let send = self.make(who, self.file(bytes.len() as u64, format)).await;
        let mut body = VecBody::new(bytes, 11);
        self.upload()
            .execute(who, send.id, bytes.len() as u64, &mut body)
            .await
            .expect("the file uploads")
    }
}

fn update_input(options: SendOptions) -> UpdateSendInput {
    UpdateSendInput {
        meta: vec![9; 20],
        payload: None,
        options,
        password_proof: None,
    }
}

async fn read_all(mut read: kemlock_app::files::BlobRead) -> Vec<u8> {
    let mut out = Vec::new();
    while let Some(chunk) = read.body.next().await {
        out.extend_from_slice(&chunk.expect("a chunk"));
    }
    out
}

// ---- making and changing ----

#[tokio::test]
async fn a_note_is_made_stored_and_logged() {
    let s = Sends::new();
    let sam = s.user("sam@example.org").await;
    let send = s.make(&sam, s.note()).await;

    assert_eq!(send.owner, sam.user);
    assert_eq!(send.kind, SendKind::Text);
    assert_eq!(send.access_count, 0);
    assert_eq!(s.sends.get(send.id), Some(send.clone()));
    assert!(
        s.world
            .store
            .events()
            .iter()
            .any(|e| e.action == "send.create" && e.actor == Some(sam.user))
    );
}

#[tokio::test]
async fn a_send_id_is_taken_once() {
    let s = Sends::new();
    let sam = s.user("sam@example.org").await;
    let note = s.note();
    s.make(&sam, note.clone()).await;
    let again = s
        .create()
        .execute(
            &sam,
            CreateSendInput {
                send: note,
                password_proof: None,
            },
        )
        .await;
    assert_eq!(again.err(), Some(SendsError::Duplicate));
}

#[tokio::test]
async fn bad_options_are_refused_and_nothing_is_stored() {
    let s = Sends::new();
    let sam = s.user("sam@example.org").await;
    let mut note = s.note();
    note.options.deletion_at = s.world.env.now() + Duration::days(40);
    let too_far = s
        .create()
        .execute(
            &sam,
            CreateSendInput {
                send: note,
                password_proof: None,
            },
        )
        .await;
    assert!(matches!(too_far.err(), Some(SendsError::Invalid(_))));

    let mut zero = s.note();
    zero.options.max_access = Some(0);
    let refused = s
        .create()
        .execute(
            &sam,
            CreateSendInput {
                send: zero,
                password_proof: None,
            },
        )
        .await;
    assert!(matches!(refused.err(), Some(SendsError::Invalid(_))));
    assert_eq!(s.sends.count(), 0);
}

#[tokio::test]
async fn the_password_is_kept_as_a_salted_hash_of_the_proof() {
    let s = Sends::new();
    let sam = s.user("sam@example.org").await;
    let send = s.make_with_password(&sam, s.note(), b"derived-proof").await;
    let password = send.password.expect("a password");
    assert_eq!(password.salt.len(), 32);
    assert_eq!(password.hash.len(), 32);
    assert!(!password.hash.windows(13).any(|w| w == b"derived-proof"));

    // Another Send with the same proof has another salt and so another hash.
    let other = s.make_with_password(&sam, s.note(), b"derived-proof").await;
    let other = other.password.expect("a password");
    assert_ne!(other.salt, password.salt);
    assert_ne!(other.hash, password.hash);

    let empty = s
        .create()
        .execute(
            &sam,
            CreateSendInput {
                send: s.note(),
                password_proof: Some(Vec::new()),
            },
        )
        .await;
    assert!(matches!(empty.err(), Some(SendsError::Invalid(_))));
}

#[tokio::test]
async fn an_owner_changes_options_and_password_but_not_their_views() {
    let s = Sends::new();
    let sam = s.user("sam@example.org").await;
    let send = s.make(&sam, s.note()).await;
    s.access()
        .execute(&access_id(send.id), None)
        .await
        .expect("a view");

    s.advance(Duration::minutes(5));
    let options = SendOptions {
        max_access: Some(10),
        hide_email: true,
        ..s.options()
    };
    let changed = s
        .update()
        .execute(
            &sam,
            send.id,
            UpdateSendInput {
                password_proof: Some(Some(b"proof".to_vec())),
                payload: Some(vec![7; 30]),
                ..update_input(options)
            },
        )
        .await
        .expect("the owner changes it");
    assert_eq!(changed.max_access, Some(10));
    assert!(changed.hide_email);
    assert_eq!(changed.payload, vec![7; 30]);
    assert_eq!(changed.meta, vec![9; 20]);
    assert!(changed.has_password());
    assert_eq!(changed.access_count, 1);
    assert_eq!(changed.sealed_key, send.sealed_key);
    assert_eq!(s.sends.get(send.id), Some(changed.clone()));
    assert!(changed.revised_at > send.revised_at);

    // Keeping the password, then removing it.
    let kept = s
        .update()
        .execute(&sam, send.id, update_input(s.options()))
        .await
        .expect("kept");
    assert!(kept.has_password());
    let removed = s
        .update()
        .execute(
            &sam,
            send.id,
            UpdateSendInput {
                password_proof: Some(None),
                ..update_input(s.options())
            },
        )
        .await
        .expect("removed");
    assert!(!removed.has_password());
}

#[tokio::test]
async fn another_account_cannot_read_change_or_delete_a_send() {
    let s = Sends::new();
    let sam = s.user("sam@example.org").await;
    let ann = s.user("ann@example.org").await;
    let send = s.make(&sam, s.note()).await;

    assert_eq!(
        s.get().execute(&ann, send.id).await.err(),
        Some(SendsError::NotFound)
    );
    assert_eq!(
        s.update()
            .execute(&ann, send.id, update_input(s.options()))
            .await
            .err(),
        Some(SendsError::NotFound)
    );
    assert_eq!(
        s.delete().execute(&ann, send.id).await.err(),
        Some(SendsError::NotFound)
    );
    assert!(s.sends.get(send.id).is_some());
    assert_eq!(
        s.get()
            .execute(&sam, send.id)
            .await
            .expect("the owner reads"),
        send
    );
}

#[tokio::test]
async fn a_list_holds_the_accounts_own_sends_newest_first() {
    let s = Sends::new();
    let sam = s.user("sam@example.org").await;
    let ann = s.user("ann@example.org").await;
    let first = s.make(&sam, s.note()).await;
    s.advance(Duration::minutes(1));
    let second = s.make(&sam, s.note()).await;
    s.make(&ann, s.note()).await;

    let listed = s.list().execute(&sam).await.expect("the list");
    let ids: Vec<SendId> = listed.iter().map(|x| x.id).collect();
    assert_eq!(ids, vec![second.id, first.id]);
}

// ---- policies ----

#[tokio::test]
async fn always_show_the_senders_email_refuses_a_send_that_hides_it() {
    let s = Sends::new();
    let sam = s.user("sam@example.org").await;
    s.rules.set(SendRules {
        disabled: false,
        force_email: true,
    });

    let mut hiding = s.note();
    hiding.options.hide_email = true;
    let refused = s
        .create()
        .execute(
            &sam,
            CreateSendInput {
                send: hiding,
                password_proof: None,
            },
        )
        .await;
    assert!(matches!(refused.err(), Some(SendsError::Policy(_))));
    assert_eq!(s.sends.count(), 0);

    // Showing it is fine, and so is changing a Send to hide it, which is refused.
    let shown = s.make(&sam, s.note()).await;
    let update = s
        .update()
        .execute(
            &sam,
            shown.id,
            update_input(SendOptions {
                hide_email: true,
                ..s.options()
            }),
        )
        .await;
    assert!(matches!(update.err(), Some(SendsError::Policy(_))));
    assert!(!s.sends.get(shown.id).expect("stored").hide_email);
}

#[tokio::test]
async fn remove_send_stops_making_and_changing_but_not_deleting() {
    let s = Sends::new();
    let sam = s.user("sam@example.org").await;
    let existing = s.make(&sam, s.note()).await;
    s.rules.set(SendRules {
        disabled: true,
        force_email: false,
    });

    let made = s
        .create()
        .execute(
            &sam,
            CreateSendInput {
                send: s.note(),
                password_proof: None,
            },
        )
        .await;
    assert!(matches!(made.err(), Some(SendsError::Policy(_))));
    let changed = s
        .update()
        .execute(&sam, existing.id, update_input(s.options()))
        .await;
    assert!(matches!(changed.err(), Some(SendsError::Policy(_))));

    s.delete()
        .execute(&sam, existing.id)
        .await
        .expect("deleting is still allowed");
    assert_eq!(s.sends.count(), 0);
}

// ---- files ----

#[tokio::test]
async fn a_file_send_is_closed_until_its_bytes_arrive() {
    let s = Sends::new();
    let sam = s.user("sam@example.org").await;
    let send = s.make(&sam, s.file(300, SendFileFormat::Kma1)).await;
    let file = send.file.expect("a file");
    assert!(!file.ready);
    assert_eq!(file.size, 300);

    let opened = s.access().execute(&access_id(send.id), None).await;
    assert_eq!(opened.err(), Some(SendsError::NotFound));

    let bytes = kma1_bytes(300);
    let mut body = VecBody::new(&bytes, 17);
    let uploaded = s
        .upload()
        .execute(&sam, send.id, 300, &mut body)
        .await
        .expect("the bytes land");
    assert!(uploaded.file.expect("a file").ready);
    assert_eq!(s.blobs.get(file.blob), Some(bytes));
    assert!(s.access().execute(&access_id(send.id), None).await.is_ok());
}

#[tokio::test]
async fn an_upload_must_match_the_announced_size() {
    let s = Sends::new();
    let sam = s.user("sam@example.org").await;
    let send = s.make(&sam, s.file(300, SendFileFormat::Kma1)).await;

    let bytes = kma1_bytes(300);
    let wrong_header = s
        .upload()
        .execute(&sam, send.id, 299, &mut VecBody::new(&bytes, 50))
        .await;
    assert_eq!(wrong_header.err(), Some(SendsError::LengthMismatch));

    let short = kma1_bytes(200);
    let short_body = s
        .upload()
        .execute(&sam, send.id, 300, &mut VecBody::new(&short, 50))
        .await;
    assert_eq!(short_body.err(), Some(SendsError::LengthMismatch));

    let long = kma1_bytes(400);
    let long_body = s
        .upload()
        .execute(&sam, send.id, 300, &mut VecBody::new(&long, 50))
        .await;
    assert_eq!(long_body.err(), Some(SendsError::LengthMismatch));

    // Nothing was stored, and the Send still waits for its file.
    assert_eq!(s.blobs.count(), 0);
    assert!(
        !s.sends
            .get(send.id)
            .expect("stored")
            .file
            .expect("file")
            .ready
    );
}

#[tokio::test]
async fn a_broken_upload_can_be_sent_again() {
    let s = Sends::new();
    let sam = s.user("sam@example.org").await;
    let send = s.make(&sam, s.file(300, SendFileFormat::Kma1)).await;
    let bytes = kma1_bytes(300);

    let broken = s
        .upload()
        .execute(
            &sam,
            send.id,
            300,
            &mut VecBody::new(&bytes[..120], 30).then_breaks(),
        )
        .await;
    assert_eq!(broken.err(), Some(SendsError::Interrupted));
    assert_eq!(s.blobs.count(), 0);

    s.upload()
        .execute(&sam, send.id, 300, &mut VecBody::new(&bytes, 30))
        .await
        .expect("the second try lands");
    let again = s
        .upload()
        .execute(&sam, send.id, 300, &mut VecBody::new(&bytes, 30))
        .await;
    assert_eq!(again.err(), Some(SendsError::AlreadyUploaded));
}

#[tokio::test]
async fn a_kma1_send_refuses_other_bytes_and_an_opaque_one_takes_them() {
    let s = Sends::new();
    let sam = s.user("sam@example.org").await;
    let kma1 = s.make(&sam, s.file(100, SendFileFormat::Kma1)).await;
    let other = vec![0x42u8; 100];
    let refused = s
        .upload()
        .execute(&sam, kma1.id, 100, &mut VecBody::new(&other, 25))
        .await;
    assert!(matches!(refused.err(), Some(SendsError::NotKma1(_))));

    let opaque = s.make(&sam, s.file(100, SendFileFormat::Opaque)).await;
    s.upload()
        .execute(&sam, opaque.id, 100, &mut VecBody::new(&other, 25))
        .await
        .expect("opaque bytes are taken as they are");
    let blob = opaque.file.expect("a file").blob;
    assert_eq!(s.blobs.get(blob), Some(other));
}

#[tokio::test]
async fn a_file_over_the_limit_is_refused_when_the_send_is_made() {
    let s = Sends::new().with_file_limit(1000);
    let sam = s.user("sam@example.org").await;
    let refused = s
        .create()
        .execute(
            &sam,
            CreateSendInput {
                send: s.file(1001, SendFileFormat::Kma1),
                password_proof: None,
            },
        )
        .await;
    assert_eq!(refused.err(), Some(SendsError::TooLarge));
    assert!(
        s.create()
            .execute(
                &sam,
                CreateSendInput {
                    send: s.file(1000, SendFileFormat::Kma1),
                    password_proof: None,
                },
            )
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn only_the_owner_uploads_and_only_to_a_file_send() {
    let s = Sends::new();
    let sam = s.user("sam@example.org").await;
    let ann = s.user("ann@example.org").await;
    let file = s.make(&sam, s.file(100, SendFileFormat::Kma1)).await;
    let bytes = kma1_bytes(100);
    let stranger = s
        .upload()
        .execute(&ann, file.id, 100, &mut VecBody::new(&bytes, 25))
        .await;
    assert_eq!(stranger.err(), Some(SendsError::NotFound));

    let note = s.make(&sam, s.note()).await;
    let to_a_note = s
        .upload()
        .execute(&sam, note.id, 100, &mut VecBody::new(&bytes, 25))
        .await;
    assert!(matches!(to_a_note.err(), Some(SendsError::Invalid(_))));
}

#[tokio::test]
async fn deleting_a_file_send_removes_its_bytes() {
    let s = Sends::new();
    let sam = s.user("sam@example.org").await;
    let send = s
        .uploaded_file(&sam, &kma1_bytes(120), SendFileFormat::Kma1)
        .await;
    assert_eq!(s.blobs.count(), 1);

    s.delete().execute(&sam, send.id).await.expect("deleted");
    assert_eq!(s.blobs.count(), 0);
    assert_eq!(s.sends.count(), 0);
    assert!(
        s.world
            .store
            .events()
            .iter()
            .any(|e| e.action == "send.delete")
    );

    // A blob that can't be deleted leaves the row so the delete can be tried again.
    let again = s
        .uploaded_file(&sam, &kma1_bytes(120), SendFileFormat::Kma1)
        .await;
    s.blobs.fail_deletes();
    let failed = s.delete().execute(&sam, again.id).await;
    assert!(matches!(failed.err(), Some(SendsError::Blob(_))));
    assert!(s.sends.get(again.id).is_some());
}

// ---- opening a Send ----

#[tokio::test]
async fn a_note_opens_with_its_ciphertext_and_the_senders_email() {
    let s = Sends::new();
    let sam = s.user("sam@example.org").await;
    let send = s.make(&sam, s.note()).await;

    let opened = s
        .access()
        .execute(&access_id(send.id), None)
        .await
        .expect("it opens");
    assert_eq!(opened.id, send.id);
    assert_eq!(opened.kind, SendKind::Text);
    assert_eq!(opened.payload, send.payload);
    assert_eq!(opened.file_size, None);
    assert_eq!(opened.sender_email.as_deref(), Some("sam@example.org"));
    assert_eq!(opened.deletion_at, send.deletion_at);
    assert_eq!(s.sends.get(send.id).expect("stored").access_count, 1);
}

#[tokio::test]
async fn a_hidden_email_stays_hidden() {
    let s = Sends::new();
    let sam = s.user("sam@example.org").await;
    let mut hiding = s.note();
    hiding.options.hide_email = true;
    let send = s.make(&sam, hiding).await;
    let opened = s
        .access()
        .execute(&access_id(send.id), None)
        .await
        .expect("it opens");
    assert_eq!(opened.sender_email, None);
}

#[tokio::test]
async fn the_view_limit_closes_the_send_after_its_last_view() {
    let s = Sends::new();
    let sam = s.user("sam@example.org").await;
    let mut limited = s.note();
    limited.options.max_access = Some(2);
    let send = s.make(&sam, limited).await;
    let id = access_id(send.id);

    assert!(s.access().execute(&id, None).await.is_ok());
    assert!(s.access().execute(&id, None).await.is_ok());
    assert_eq!(
        s.access().execute(&id, None).await.err(),
        Some(SendsError::NotFound)
    );
    assert_eq!(s.sends.get(send.id).expect("stored").access_count, 2);
    // The owner still sees it, used up.
    assert!(s.get().execute(&sam, send.id).await.is_ok());
}

#[tokio::test]
async fn an_expired_deleted_or_disabled_send_is_not_found() {
    let s = Sends::new();
    let sam = s.user("sam@example.org").await;

    let mut expiring = s.note();
    expiring.options.expires_at = Some(s.world.env.now() + Duration::hours(2));
    let expiring = s.make(&sam, expiring).await;
    let plain = s.make(&sam, s.note()).await;
    let mut off = s.note();
    off.options.disabled = true;
    let off = s.make(&sam, off).await;

    assert!(
        s.access()
            .execute(&access_id(expiring.id), None)
            .await
            .is_ok()
    );
    assert_eq!(
        s.access().execute(&access_id(off.id), None).await.err(),
        Some(SendsError::NotFound)
    );

    s.advance(Duration::hours(3));
    assert_eq!(
        s.access()
            .execute(&access_id(expiring.id), None)
            .await
            .err(),
        Some(SendsError::NotFound)
    );
    assert!(s.access().execute(&access_id(plain.id), None).await.is_ok());

    s.advance(Duration::days(8));
    assert_eq!(
        s.access().execute(&access_id(plain.id), None).await.err(),
        Some(SendsError::NotFound),
        "past its deletion date, before the job removed it"
    );
}

#[tokio::test]
async fn an_unknown_or_malformed_access_id_is_not_found() {
    let s = Sends::new();
    assert_eq!(
        s.access()
            .execute(&access_id(SendId::random()), None)
            .await
            .err(),
        Some(SendsError::NotFound)
    );
    for bad in [
        "",
        "short",
        "not base64!!",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    ] {
        assert_eq!(
            s.access().execute(bad, None).await.err(),
            Some(SendsError::NotFound),
            "{bad:?}"
        );
    }
}

#[tokio::test]
async fn a_password_is_asked_for_and_checked_without_counting_a_view() {
    let s = Sends::new();
    let sam = s.user("sam@example.org").await;
    let send = s.make_with_password(&sam, s.note(), b"proof-1").await;
    let id = access_id(send.id);

    assert_eq!(s.access().needs_password(&id).await, Ok(true));
    assert_eq!(
        s.access().execute(&id, None).await.err(),
        Some(SendsError::PasswordRequired)
    );
    assert_eq!(
        s.access()
            .execute(&id, Some(b"proof-2".as_slice()))
            .await
            .err(),
        Some(SendsError::WrongPassword)
    );
    assert_eq!(
        s.access().execute(&id, Some(b"".as_slice())).await.err(),
        Some(SendsError::WrongPassword)
    );
    assert_eq!(s.sends.get(send.id).expect("stored").access_count, 0);

    let opened = s
        .access()
        .execute(&id, Some(b"proof-1".as_slice()))
        .await
        .expect("the right proof opens it");
    assert_eq!(opened.payload, send.payload);
    assert_eq!(s.sends.get(send.id).expect("stored").access_count, 1);

    let open = s.make(&sam, s.note()).await;
    assert_eq!(
        s.access().needs_password(&access_id(open.id)).await,
        Ok(false)
    );
}

#[tokio::test]
async fn a_closed_send_says_nothing_about_its_password() {
    let s = Sends::new();
    let sam = s.user("sam@example.org").await;
    let mut off = s.note();
    off.options.disabled = true;
    let send = s.make_with_password(&sam, off, b"proof").await;
    let id = access_id(send.id);
    for proof in [None, Some(&b"proof"[..]), Some(&b"wrong"[..])] {
        assert_eq!(
            s.access().execute(&id, proof).await.err(),
            Some(SendsError::NotFound)
        );
    }
    assert_eq!(
        s.access().needs_password(&id).await,
        Err(SendsError::NotFound)
    );
}

#[tokio::test]
async fn a_file_send_describes_freely_and_counts_the_download() {
    let s = Sends::new();
    let sam = s.user("sam@example.org").await;
    let bytes = kma1_bytes(500);
    let mut limited = s.file(500, SendFileFormat::Kma1);
    limited.options.max_access = Some(1);
    let send = s.make(&sam, limited).await;
    let mut body = VecBody::new(&bytes, 64);
    s.upload()
        .execute(&sam, send.id, 500, &mut body)
        .await
        .expect("uploaded");
    let id = access_id(send.id);

    for _ in 0..3 {
        let described = s.access().execute(&id, None).await.expect("described");
        assert_eq!(described.kind, SendKind::File);
        assert_eq!(described.file_size, Some(500));
        assert_eq!(described.payload, send.payload);
    }
    assert_eq!(s.sends.get(send.id).expect("stored").access_count, 0);

    let download = s.access().download(&id, None).await.expect("downloads");
    assert_eq!(download.id, send.id);
    assert_eq!(download.read.size, 500);
    assert_eq!(read_all(download.read).await, bytes);
    assert_eq!(s.sends.get(send.id).expect("stored").access_count, 1);

    // The one view is used: neither the description nor a second download is open.
    assert_eq!(
        s.access().execute(&id, None).await.err(),
        Some(SendsError::NotFound)
    );
    assert_eq!(
        s.access().download(&id, None).await.err(),
        Some(SendsError::NotFound)
    );
}

#[tokio::test]
async fn a_file_download_needs_the_password_and_a_note_has_no_download() {
    let s = Sends::new();
    let sam = s.user("sam@example.org").await;
    let bytes = kma1_bytes(120);
    let send = s
        .make_with_password(&sam, s.file(120, SendFileFormat::Kma1), b"proof")
        .await;
    s.upload()
        .execute(&sam, send.id, 120, &mut VecBody::new(&bytes, 40))
        .await
        .expect("uploaded");
    let id = access_id(send.id);
    assert_eq!(
        s.access().download(&id, None).await.err(),
        Some(SendsError::PasswordRequired)
    );
    assert_eq!(
        s.access()
            .download(&id, Some(b"nope".as_slice()))
            .await
            .err(),
        Some(SendsError::WrongPassword)
    );
    assert_eq!(s.sends.get(send.id).expect("stored").access_count, 0);
    assert!(
        s.access()
            .download(&id, Some(b"proof".as_slice()))
            .await
            .is_ok()
    );

    let note = s.make(&sam, s.note()).await;
    assert_eq!(
        s.access().download(&access_id(note.id), None).await.err(),
        Some(SendsError::NotFound)
    );
}

#[test]
fn an_access_id_is_the_ids_bytes_in_base64url() {
    let id = SendId::random();
    let text = access_id(id);
    assert_eq!(text.len(), 22);
    assert!(
        text.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    );
    assert_eq!(parse_access_id(&text), Some(id));
    assert_eq!(parse_access_id(&text[..21]), None);
    assert_eq!(parse_access_id(&format!("{text}A")), None);
}

// ---- the job ----

#[tokio::test]
async fn the_job_removes_sends_past_their_date_and_their_files() {
    let s = Sends::new();
    let sam = s.user("sam@example.org").await;
    let soon = {
        let mut n = s.note();
        n.options.deletion_at = s.world.env.now() + Duration::days(1);
        s.make(&sam, n).await
    };
    let file_soon = {
        let mut n = s.file(120, SendFileFormat::Kma1);
        n.options.deletion_at = s.world.env.now() + Duration::days(1);
        let send = s.make(&sam, n).await;
        let bytes = kma1_bytes(120);
        s.upload()
            .execute(&sam, send.id, 120, &mut VecBody::new(&bytes, 40))
            .await
            .expect("uploaded");
        send
    };
    let later = s.make(&sam, s.note()).await;
    assert_eq!(s.blobs.count(), 1);

    assert_eq!(s.purge().execute().await, Ok(0), "nothing is due yet");
    s.advance(Duration::days(2));
    assert_eq!(s.purge().execute().await, Ok(2));
    assert!(s.sends.get(soon.id).is_none());
    assert!(s.sends.get(file_soon.id).is_none());
    assert!(s.sends.get(later.id).is_some());
    assert_eq!(s.blobs.count(), 0);
}

#[tokio::test]
async fn the_job_removes_a_file_send_whose_bytes_never_came() {
    let s = Sends::new();
    let sam = s.user("sam@example.org").await;
    let abandoned = s.make(&sam, s.file(120, SendFileFormat::Kma1)).await;
    let waiting = s.make(&sam, s.note()).await;

    s.advance(Duration::hours(23));
    assert_eq!(s.purge().execute().await, Ok(0));
    s.advance(Duration::hours(2));
    assert_eq!(s.purge().execute().await, Ok(1));
    assert!(s.sends.get(abandoned.id).is_none());
    assert!(s.sends.get(waiting.id).is_some());
}

#[tokio::test]
async fn a_blob_that_cannot_be_deleted_stops_the_job_and_keeps_the_row() {
    let s = Sends::new();
    let sam = s.user("sam@example.org").await;
    let send = {
        let mut n = s.file(120, SendFileFormat::Kma1);
        n.options.deletion_at = s.world.env.now() + Duration::days(1);
        let send = s.make(&sam, n).await;
        s.upload()
            .execute(&sam, send.id, 120, &mut VecBody::new(&kma1_bytes(120), 40))
            .await
            .expect("uploaded");
        send
    };
    s.advance(Duration::days(2));
    s.blobs.fail_deletes();
    assert!(matches!(
        s.purge().execute().await,
        Err(SendsError::Blob(_))
    ));
    assert!(s.sends.get(send.id).is_some(), "left for the next run");
}

// ---- erasing an account's Sends ----

#[tokio::test]
async fn erasing_an_account_deletes_its_sends_and_their_files_and_no_one_elses() {
    let s = Sends::new();
    let sam = s.user("sam@example.org").await;
    let kim = s.user("kim@example.org").await;
    let note = s.make(&sam, s.note()).await;
    let file = s
        .uploaded_file(&sam, &kma1_bytes(120), SendFileFormat::Kma1)
        .await;
    let kims = s.make(&kim, s.note()).await;
    assert_eq!(s.blobs.count(), 1);

    let erased = EraseSends {
        sends: s.sends.clone(),
        blobs: s.blobs.clone(),
    }
    .erase_sends(sam.user)
    .await;

    assert_eq!(erased, Ok(2));
    assert!(s.sends.get(note.id).is_none());
    assert!(s.sends.get(file.id).is_none());
    assert_eq!(s.blobs.count(), 0, "the file went with its Send");
    assert!(
        s.sends.get(kims.id).is_some(),
        "another account's Send stays"
    );
}

#[tokio::test]
async fn a_file_that_cannot_be_deleted_stops_the_erasure_and_keeps_its_row() {
    let s = Sends::new();
    let sam = s.user("sam@example.org").await;
    let file = s
        .uploaded_file(&sam, &kma1_bytes(120), SendFileFormat::Kma1)
        .await;
    s.blobs.fail_deletes();

    let erased = EraseSends {
        sends: s.sends.clone(),
        blobs: s.blobs.clone(),
    }
    .erase_sends(sam.user)
    .await;

    assert!(erased.is_err());
    assert!(s.sends.get(file.id).is_some(), "left for the next attempt");
}

#[tokio::test]
async fn an_account_with_no_sends_erases_none() {
    let s = Sends::new();
    let sam = s.user("sam@example.org").await;
    let erased = EraseSends {
        sends: s.sends.clone(),
        blobs: s.blobs.clone(),
    }
    .erase_sends(sam.user)
    .await;
    assert_eq!(erased, Ok(0));
}

#[tokio::test]
async fn the_file_send_quota_counts_the_accounts_files_and_zero_is_off() {
    let mut s = Sends::new();
    let sam = s.user("sam@example.org").await;
    let make = |s: &Sends, size: u64| {
        let create = s.create();
        let send = s.file(size, SendFileFormat::Opaque);
        let who = sam;
        async move {
            create
                .execute(
                    &who,
                    CreateSendInput {
                        send,
                        password_proof: None,
                    },
                )
                .await
                .map(|_| ())
        }
    };
    // A note takes no space, and no quota means any file.
    assert_eq!(make(&s, 4_000).await, Ok(()));

    s.config.quota = Some(10_000);
    assert_eq!(make(&s, 6_000).await, Ok(()));
    assert_eq!(
        make(&s, 1).await,
        Err(SendsError::Quota(QuotaRefusal::Reached))
    );
    s.config.quota = Some(12_000);
    assert_eq!(
        make(&s, 2_001).await,
        Err(SendsError::Quota(QuotaRefusal::Exceeded))
    );
    assert_eq!(make(&s, 2_000).await, Ok(()));

    s.config.quota = Some(0);
    assert_eq!(
        make(&s, 1).await,
        Err(SendsError::Quota(QuotaRefusal::Disabled))
    );
}

#[tokio::test]
async fn a_quota_lowered_after_the_send_was_made_is_held_to_when_the_bytes_arrive() {
    let mut s = Sends::new();
    let sam = s.user("sam@example.org").await;
    s.config.quota = Some(10_000);
    let send = s.make(&sam, s.file(5_000, SendFileFormat::Opaque)).await;

    s.config.quota = Some(4_000);
    let bytes = vec![7u8; 5_000];
    let refused = s
        .upload()
        .execute(&sam, send.id, 5_000, &mut VecBody::new(&bytes, 100))
        .await;
    assert_eq!(refused, Err(SendsError::Quota(QuotaRefusal::Exceeded)));

    s.config.quota = Some(5_000);
    let opened = s
        .upload()
        .execute(&sam, send.id, 5_000, &mut VecBody::new(&bytes, 100))
        .await
        .expect("the file fits what is left");
    assert!(opened.file.is_some_and(|f| f.ready));
}

#[tokio::test]
async fn the_sends_of_a_disabled_or_an_erasing_account_are_closed_until_it_is_open_again() {
    let s = Sends::new();
    let sam = s.user("sam@example.org").await;
    let send = s.make(&sam, s.note()).await;
    let id = access_id(send.id);
    assert!(s.access().execute(&id, None).await.is_ok());
    assert_eq!(s.access().needs_password(&id).await, Ok(false));

    // An admin disables the account: its Sends answer as if they weren't there.
    s.world.store.set_account_disabled(sam.user, true);
    assert_eq!(
        s.access().execute(&id, None).await.err(),
        Some(SendsError::NotFound)
    );
    assert_eq!(
        s.access().needs_password(&id).await,
        Err(SendsError::NotFound)
    );
    s.world.store.set_account_disabled(sam.user, false);
    assert!(s.access().execute(&id, None).await.is_ok());

    // The same while its erasure waits out the grace period.
    s.world.store.set_erasure_pending(sam.user, true);
    assert_eq!(
        s.access().execute(&id, None).await.err(),
        Some(SendsError::NotFound)
    );
    s.world.store.set_erasure_pending(sam.user, false);
    assert!(s.access().execute(&id, None).await.is_ok());
}
