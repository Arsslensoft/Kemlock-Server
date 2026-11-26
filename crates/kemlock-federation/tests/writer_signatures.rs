//! A replica in a vault's set can't delete, roll back or flood the vault's items: every `kem1`
//! change also carries the writing account's signature (docs/crypto.md, "Signed item writes"),
//! a version replaces the head only at a higher revision, and an origin is held to a quota.
//!
//! Two servers in one process, as in `two_servers.rs`, with the changes of a vault pulled over an
//! in-memory channel.

use kemlock_crypto::{bundle::Bundle, item_write, kx1, owner::Owner as CryptoOwner, sig1};
use kemlock_domain::{
    ChangeId, Hlc, ItemDraft, ItemFormat, ItemId, ItemKind, Owner, Revision, UserId, WriteSignature,
};
use kemlock_federation::change::ChangeRecord;
use kemlock_federation::members::MemberAccount;
use kemlock_federation::memory::MemoryStore;
use kemlock_federation::message::{Request, Response};
use kemlock_federation::pairing::{self, PairingCode, PairingInitiator};
use kemlock_federation::ports::{ApplyOutcome, ReplicaStore};
use kemlock_federation::quota::Quota;
use kemlock_federation::replicate::Channel;
use kemlock_federation::testing::{draft, identity};
use kemlock_federation::wire::ChangeKey;
use kemlock_federation::{Replica, Suite, unix_now};
use std::sync::Arc;

type Server = Arc<Replica<MemoryStore>>;

/// Hands requests straight to the other server's `serve`, as one peer of a session would.
struct Direct {
    to: Server,
    from: kemlock_domain::ServerId,
}

impl Channel for Direct {
    async fn call(&mut self, request: &Request) -> Result<Response, kemlock_federation::FedError> {
        Ok(self.to.serve(self.from, request, unix_now()).await.response)
    }
}

fn server(seed: u8, quota: Option<Quota>) -> Server {
    let id = identity(seed, unix_now(), &Suite::IMPLEMENTED);
    let mut replica = Replica::new(MemoryStore::new(id.server), Arc::new(id));
    if let Some(quota) = quota {
        replica = replica.with_quota(quota);
    }
    Arc::new(replica)
}

async fn pair(a: &Server, b: &Server) {
    let now = unix_now();
    let shown = PairingCode::generate();
    let typed = PairingCode::parse(&shown.display()).expect("the code reads back");
    let (initiator, first) = PairingInitiator::start(&typed, &b.identity()).expect("start");
    let (pending, second) = pairing::respond(shown, &a.identity(), &first).expect("respond");
    let (paired_b, third) = initiator.finish(&second, now).expect("message 2");
    let paired_a = pending.finish(&third, now).expect("message 3");
    a.pin_peer(&paired_a.descriptor, now)
        .await
        .expect("A pins B");
    b.pin_peer(&paired_b.descriptor, now)
        .await
        .expect("B pins A");
}

struct Writer {
    id: UserId,
    key: sig1::SigningKey,
}

impl Writer {
    fn new() -> Writer {
        Writer {
            id: UserId::random(),
            key: sig1::SigningKey::from_bytes(&[0x44; 64]),
        }
    }

    /// The account as a server holds a copy of it: its bundle at key version 1.
    fn account(&self) -> MemberAccount {
        let bundle = Bundle {
            account_id: *self.id.as_bytes(),
            key_version: 1,
            kx1_public: kx1::PublicKey::from_bytes(&[1; 1600]).expect("length"),
            sig1_public: self.key.public_key().expect("public key"),
        }
        .to_bytes();
        MemberAccount {
            id: self.id,
            email: "writer@example.org".to_owned(),
            name: None,
            mode: kemlock_domain::AccountMode::KemlockOnly,
            kdf: kemlock_domain::KdfParams::new_account([1; 16]),
            wrapped_root_key: vec![1; 8],
            public_bundle: bundle,
            bundle_signature: vec![2; 8],
            sealed_private_keys: vec![3; 8],
            key_version: 1,
            created_at: 1,
            updated_at: 1,
            devices: Vec::new(),
            past_bundles: Vec::new(),
        }
    }

    /// `draft` signed by this writer, as a device would have signed it.
    fn sign(&self, mut draft: ItemDraft) -> ItemDraft {
        let sealed = match (&draft.ciphertext, &draft.item_key) {
            (Some(c), Some(k)) => Some((c.as_slice(), k.as_slice())),
            _ => None,
        };
        let statement = item_write::Statement {
            owner: CryptoOwner::from_bytes(&draft.owner.to_bytes()).expect("owner"),
            item_id: *draft.id.as_bytes(),
            kind: draft.kind.as_str(),
            revision: draft.revision.0,
            deleted: draft.deleted_at.is_some(),
            envelope: item_write::envelope_hash(draft.key_version, sealed).expect("hash"),
            writer: *self.id.as_bytes(),
            writer_key_version: 1,
        };
        let signature = statement.sign(&self.key).expect("signs");
        draft.signature = Some(WriteSignature {
            writer: self.id,
            key_version: 1,
            signature,
        });
        draft
    }
}

/// A tombstone draft for revision `revision` of `id`.
fn tombstone(id: ItemId, owner: Owner, expected: u64, revision: u64, at_ms: u64) -> ItemDraft {
    ItemDraft {
        ciphertext: None,
        item_key: None,
        deleted_at: Some(kemlock_federation::change::ms_to_time(at_ms).expect("a time")),
        ..draft(id, owner, Some(expected), revision, at_ms)
    }
}

async fn vault_pair(writer: &Writer) -> (Server, Server, Owner) {
    let a = server(1, None);
    let b = server(2, None);
    pair(&a, &b).await;
    let vault = Owner::User(writer.id);
    a.federate(vault, vec![b.server_id()])
        .await
        .expect("federate");
    b.accept_vault(vault, a.server_id(), vec![b.server_id()])
        .await
        .expect("accept");
    a.store().set_member_account(writer.account());
    b.store().set_member_account(writer.account());
    (a, b, vault)
}

#[tokio::test]
async fn a_replica_cannot_delete_what_the_account_wrote_with_a_signature() {
    let writer = Writer::new();
    let (a, b, vault) = vault_pair(&writer).await;
    let item = ItemId::random();
    a.store()
        .put(writer.sign(draft(item, vault, None, 1, 1_000)))
        .expect("the account's signed write");

    let mut a_to_b = Direct {
        to: a.clone(),
        from: b.server_id(),
    };
    let report = b
        .pull(&mut a_to_b, a.server_id(), vault)
        .await
        .expect("B pulls from A");
    assert_eq!(report.counts.applied, 1);
    assert_eq!(report.counts.refused, 0);

    // A turns malicious: it signs, as a server, a tombstone no device wrote. B has seen a signed
    // write of the vault, so it takes no unsigned change of it.
    a.store()
        .put(tombstone(item, vault, 1, 2, 2_000))
        .expect("A's own unsigned tombstone");
    let report = b
        .pull(&mut a_to_b, a.server_id(), vault)
        .await
        .expect("B pulls again");
    assert_eq!(report.counts.applied, 0);
    assert_eq!(report.counts.refused, 1);
    let held = b.store().get(item).expect("the item is still there");
    assert_eq!(held.revision, Revision(1));
    assert!(!held.is_tombstone());

    // A tombstone the account signed does go through.
    a.store()
        .put(writer.sign(tombstone(item, vault, 2, 3, 3_000)))
        .expect("the account's signed delete");
    let report = b
        .pull(&mut a_to_b, a.server_id(), vault)
        .await
        .expect("B pulls the delete");
    assert!(report.counts.applied >= 1);
    assert!(b.store().get(item).expect("the head").is_tombstone());
}

#[tokio::test]
async fn a_signature_made_by_another_key_is_refused() {
    let writer = Writer::new();
    let (a, b, vault) = vault_pair(&writer).await;
    let thief = Writer {
        id: writer.id,
        key: sig1::SigningKey::from_bytes(&[0x45; 64]),
    };
    let item = ItemId::random();
    a.store()
        .put(thief.sign(draft(item, vault, None, 1, 1_000)))
        .expect("a write by a replica that holds no account key");
    let mut a_to_b = Direct {
        to: a.clone(),
        from: b.server_id(),
    };
    let report = b
        .pull(&mut a_to_b, a.server_id(), vault)
        .await
        .expect("B pulls from A");
    assert_eq!(report.counts.applied, 0);
    assert_eq!(report.counts.refused, 1);
    assert!(b.store().get(item).is_none());
}

#[tokio::test]
async fn a_writer_whose_keys_a_replica_does_not_hold_yet_is_left_out_not_lost() {
    let writer = Writer::new();
    let a = server(1, None);
    let b = server(2, None);
    pair(&a, &b).await;
    let vault = Owner::User(writer.id);
    a.federate(vault, vec![b.server_id()])
        .await
        .expect("federate");
    b.accept_vault(vault, a.server_id(), vec![b.server_id()])
        .await
        .expect("accept");
    a.store().set_member_account(writer.account());
    let item = ItemId::random();
    a.store()
        .put(writer.sign(draft(item, vault, None, 1, 1_000)))
        .expect("a signed write");
    let mut a_to_b = Direct {
        to: a.clone(),
        from: b.server_id(),
    };
    // B has not yet received the account's copy: the change waits.
    let report = b
        .pull(&mut a_to_b, a.server_id(), vault)
        .await
        .expect("a pull");
    assert_eq!(report.counts.refused, 1);
    assert!(b.store().get(item).is_none());
    // The copy arrives; the comparison that follows fetches the change.
    b.store().set_member_account(writer.account());
    let reconciled = b
        .reconcile(&mut a_to_b, a.server_id(), vault)
        .await
        .expect("a comparison");
    assert_eq!(reconciled.fetched.applied, 1);
    assert!(b.store().get(item).is_some());
}

#[tokio::test]
async fn an_origin_over_its_quota_is_left_out() {
    let a = server(1, None);
    let b = server(
        2,
        Some(Quota {
            records_per_window: 2,
            bytes_per_window: u64::MAX,
            max_record_bytes: usize::MAX,
        }),
    );
    pair(&a, &b).await;
    let vault = Owner::User(UserId::random());
    a.federate(vault, vec![b.server_id()])
        .await
        .expect("federate");
    b.accept_vault(vault, a.server_id(), vec![b.server_id()])
        .await
        .expect("accept");
    for n in 0..3u64 {
        a.store()
            .put(draft(ItemId::random(), vault, None, 1, 1_000 + n))
            .expect("a put");
    }
    let mut a_to_b = Direct {
        to: a.clone(),
        from: b.server_id(),
    };
    let report = b
        .pull(&mut a_to_b, a.server_id(), vault)
        .await
        .expect("B pulls from A");
    assert_eq!(report.counts.applied, 2);
    assert_eq!(report.counts.refused, 1);
    assert_eq!(b.store().len(), 2);
}

#[tokio::test]
async fn a_record_that_names_the_head_at_a_lower_revision_is_not_applied() {
    let store = MemoryStore::new(kemlock_domain::ServerId::random());
    let owner = Owner::User(UserId::random());
    let item = ItemId::random();
    store
        .put(draft(item, owner, None, 1, 1_000))
        .expect("rev 1");
    store
        .put(draft(item, owner, Some(1), 2, 2_000))
        .expect("rev 2");
    let head = store
        .put(draft(item, owner, Some(2), 3, 3_000))
        .expect("rev 3");

    // A replica re-signs the first ciphertext as a new change with a late clock, naming the head.
    let origin = kemlock_domain::ServerId::random();
    let replay = ChangeRecord {
        change: ChangeId {
            origin,
            seq: 1,
            hlc: Hlc::from_parts(unix_now() * 1000, 0),
        },
        item,
        owner,
        kind: ItemKind::try_from("login".to_owned()).expect("kind"),
        format: ItemFormat::Kem1,
        revision: Revision(2),
        key_version: 1,
        ciphertext: Some(vec![1; 40]),
        item_key: Some(vec![9; 60]),
        deleted: false,
        updated_at_ms: unix_now() * 1000,
        lineage: vec![ChangeKey::of(&head.change)],
        write: None,
    };
    assert_eq!(
        store.apply(&replay, &[7; 8]).await,
        Ok(ApplyOutcome::Refused)
    );
    assert_eq!(store.get(item).expect("the head").revision, Revision(3));

    // The same record at a revision above the head replaces it.
    let forward = ChangeRecord {
        change: ChangeId {
            origin,
            seq: 2,
            hlc: Hlc::from_parts(unix_now() * 1000, 1),
        },
        revision: Revision(4),
        ..replay
    };
    assert_eq!(
        store.apply(&forward, &[7; 8]).await,
        Ok(ApplyOutcome::Applied)
    );
}
