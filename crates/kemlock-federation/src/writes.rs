//! Checking the writing account's signature on a change record (docs/crypto.md, "Signed item
//! writes"; docs/federation.md, "Writer signatures").
//!
//! The origin server's signature says which server accepted a write. This says which account made
//! it, which a replica in the vault's set can neither make nor change: so it can't delete, roll
//! back or rewrite items the account did not.

use crate::change::ChangeRecord;
use crate::error::Result;
use crate::extra::MemberStore;
use crate::ports::ReplicaStore;
use kemlock_crypto::{item_write, owner::Owner as CryptoOwner};
use kemlock_domain::{ItemFormat, Owner};

/// What a server says in its descriptor when it understands a record with a writer signature
/// (field 15 of a change record, `docs/federation.md`, "Writer signatures") and ranks the head of an
/// item by revision first ("Rollback"). A server that doesn't refuses the records of a server that
/// signs: every server of a vault must be upgraded before its writes are signed.
pub const SIGNED_WRITES_CAPABILITY: &str = "x-kemlock-signed-writes1";

/// What a server says when it reads the past bundles of a member account record (payload key 14,
/// `docs/federation.md`, "Member accounts"). A server that doesn't refuses the whole record.
pub const PAST_BUNDLES_CAPABILITY: &str = "x-kemlock-past-bundles1";

/// How far past the moment an account replaced its keys a change made by a server with a slow clock
/// may still be dated, and be taken as signed before it.
const RETIRED_KEY_SLACK_SECS: u64 = 300;

/// What to do with a record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Accept,
    /// Leave it out, for this reason: it will not do later either.
    Refuse(&'static str),
    /// Leave it out for now, for this reason: what it needs (the writer's keys, the list of the
    /// space's members) may arrive, and a later comparison fetches it again.
    Defer(&'static str),
}

/// The statement a record's writer signed, rebuilt from the record. `None` when the record carries
/// no signature, or can't have a statement (a revision of 0, say).
pub fn statement_of(record: &ChangeRecord) -> Option<item_write::Statement<'_>> {
    let write = record.write.as_ref()?;
    let sealed = match (&record.ciphertext, &record.item_key) {
        (Some(ciphertext), Some(item_key)) => Some((ciphertext.as_slice(), item_key.as_slice())),
        _ => None,
    };
    Some(item_write::Statement {
        owner: CryptoOwner::from_bytes(&record.owner.to_bytes()).ok()?,
        item_id: *record.item.as_bytes(),
        kind: record.kind.as_str(),
        revision: record.revision.0,
        deleted: record.deleted,
        envelope: item_write::envelope_hash(record.key_version, sealed).ok()?,
        writer: *write.writer.as_bytes(),
        writer_key_version: write.key_version,
        collection: record.collection.map(|c| *c.0.as_bytes()),
    })
}

/// Judges a `kem1` record against the writer's signature and the owner's signed-only flag. A `bw`
/// record is accepted: it has no `kem1` envelope to sign.
///
/// - With a signature: the writer must be allowed for the owner (the vault's own account, or a
///   member of the space, from this server's replicated member list); this server must hold the
///   writer's bundle at the key version the signature names; and the signature must verify over
///   the statement rebuilt from the record.
/// - Without one: refused when the owner is signed-only here.
pub async fn judge<S: ReplicaStore + MemberStore>(
    store: &S,
    record: &ChangeRecord,
) -> Result<Verdict> {
    if record.format != ItemFormat::Kem1 {
        return Ok(Verdict::Accept);
    }
    let Some(write) = &record.write else {
        return Ok(if store.owner_signed_only(record.owner).await? {
            Verdict::Refuse("an unsigned change for an owner that accepts signed writes only")
        } else {
            Verdict::Accept
        });
    };
    // A member who has since left still wrote what they wrote before: the signature says who made
    // it, and the home checked their right to at the time.
    let allowed = match record.owner {
        Owner::User(user) => user == write.writer,
        Owner::Space(_) => store
            .writer_ids(record.owner)
            .await?
            .contains(&write.writer),
    };
    if !allowed {
        // The member list of a space may not have arrived yet; a personal vault is never written
        // by another account.
        let why = "a change written by an account that may not write here";
        return Ok(match record.owner {
            Owner::User(_) => Verdict::Refuse(why),
            Owner::Space(_) => Verdict::Defer(why),
        });
    }
    // A write into a space names its collection, which the signature covers, and the writer must
    // be able to edit it. The home checked that at write time; this stops a member from writing
    // into a collection they can't edit through a replica that doesn't ask. A collection or
    // member this server doesn't know yet is left out for now.
    if let Owner::Space(_) = record.owner {
        let Some(collection) = record.collection else {
            return Ok(Verdict::Refuse(
                "a signed change of a space that names no collection",
            ));
        };
        match store
            .writer_may_edit(record.owner, write.writer, collection)
            .await?
        {
            Some(true) => {}
            Some(false) => {
                return Ok(Verdict::Refuse(
                    "a change into a collection its writer may not edit",
                ));
            }
            None => {
                return Ok(Verdict::Defer(
                    "a change into a collection this server does not know yet",
                ));
            }
        }
    }
    // The bundle of the key version the signature names, which may be one the account has
    // replaced since (docs/crypto.md, "Signed item writes", "Key versions").
    let Some(bundle) = store.writer_bundle(write.writer, write.key_version).await? else {
        return Ok(Verdict::Defer(
            "a change by a writer whose keys at that version we do not hold",
        ));
    };
    // Keys the account has replaced signed nothing after it did (a stolen old key must not write
    // new changes): only a change made before then, by the clock of the server that accepted it.
    if let Some(retired) = store
        .writer_bundle_retired_at(write.writer, write.key_version)
        .await?
    {
        let made = record.change.hlc.millis() / 1000;
        if made >= u64::try_from(retired).unwrap_or(0).saturating_add(RETIRED_KEY_SLACK_SECS) {
            return Ok(Verdict::Refuse(
                "a change signed with keys the account had replaced by then",
            ));
        }
    }
    let Some(statement) = statement_of(record) else {
        return Ok(Verdict::Refuse(
            "a change whose writer statement can't be made",
        ));
    };
    Ok(
        match item_write::verify_with_bundle(&statement, &bundle, &write.signature) {
            Ok(()) => Verdict::Accept,
            Err(_) => Verdict::Refuse("a change whose writer signature does not verify"),
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::members::MemberAccount;
    use crate::memory::MemoryStore;
    use kemlock_crypto::{bundle::Bundle, kx1, sig1};
    use kemlock_domain::spaces::CollectionId;
    use kemlock_domain::{
        AccountMode, ChangeId, Hlc, ItemId, ItemKind, KdfParams, Revision, ServerId, SpaceId,
        UserId, WriteSignature,
    };

    fn account(id: UserId, bundle: Vec<u8>, key_version: u32) -> MemberAccount {
        MemberAccount {
            id,
            email: "writer@example.org".to_owned(),
            name: None,
            mode: AccountMode::KemlockOnly,
            kdf: KdfParams::new_account([1; 16]),
            wrapped_root_key: vec![1; 8],
            public_bundle: bundle,
            bundle_signature: vec![2; 8],
            sealed_private_keys: vec![3; 8],
            key_version,
            created_at: 1,
            updated_at: 1,
            devices: Vec::new(),
            past_bundles: Vec::new(),
        }
    }

    /// A live `kem1` record of `owner`, signed by `writer` with `key`.
    fn signed_record(owner: Owner, writer: UserId, key: &sig1::SigningKey) -> ChangeRecord {
        let mut record = ChangeRecord {
            change: ChangeId {
                origin: ServerId::random(),
                seq: 1,
                hlc: Hlc::from_parts(1_700_000_000_000, 0),
            },
            item: ItemId::random(),
            owner,
            kind: ItemKind::try_from("login".to_owned()).expect("kind"),
            format: ItemFormat::Kem1,
            revision: Revision(2),
            key_version: 1,
            ciphertext: Some(vec![7; 40]),
            item_key: Some(vec![8; 60]),
            deleted: false,
            updated_at_ms: 1_700_000_000_123,
            lineage: Vec::new(),
            write: None,
            collection: None,
        };
        // An item of a space is written into a collection, which the signature covers.
        if matches!(owner, Owner::Space(_)) {
            record.collection = Some(CollectionId(uuid::Uuid::from_bytes([0xC0; 16])));
        }
        sign(&mut record, writer, key);
        record
    }

    fn sign(record: &mut ChangeRecord, writer: UserId, key: &sig1::SigningKey) {
        record.write = Some(WriteSignature {
            writer,
            key_version: 1,
            signature: vec![0; WriteSignature::SIGNATURE_LEN],
        });
        let signature = {
            let statement = statement_of(record).expect("a statement");
            statement.sign(key).expect("signs")
        };
        if let Some(write) = &mut record.write {
            write.signature = signature;
        }
    }

    /// A store that holds `writer`'s bundle (made from `key`).
    fn store_for(writer: UserId, key: &sig1::SigningKey) -> MemoryStore {
        let bundle = Bundle {
            account_id: *writer.as_bytes(),
            key_version: 1,
            kx1_public: kx1::PublicKey::from_bytes(&[1; 1600]).expect("length"),
            sig1_public: key.public_key().expect("public key"),
        }
        .to_bytes();
        let store = MemoryStore::new(ServerId::random());
        store.set_member_account(account(writer, bundle, 1));
        store
    }

    fn verdict_is_refusal(verdict: Result<Verdict>) -> bool {
        matches!(verdict, Ok(Verdict::Refuse(_) | Verdict::Defer(_)))
    }

    #[tokio::test]
    async fn a_record_signed_by_its_writer_is_accepted() {
        let writer = UserId::random();
        let key = sig1::SigningKey::from_bytes(&[5; 64]);
        let store = store_for(writer, &key);
        let record = signed_record(Owner::User(writer), writer, &key);
        assert_eq!(judge(&store, &record).await, Ok(Verdict::Accept));
    }

    #[tokio::test]
    async fn a_changed_record_a_forgery_and_a_stranger_are_refused() {
        let writer = UserId::random();
        let key = sig1::SigningKey::from_bytes(&[5; 64]);
        let store = store_for(writer, &key);
        let record = signed_record(Owner::User(writer), writer, &key);

        // What the writer signed is bound to: the ciphertext, the revision.
        let mut changed = record.clone();
        changed.ciphertext = Some(vec![1; 40]);
        assert!(verdict_is_refusal(judge(&store, &changed).await));
        let mut changed = record.clone();
        changed.revision = Revision(record.revision.0 + 1);
        assert!(verdict_is_refusal(judge(&store, &changed).await));

        // A signature made by another key.
        let other = sig1::SigningKey::from_bytes(&[9; 64]);
        let forged = signed_record(Owner::User(writer), writer, &other);
        assert!(verdict_is_refusal(judge(&store, &forged).await));

        // A signed record of another account's vault.
        let stranger = UserId::random();
        let not_theirs = signed_record(Owner::User(writer), stranger, &key);
        assert!(verdict_is_refusal(judge(&store, &not_theirs).await));

        // A writer this server holds no keys for.
        let empty = MemoryStore::new(ServerId::random());
        assert!(verdict_is_refusal(judge(&empty, &record).await));
    }

    #[tokio::test]
    async fn another_key_version_of_the_writer_is_refused() {
        let writer = UserId::random();
        let key = sig1::SigningKey::from_bytes(&[5; 64]);
        let store = store_for(writer, &key);
        let mut record = signed_record(Owner::User(writer), writer, &key);
        if let Some(write) = &mut record.write {
            write.key_version = 2;
        }
        assert!(verdict_is_refusal(judge(&store, &record).await));
    }

    #[tokio::test]
    async fn an_unsigned_record_is_refused_once_the_owner_is_signed_only_and_not_by_a_signed_one() {
        let writer = UserId::random();
        let key = sig1::SigningKey::from_bytes(&[5; 64]);
        let store = store_for(writer, &key);
        let signed = signed_record(Owner::User(writer), writer, &key);
        let mut unsigned = signed_record(Owner::User(writer), writer, &key);
        unsigned.write = None;
        assert_eq!(judge(&store, &unsigned).await, Ok(Verdict::Accept));

        ReplicaStore::apply(&store, &signed, &[1; 8])
            .await
            .expect("applies");
        // A signed record doesn't set the flag; the owner's request does.
        assert_eq!(judge(&store, &unsigned).await, Ok(Verdict::Accept));
        store.set_signed_only(Owner::User(writer), true);
        assert!(verdict_is_refusal(judge(&store, &unsigned).await));
        store.set_signed_only(Owner::User(writer), false);
        assert_eq!(judge(&store, &unsigned).await, Ok(Verdict::Accept));
    }

    #[tokio::test]
    async fn a_space_record_needs_a_member() {
        let writer = UserId::random();
        let key = sig1::SigningKey::from_bytes(&[5; 64]);
        let store = store_for(writer, &key);
        let space = Owner::Space(SpaceId::random());
        let record = signed_record(space, writer, &key);
        assert!(verdict_is_refusal(judge(&store, &record).await));
        store.set_members(space, vec![writer]);
        assert_eq!(judge(&store, &record).await, Ok(Verdict::Accept));
    }

    #[tokio::test]
    async fn a_member_who_left_still_wrote_what_they_signed_and_a_stranger_waits_for_the_list() {
        let writer = UserId::random();
        let key = sig1::SigningKey::from_bytes(&[5; 64]);
        let store = store_for(writer, &key);
        let space = Owner::Space(SpaceId::random());
        let record = signed_record(space, writer, &key);
        // Not a member now: the list may not have arrived, so the record is left out for now.
        assert!(matches!(
            judge(&store, &record).await,
            Ok(Verdict::Defer(_))
        ));
        // Taken out of the space since: what they signed before is still theirs.
        store.set_former_members(space, vec![writer]);
        assert_eq!(judge(&store, &record).await, Ok(Verdict::Accept));
        // Their signature still has to verify, and then it is refused for good.
        let mut forged = signed_record(space, writer, &key);
        forged.revision = Revision(9);
        assert!(matches!(
            judge(&store, &forged).await,
            Ok(Verdict::Refuse(_))
        ));
    }

    #[tokio::test]
    async fn a_signed_write_into_a_space_is_for_the_collection_it_names_and_one_its_writer_may_edit() {
        let writer = UserId::random();
        let key = sig1::SigningKey::from_bytes(&[5; 64]);
        let store = store_for(writer, &key);
        let space = Owner::Space(SpaceId::random());
        store.set_members(space, vec![writer]);
        let record = signed_record(space, writer, &key);
        let collection = record.collection.expect("a collection");
        assert_eq!(judge(&store, &record).await, Ok(Verdict::Accept));

        // The collection is what was signed: a replica that moves the item breaks the signature.
        let moved = record
            .clone()
            .in_collection(Some(CollectionId(uuid::Uuid::from_bytes([0xC1; 16]))));
        assert!(matches!(
            judge(&store, &moved).await,
            Ok(Verdict::Refuse(_))
        ));
        // A signed write of a space that names no collection is no write of the space.
        assert!(matches!(
            judge(&store, &record.clone().in_collection(None)).await,
            Ok(Verdict::Refuse(_))
        ));
        // A member who may not edit the collection did not write into it, whatever they signed.
        store.set_edit(space, writer, collection, Some(false));
        assert!(matches!(
            judge(&store, &record).await,
            Ok(Verdict::Refuse(_))
        ));
        // A collection this server hasn't heard of yet is a reason to wait.
        store.set_edit(space, writer, collection, None);
        assert!(matches!(
            judge(&store, &record).await,
            Ok(Verdict::Defer(_))
        ));
    }

    #[tokio::test]
    async fn a_bitwarden_record_is_not_judged() {
        let writer = UserId::random();
        let key = sig1::SigningKey::from_bytes(&[5; 64]);
        let mut record = signed_record(Owner::User(writer), writer, &key);
        record.write = None;
        record.format = ItemFormat::Bw;
        let store = MemoryStore::new(ServerId::random());
        assert_eq!(judge(&store, &record).await, Ok(Verdict::Accept));
    }

    #[tokio::test]
    async fn a_write_signed_before_a_key_replacement_is_checked_against_the_past_bundle() {
        use crate::members::PastBundle;
        let writer = UserId::random();
        let old_key = sig1::SigningKey::from_bytes(&[5; 64]);
        let new_key = sig1::SigningKey::from_bytes(&[6; 64]);
        let bundle_of = |version: u32, key: &sig1::SigningKey| {
            Bundle {
                account_id: *writer.as_bytes(),
                key_version: version,
                kx1_public: kx1::PublicKey::from_bytes(&[1; 1600]).expect("length"),
                sig1_public: key.public_key().expect("public key"),
            }
            .to_bytes()
        };
        // The account is at key version 2 now and kept its first bundle.
        let store = MemoryStore::new(ServerId::random());
        let mut copy = account(writer, bundle_of(2, &new_key), 2);
        copy.past_bundles = vec![PastBundle {
            key_version: 1,
            public_bundle: bundle_of(1, &old_key),
            bundle_signature: vec![0; 8],
            // The account replaced them a long time after the records below were made.
            superseded_at: 1_800_000_000,
        }];
        store.set_member_account(copy);

        // A write signed under version 1 (by the old key) verifies against that bundle.
        let before = signed_record(Owner::User(writer), writer, &old_key);
        assert_eq!(judge(&store, &before).await, Ok(Verdict::Accept));
        // The old key can't sign as version 2, and the new key can't sign as version 1.
        let mut as_new = signed_record(Owner::User(writer), writer, &old_key);
        if let Some(write) = &mut as_new.write {
            write.key_version = 2;
        }
        assert!(verdict_is_refusal(judge(&store, &as_new).await));
        let by_new_as_old = signed_record(Owner::User(writer), writer, &new_key);
        assert!(verdict_is_refusal(judge(&store, &by_new_as_old).await));
        // A version the replica holds no bundle for is refused.
        let mut third = signed_record(Owner::User(writer), writer, &old_key);
        if let Some(write) = &mut third.write {
            write.key_version = 3;
        }
        assert!(verdict_is_refusal(judge(&store, &third).await));
    }

    #[tokio::test]
    async fn the_keys_an_account_replaced_sign_nothing_made_after_it_did() {
        use crate::members::PastBundle;
        let writer = UserId::random();
        let old_key = sig1::SigningKey::from_bytes(&[5; 64]);
        let new_key = sig1::SigningKey::from_bytes(&[6; 64]);
        let bundle_of = |version: u32, key: &sig1::SigningKey| {
            Bundle {
                account_id: *writer.as_bytes(),
                key_version: version,
                kx1_public: kx1::PublicKey::from_bytes(&[1; 1600]).expect("length"),
                sig1_public: key.public_key().expect("public key"),
            }
            .to_bytes()
        };
        // The records are made at 1_700_000_000 s.
        let held = |superseded_at: i64| {
            let store = MemoryStore::new(ServerId::random());
            let mut copy = account(writer, bundle_of(2, &new_key), 2);
            copy.past_bundles = vec![PastBundle {
                key_version: 1,
                public_bundle: bundle_of(1, &old_key),
                bundle_signature: vec![0; 8],
                superseded_at,
            }];
            store.set_member_account(copy);
            store
        };
        let record = signed_record(Owner::User(writer), writer, &old_key);
        assert_eq!(
            judge(&held(1_700_000_001), &record).await,
            Ok(Verdict::Accept)
        );
        // A little past the moment, for a clock that runs slow, is still before it.
        assert_eq!(
            judge(&held(1_699_999_900), &record).await,
            Ok(Verdict::Accept)
        );
        // Made after the account replaced the keys: the old key is no longer the account.
        assert!(verdict_is_refusal(
            judge(&held(1_699_000_000), &record).await
        ));
    }
}
