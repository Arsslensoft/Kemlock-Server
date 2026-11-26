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

/// What to do with a record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Accept,
    /// Leave it out, for this reason.
    Refuse(&'static str),
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
    let allowed = match record.owner {
        Owner::User(user) => user == write.writer,
        Owner::Space(_) => store.member_ids(record.owner).await?.contains(&write.writer),
    };
    if !allowed {
        return Ok(Verdict::Refuse(
            "a change written by an account that may not write here",
        ));
    }
    let Some((version, bundle)) = store.writer_bundle(write.writer).await? else {
        return Ok(Verdict::Refuse(
            "a change by a writer whose keys we do not hold",
        ));
    };
    if version != write.key_version {
        return Ok(Verdict::Refuse(
            "a change signed under another key version of its writer",
        ));
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
        };
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
        matches!(verdict, Ok(Verdict::Refuse(_)))
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
    async fn an_unsigned_record_is_refused_once_a_signed_one_was_applied() {
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
        assert!(verdict_is_refusal(judge(&store, &unsigned).await));
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
    async fn a_bitwarden_record_is_not_judged() {
        let writer = UserId::random();
        let key = sig1::SigningKey::from_bytes(&[5; 64]);
        let mut record = signed_record(Owner::User(writer), writer, &key);
        record.write = None;
        record.format = ItemFormat::Bw;
        let store = MemoryStore::new(ServerId::random());
        assert_eq!(judge(&store, &record).await, Ok(Verdict::Accept));
    }
}
