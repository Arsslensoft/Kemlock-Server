//! Giving the account's keys to someone else, and proving a person compared a fingerprint.
//!
//! - **Sealing the root key** (`docs/crypto.md`, sealed box): to a new device's one-time `kx1` key
//!   under `"device-approval"`, with `aad = account id ‖ approval request id`, to an emergency
//!   contact under `"emergency-access"` (`seal_emergency_key`, from a bundle it verifies), with
//!   `aad = the contact's account id`, or to a space's
//!   recovery key under `"account-recovery"`, with `aad = space id ‖ account id ‖ u64be(keySeq)`.
//!   Only these three contexts, so the page can't have the root key sealed under a context that means something
//!   else.
//! - **The member confirmation** (`docs/crypto.md`, "Member confirmation"): the 134-byte statement
//!   is built here from what the page compared, the confirmer is always the unlocked account, and
//!   only a statement of that shape, under context `"confirm"`, is ever signed: the `sig1` key
//!   that signs the account's own bundle can't be driven to sign anything else.
//! - **A released emergency key**: another account's root key, opened with this account's `kx1`
//!   key and kept as a handle, so the grantee's page can open the grantor's items without ever
//!   holding the key.

use kemlock_crypto::{
    bundle::{Bundle, FINGERPRINT_LEN},
    confirm::{STATEMENT_LEN, Statement},
    kem1,
    keys::{ITEM_WRAP_LABEL, RootKey},
    kx1,
    owner::OwnerKind,
    sealed_box::{self, context},
    sig1::context::CONFIRM,
};
use zeroize::Zeroizing;

use crate::{
    error::Error,
    session::{FIRST_KEY_VERSION, SealedItemRef, Session, Slot},
};

/// The context a signed statement must be made under.
pub(crate) const CONFIRM_CONTEXT: &str = CONFIRM;

/// What every confirmation statement starts with.
const STATEMENT_LABEL: &[u8] = b"kemlock/v1/confirm";

/// The raw facts of a confirmation, as the page compared them.
pub(crate) struct Facts {
    pub(crate) space: [u8; 16],
    pub(crate) member: [u8; 16],
    pub(crate) member_key_version: u32,
    pub(crate) fingerprint: [u8; FINGERPRINT_LEN],
}

fn fingerprint_of(bytes: &[u8]) -> Result<[u8; FINGERPRINT_LEN], Error> {
    bytes.try_into().map_err(|_| Error::Invalid)
}

impl Facts {
    pub(crate) fn new(
        space: [u8; 16],
        member: [u8; 16],
        member_key_version: u32,
        fingerprint: &[u8],
    ) -> Result<Facts, Error> {
        Ok(Facts {
            space,
            member,
            member_key_version,
            fingerprint: fingerprint_of(fingerprint)?,
        })
    }

    fn statement(&self, confirmer: [u8; 16]) -> Statement<'_> {
        Statement {
            space: self.space,
            member: self.member,
            member_key_version: self.member_key_version,
            fingerprint: &self.fingerprint,
            confirmer,
        }
    }
}

/// Whether `signature` is the confirmer's `sig1` signature, under their bundle's key, over exactly
/// the statement these facts give with the bundle's own account as confirmer. Public data only, so
/// it needs no session. Anything malformed is simply `false`.
pub(crate) fn verify_confirmation(
    confirmer_bundle: &[u8],
    facts: &Facts,
    statement: &[u8],
    signature: &[u8],
) -> bool {
    let Ok(bundle) = Bundle::from_bytes(confirmer_bundle) else {
        return false;
    };
    facts
        .statement(bundle.account_id)
        .verify(&bundle.sig1_public, statement, signature)
        .is_ok()
}

impl Session {
    /// Seals the unlocked account's root key to `recipient_kx1` (1,600 bytes) under `box_context`.
    ///
    /// - `"device-approval"`: `aad` is the account id followed by the approval request id (32
    ///   bytes), and the account id must be this account's, so an approval can't carry another
    ///   account's key.
    /// - `"emergency-access"` is not sealed here: [`Session::seal_emergency_key`] does it, from a
    ///   bundle it verifies itself, so the page can't have the root key sealed to a key of its choice.
    /// - `"account-recovery"`: `aad` is the space id, this account's id and `u64be(keySeq)` (40
    ///   bytes), and the account id must be this account's; the key is the space's recovery key.
    pub(crate) fn seal_root_key(
        &self,
        recipient_kx1: &[u8],
        box_context: &str,
        aad: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let unlocked = self.unlocked()?;
        match box_context {
            context::DEVICE_APPROVAL => {
                if aad.len() != 32 || aad[..16] != unlocked.account_id {
                    return Err(Error::Invalid);
                }
            }
            context::ACCOUNT_RECOVERY => {
                if aad.len() != 40 || aad[16..32] != unlocked.account_id {
                    return Err(Error::Invalid);
                }
            }
            _ => return Err(Error::Invalid),
        }
        let public = kx1::PublicKey::from_bytes(recipient_kx1)?;
        Ok(sealed_box::seal(
            &public,
            box_context,
            aad,
            unlocked.root.as_bytes(),
        )?)
    }

    /// Seals the unlocked account's root key to the recovery key `recovery_kx1` of `space`, set by
    /// chain record `key_seq`, under `"account-recovery"` with the aad `space ‖ account ‖
    /// u64be(key_seq)`.
    pub(crate) fn seal_root_key_for_recovery(
        &self,
        space: &[u8; 16],
        recovery_kx1: &[u8],
        key_seq: u64,
    ) -> Result<Vec<u8>, Error> {
        let account = self.unlocked()?.account_id;
        let mut aad = Vec::with_capacity(40);
        aad.extend_from_slice(space);
        aad.extend_from_slice(&account);
        aad.extend_from_slice(&key_seq.to_be_bytes());
        self.seal_root_key(recovery_kx1, context::ACCOUNT_RECOVERY, &aad)
    }

    /// Seals the unlocked account's root key to an emergency contact, under `"emergency-access"`
    /// with the aad `grantee` (the contact's account id, 16 bytes). The key sealed to is the one in
    /// `bundle`, which must carry its own `sig1` signature (`bundle_signature`) and name `grantee`
    /// as its account, and the grantee can't be this account. A page that holds no bundle of
    /// the contact's making can therefore not have the root key sealed to a key it chose.
    pub(crate) fn seal_emergency_key(
        &self,
        bundle: &[u8],
        bundle_signature: &[u8],
        grantee: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let unlocked = self.unlocked()?;
        let parsed = Bundle::from_bytes(bundle)?;
        if grantee.len() != 16
            || parsed.account_id.as_slice() != grantee
            || parsed.account_id == unlocked.account_id
            || parsed.verify_self_signature(bundle_signature).is_err()
        {
            return Err(Error::Invalid);
        }
        Ok(sealed_box::seal(
            &parsed.kx1_public,
            context::EMERGENCY_ACCESS,
            grantee,
            unlocked.root.as_bytes(),
        )?)
    }

    /// The statement the unlocked account would sign: the confirmation of `facts`, with this
    /// account as the confirmer.
    pub(crate) fn confirmation_statement(&self, facts: &Facts) -> Result<Vec<u8>, Error> {
        let unlocked = self.unlocked()?;
        Ok(facts.statement(unlocked.account_id).to_bytes())
    }

    /// A `sig1` signature of the unlocked account over `statement`. Only a confirmation statement
    /// naming this account as the confirmer, under context `"confirm"`, is signed.
    pub(crate) fn sign_statement(&self, statement: &[u8], context: &str) -> Result<Vec<u8>, Error> {
        let unlocked = self.unlocked()?;
        if context != CONFIRM_CONTEXT
            || statement.len() != STATEMENT_LEN
            || !statement.starts_with(STATEMENT_LABEL)
            || statement[STATEMENT_LEN - 16..] != unlocked.account_id
        {
            return Err(Error::Invalid);
        }
        let (_, sig_private) = unlocked.private.as_ref().ok_or(Error::Locked)?;
        Ok(sig_private.sign(context, statement)?)
    }

    /// Opens a root key sealed to this account for emergency access (`aad` is this account's id)
    /// and keeps it behind a handle: the grantor's key, held here and never returned.
    pub(crate) fn open_emergency_key(&mut self, sealed: &[u8]) -> Result<u32, Error> {
        let unlocked = self.unlocked()?;
        let (kx_private, _) = unlocked.private.as_ref().ok_or(Error::Locked)?;
        let plain = sealed_box::open(
            kx_private,
            context::EMERGENCY_ACCESS,
            &unlocked.account_id,
            sealed,
        )?;
        let mut root = Zeroizing::new([0u8; 64]);
        if plain.len() != root.len() {
            return Err(Error::Invalid);
        }
        root.copy_from_slice(&plain);
        self.insert(Slot::Root(root))
    }

    /// Opens one of the grantor's own items with an emergency key. The owner must be a user's own
    /// vault; `key_version` is the one the item says, or the first.
    pub(crate) fn open_item_with_emergency_key(
        &self,
        handle: u32,
        item: &SealedItemRef<'_>,
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        if item.owner.kind() != OwnerKind::User {
            return Err(Error::Invalid);
        }
        let slot = self.root_slot(handle)?;
        let root = RootKey::from_bytes(&slot);
        let wrap = root.user_key()?.child(ITEM_WRAP_LABEL)?;
        let item_key = kem1::unwrap_item_key(
            &wrap,
            item.item_key,
            item.id,
            item.owner,
            item.key_version.unwrap_or(FIRST_KEY_VERSION),
        )?;
        Ok(kem1::open_item(
            &item_key,
            item.id,
            item.revision,
            item.kind,
            item.owner,
            item.ciphertext,
        )?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Everything that touches `kx1` runs in WebAssembly (src/tests.rs); these are the parts that
    // do not.

    #[test]
    fn a_locked_session_shares_nothing() {
        let mut session = Session::new();
        let facts = Facts::new([1; 16], [2; 16], 1, &[3; 64]).expect("facts");
        assert_eq!(
            session.seal_root_key(&[0; 1600], "device-approval", &[0; 32]),
            Err(Error::Locked)
        );
        assert_eq!(session.confirmation_statement(&facts), Err(Error::Locked));
        assert_eq!(
            session.sign_statement(&[0; STATEMENT_LEN], CONFIRM_CONTEXT),
            Err(Error::Locked)
        );
        assert_eq!(session.open_emergency_key(&[0; 1700]), Err(Error::Locked));
    }

    #[test]
    fn the_statement_label_is_the_one_kemlock_crypto_writes() {
        let facts = Facts::new([1; 16], [2; 16], 7, &[3; 64]).expect("facts");
        let bytes = facts.statement([4; 16]).to_bytes();
        assert_eq!(bytes.len(), STATEMENT_LEN);
        assert!(bytes.starts_with(STATEMENT_LABEL));
        assert_eq!(&bytes[STATEMENT_LEN - 16..], &[4; 16]);
    }

    #[test]
    fn a_fingerprint_has_64_bytes() {
        for len in [0, 63, 65] {
            assert!(Facts::new([1; 16], [2; 16], 1, &vec![0; len]).is_err());
        }
    }

    #[test]
    fn a_bundle_that_is_not_one_verifies_nothing() {
        let facts = Facts::new([1; 16], [2; 16], 1, &[3; 64]).expect("facts");
        assert!(!verify_confirmation(&[], &facts, &[0; 134], &[0; 3373]));
        assert!(!verify_confirmation(
            &[0; 7242], &facts, &[0; 134], &[0; 3373]
        ));
    }

    #[test]
    fn an_unknown_emergency_handle_is_refused() {
        let session = Session::new();
        assert!(session.root_slot(1).is_err());
    }
}
