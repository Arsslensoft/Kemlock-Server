//! The Recovery Kit (`docs/crypto.md`, "The Recovery Kit"), for the browser.
//!
//! An unlocked session makes a kit: a random kit key, split into 3 pieces (any 2 rebuild it), and
//! its root key wrapped under that key. The page gets the pieces' text to show once and the wrap
//! for the server to keep; the kit key and the root key stay here. A locked session reads pieces,
//! rebuilds the kit key, opens the wrap the server returned and keeps the root key behind a
//! handle, which `unlock_with_root` turns into an open vault.

use kemlock_crypto::recovery_kit::{self, KIT_KEY_LEN, KitPiece, PieceProblem};
use zeroize::Zeroizing;

use crate::{
    error::Error,
    session::{Session, Slot},
};

/// Pieces needed to rebuild the kit key.
pub(crate) const THRESHOLD: u8 = 2;
/// Pieces a kit is made in.
pub(crate) const PIECES: u8 = 3;

/// A new kit as the page needs it.
pub(crate) struct MadeKit {
    pub(crate) kit_id: String,
    /// The pieces' text, with their checks.
    pub(crate) pieces: Vec<String>,
    /// The root key wrapped under the kit key.
    pub(crate) wrapped: Vec<u8>,
    pub(crate) key_version: u32,
}

/// Reads a piece however it was typed.
pub(crate) fn read_piece(text: &str) -> Result<KitPiece, PieceProblem> {
    recovery_kit::parse_piece(text)
}

/// Whether `texts` read as pieces of one kit with none twice. Passes with fewer pieces than the
/// kit needs; [`Session::kit_open_root`] insists on enough.
pub(crate) fn check_set(texts: &[String]) -> Result<(), PieceProblem> {
    let pieces = texts
        .iter()
        .map(|t| read_piece(t))
        .collect::<Result<Vec<_>, _>>()?;
    match recovery_kit::rebuild_key(&pieces) {
        Ok(_) | Err(PieceProblem::NotEnough) => Ok(()),
        Err(problem) => Err(problem),
    }
}

impl Session {
    /// Makes a Recovery Kit for the open account: a 2-of-3 split of a new kit key, and the root key
    /// wrapped under it, for `POST` or `PUT /kem/v1/account/recovery-kit`.
    pub(crate) fn kit_make(&self) -> Result<MadeKit, Error> {
        let unlocked = self.unlocked()?;
        let (kit_id, key, pieces) = recovery_kit::make_kit(THRESHOLD, PIECES)?;
        let wrapped = recovery_kit::seal(
            &key,
            &kit_id,
            &unlocked.root,
            &unlocked.account_id,
            unlocked.key_version,
        )?;
        Ok(MadeKit {
            kit_id,
            pieces,
            wrapped,
            key_version: unlocked.key_version,
        })
    }

    /// Opens a kit's wrap of the root key with pieces of the kit and keeps the root key behind a new
    /// handle for `unlock_with_root`. Fails for pieces that are not a set of enough, for another
    /// kit than the wrap's, and for a wrap of another account or key version.
    pub(crate) fn kit_open_root(
        &mut self,
        pieces: &[String],
        kit_id: &str,
        account: &[u8; 16],
        key_version: u32,
        wrapped: &[u8],
    ) -> Result<u32, Error> {
        let parsed = pieces
            .iter()
            .map(|t| read_piece(t))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| Error::Invalid)?;
        if parsed.first().map(|p| p.kit_id.as_str()) != Some(kit_id) {
            return Err(Error::Invalid);
        }
        let key: Zeroizing<[u8; KIT_KEY_LEN]> =
            recovery_kit::rebuild_key(&parsed).map_err(|_| Error::Invalid)?;
        let root = recovery_kit::open(&key, kit_id, wrapped, account, key_version)?;
        self.insert(Slot::Root(Zeroizing::new(*root.as_bytes())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::Session;

    #[test]
    fn a_locked_session_makes_no_kit() {
        assert_eq!(Session::new().kit_make().err(), Some(Error::Locked));
    }

    #[test]
    fn a_wrap_that_does_not_open_leaves_no_handle() {
        let (kit_id, _, pieces) = recovery_kit::make_kit(THRESHOLD, PIECES).expect("a kit");
        let mut session = Session::new();
        assert_eq!(
            session.kit_open_root(&pieces[..2], &kit_id, &[1; 16], 1, &[0; 92]),
            Err(Error::Invalid)
        );
        assert!(!session.is_unlocked());
    }

    #[test]
    fn one_piece_or_another_kits_id_opens_nothing() {
        let (kit_id, key, pieces) = recovery_kit::make_kit(THRESHOLD, PIECES).expect("a kit");
        let root = kemlock_crypto::keys::RootKey::from_bytes(&[5; 64]);
        let wrapped = recovery_kit::seal(&key, &kit_id, &root, &[1; 16], 1).expect("a wrap");
        let mut session = Session::new();
        assert_eq!(
            session.kit_open_root(&pieces[..1], &kit_id, &[1; 16], 1, &wrapped),
            Err(Error::Invalid)
        );
        assert_eq!(
            session.kit_open_root(&pieces[..2], "AAAAAAAA", &[1; 16], 1, &wrapped),
            Err(Error::Invalid)
        );
        assert!(
            session
                .kit_open_root(&[pieces[2].clone(), pieces[0].clone()], &kit_id, &[1; 16], 1, &wrapped)
                .is_ok()
        );
    }

    #[test]
    fn a_set_is_checked_for_typos_other_kits_and_repeats() {
        let (_, _, one) = recovery_kit::make_kit(THRESHOLD, PIECES).expect("a kit");
        let (_, _, two) = recovery_kit::make_kit(THRESHOLD, PIECES).expect("another");
        assert_eq!(check_set(&one[..1]), Ok(()));
        assert_eq!(check_set(&one[..2]), Ok(()));
        assert_eq!(
            check_set(&[one[0].clone(), two[1].clone()]),
            Err(PieceProblem::OtherKit)
        );
        assert_eq!(
            check_set(&[one[0].clone(), one[0].to_lowercase()]),
            Err(PieceProblem::Duplicate)
        );
        assert_eq!(check_set(&["nonsense".to_owned()]), Err(PieceProblem::Format));
    }
}
