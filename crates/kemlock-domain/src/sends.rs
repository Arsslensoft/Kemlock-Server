//! Sends: a note or a file shared by a link, with a view limit, an optional password and a date it
//! deletes itself.
//!
//! The key to a Send travels in the link's fragment (`https://host/#/send/<access id>/<key>`),
//! which a browser never sends to a server, so the server holds only ciphertext it cannot open. A
//! Send has three sealed parts, all opaque here:
//!
//! - `payload`: what a recipient opens with the key from the link (the note, or a file's name and
//!   size). The public access route returns this and nothing else that is sealed.
//! - `sealed_key`: the Send's key sealed under the owner's own key, so the owner's devices can show
//!   the link again.
//! - `meta`: the name and notes the owner sees in their list, sealed under the owner's key.
//!
//! A file Send keeps its bytes in blob storage under a random id ([`SendFile`]), as an
//! attachment does.
//!
//! A recipient proves a password with a value their client derived from it, which the server keeps
//! only as a salted hash ([`SendPassword`]); the server never sees the password itself.
//!
//! A Send has two dates, as in Bitwarden: `expires_at` ends access (the link stops working, the
//! owner still sees the Send) and `deletion_at` removes the Send. Both are optional in Bitwarden's
//! UI; here the deletion date is required and is at most 30 days away.

use crate::attachment::BlobId;
use crate::ids::UserId;
use std::fmt;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

/// The most days ahead a Send's deletion date may be.
pub const MAX_DELETION_DAYS: i64 = 30;
/// A client's clock may be this far ahead of the server's without its "30 days" being refused.
pub const CLOCK_SKEW: Duration = Duration::hours(1);
/// The longest sealed name-and-notes block.
pub const MAX_META_LEN: usize = 16 * 1024;
/// The longest sealed Send key (a few hundred bytes cover any wrap).
pub const MAX_SEALED_KEY_LEN: usize = 2048;
/// The longest note or file descriptor a recipient opens: 256 KiB of ciphertext.
pub const MAX_PAYLOAD_LEN: usize = 256 * 1024;
/// The longest value a client may send as a Send's password proof.
pub const MAX_PASSWORD_PROOF_LEN: usize = 1024;
/// The size of a stored password hash.
pub const PASSWORD_HASH_LEN: usize = 32;
/// The size of a password salt.
pub const PASSWORD_SALT_LEN: usize = 32;

/// A Send's id. Its public face, the *access id* the link carries, is the same 16 bytes in unpadded
/// base64url (as in Bitwarden and Vaultwarden; `kemlock-app` converts).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SendId(pub Uuid);

impl SendId {
    /// A new random id (UUID v4).
    pub fn random() -> Self {
        Self(Uuid::new_v4())
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        self.0.as_bytes()
    }
}

impl fmt::Debug for SendId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SendId({})", self.0)
    }
}

impl fmt::Display for SendId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl std::str::FromStr for SendId {
    type Err = uuid::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(s).map(Self)
    }
}

/// What a Send holds. The numbers are Bitwarden's.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SendKind {
    Text,
    File,
}

impl SendKind {
    /// Bitwarden's `type`: 0 text, 1 file.
    pub fn code(self) -> i16 {
        match self {
            SendKind::Text => 0,
            SendKind::File => 1,
        }
    }

    pub fn from_code(code: i16) -> Option<SendKind> {
        match code {
            0 => Some(SendKind::Text),
            1 => Some(SendKind::File),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            SendKind::Text => "text",
            SendKind::File => "file",
        }
    }

    pub fn parse(text: &str) -> Option<SendKind> {
        match text {
            "text" => Some(SendKind::Text),
            "file" => Some(SendKind::File),
            _ => None,
        }
    }
}

/// How a file Send's bytes are laid out, which decides what storage checks on upload.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SendFileFormat {
    /// `KMA1` chunked AES-256-GCM, as Kemlock's own clients write it. Storage checks the header
    /// and the length.
    Kma1,
    /// Whatever a Bitwarden app encrypted (its own buffer format). Storage checks only the size.
    Opaque,
}

impl SendFileFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            SendFileFormat::Kma1 => "kma1",
            SendFileFormat::Opaque => "opaque",
        }
    }

    pub fn parse(text: &str) -> Option<SendFileFormat> {
        match text {
            "kma1" => Some(SendFileFormat::Kma1),
            "opaque" => Some(SendFileFormat::Opaque),
            _ => None,
        }
    }
}

/// A file Send's bytes in blob storage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SendFile {
    pub blob: BlobId,
    /// The size of the stored bytes, announced when the Send was made and what the upload must
    /// then match exactly.
    pub size: u64,
    pub format: SendFileFormat,
    /// Whether the bytes have arrived. A file Send whose bytes haven't is not open to anyone.
    pub ready: bool,
}

/// How a Send checks a password: a salted hash of the value the client derived from it.
#[derive(Clone, PartialEq, Eq)]
pub struct SendPassword {
    pub salt: Vec<u8>,
    pub hash: Vec<u8>,
}

impl fmt::Debug for SendPassword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SendPassword").finish_non_exhaustive()
    }
}

/// A Send as stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SendRecord {
    pub id: SendId,
    pub owner: UserId,
    pub kind: SendKind,
    /// The name and notes, sealed under the owner's key. Opaque.
    pub meta: Vec<u8>,
    /// The Send's key, sealed under the owner's key. Opaque.
    pub sealed_key: Vec<u8>,
    /// What a recipient opens with the key from the link. Opaque.
    pub payload: Vec<u8>,
    /// The bytes of a file Send; `None` for a note.
    pub file: Option<SendFile>,
    pub password: Option<SendPassword>,
    /// How many times it may be opened; `None` for no limit.
    pub max_access: Option<u32>,
    pub access_count: u32,
    /// Whether the recipient is told who sent it: `false` shows the owner's email.
    pub hide_email: bool,
    /// The owner switched it off: no one can open it, and the owner can switch it on again.
    pub disabled: bool,
    /// After this the link stops working; the owner still sees the Send.
    pub expires_at: Option<OffsetDateTime>,
    /// After this the Send is deleted, bytes included.
    pub deletion_at: OffsetDateTime,
    pub created_at: OffsetDateTime,
    pub revised_at: OffsetDateTime,
}

/// What a client gives when it makes a Send.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewSend {
    pub id: SendId,
    pub kind: SendKind,
    pub meta: Vec<u8>,
    pub sealed_key: Vec<u8>,
    pub payload: Vec<u8>,
    /// For a file Send: the size of the bytes about to be uploaded, and their layout.
    pub file: Option<(u64, SendFileFormat)>,
    pub options: SendOptions,
}

/// The settings of a Send a client may choose and later change.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SendOptions {
    pub max_access: Option<u32>,
    pub hide_email: bool,
    pub disabled: bool,
    pub expires_at: Option<OffsetDateTime>,
    pub deletion_at: OffsetDateTime,
}

/// What a change does to a Send's password.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PasswordChange {
    Keep,
    Remove,
    Set(SendPassword),
}

/// The limits an admin may set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SendLimits {
    /// The most bytes one file Send may hold. 100 MiB by default, as an attachment.
    pub max_file_size: u64,
}

impl SendLimits {
    pub const DEFAULT_MAX_FILE_SIZE: u64 = 100 * 1024 * 1024;
}

impl Default for SendLimits {
    fn default() -> Self {
        SendLimits {
            max_file_size: Self::DEFAULT_MAX_FILE_SIZE,
        }
    }
}

/// Why a Send is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SendError {
    #[error("{0}")]
    Invalid(&'static str),
    #[error("the file is larger than this server allows")]
    TooLarge,
}

fn check_len(value: &[u8], max: usize, what: &'static str) -> Result<(), SendError> {
    if value.is_empty() || value.len() > max {
        return Err(SendError::Invalid(what));
    }
    Ok(())
}

impl SendOptions {
    /// Checks the options against `now`: a view limit of at least 1, a deletion date in the
    /// future and at most 30 days away (a client clock up to an hour fast is forgiven), and an
    /// expiry that doesn't come after the deletion.
    pub fn check(&self, now: OffsetDateTime) -> Result<(), SendError> {
        if self.max_access == Some(0) {
            return Err(SendError::Invalid("a view limit must be at least 1"));
        }
        if self.deletion_at <= now {
            return Err(SendError::Invalid(
                "the deletion date must be in the future",
            ));
        }
        if self.deletion_at > now + Duration::days(MAX_DELETION_DAYS) + CLOCK_SKEW {
            return Err(SendError::Invalid(
                "the deletion date must be at most 30 days away",
            ));
        }
        if self.expires_at.is_some_and(|at| at > self.deletion_at) {
            return Err(SendError::Invalid(
                "the expiry can't come after the deletion date",
            ));
        }
        Ok(())
    }
}

/// Refuses a password proof of an unreasonable size. The proof is the client's derived value.
pub fn check_password_proof(proof: &[u8]) -> Result<(), SendError> {
    check_len(
        proof,
        MAX_PASSWORD_PROOF_LEN,
        "the password proof must be 1 to 1,024 bytes",
    )
}

impl SendRecord {
    /// Makes a Send, checking its parts and options. `password` is the already hashed password,
    /// if the Send has one. A file Send starts with its bytes missing.
    pub fn create(
        new: NewSend,
        owner: UserId,
        password: Option<SendPassword>,
        blob: Option<BlobId>,
        limits: SendLimits,
        now: OffsetDateTime,
    ) -> Result<SendRecord, SendError> {
        check_len(
            &new.meta,
            MAX_META_LEN,
            "the sealed name must be 1 byte to 16 KiB",
        )?;
        check_len(
            &new.sealed_key,
            MAX_SEALED_KEY_LEN,
            "the sealed key must be 1 byte to 2 KiB",
        )?;
        check_len(
            &new.payload,
            MAX_PAYLOAD_LEN,
            "the content must be 1 byte to 256 KiB of ciphertext",
        )?;
        new.options.check(now)?;
        let file = match (new.kind, new.file, blob) {
            (SendKind::Text, None, _) => None,
            (SendKind::File, Some((size, format)), Some(blob)) => {
                if size == 0 {
                    return Err(SendError::Invalid("the file is empty"));
                }
                if size > limits.max_file_size {
                    return Err(SendError::TooLarge);
                }
                Some(SendFile {
                    blob,
                    size,
                    format,
                    ready: false,
                })
            }
            (SendKind::File, _, _) => {
                return Err(SendError::Invalid("a file Send needs the size of its file"));
            }
            (SendKind::Text, Some(_), _) => {
                return Err(SendError::Invalid("a note has no file"));
            }
        };
        Ok(SendRecord {
            id: new.id,
            owner,
            kind: new.kind,
            meta: new.meta,
            sealed_key: new.sealed_key,
            payload: new.payload,
            file,
            password,
            max_access: new.options.max_access,
            access_count: 0,
            hide_email: new.options.hide_email,
            disabled: new.options.disabled,
            expires_at: new.options.expires_at,
            deletion_at: new.options.deletion_at,
            created_at: now,
            revised_at: now,
        })
    }

    /// Applies an owner's change: new name and notes, new options, a password change and, for a
    /// note, new content. A file Send's content and file can't change. The view count stays; a
    /// limit lower than the count simply closes the Send.
    pub fn revise(
        &mut self,
        meta: Vec<u8>,
        payload: Option<Vec<u8>>,
        options: SendOptions,
        password: PasswordChange,
        now: OffsetDateTime,
    ) -> Result<(), SendError> {
        check_len(
            &meta,
            MAX_META_LEN,
            "the sealed name must be 1 byte to 16 KiB",
        )?;
        options.check(now)?;
        if let Some(payload) = &payload {
            if self.kind == SendKind::File {
                return Err(SendError::Invalid("a file Send's content can't change"));
            }
            check_len(
                payload,
                MAX_PAYLOAD_LEN,
                "the content must be 1 byte to 256 KiB of ciphertext",
            )?;
        }
        self.meta = meta;
        if let Some(payload) = payload {
            self.payload = payload;
        }
        self.max_access = options.max_access;
        self.hide_email = options.hide_email;
        self.disabled = options.disabled;
        self.expires_at = options.expires_at;
        self.deletion_at = options.deletion_at;
        match password {
            PasswordChange::Keep => {}
            PasswordChange::Remove => self.password = None,
            PasswordChange::Set(p) => self.password = Some(p),
        }
        self.revised_at = now;
        Ok(())
    }

    pub fn has_password(&self) -> bool {
        self.password.is_some()
    }

    /// Whether the Send's deletion date has passed.
    pub fn is_deleted_by(&self, now: OffsetDateTime) -> bool {
        self.deletion_at <= now
    }

    /// Whether the view limit is used up.
    pub fn is_exhausted(&self) -> bool {
        self.max_access.is_some_and(|max| self.access_count >= max)
    }

    /// Whether a recipient may open it now: switched on, before its expiry and deletion, with
    /// views left, and (for a file) with its bytes uploaded.
    pub fn is_open(&self, now: OffsetDateTime) -> bool {
        !self.disabled
            && !self.is_deleted_by(now)
            && self.expires_at.is_none_or(|at| at > now)
            && !self.is_exhausted()
            && self.file.is_none_or(|f| f.ready)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    const NOW: OffsetDateTime = datetime!(2026-06-01 12:00 UTC);

    fn options() -> SendOptions {
        SendOptions {
            max_access: None,
            hide_email: false,
            disabled: false,
            expires_at: None,
            deletion_at: NOW + Duration::days(7),
        }
    }

    fn note() -> NewSend {
        NewSend {
            id: SendId::random(),
            kind: SendKind::Text,
            meta: vec![1; 40],
            sealed_key: vec![2; 100],
            payload: vec![3; 60],
            file: None,
            options: options(),
        }
    }

    fn file(size: u64) -> NewSend {
        NewSend {
            kind: SendKind::File,
            file: Some((size, SendFileFormat::Kma1)),
            ..note()
        }
    }

    fn make(new: NewSend) -> Result<SendRecord, SendError> {
        SendRecord::create(
            new,
            UserId::random(),
            None,
            Some(BlobId::random()),
            SendLimits::default(),
            NOW,
        )
    }

    #[test]
    fn a_note_is_made_open_and_unviewed() {
        let send = make(note()).expect("a valid note");
        assert_eq!(send.kind, SendKind::Text);
        assert_eq!(send.access_count, 0);
        assert!(send.file.is_none());
        assert!(send.is_open(NOW));
        assert_eq!(send.created_at, NOW);
    }

    #[test]
    fn a_file_send_is_closed_until_its_bytes_arrive() {
        let mut send = make(file(1000)).expect("a valid file send");
        let stored = send.file.expect("a file");
        assert_eq!(stored.size, 1000);
        assert!(!stored.ready);
        assert!(!send.is_open(NOW));
        send.file = Some(SendFile {
            ready: true,
            ..stored
        });
        assert!(send.is_open(NOW));
    }

    #[test]
    fn kinds_round_trip_bitwardens_numbers_and_text() {
        for kind in [SendKind::Text, SendKind::File] {
            assert_eq!(SendKind::from_code(kind.code()), Some(kind));
            assert_eq!(SendKind::parse(kind.as_str()), Some(kind));
        }
        assert_eq!(SendKind::Text.code(), 0);
        assert_eq!(SendKind::File.code(), 1);
        assert_eq!(SendKind::from_code(2), None);
        for format in [SendFileFormat::Kma1, SendFileFormat::Opaque] {
            assert_eq!(SendFileFormat::parse(format.as_str()), Some(format));
        }
    }

    #[test]
    fn the_deletion_date_is_one_hour_to_thirty_days_ahead() {
        let at = |deletion_at| SendOptions {
            deletion_at,
            ..options()
        };
        assert!(at(NOW + Duration::hours(1)).check(NOW).is_ok());
        assert!(at(NOW + Duration::days(30)).check(NOW).is_ok());
        // A client whose clock is a little fast still gets its 30 days.
        assert!(
            at(NOW + Duration::days(30) + Duration::minutes(30))
                .check(NOW)
                .is_ok()
        );
        assert!(at(NOW + Duration::days(31)).check(NOW).is_err());
        assert!(at(NOW).check(NOW).is_err());
        assert!(at(NOW - Duration::days(1)).check(NOW).is_err());
    }

    #[test]
    fn a_view_limit_of_zero_and_an_expiry_after_the_deletion_are_refused() {
        let zero = SendOptions {
            max_access: Some(0),
            ..options()
        };
        assert!(zero.check(NOW).is_err());
        let late = SendOptions {
            expires_at: Some(NOW + Duration::days(8)),
            ..options()
        };
        assert!(late.check(NOW).is_err());
        let fine = SendOptions {
            max_access: Some(1),
            expires_at: Some(NOW + Duration::days(3)),
            ..options()
        };
        assert!(fine.check(NOW).is_ok());
    }

    #[test]
    fn sealed_parts_must_be_present_and_not_too_long() {
        let mut n = note();
        n.meta.clear();
        assert!(make(n).is_err());
        let mut n = note();
        n.sealed_key = vec![0; MAX_SEALED_KEY_LEN + 1];
        assert!(make(n).is_err());
        let mut n = note();
        n.payload = vec![0; MAX_PAYLOAD_LEN + 1];
        assert!(make(n).is_err());
        let mut n = note();
        n.payload = vec![0; MAX_PAYLOAD_LEN];
        assert!(make(n).is_ok());
    }

    #[test]
    fn a_file_needs_a_size_within_the_limit_and_a_note_has_no_file() {
        assert_eq!(make(file(0)), Err(SendError::Invalid("the file is empty")));
        assert_eq!(
            make(file(SendLimits::DEFAULT_MAX_FILE_SIZE + 1)),
            Err(SendError::TooLarge)
        );
        assert!(make(file(SendLimits::DEFAULT_MAX_FILE_SIZE)).is_ok());
        let no_size = NewSend {
            kind: SendKind::File,
            ..note()
        };
        assert!(make(no_size).is_err());
        let stray = NewSend {
            file: Some((10, SendFileFormat::Kma1)),
            ..note()
        };
        assert!(make(stray).is_err());
    }

    #[test]
    fn a_send_closes_by_switch_expiry_deletion_or_its_view_limit() {
        let base = make(note()).expect("a note");
        assert!(base.is_open(NOW));

        let off = SendRecord {
            disabled: true,
            ..base.clone()
        };
        assert!(!off.is_open(NOW));

        let expiring = SendRecord {
            expires_at: Some(NOW + Duration::hours(2)),
            ..base.clone()
        };
        assert!(expiring.is_open(NOW + Duration::hours(1)));
        assert!(!expiring.is_open(NOW + Duration::hours(2)));

        assert!(base.is_open(NOW + Duration::days(7) - Duration::seconds(1)));
        assert!(!base.is_open(NOW + Duration::days(7)));
        assert!(base.is_deleted_by(NOW + Duration::days(7)));

        let limited = SendRecord {
            max_access: Some(2),
            access_count: 1,
            ..base.clone()
        };
        assert!(limited.is_open(NOW));
        let used = SendRecord {
            access_count: 2,
            ..limited
        };
        assert!(used.is_exhausted());
        assert!(!used.is_open(NOW));
    }

    #[test]
    fn revising_changes_options_and_password_and_keeps_the_count() {
        let mut send = make(note()).expect("a note");
        send.access_count = 3;
        let later = NOW + Duration::minutes(5);
        let password = SendPassword {
            salt: vec![1; PASSWORD_SALT_LEN],
            hash: vec![2; PASSWORD_HASH_LEN],
        };
        send.revise(
            vec![9; 10],
            Some(vec![8; 20]),
            SendOptions {
                max_access: Some(5),
                hide_email: true,
                disabled: true,
                expires_at: Some(NOW + Duration::days(1)),
                deletion_at: NOW + Duration::days(2),
            },
            PasswordChange::Set(password.clone()),
            later,
        )
        .expect("a valid change");
        assert_eq!(send.meta, vec![9; 10]);
        assert_eq!(send.payload, vec![8; 20]);
        assert_eq!(send.max_access, Some(5));
        assert!(send.hide_email && send.disabled);
        assert_eq!(send.access_count, 3);
        assert_eq!(send.password, Some(password));
        assert_eq!(send.revised_at, later);
        assert_eq!(send.created_at, NOW);

        let options = options();
        send.revise(
            vec![9; 10],
            None,
            options.clone(),
            PasswordChange::Keep,
            later,
        )
        .expect("kept");
        assert!(send.has_password());
        send.revise(vec![9; 10], None, options, PasswordChange::Remove, later)
            .expect("removed");
        assert!(!send.has_password());
    }

    #[test]
    fn a_file_sends_content_cannot_be_replaced_and_a_bad_change_changes_nothing() {
        let mut send = make(file(500)).expect("a file send");
        let before = send.clone();
        let refused = send.revise(
            vec![9; 10],
            Some(vec![8; 20]),
            options(),
            PasswordChange::Keep,
            NOW,
        );
        assert!(refused.is_err());
        assert_eq!(send, before);

        let bad = send.revise(
            vec![9; 10],
            None,
            SendOptions {
                max_access: Some(0),
                ..options()
            },
            PasswordChange::Keep,
            NOW,
        );
        assert!(bad.is_err());
        assert_eq!(send, before);
    }

    #[test]
    fn password_proofs_have_a_size_and_secrets_stay_out_of_debug_output() {
        assert!(check_password_proof(&[]).is_err());
        assert!(check_password_proof(&[1; MAX_PASSWORD_PROOF_LEN]).is_ok());
        assert!(check_password_proof(&[1; MAX_PASSWORD_PROOF_LEN + 1]).is_err());
        let password = SendPassword {
            salt: vec![7; 4],
            hash: vec![8; 4],
        };
        assert!(!format!("{password:?}").contains('7'));
    }

    #[test]
    fn send_ids_parse_and_print_as_uuids() {
        let id = SendId::random();
        assert_eq!(id.to_string().parse::<SendId>(), Ok(id));
        assert!("not-a-uuid".parse::<SendId>().is_err());
        assert_eq!(id.as_bytes().len(), 16);
    }
}
