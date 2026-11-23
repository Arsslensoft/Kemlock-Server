//! The neutral batch every parser returns.
//!
//! It is what the web vault shows in its preview and what the client turns into Kemlock items:
//! logins, codes, notes, cards, identities, keys and files, in folders nested as in the source,
//! plus the shared vaults the export named and each entry that was left out, with its reason. It
//! carries plaintext secrets, so a caller holds it only as long as the import runs.
//!
//! The shapes follow the app's own models (`Login`, `OtpAccount`, `Passkey`, and the card and
//! identity kinds of `add-cards-identities-and-websites`), so a batch maps to them one for one.

use serde::{Deserialize, Serialize};

/// The COSE number of ES256, the only passkey algorithm Kemlock keeps today.
pub const COSE_ES256: i32 = -7;

/// An export format this crate reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Format {
    /// Chrome, Edge and Google Password Manager CSV.
    ChromeCsv,
    /// Safari and Apple Passwords CSV.
    SafariCsv,
    /// Firefox CSV.
    FirefoxCsv,
    /// Bitwarden JSON: plain, password-protected or account-restricted.
    BitwardenJson,
    /// Bitwarden CSV.
    BitwardenCsv,
    /// LastPass CSV.
    LastPassCsv,
    /// 1Password 1PUX (a ZIP).
    OnePasswordPux,
    /// 1Password CSV, from the Mac or the Windows app.
    OnePasswordCsv,
    /// Dashlane's CSV export, a ZIP of CSV files.
    DashlaneZip,
    /// One of Dashlane's CSV files.
    DashlaneCsv,
    /// NordPass CSV.
    NordPassCsv,
    /// Keeper JSON.
    KeeperJson,
    /// Proton Pass JSON.
    ProtonPassJson,
    /// Proton Pass export with files (a ZIP of the JSON and the files).
    ProtonPassZip,
    /// Proton Pass JSON encrypted with a passphrase (OpenPGP).
    ProtonPassPgp,
    /// KeePass, KeePassXC and compatible KDBX 3.1 and 4 databases.
    Kdbx,
    /// Enpass JSON.
    EnpassJson,
    /// RoboForm CSV.
    RoboFormCsv,
}

impl Format {
    /// Every format, in the order a "From" list shows them.
    pub const ALL: [Format; 18] = [
        Format::ChromeCsv,
        Format::SafariCsv,
        Format::FirefoxCsv,
        Format::BitwardenJson,
        Format::BitwardenCsv,
        Format::LastPassCsv,
        Format::OnePasswordPux,
        Format::OnePasswordCsv,
        Format::DashlaneZip,
        Format::DashlaneCsv,
        Format::NordPassCsv,
        Format::KeeperJson,
        Format::ProtonPassJson,
        Format::ProtonPassZip,
        Format::ProtonPassPgp,
        Format::Kdbx,
        Format::EnpassJson,
        Format::RoboFormCsv,
    ];

    /// The app a login came from, for the `source` of the items made from it ("Chrome", not
    /// "Chrome CSV"). Chrome's parser also reads Edge and Google Password Manager.
    pub fn source_name(self) -> &'static str {
        match self {
            Format::ChromeCsv => "Chrome",
            Format::SafariCsv => "Safari",
            Format::FirefoxCsv => "Firefox",
            Format::BitwardenJson | Format::BitwardenCsv => "Bitwarden",
            Format::LastPassCsv => "LastPass",
            Format::OnePasswordPux | Format::OnePasswordCsv => "1Password",
            Format::DashlaneZip | Format::DashlaneCsv => "Dashlane",
            Format::NordPassCsv => "NordPass",
            Format::KeeperJson => "Keeper",
            Format::ProtonPassJson | Format::ProtonPassZip | Format::ProtonPassPgp => "Proton Pass",
            Format::Kdbx => "KeePass",
            Format::EnpassJson => "Enpass",
            Format::RoboFormCsv => "RoboForm",
        }
    }
}

/// A folder, nested as in the source.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Folder {
    /// The last part of the path.
    pub name: String,
    /// Index into [`ImportBatch::folders`] of the folder it sits in.
    pub parent: Option<usize>,
    /// The whole path, parts joined with `/`.
    pub path: String,
}

/// What kind of shared place a [`SharedVault`] was.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SharedKind {
    /// A vault shared with others (1Password, Proton Pass).
    #[default]
    Vault,
    /// A collection (Bitwarden organisations).
    Collection,
    /// A shared folder (Keeper).
    SharedFolder,
}

/// A shared vault, collection or shared folder the export named. The preview asks per vault: a new
/// space, preselected, or a folder.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SharedVault {
    /// Its name.
    pub name: String,
    /// What it was.
    pub kind: SharedKind,
    /// The source's id for it, when it has one.
    pub source_id: Option<String>,
}

/// What every entry carries besides its own fields.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Meta {
    /// Index into [`ImportBatch::folders`].
    pub folder: Option<usize>,
    /// Indexes into [`ImportBatch::spaces`] of the shared vaults it sits in.
    pub spaces: Vec<usize>,
    /// Starred, pinned or favourite in the source.
    pub favorite: bool,
    /// Epoch milliseconds, when the source says.
    pub created_ms: Option<i64>,
    /// Epoch milliseconds, when the source says.
    pub modified_ms: Option<i64>,
    /// The source's id for the entry, when it has one.
    pub source_id: Option<String>,
    /// Tags beyond the first one a source turns into a folder (1Password), and KeePass tags.
    pub tags: Vec<String>,
}

/// How a custom field is shown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FieldKind {
    /// Plain text.
    #[default]
    Text,
    /// Hidden until revealed.
    Hidden,
    /// `"true"` or `"false"`.
    Boolean,
    /// A field that shows another field of the item.
    Linked,
}

/// A named value on an entry.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct CustomField {
    /// The label.
    pub name: String,
    /// The value.
    pub value: String,
    /// How it is shown.
    pub kind: FieldKind,
}

/// Bitwarden's match rules for a website, which Kemlock's `uris` adopt by number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UriMatch {
    /// Base domain (0).
    BaseDomain,
    /// Host (1).
    Host,
    /// Starts with (2).
    StartsWith,
    /// Exact (3).
    Exact,
    /// Regular expression (4).
    RegularExpression,
    /// Never (5).
    Never,
}

impl UriMatch {
    /// The rule for Bitwarden's number; `None` for one this crate doesn't know (the default rule).
    pub fn from_number(n: i64) -> Option<UriMatch> {
        match n {
            0 => Some(UriMatch::BaseDomain),
            1 => Some(UriMatch::Host),
            2 => Some(UriMatch::StartsWith),
            3 => Some(UriMatch::Exact),
            4 => Some(UriMatch::RegularExpression),
            5 => Some(UriMatch::Never),
            _ => None,
        }
    }

    /// Bitwarden's number for the rule.
    pub fn number(self) -> u8 {
        match self {
            UriMatch::BaseDomain => 0,
            UriMatch::Host => 1,
            UriMatch::StartsWith => 2,
            UriMatch::Exact => 3,
            UriMatch::RegularExpression => 4,
            UriMatch::Never => 5,
        }
    }
}

/// A website a login fills on.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct UriRule {
    /// The address as exported (a missing scheme is filled in as `http://`).
    pub uri: String,
    /// The match rule; `None` is the default.
    pub match_rule: Option<UriMatch>,
}

/// A password a login had before.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct PreviousPassword {
    /// The old password.
    pub password: String,
    /// Epoch milliseconds when it was replaced.
    pub until_ms: i64,
}

/// A passkey with its private key.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Passkey {
    /// The credential id, base64url without padding.
    pub credential_id: String,
    /// The relying party, lower case.
    pub rp_id: String,
    /// The name the site gave itself.
    pub rp_name: Option<String>,
    /// The user handle, base64url without padding.
    pub user_handle: String,
    /// The account's name at the site.
    pub user_name: String,
    /// A display name.
    pub user_display_name: Option<String>,
    /// The private key, PKCS#8 DER in standard base64.
    pub private_key: String,
    /// The COSE algorithm; parsers keep only [`COSE_ES256`].
    pub algorithm: i32,
    /// Epoch milliseconds when it was made, when the source says.
    pub created_ms: Option<i64>,
}

/// A login.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Login {
    /// Its name.
    pub name: String,
    /// Every website, with its match rule.
    pub uris: Vec<UriRule>,
    /// The username.
    pub username: Option<String>,
    /// The password.
    pub password: Option<String>,
    /// A TOTP seed or `otpauth://` link; the client makes a code entry linked to the login.
    pub totp: Option<String>,
    /// The note.
    pub notes: Option<String>,
    /// Custom fields.
    pub fields: Vec<CustomField>,
    /// Earlier passwords, newest first, at most five.
    pub previous_passwords: Vec<PreviousPassword>,
    /// Passkeys, ES256 with their private keys.
    pub passkeys: Vec<Passkey>,
    /// Folder, spaces, dates.
    pub meta: Meta,
}

/// A code on its own: an authenticator entry, or a TOTP field on something that isn't a login.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Code {
    /// Its name.
    pub name: String,
    /// A base32 seed or an `otpauth://` link.
    pub value: String,
    /// The note.
    pub notes: Option<String>,
    /// Folder, spaces, dates.
    pub meta: Meta,
}

/// A note.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Note {
    /// Its title.
    pub name: String,
    /// The text.
    pub text: Option<String>,
    /// Custom fields.
    pub fields: Vec<CustomField>,
    /// Folder, spaces, dates.
    pub meta: Meta,
}

/// A payment card.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Card {
    /// Its name.
    pub name: String,
    /// The cardholder.
    pub cardholder: Option<String>,
    /// The number as digits (spaces and dashes dropped).
    pub number: Option<String>,
    /// The brand: Visa, Mastercard, Amex, Discover, Diners, JCB, UnionPay or Maestro.
    pub brand: Option<String>,
    /// 1 to 12.
    pub exp_month: Option<u8>,
    /// Four digits.
    pub exp_year: Option<u16>,
    /// The security code.
    pub code: Option<String>,
    /// The PIN.
    pub pin: Option<String>,
    /// "Valid from" month.
    pub valid_from_month: Option<u8>,
    /// "Valid from" year.
    pub valid_from_year: Option<u16>,
    /// The note.
    pub notes: Option<String>,
    /// Custom fields.
    pub fields: Vec<CustomField>,
    /// Folder, spaces, dates.
    pub meta: Meta,
}

/// One postal address.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Address {
    /// Up to three lines.
    pub lines: Vec<String>,
    /// City or town.
    pub city: Option<String>,
    /// State, province or region.
    pub region: Option<String>,
    /// Postal or zip code.
    pub postal_code: Option<String>,
    /// Country.
    pub country: Option<String>,
}

/// What an identity document is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DocumentKind {
    /// A passport.
    Passport,
    /// A driver's licence.
    DriversLicence,
    /// An identity card.
    IdCard,
    /// A tax or social security number.
    TaxNumber,
    /// Anything else (a membership, an outdoor licence).
    #[default]
    Other,
}

/// An identity document. Its number is a secret.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct IdDocument {
    /// What it is.
    pub kind: DocumentKind,
    /// Its number.
    pub number: Option<String>,
    /// Issuing country.
    pub issuing_country: Option<String>,
    /// Issuing authority.
    pub issuing_authority: Option<String>,
    /// `yyyy-mm-dd`.
    pub issued_on: Option<String>,
    /// `yyyy-mm-dd`.
    pub expires_on: Option<String>,
}

/// A person's details.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Identity {
    /// Its name.
    pub name: String,
    /// Mr, Ms, Dr.
    pub title: Option<String>,
    /// Given name.
    pub given_name: Option<String>,
    /// Middle name.
    pub middle_name: Option<String>,
    /// Family name.
    pub family_name: Option<String>,
    /// Company.
    pub company: Option<String>,
    /// Email.
    pub email: Option<String>,
    /// Phone.
    pub phone: Option<String>,
    /// Username.
    pub username: Option<String>,
    /// `yyyy-mm-dd`.
    pub birth_date: Option<String>,
    /// The address.
    pub address: Option<Address>,
    /// Passport, licence, tax number and the like.
    pub documents: Vec<IdDocument>,
    /// The note.
    pub notes: Option<String>,
    /// Custom fields.
    pub fields: Vec<CustomField>,
    /// Folder, spaces, dates.
    pub meta: Meta,
}

/// An SSH key.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SshKey {
    /// Its name.
    pub name: String,
    /// The private key as exported (OpenSSH or PKCS#8 PEM).
    pub private_key: String,
    /// The public key.
    pub public_key: Option<String>,
    /// The fingerprint.
    pub fingerprint: Option<String>,
    /// The note.
    pub notes: Option<String>,
    /// Custom fields.
    pub fields: Vec<CustomField>,
    /// Folder, spaces, dates.
    pub meta: Meta,
}

/// The kind of entry a file belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ItemKind {
    /// A [`Login`].
    Login,
    /// A [`Code`].
    Code,
    /// A [`Note`].
    Note,
    /// A [`Card`].
    Card,
    /// An [`Identity`].
    Identity,
    /// An [`SshKey`].
    SshKey,
}

/// An entry of a batch, by kind and index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemRef {
    /// Which list.
    pub kind: ItemKind,
    /// Index into that list.
    pub index: usize,
}

/// A file from the export (a 1Password document, a KeePass attachment, a Proton Pass file). The
/// client encrypts it and uploads it through `POST /kem/v1/items/{id}/files`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ImportFile {
    /// The file name.
    pub name: String,
    /// The media type, when known.
    pub media_type: Option<String>,
    /// The bytes, as base64 in JSON.
    #[serde(with = "b64_bytes")]
    pub data: Vec<u8>,
    /// The entry it is attached to; `None` is a file with no entry.
    pub owner: Option<ItemRef>,
}

/// Why an entry was left out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SkipReason {
    /// In the trash.
    Trashed,
    /// A kind of item Kemlock doesn't have (the detail names it).
    UnsupportedKind,
    /// A passkey whose algorithm Kemlock doesn't keep.
    UnsupportedPasskey,
    /// A passkey or key that is damaged or missing what it needs.
    BadKey,
    /// Missing what makes it an entry, or damaged.
    Malformed,
    /// Over the entry limit; `count` says how many.
    OverLimit,
    /// A file that was too large or over the ZIP limits.
    FileOverLimit,
    /// Anything else, with the detail.
    #[default]
    Other,
}

/// An entry that was left out, and why.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Skipped {
    /// The entry's title, when it has one. Never a secret.
    pub name: Option<String>,
    /// Why.
    pub reason: SkipReason,
    /// More, such as the name of an unsupported kind.
    pub detail: Option<String>,
    /// How many entries this stands for (more than one only for [`SkipReason::OverLimit`]).
    pub count: usize,
}

/// What one export held.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportBatch {
    /// The format it was read as.
    pub format: Format,
    /// Folders, parents before children.
    pub folders: Vec<Folder>,
    /// Shared vaults, collections and shared folders.
    pub spaces: Vec<SharedVault>,
    /// Logins.
    pub logins: Vec<Login>,
    /// Codes on their own.
    pub codes: Vec<Code>,
    /// Notes.
    pub notes: Vec<Note>,
    /// Cards.
    pub cards: Vec<Card>,
    /// Identities.
    pub identities: Vec<Identity>,
    /// SSH keys.
    pub ssh_keys: Vec<SshKey>,
    /// Files.
    pub files: Vec<ImportFile>,
    /// Entries left out.
    pub skipped: Vec<Skipped>,
}

impl ImportBatch {
    /// An empty batch for `format`.
    pub fn new(format: Format) -> ImportBatch {
        ImportBatch {
            format,
            folders: Vec::new(),
            spaces: Vec::new(),
            logins: Vec::new(),
            codes: Vec::new(),
            notes: Vec::new(),
            cards: Vec::new(),
            identities: Vec::new(),
            ssh_keys: Vec::new(),
            files: Vec::new(),
            skipped: Vec::new(),
        }
    }

    /// Logins, codes, notes, cards, identities and keys together.
    pub fn entry_count(&self) -> usize {
        self.logins.len()
            + self.codes.len()
            + self.notes.len()
            + self.cards.len()
            + self.identities.len()
            + self.ssh_keys.len()
    }

    /// How many entries were left out, counting each [`Skipped::count`].
    pub fn skipped_count(&self) -> usize {
        self.skipped.iter().map(|s| s.count.max(1)).sum()
    }
}

/// `Vec<u8>` as a base64 string in serde formats.
mod b64_bytes {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(bytes))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(d)?;
        STANDARD
            .decode(text.as_bytes())
            .map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_batch_round_trips_through_json() {
        let mut batch = ImportBatch::new(Format::KeeperJson);
        batch.logins.push(Login {
            name: "Mail".into(),
            uris: vec![UriRule {
                uri: "https://mail.example".into(),
                match_rule: Some(UriMatch::Host),
            }],
            ..Login::default()
        });
        batch.files.push(ImportFile {
            name: "a.txt".into(),
            data: vec![1, 2, 3, 255],
            owner: Some(ItemRef {
                kind: ItemKind::Login,
                index: 0,
            }),
            ..ImportFile::default()
        });
        let json = serde_json::to_string(&batch).expect("serialise");
        assert!(json.contains("\"AQID/w==\""));
        let back: ImportBatch = serde_json::from_str(&json).expect("parse");
        assert_eq!(back, batch);
    }

    #[test]
    fn match_numbers_follow_bitwarden() {
        for n in 0..=5 {
            assert_eq!(
                UriMatch::from_number(n).map(|m| i64::from(m.number())),
                Some(n)
            );
        }
        assert_eq!(UriMatch::from_number(9), None);
    }

    #[test]
    fn every_format_has_a_source_name() {
        for f in Format::ALL {
            assert!(!f.source_name().is_empty());
        }
    }

    #[test]
    fn counts_add_up() {
        let mut batch = ImportBatch::new(Format::ChromeCsv);
        batch.notes.push(Note::default());
        batch.cards.push(Card::default());
        batch.skipped.push(Skipped {
            count: 5,
            reason: SkipReason::OverLimit,
            ..Skipped::default()
        });
        batch.skipped.push(Skipped::default());
        assert_eq!(batch.entry_count(), 2);
        assert_eq!(batch.skipped_count(), 6);
    }
}
