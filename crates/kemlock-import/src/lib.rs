//! Reads the exports of other password managers into one neutral batch.
//!
//! Pure Rust, no I/O: bytes in, an [`ImportBatch`] out. It runs natively in the `kemlock` CLI and
//! compiles to WebAssembly for the web vault's import worker. Every format has a module with
//! `parse(bytes, &Context)`; [`detect`] finds the format from the content, and [`parse`] does both.
//!
//! ```
//! use kemlock_import::{Context, Limits, chrome};
//!
//! let csv = "name,url,username,password,note\nMail,https://mail.example,ada,hunter2,\n";
//! let limits = Limits::default();
//! let batch = chrome::parse(csv.as_bytes(), &Context::new(&limits)).unwrap();
//! assert_eq!(batch.logins[0].name, "Mail");
//! ```
//!
//! # Formats
//!
//! Chrome, Edge and Google CSV ([`chrome`]); Safari and Apple Passwords CSV ([`safari`]); Firefox
//! CSV ([`firefox`]); Bitwarden JSON, plain or password-protected ([`bitwarden`]), and CSV
//! ([`bitwarden_csv`]); LastPass CSV ([`lastpass`]); 1Password 1PUX ([`onepassword`]) and CSV
//! ([`onepassword_csv`]); Dashlane's CSV ZIP ([`dashlane`]); NordPass CSV ([`nordpass`]); Keeper
//! JSON ([`keeper`]); Proton Pass JSON, ZIP and passphrase-encrypted PGP ([`protonpass`]); KeePass
//! KDBX 3.1 and 4 with a key file ([`kdbx`]); Enpass JSON ([`enpass`]); RoboForm CSV
//! ([`roboform`]).
//!
//! # Limits
//!
//! [`Limits`] caps the file size, the entry count, ZIP entries and inflated size, and key
//! derivation cost; every parser applies them before the work they bound. An entry a parser can't
//! use is listed in [`ImportBatch::skipped`] with its reason.
//!
//! # Licence
//!
//! The parsers ported from Bitwarden's `libs/importer` (GPL-3.0) say so at the top of each file,
//! and `NOTICE` lists them. The crate is AGPL-3.0-only, which GPL-3.0 code may be combined into.

pub mod bitwarden;
pub mod bitwarden_csv;
pub mod bitwarden_export;
pub mod builder;
pub mod bwcrypto;
pub mod chrome;
pub mod context;
pub mod csv;
pub mod dashlane;
pub mod detect;
pub mod enpass;
pub mod error;
pub mod firefox;
pub mod kdbx;
pub mod keeper;
pub mod lastpass;
pub mod limits;
pub mod model;
pub mod nordpass;
pub mod onepassword;
pub mod onepassword_csv;
pub mod passkey;
pub mod protonpass;
pub mod roboform;
pub mod safari;
pub mod util;
pub mod zip;

pub use context::Context;
pub use detect::{Detected, ImportOptions, detect, parse, parse_as};
pub use error::{ImportError, Result};
pub use limits::Limits;
pub use model::{Format, ImportBatch};
