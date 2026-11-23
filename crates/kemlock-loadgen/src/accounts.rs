//! The file `seed` writes and the other commands and k6 read: who was made, what they hold, and
//! where each one's sync cursor stood when seeding ended.

use crate::device::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// A valid ciphertext and item key (base64url) for k6 to reuse in its puts. The server checks
/// only their lengths, and a random 2 KiB value is not one k6 can make with the right trailing
/// bits, so the seeder hands over two that decode.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Sample {
    pub(crate) ciphertext: String,
    pub(crate) item_key: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AccountEntry {
    pub(crate) index: usize,
    pub(crate) email: String,
    pub(crate) user_id: String,
    /// Every item the account holds, all at revision 1 after seeding.
    pub(crate) item_ids: Vec<String>,
    /// The sync cursor after the last seeded item: a `since` that answers 304.
    pub(crate) cursor: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AccountsFile {
    pub(crate) base_url: String,
    pub(crate) domain: String,
    pub(crate) sample: Sample,
    pub(crate) accounts: Vec<AccountEntry>,
}

impl AccountsFile {
    pub(crate) fn load(path: &Path) -> Result<AccountsFile> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("can't read {}: {e}", path.display()))?;
        let file: AccountsFile = serde_json::from_str(&text)
            .map_err(|e| format!("{} isn't an accounts file: {e}", path.display()))?;
        Ok(file)
    }

    pub(crate) fn save(&self, path: &Path) -> Result<()> {
        std::fs::write(path, serde_json::to_string(self)?)
            .map_err(|e| format!("can't write {}: {e}", path.display()))?;
        Ok(())
    }
}

/// The email of the n-th account.
pub(crate) fn email(prefix: &str, index: usize) -> String {
    format!("{prefix}-{index:04}@example.org")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emails_are_stable_and_distinct() {
        assert_eq!(email("load", 7), "load-0007@example.org");
        assert_ne!(email("load", 1), email("load", 2));
    }

    #[test]
    fn a_file_round_trips_in_camel_case() {
        let file = AccountsFile {
            base_url: "http://127.0.0.1:8080".to_owned(),
            domain: "http://127.0.0.1:8080".to_owned(),
            sample: Sample {
                ciphertext: "AAAA".to_owned(),
                item_key: "BBBB".to_owned(),
            },
            accounts: vec![AccountEntry {
                index: 0,
                email: email("load", 0),
                user_id: "u".to_owned(),
                item_ids: vec!["i".to_owned()],
                cursor: "c".to_owned(),
            }],
        };
        let json = serde_json::to_string(&file).expect("serializes");
        assert!(json.contains("\"itemIds\""));
        assert!(json.contains("\"baseUrl\""));
        let back: AccountsFile = serde_json::from_str(&json).expect("parses");
        assert_eq!(back.accounts[0].item_ids, vec!["i".to_owned()]);
    }
}
