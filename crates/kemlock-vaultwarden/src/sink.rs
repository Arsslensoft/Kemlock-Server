//! The store side of the move.
//!
//! [`ImportSink`] is what Kemlock Server's store has to offer the importer. This crate defines it
//! and tests the mapping against a recording sink; `kemlock-store-sql` implements it as
//! `SqlImportSink`, over the tables of the Bitwarden API and the data folder's files, and
//! `kemlock-cli import-vaultwarden --apply` hands that to [`apply`], once, or twice with
//! `--twice` (the second time with only what changed). One pass is one transaction there:
//! [`ImportSink::finish`] commits it.
//!
//! Every method is an idempotent upsert keyed by the primary key of what it puts, so the second
//! pass of a two-pass copy can run the same methods again with only what changed, then delete
//! what was removed.

use crate::diff::Deletion;
use crate::mapping::{
    FileCopy, MappedAccount, MappedAttachment, MappedCipherState, MappedFolder, MappedImport,
    MappedItem, MappedRsaKey,
};
use crate::schema;
use crate::settings::MappedSettings;
use crate::snapshot::{RowKey, Table};
use std::collections::BTreeMap;
use std::future::Future;

/// Where the mapped data goes. See the module docs.
pub trait ImportSink: Send {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Upserts accounts in Compatible mode, with every Bitwarden column kept.
    fn put_accounts(
        &mut self,
        accounts: &[MappedAccount],
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    fn put_folders(
        &mut self,
        folders: &[MappedFolder],
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Upserts `bw` items.
    fn put_items(
        &mut self,
        items: &[MappedItem],
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    fn put_cipher_states(
        &mut self,
        states: &[MappedCipherState],
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    fn put_attachments(
        &mut self,
        attachments: &[MappedAttachment],
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Upserts the rows of a carried table (named as in Vaultwarden) as they are.
    fn put_carried(
        &mut self,
        table: &Table,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    fn put_settings(
        &mut self,
        settings: &MappedSettings,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Keeps `rsa_key.pem`, so tokens signed with it still verify.
    fn put_rsa_key(
        &mut self,
        key: &MappedRsaKey,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Copies a file into file storage, unchanged.
    fn copy_file(
        &mut self,
        file: &FileCopy,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Deletes rows by their Vaultwarden table and primary key (what a second pass learned from
    /// the diff). A row that is already gone is not an error.
    fn delete_rows(
        &mut self,
        table: &'static str,
        keys: &[RowKey],
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Makes everything put so far durable, or does nothing for a sink that wrote as it went.
    fn finish(&mut self) -> impl Future<Output = Result<(), Self::Error>> + Send;
}

/// How much was put.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ApplyReport {
    pub accounts: usize,
    pub folders: usize,
    pub items: usize,
    pub cipher_states: usize,
    pub attachments: usize,
    pub carried_rows: usize,
    pub settings: usize,
    pub rsa_key: bool,
    pub files: usize,
    pub file_bytes: u64,
    pub deleted_rows: usize,
}

/// Puts a mapped import into a sink, then deletes the rows of `deletions`. Parents go before
/// what refers to them: accounts, folders, items, then everything else; files last, because
/// they are the slow part.
pub async fn apply<S: ImportSink>(
    mapped: &MappedImport,
    deletions: &[Deletion],
    sink: &mut S,
) -> Result<ApplyReport, S::Error> {
    let mut report = ApplyReport::default();

    sink.put_accounts(&mapped.accounts).await?;
    report.accounts = mapped.accounts.len();
    sink.put_folders(&mapped.folders).await?;
    report.folders = mapped.folders.len();
    sink.put_items(&mapped.items).await?;
    report.items = mapped.items.len();
    sink.put_cipher_states(&mapped.cipher_states).await?;
    report.cipher_states = mapped.cipher_states.len();
    sink.put_attachments(&mapped.attachments).await?;
    report.attachments = mapped.attachments.len();

    for table in &mapped.carried {
        if !table.is_empty() {
            sink.put_carried(table).await?;
            report.carried_rows += table.len();
        }
    }
    if !mapped.settings.values.is_empty() || !mapped.settings.ignored.is_empty() {
        sink.put_settings(&mapped.settings).await?;
        report.settings = mapped.settings.values.len();
    }
    if let Some(key) = &mapped.rsa_key {
        sink.put_rsa_key(key).await?;
        report.rsa_key = true;
    }
    for file in &mapped.files {
        sink.copy_file(file).await?;
        report.files += 1;
        report.file_bytes += file.size;
    }

    // Children before parents, so a store with foreign keys never sees a dangling row.
    let mut by_table: BTreeMap<&'static str, Vec<RowKey>> = BTreeMap::new();
    for deletion in deletions {
        by_table
            .entry(deletion.table)
            .or_default()
            .push(deletion.key.clone());
    }
    for spec in schema::TABLES.iter().rev() {
        if let Some(keys) = by_table.get(spec.name) {
            sink.delete_rows(spec.name, keys).await?;
            report.deleted_rows += keys.len();
        }
    }

    sink.finish().await?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema;
    use crate::snapshot::Cell;
    use std::convert::Infallible;

    /// Records the calls it gets, in order.
    #[derive(Debug, Default)]
    struct Recording {
        calls: Vec<String>,
    }

    impl ImportSink for Recording {
        type Error = Infallible;

        async fn put_accounts(&mut self, a: &[MappedAccount]) -> Result<(), Infallible> {
            self.calls.push(format!("accounts {}", a.len()));
            Ok(())
        }
        async fn put_folders(&mut self, f: &[MappedFolder]) -> Result<(), Infallible> {
            self.calls.push(format!("folders {}", f.len()));
            Ok(())
        }
        async fn put_items(&mut self, i: &[MappedItem]) -> Result<(), Infallible> {
            self.calls.push(format!("items {}", i.len()));
            Ok(())
        }
        async fn put_cipher_states(&mut self, s: &[MappedCipherState]) -> Result<(), Infallible> {
            self.calls.push(format!("states {}", s.len()));
            Ok(())
        }
        async fn put_attachments(&mut self, a: &[MappedAttachment]) -> Result<(), Infallible> {
            self.calls.push(format!("attachments {}", a.len()));
            Ok(())
        }
        async fn put_carried(&mut self, t: &Table) -> Result<(), Infallible> {
            self.calls.push(format!("carried {} {}", t.name(), t.len()));
            Ok(())
        }
        async fn put_settings(&mut self, s: &MappedSettings) -> Result<(), Infallible> {
            self.calls.push(format!("settings {}", s.values.len()));
            Ok(())
        }
        async fn put_rsa_key(&mut self, _: &MappedRsaKey) -> Result<(), Infallible> {
            self.calls.push("rsa".to_owned());
            Ok(())
        }
        async fn copy_file(&mut self, f: &FileCopy) -> Result<(), Infallible> {
            self.calls.push(format!("copy {}", f.storage_key));
            Ok(())
        }
        async fn delete_rows(&mut self, t: &'static str, k: &[RowKey]) -> Result<(), Infallible> {
            self.calls.push(format!("delete {t} {}", k.len()));
            Ok(())
        }
        async fn finish(&mut self) -> Result<(), Infallible> {
            self.calls.push("finish".to_owned());
            Ok(())
        }
    }

    fn run<F: Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("a runtime")
            .block_on(future)
    }

    #[test]
    fn parents_go_first_and_deletions_children_first() {
        let mut mapped = MappedImport::default();
        let mut carried = Table::empty(&schema::INVITATIONS);
        carried.insert(vec![Cell::Text("a@x.org".into())]);
        mapped.carried.push(carried);
        mapped.carried.push(Table::empty(&schema::SENDS));
        let deletions = vec![
            Deletion {
                table: "users",
                key: vec!["u".into()],
            },
            Deletion {
                table: "attachments",
                key: vec!["a".into()],
            },
            Deletion {
                table: "attachments",
                key: vec!["b".into()],
            },
        ];
        let mut sink = Recording::default();
        let report = run(apply(&mapped, &deletions, &mut sink)).expect("infallible");
        assert_eq!(
            sink.calls,
            vec![
                "accounts 0",
                "folders 0",
                "items 0",
                "states 0",
                "attachments 0",
                "carried invitations 1",
                "delete attachments 2",
                "delete users 1",
                "finish",
            ]
        );
        assert_eq!(report.carried_rows, 1);
        assert_eq!(report.deleted_rows, 3);
    }
}
