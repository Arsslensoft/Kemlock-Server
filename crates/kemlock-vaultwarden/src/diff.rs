//! What changed between two snapshots taken minutes apart: the first while Vaultwarden runs, the
//! second after it stops.
//!
//! Rows are compared by primary key. A row in the second snapshot and not the first is added; a
//! row in both with different cells is changed (the diff names the columns); a row in the first
//! and not the second is removed. Removal needs a diff because a deleted row leaves nothing
//! behind to find by date.

use crate::snapshot::{DataFiles, RowKey, Table, VaultwardenSnapshot, key_string};
use std::collections::BTreeMap;
use std::fmt;

/// One row that exists in both snapshots with different cells.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RowChange {
    pub key: RowKey,
    /// The columns whose values differ.
    pub columns: Vec<&'static str>,
}

/// What changed in one table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TableDiff {
    pub table: &'static str,
    pub added: Vec<RowKey>,
    pub changed: Vec<RowChange>,
    pub removed: Vec<RowKey>,
}

impl TableDiff {
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.changed.is_empty() && self.removed.is_empty()
    }

    pub fn len(&self) -> usize {
        self.added.len() + self.changed.len() + self.removed.len()
    }
}

/// What changed in a folder of files, by path under the folder and size.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FileDiff {
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub resized: Vec<String>,
}

impl FileDiff {
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.resized.is_empty()
    }

    fn between(first: &BTreeMap<String, u64>, second: &BTreeMap<String, u64>) -> FileDiff {
        let mut out = FileDiff::default();
        for (path, size) in second {
            match first.get(path) {
                None => out.added.push(path.clone()),
                Some(old) if old != size => out.resized.push(path.clone()),
                Some(_) => {}
            }
        }
        for path in first.keys() {
            if !second.contains_key(path) {
                out.removed.push(path.clone());
            }
        }
        out
    }
}

/// A row the second pass must delete from the copy made by the first.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Deletion {
    pub table: &'static str,
    pub key: RowKey,
}

/// Everything that changed between two snapshots.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotDiff {
    /// Only tables with changes.
    pub tables: Vec<TableDiff>,
    pub attachment_files: FileDiff,
    pub send_files: FileDiff,
    pub rsa_key_changed: bool,
    pub config_changed: bool,
}

/// Compares two snapshots of the same server.
pub fn diff(first: &VaultwardenSnapshot, second: &VaultwardenSnapshot) -> SnapshotDiff {
    let mut tables = Vec::new();
    for (old, new) in first.tables().into_iter().zip(second.tables()) {
        let d = diff_table(old, new);
        if !d.is_empty() {
            tables.push(d);
        }
    }
    let (a, b): (&DataFiles, &DataFiles) = (&first.files, &second.files);
    SnapshotDiff {
        tables,
        attachment_files: FileDiff::between(&a.attachment_files, &b.attachment_files),
        send_files: FileDiff::between(&a.send_files, &b.send_files),
        rsa_key_changed: a.rsa_key_pem != b.rsa_key_pem || a.rsa_pub_pem != b.rsa_pub_pem,
        config_changed: a.config_json != b.config_json,
    }
}

fn diff_table(old: &Table, new: &Table) -> TableDiff {
    let spec = new.spec();
    let mut out = TableDiff {
        table: spec.name,
        added: Vec::new(),
        changed: Vec::new(),
        removed: Vec::new(),
    };
    for key in new.keys() {
        match (old.cells(key), new.cells(key)) {
            (None, _) => out.added.push(key.clone()),
            (Some(before), Some(after)) if before != after => {
                let columns = spec
                    .cols
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| before.get(*i) != after.get(*i))
                    .map(|(_, c)| c.name)
                    .collect();
                out.changed.push(RowChange {
                    key: key.clone(),
                    columns,
                });
            }
            _ => {}
        }
    }
    for key in old.keys() {
        if new.cells(key).is_none() {
            out.removed.push(key.clone());
        }
    }
    out
}

impl SnapshotDiff {
    /// Nothing changed at all.
    pub fn is_empty(&self) -> bool {
        self.tables.is_empty()
            && self.attachment_files.is_empty()
            && self.send_files.is_empty()
            && !self.rsa_key_changed
            && !self.config_changed
    }

    /// The diff of one table, if it changed.
    pub fn table(&self, name: &str) -> Option<&TableDiff> {
        self.tables.iter().find(|t| t.table == name)
    }

    /// How many rows were added, changed or removed in all.
    pub fn row_changes(&self) -> usize {
        self.tables.iter().map(TableDiff::len).sum()
    }

    /// The rows the second pass deletes from the first pass's copy.
    pub fn deletions(&self) -> Vec<Deletion> {
        self.tables
            .iter()
            .flat_map(|t| {
                t.removed.iter().map(move |key| Deletion {
                    table: t.table,
                    key: key.clone(),
                })
            })
            .collect()
    }
}

impl fmt::Display for SnapshotDiff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_empty() {
            return writeln!(f, "nothing changed between the two copies");
        }
        for t in &self.tables {
            writeln!(
                f,
                "{:<22} {} added, {} changed, {} removed",
                t.table,
                t.added.len(),
                t.changed.len(),
                t.removed.len()
            )?;
            for key in &t.removed {
                writeln!(f, "  removed {}", key_string(key))?;
            }
        }
        for (name, files) in [
            ("attachment files", &self.attachment_files),
            ("send files", &self.send_files),
        ] {
            if !files.is_empty() {
                writeln!(
                    f,
                    "{:<22} {} added, {} resized, {} removed",
                    name,
                    files.added.len(),
                    files.resized.len(),
                    files.removed.len()
                )?;
            }
        }
        if self.rsa_key_changed {
            writeln!(f, "rsa_key.pem changed")?;
        }
        if self.config_changed {
            writeln!(f, "config.json changed")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema;
    use crate::snapshot::{Cell, SnapshotMeta};

    fn snapshot(users: Vec<(&str, &str)>, files: DataFiles) -> VaultwardenSnapshot {
        let rows = users
            .into_iter()
            .map(|(uuid, name)| {
                let mut cells = vec![Cell::Null; schema::USERS.cols.len()];
                cells[schema::USERS.index_of("uuid").expect("column")] =
                    Cell::Text(uuid.to_owned());
                cells[schema::USERS.index_of("name").expect("column")] =
                    Cell::Text(name.to_owned());
                cells
            })
            .collect();
        VaultwardenSnapshot::from_tables(
            SnapshotMeta {
                database: "SQLite",
                release: "1.37.5",
                source: "test".into(),
            },
            vec![Table::from_rows(&schema::USERS, rows)],
            files,
        )
    }

    #[test]
    fn added_changed_and_removed_rows_are_found_by_key() {
        let first = snapshot(
            vec![("a", "Ann"), ("b", "Bob"), ("c", "Cy")],
            DataFiles::default(),
        );
        let second = snapshot(
            vec![("a", "Ann"), ("b", "Robert"), ("d", "Di")],
            DataFiles::default(),
        );
        let d = diff(&first, &second);
        let users = d.table("users").expect("users changed");
        assert_eq!(users.added, vec![vec!["d".to_owned()]]);
        assert_eq!(users.removed, vec![vec!["c".to_owned()]]);
        assert_eq!(
            users.changed,
            vec![RowChange {
                key: vec!["b".to_owned()],
                columns: vec!["name"],
            }]
        );
        assert_eq!(d.tables.len(), 1, "unchanged tables are left out");
        assert_eq!(d.row_changes(), 3);
        assert_eq!(
            d.deletions(),
            vec![Deletion {
                table: "users",
                key: vec!["c".to_owned()]
            }]
        );
    }

    #[test]
    fn identical_snapshots_have_an_empty_diff() {
        let a = snapshot(vec![("a", "Ann")], DataFiles::default());
        let d = diff(&a, &a.clone());
        assert!(d.is_empty());
        assert!(d.deletions().is_empty());
        assert!(d.to_string().contains("nothing changed"));
    }

    #[test]
    fn files_keys_and_config_are_compared_too() {
        let mut one = DataFiles::default();
        one.attachment_files.insert("c1/a1".into(), 10);
        one.attachment_files.insert("c1/a2".into(), 20);
        one.rsa_key_pem = Some(b"key".to_vec());
        let mut two = DataFiles::default();
        two.attachment_files.insert("c1/a1".into(), 11);
        two.attachment_files.insert("c1/a3".into(), 5);
        two.rsa_key_pem = Some(b"key".to_vec());
        two.config_json = Some("{}".into());
        let d = diff(&snapshot(vec![], one), &snapshot(vec![], two));
        assert_eq!(d.attachment_files.added, vec!["c1/a3".to_owned()]);
        assert_eq!(d.attachment_files.removed, vec!["c1/a2".to_owned()]);
        assert_eq!(d.attachment_files.resized, vec!["c1/a1".to_owned()]);
        assert!(!d.rsa_key_changed);
        assert!(d.config_changed);
        assert!(!d.is_empty());
    }
}
