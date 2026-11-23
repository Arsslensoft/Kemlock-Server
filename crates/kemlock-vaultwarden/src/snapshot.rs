//! A neutral copy of a Vaultwarden server's data: its rows exactly as stored (nothing decrypted,
//! nothing interpreted) and the files beside them.

use crate::schema::{self, Kind, TableSpec};
use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;

/// One cell of a row.
#[derive(Clone, PartialEq, Eq)]
pub enum Cell {
    Null,
    /// Integers and booleans (0 or 1).
    Int(i64),
    /// Text, and dates as the database prints them (`2024-05-01 10:00:00.123456`).
    Text(String),
    Bytes(Vec<u8>),
}

impl fmt::Debug for Cell {
    // Rows hold password hashes and wrapped keys; keep them out of logs.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Cell::Null => f.write_str("NULL"),
            Cell::Int(n) => write!(f, "{n}"),
            Cell::Text(s) => write!(f, "text({} bytes)", s.len()),
            Cell::Bytes(b) => write!(f, "blob({} bytes)", b.len()),
        }
    }
}

impl Cell {
    /// How a key column prints, for row keys and messages.
    pub fn key_text(&self) -> String {
        match self {
            Cell::Null => String::new(),
            Cell::Int(n) => n.to_string(),
            Cell::Text(s) => s.clone(),
            Cell::Bytes(b) => b.iter().map(|x| format!("{x:02x}")).collect(),
        }
    }
}

/// A row's primary key: the key columns' values as text, in the spec's key order.
pub type RowKey = Vec<String>;

/// Prints a key as `a/b`.
pub fn key_string(key: &[String]) -> String {
    key.join("/")
}

/// A borrowed row with its column names, for reading cells by name.
#[derive(Clone, Copy)]
pub struct RowRef<'a> {
    spec: &'static TableSpec,
    cells: &'a [Cell],
}

impl fmt::Debug for RowRef<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} row {}", self.spec.name, self.key_text())
    }
}

impl<'a> RowRef<'a> {
    pub fn new(spec: &'static TableSpec, cells: &'a [Cell]) -> Self {
        RowRef { spec, cells }
    }

    pub fn table(&self) -> &'static str {
        self.spec.name
    }

    /// The cell of a column; `Null` for a column the table doesn't have.
    pub fn cell(&self, column: &str) -> &'a Cell {
        const NULL: &Cell = &Cell::Null;
        self.spec
            .index_of(column)
            .and_then(|i| self.cells.get(i))
            .unwrap_or(NULL)
    }

    pub fn text(&self, column: &str) -> Option<&'a str> {
        match self.cell(column) {
            Cell::Text(s) => Some(s.as_str()),
            _ => None,
        }
    }

    pub fn int(&self, column: &str) -> Option<i64> {
        match self.cell(column) {
            Cell::Int(n) => Some(*n),
            _ => None,
        }
    }

    pub fn bool(&self, column: &str) -> Option<bool> {
        self.int(column).map(|n| n != 0)
    }

    pub fn bytes(&self, column: &str) -> Option<&'a [u8]> {
        match self.cell(column) {
            Cell::Bytes(b) => Some(b.as_slice()),
            _ => None,
        }
    }

    /// The row's primary key.
    pub fn key(&self) -> RowKey {
        self.spec
            .key_indexes()
            .into_iter()
            .map(|i| self.cells.get(i).map(Cell::key_text).unwrap_or_default())
            .collect()
    }

    /// The key as `a/b`, for messages.
    pub fn key_text(&self) -> String {
        key_string(&self.key())
    }

    /// The row as a JSON object keyed by column name: text and integers as they are, `NULL` as
    /// `null` and bytes as `{"hex": "…"}`. This is what a store keeps of a carried row.
    pub fn to_json(&self) -> serde_json::Value {
        let mut map = serde_json::Map::new();
        for (column, cell) in self.spec.cols.iter().zip(self.cells.iter()) {
            let value = match cell {
                Cell::Null => serde_json::Value::Null,
                Cell::Int(n) => serde_json::Value::from(*n),
                Cell::Text(s) => serde_json::Value::String(s.clone()),
                Cell::Bytes(_) => serde_json::json!({ "hex": cell.key_text() }),
            };
            map.insert(column.name.to_owned(), value);
        }
        serde_json::Value::Object(map)
    }
}

/// One table's rows, keyed by primary key.
#[derive(Clone, PartialEq, Eq)]
pub struct Table {
    spec: &'static TableSpec,
    rows: BTreeMap<RowKey, Vec<Cell>>,
}

impl fmt::Debug for Table {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Table({}, {} rows)", self.spec.name, self.rows.len())
    }
}

impl Table {
    pub fn empty(spec: &'static TableSpec) -> Self {
        Table {
            spec,
            rows: BTreeMap::new(),
        }
    }

    /// Builds a table from rows of cells in the spec's column order. A row with the same key as
    /// an earlier one replaces it.
    pub fn from_rows(spec: &'static TableSpec, rows: Vec<Vec<Cell>>) -> Self {
        let mut table = Table::empty(spec);
        for cells in rows {
            table.insert(cells);
        }
        table
    }

    /// Adds a row of cells in the spec's column order.
    pub fn insert(&mut self, cells: Vec<Cell>) {
        let key = RowRef::new(self.spec, &cells).key();
        self.rows.insert(key, cells);
    }

    pub fn spec(&self) -> &'static TableSpec {
        self.spec
    }

    pub fn name(&self) -> &'static str {
        self.spec.name
    }

    pub fn len(&self) -> usize {
        self.rows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// The rows in key order.
    pub fn rows(&self) -> impl Iterator<Item = RowRef<'_>> {
        let spec = self.spec;
        self.rows
            .values()
            .map(move |cells| RowRef::new(spec, cells.as_slice()))
    }

    pub fn get(&self, key: &[String]) -> Option<RowRef<'_>> {
        self.rows
            .get(key)
            .map(|cells| RowRef::new(self.spec, cells.as_slice()))
    }

    pub fn keys(&self) -> impl Iterator<Item = &RowKey> {
        self.rows.keys()
    }

    /// The raw cells of a row, in the spec's column order.
    pub fn cells(&self, key: &[String]) -> Option<&[Cell]> {
        self.rows.get(key).map(Vec::as_slice)
    }

    /// The rows that are new or different compared with `older`.
    pub fn delta(&self, older: &Table) -> Table {
        let mut out = Table::empty(self.spec);
        for (key, cells) in &self.rows {
            if older.rows.get(key) != Some(cells) {
                out.rows.insert(key.clone(), cells.clone());
            }
        }
        out
    }

    /// The kind of a column, if the table has it.
    pub fn column_kind(&self, column: &str) -> Option<Kind> {
        self.spec
            .index_of(column)
            .and_then(|i| self.spec.cols.get(i))
            .map(|c| c.kind)
    }
}

/// Where the rows came from, for the plan and the report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotMeta {
    /// `SQLite`, `PostgreSQL` or `MySQL`.
    pub database: &'static str,
    /// The Vaultwarden release whose schema the database matched.
    pub release: &'static str,
    /// The folder or URL, with any password in the URL hidden.
    pub source: String,
}

/// The files beside the database.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct DataFiles {
    /// The data folder, when there is one.
    pub root: Option<PathBuf>,
    /// `attachments/`, when it exists.
    pub attachments_dir: Option<PathBuf>,
    /// `sends/`, when it exists.
    pub sends_dir: Option<PathBuf>,
    /// The attachment files found, as `<cipher>/<attachment>` with their sizes.
    pub attachment_files: BTreeMap<String, u64>,
    /// The send files found, as `<send>/<file>` with their sizes.
    pub send_files: BTreeMap<String, u64>,
    /// `rsa_key.pem`: the private key that signs Vaultwarden's tokens.
    pub rsa_key_pem: Option<Vec<u8>>,
    /// `rsa_key.pub.pem`, when it exists.
    pub rsa_pub_pem: Option<Vec<u8>>,
    /// `config.json`, as text.
    pub config_json: Option<String>,
}

impl fmt::Debug for DataFiles {
    // The private key stays out of logs.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DataFiles")
            .field("root", &self.root)
            .field("attachment_files", &self.attachment_files.len())
            .field("send_files", &self.send_files.len())
            .field("rsa_key", &self.rsa_key_pem.is_some())
            .field("config_json", &self.config_json.is_some())
            .finish()
    }
}

/// Everything a Vaultwarden server keeps, as it was when read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultwardenSnapshot {
    pub meta: SnapshotMeta,
    pub users: Table,
    pub devices: Table,
    pub ciphers: Table,
    pub folders: Table,
    pub folders_ciphers: Table,
    pub favorites: Table,
    pub archives: Table,
    pub attachments: Table,
    pub organizations: Table,
    pub users_organizations: Table,
    pub collections: Table,
    pub ciphers_collections: Table,
    pub users_collections: Table,
    pub groups: Table,
    pub collections_groups: Table,
    pub groups_users: Table,
    pub org_policies: Table,
    pub organization_api_key: Table,
    pub twofactor: Table,
    pub twofactor_incomplete: Table,
    pub emergency_access: Table,
    pub sends: Table,
    pub event: Table,
    pub auth_requests: Table,
    pub sso_users: Table,
    pub invitations: Table,
    pub files: DataFiles,
}

impl VaultwardenSnapshot {
    /// Builds a snapshot from tables read in any order; a table that is missing is empty.
    pub fn from_tables(meta: SnapshotMeta, tables: Vec<Table>, files: DataFiles) -> Self {
        let mut by_name: BTreeMap<&'static str, Table> =
            tables.into_iter().map(|t| (t.name(), t)).collect();
        let mut take = |spec: &'static TableSpec| {
            by_name
                .remove(spec.name)
                .unwrap_or_else(|| Table::empty(spec))
        };
        VaultwardenSnapshot {
            meta,
            users: take(&schema::USERS),
            devices: take(&schema::DEVICES),
            ciphers: take(&schema::CIPHERS),
            folders: take(&schema::FOLDERS),
            folders_ciphers: take(&schema::FOLDERS_CIPHERS),
            favorites: take(&schema::FAVORITES),
            archives: take(&schema::ARCHIVES),
            attachments: take(&schema::ATTACHMENTS),
            organizations: take(&schema::ORGANIZATIONS),
            users_organizations: take(&schema::USERS_ORGANIZATIONS),
            collections: take(&schema::COLLECTIONS),
            ciphers_collections: take(&schema::CIPHERS_COLLECTIONS),
            users_collections: take(&schema::USERS_COLLECTIONS),
            groups: take(&schema::GROUPS),
            collections_groups: take(&schema::COLLECTIONS_GROUPS),
            groups_users: take(&schema::GROUPS_USERS),
            org_policies: take(&schema::ORG_POLICIES),
            organization_api_key: take(&schema::ORGANIZATION_API_KEY),
            twofactor: take(&schema::TWOFACTOR),
            twofactor_incomplete: take(&schema::TWOFACTOR_INCOMPLETE),
            emergency_access: take(&schema::EMERGENCY_ACCESS),
            sends: take(&schema::SENDS),
            event: take(&schema::EVENT),
            auth_requests: take(&schema::AUTH_REQUESTS),
            sso_users: take(&schema::SSO_USERS),
            invitations: take(&schema::INVITATIONS),
            files,
        }
    }

    /// Every table, in the order of [`schema::TABLES`].
    pub fn tables(&self) -> Vec<&Table> {
        vec![
            &self.users,
            &self.devices,
            &self.ciphers,
            &self.folders,
            &self.folders_ciphers,
            &self.favorites,
            &self.archives,
            &self.attachments,
            &self.organizations,
            &self.users_organizations,
            &self.collections,
            &self.ciphers_collections,
            &self.users_collections,
            &self.groups,
            &self.collections_groups,
            &self.groups_users,
            &self.org_policies,
            &self.organization_api_key,
            &self.twofactor,
            &self.twofactor_incomplete,
            &self.emergency_access,
            &self.sends,
            &self.event,
            &self.auth_requests,
            &self.sso_users,
            &self.invitations,
        ]
    }

    /// A table by name.
    pub fn table(&self, name: &str) -> Option<&Table> {
        self.tables().into_iter().find(|t| t.name() == name)
    }

    /// How many rows the snapshot holds in all.
    pub fn row_count(&self) -> usize {
        self.tables().iter().map(|t| t.len()).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user_cells(uuid: &str, email: &str) -> Vec<Cell> {
        let mut cells = vec![Cell::Null; schema::USERS.cols.len()];
        cells[schema::USERS.index_of("uuid").expect("column")] = Cell::Text(uuid.to_owned());
        cells[schema::USERS.index_of("email").expect("column")] = Cell::Text(email.to_owned());
        cells[schema::USERS.index_of("enabled").expect("column")] = Cell::Int(1);
        cells
    }

    #[test]
    fn rows_are_keyed_and_read_by_column_name() {
        let table = Table::from_rows(
            &schema::USERS,
            vec![user_cells("b", "b@x.org"), user_cells("a", "a@x.org")],
        );
        assert_eq!(table.len(), 2);
        let first = table.rows().next().expect("a row");
        assert_eq!(first.text("email"), Some("a@x.org"));
        assert_eq!(first.bool("enabled"), Some(true));
        assert_eq!(first.key(), vec!["a".to_owned()]);
        // A column the table doesn't have, and a NULL one, both read as nothing.
        assert_eq!(first.text("nope"), None);
        assert_eq!(first.text("name"), None);
    }

    #[test]
    fn a_row_becomes_a_json_object_by_column_name() {
        let mut cells = user_cells("a", "a@x.org");
        cells[schema::USERS.index_of("password_hash").expect("column")] =
            Cell::Bytes(vec![0xAB, 0x01]);
        let table = Table::from_rows(&schema::USERS, vec![cells]);
        let json = table.rows().next().expect("a row").to_json();
        assert_eq!(json["uuid"], "a");
        assert_eq!(json["email"], "a@x.org");
        assert_eq!(json["enabled"], 1);
        assert_eq!(json["name"], serde_json::Value::Null);
        assert_eq!(json["password_hash"]["hex"], "ab01");
        assert_eq!(
            json.as_object().map(serde_json::Map::len),
            Some(schema::USERS.cols.len())
        );
    }

    #[test]
    fn composite_keys_follow_the_spec_order() {
        let table = Table::from_rows(
            &schema::FOLDERS_CIPHERS,
            vec![vec![
                Cell::Text("cipher".into()),
                Cell::Text("folder".into()),
            ]],
        );
        let row = table.rows().next().expect("a row");
        assert_eq!(row.key(), vec!["cipher".to_owned(), "folder".to_owned()]);
        assert_eq!(row.key_text(), "cipher/folder");
    }

    #[test]
    fn debug_output_hides_row_contents() {
        let table = Table::from_rows(&schema::USERS, vec![user_cells("a", "secret@x.org")]);
        let text = format!("{table:?} {:?}", table.rows().next().expect("a row"));
        assert!(!text.contains("secret"), "{text}");
        assert_eq!(
            format!("{:?}", Cell::Text("hunter2".into())),
            "text(7 bytes)"
        );
    }

    #[test]
    fn delta_keeps_new_and_changed_rows() {
        let old = Table::from_rows(
            &schema::USERS,
            vec![user_cells("a", "a@x.org"), user_cells("b", "b@x.org")],
        );
        let new = Table::from_rows(
            &schema::USERS,
            vec![
                user_cells("a", "a@x.org"),
                user_cells("b", "b2@x.org"),
                user_cells("c", "c@x.org"),
            ],
        );
        let delta = new.delta(&old);
        let keys: Vec<_> = delta.keys().cloned().collect();
        assert_eq!(keys, vec![vec!["b".to_owned()], vec!["c".to_owned()]]);
    }

    #[test]
    fn a_snapshot_names_all_twenty_six_tables() {
        let meta = SnapshotMeta {
            database: "SQLite",
            release: "1.37.5",
            source: "test".into(),
        };
        let snapshot = VaultwardenSnapshot::from_tables(meta, Vec::new(), DataFiles::default());
        assert_eq!(snapshot.tables().len(), schema::TABLES.len());
        for (table, spec) in snapshot.tables().iter().zip(schema::TABLES) {
            assert_eq!(table.name(), spec.name);
        }
        assert_eq!(snapshot.row_count(), 0);
        assert!(snapshot.table("ciphers").is_some());
    }
}
