//! What the importer knows of Vaultwarden's schema: the tables and columns it reads, the
//! migrations of each release it accepts, and the `SELECT` for each table on each database.
//!
//! The columns are Vaultwarden 1.37.5's `src/db/schema.rs` (what its models read), plus the
//! `created_at` of `sso_users`, which its migrations create and its schema file leaves out. Tables
//! that only hold short-lived state (`sso_auth`, `twofactor_duo_ctx`) are not read: a second
//! sign-in redoes them.

use crate::migrations_1_37_5::{MYSQL_1_37_5, POSTGRESQL_1_37_5, SQLITE_1_37_5};

/// What a column holds, which decides how it is read and compared.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Text,
    Int,
    Bool,
    Blob,
    /// A `DATETIME` or `TIMESTAMP`, read as the text the database prints (UTC, no zone).
    Time,
}

/// One column.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Col {
    pub name: &'static str,
    pub kind: Kind,
}

/// One table: its name, the columns that make its primary key, and every column read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TableSpec {
    pub name: &'static str,
    pub key: &'static [&'static str],
    pub cols: &'static [Col],
}

impl TableSpec {
    /// The position of a column, or `None` if the table has no such column.
    pub fn index_of(&self, column: &str) -> Option<usize> {
        self.cols.iter().position(|c| c.name == column)
    }

    /// The positions of the primary key's columns.
    pub fn key_indexes(&self) -> Vec<usize> {
        self.key
            .iter()
            .filter_map(|k| self.index_of(k))
            .collect::<Vec<_>>()
    }
}

const fn t(name: &'static str) -> Col {
    Col {
        name,
        kind: Kind::Text,
    }
}
const fn i(name: &'static str) -> Col {
    Col {
        name,
        kind: Kind::Int,
    }
}
const fn b(name: &'static str) -> Col {
    Col {
        name,
        kind: Kind::Bool,
    }
}
const fn x(name: &'static str) -> Col {
    Col {
        name,
        kind: Kind::Blob,
    }
}
const fn d(name: &'static str) -> Col {
    Col {
        name,
        kind: Kind::Time,
    }
}

pub const USERS: TableSpec = TableSpec {
    name: "users",
    key: &["uuid"],
    cols: &[
        t("uuid"),
        b("enabled"),
        d("created_at"),
        d("updated_at"),
        d("verified_at"),
        d("last_verifying_at"),
        i("login_verify_count"),
        t("email"),
        t("email_new"),
        t("email_new_token"),
        t("name"),
        x("password_hash"),
        x("salt"),
        i("password_iterations"),
        t("password_hint"),
        t("akey"),
        t("private_key"),
        t("public_key"),
        t("totp_secret"),
        t("totp_recover"),
        t("security_stamp"),
        t("stamp_exception"),
        t("equivalent_domains"),
        t("excluded_globals"),
        i("client_kdf_type"),
        i("client_kdf_iter"),
        i("client_kdf_memory"),
        i("client_kdf_parallelism"),
        t("api_key"),
        t("avatar_color"),
        t("external_id"),
        t("key_id"),
    ],
};

pub const DEVICES: TableSpec = TableSpec {
    name: "devices",
    key: &["uuid", "user_uuid"],
    cols: &[
        t("uuid"),
        d("created_at"),
        d("updated_at"),
        t("user_uuid"),
        t("name"),
        i("atype"),
        t("push_uuid"),
        t("push_token"),
        t("refresh_token"),
        t("twofactor_remember"),
    ],
};

pub const CIPHERS: TableSpec = TableSpec {
    name: "ciphers",
    key: &["uuid"],
    cols: &[
        t("uuid"),
        d("created_at"),
        d("updated_at"),
        t("user_uuid"),
        t("organization_uuid"),
        t("key"),
        i("atype"),
        t("name"),
        t("notes"),
        t("fields"),
        t("data"),
        t("password_history"),
        d("deleted_at"),
        i("reprompt"),
    ],
};

pub const FOLDERS: TableSpec = TableSpec {
    name: "folders",
    key: &["uuid"],
    cols: &[
        t("uuid"),
        d("created_at"),
        d("updated_at"),
        t("user_uuid"),
        t("name"),
    ],
};

pub const FOLDERS_CIPHERS: TableSpec = TableSpec {
    name: "folders_ciphers",
    key: &["cipher_uuid", "folder_uuid"],
    cols: &[t("cipher_uuid"), t("folder_uuid")],
};

pub const FAVORITES: TableSpec = TableSpec {
    name: "favorites",
    key: &["user_uuid", "cipher_uuid"],
    cols: &[t("user_uuid"), t("cipher_uuid")],
};

pub const ARCHIVES: TableSpec = TableSpec {
    name: "archives",
    key: &["user_uuid", "cipher_uuid"],
    cols: &[t("user_uuid"), t("cipher_uuid"), d("archived_at")],
};

pub const ATTACHMENTS: TableSpec = TableSpec {
    name: "attachments",
    key: &["id"],
    cols: &[
        t("id"),
        t("cipher_uuid"),
        t("file_name"),
        i("file_size"),
        t("akey"),
    ],
};

pub const ORGANIZATIONS: TableSpec = TableSpec {
    name: "organizations",
    key: &["uuid"],
    cols: &[
        t("uuid"),
        t("name"),
        t("billing_email"),
        t("private_key"),
        t("public_key"),
    ],
};

pub const USERS_ORGANIZATIONS: TableSpec = TableSpec {
    name: "users_organizations",
    key: &["uuid"],
    cols: &[
        t("uuid"),
        t("user_uuid"),
        t("org_uuid"),
        t("invited_by_email"),
        b("access_all"),
        t("akey"),
        i("status"),
        i("atype"),
        t("reset_password_key"),
        t("external_id"),
    ],
};

pub const COLLECTIONS: TableSpec = TableSpec {
    name: "collections",
    key: &["uuid"],
    cols: &[t("uuid"), t("org_uuid"), t("name"), t("external_id")],
};

pub const CIPHERS_COLLECTIONS: TableSpec = TableSpec {
    name: "ciphers_collections",
    key: &["cipher_uuid", "collection_uuid"],
    cols: &[t("cipher_uuid"), t("collection_uuid")],
};

pub const USERS_COLLECTIONS: TableSpec = TableSpec {
    name: "users_collections",
    key: &["user_uuid", "collection_uuid"],
    cols: &[
        t("user_uuid"),
        t("collection_uuid"),
        b("read_only"),
        b("hide_passwords"),
        b("manage"),
    ],
};

pub const GROUPS: TableSpec = TableSpec {
    name: "groups",
    key: &["uuid"],
    cols: &[
        t("uuid"),
        t("organizations_uuid"),
        t("name"),
        b("access_all"),
        t("external_id"),
        d("creation_date"),
        d("revision_date"),
    ],
};

pub const COLLECTIONS_GROUPS: TableSpec = TableSpec {
    name: "collections_groups",
    key: &["collections_uuid", "groups_uuid"],
    cols: &[
        t("collections_uuid"),
        t("groups_uuid"),
        b("read_only"),
        b("hide_passwords"),
        b("manage"),
    ],
};

pub const GROUPS_USERS: TableSpec = TableSpec {
    name: "groups_users",
    key: &["groups_uuid", "users_organizations_uuid"],
    cols: &[t("groups_uuid"), t("users_organizations_uuid")],
};

pub const ORG_POLICIES: TableSpec = TableSpec {
    name: "org_policies",
    key: &["uuid"],
    cols: &[
        t("uuid"),
        t("org_uuid"),
        i("atype"),
        b("enabled"),
        t("data"),
        d("revision_date"),
    ],
};

pub const ORGANIZATION_API_KEY: TableSpec = TableSpec {
    name: "organization_api_key",
    key: &["uuid", "org_uuid"],
    cols: &[
        t("uuid"),
        t("org_uuid"),
        i("atype"),
        t("api_key"),
        d("revision_date"),
    ],
};

pub const TWOFACTOR: TableSpec = TableSpec {
    name: "twofactor",
    key: &["uuid"],
    cols: &[
        t("uuid"),
        t("user_uuid"),
        i("atype"),
        b("enabled"),
        t("data"),
        i("last_used"),
    ],
};

pub const TWOFACTOR_INCOMPLETE: TableSpec = TableSpec {
    name: "twofactor_incomplete",
    key: &["user_uuid", "device_uuid"],
    cols: &[
        t("user_uuid"),
        t("device_uuid"),
        t("device_name"),
        i("device_type"),
        d("login_time"),
        t("ip_address"),
    ],
};

pub const EMERGENCY_ACCESS: TableSpec = TableSpec {
    name: "emergency_access",
    key: &["uuid"],
    cols: &[
        t("uuid"),
        t("grantor_uuid"),
        t("grantee_uuid"),
        t("email"),
        t("key_encrypted"),
        i("atype"),
        i("status"),
        i("wait_time_days"),
        d("recovery_initiated_at"),
        d("last_notification_at"),
        d("updated_at"),
        d("created_at"),
    ],
};

pub const SENDS: TableSpec = TableSpec {
    name: "sends",
    key: &["uuid"],
    cols: &[
        t("uuid"),
        t("user_uuid"),
        t("organization_uuid"),
        t("name"),
        t("notes"),
        i("atype"),
        t("data"),
        t("akey"),
        x("password_hash"),
        x("password_salt"),
        i("password_iter"),
        i("max_access_count"),
        i("access_count"),
        d("creation_date"),
        d("revision_date"),
        d("expiration_date"),
        d("deletion_date"),
        b("disabled"),
        b("hide_email"),
    ],
};

pub const EVENT: TableSpec = TableSpec {
    name: "event",
    key: &["uuid"],
    cols: &[
        t("uuid"),
        i("event_type"),
        t("user_uuid"),
        t("org_uuid"),
        t("cipher_uuid"),
        t("collection_uuid"),
        t("group_uuid"),
        t("org_user_uuid"),
        t("act_user_uuid"),
        i("device_type"),
        t("ip_address"),
        d("event_date"),
        t("policy_uuid"),
        t("provider_uuid"),
        t("provider_user_uuid"),
        t("provider_org_uuid"),
    ],
};

pub const AUTH_REQUESTS: TableSpec = TableSpec {
    name: "auth_requests",
    key: &["uuid"],
    cols: &[
        t("uuid"),
        t("user_uuid"),
        t("organization_uuid"),
        t("request_device_identifier"),
        i("device_type"),
        t("request_ip"),
        t("response_device_id"),
        t("access_code"),
        t("public_key"),
        t("enc_key"),
        t("master_password_hash"),
        b("approved"),
        d("creation_date"),
        d("response_date"),
        d("authentication_date"),
    ],
};

pub const SSO_USERS: TableSpec = TableSpec {
    name: "sso_users",
    key: &["user_uuid"],
    cols: &[t("user_uuid"), t("identifier"), d("created_at")],
};

pub const INVITATIONS: TableSpec = TableSpec {
    name: "invitations",
    key: &["email"],
    cols: &[t("email")],
};

/// Every table the importer reads, in the order a snapshot lists them.
pub const TABLES: &[&TableSpec] = &[
    &USERS,
    &DEVICES,
    &CIPHERS,
    &FOLDERS,
    &FOLDERS_CIPHERS,
    &FAVORITES,
    &ARCHIVES,
    &ATTACHMENTS,
    &ORGANIZATIONS,
    &USERS_ORGANIZATIONS,
    &COLLECTIONS,
    &CIPHERS_COLLECTIONS,
    &USERS_COLLECTIONS,
    &GROUPS,
    &COLLECTIONS_GROUPS,
    &GROUPS_USERS,
    &ORG_POLICIES,
    &ORGANIZATION_API_KEY,
    &TWOFACTOR,
    &TWOFACTOR_INCOMPLETE,
    &EMERGENCY_ACCESS,
    &SENDS,
    &EVENT,
    &AUTH_REQUESTS,
    &SSO_USERS,
    &INVITATIONS,
];

/// The spec of a table by name.
pub fn spec(name: &str) -> Option<&'static TableSpec> {
    TABLES.iter().copied().find(|t| t.name == name)
}

/// The database a Vaultwarden server keeps its rows in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dialect {
    Sqlite,
    Postgres,
    MySql,
}

impl Dialect {
    pub fn name(self) -> &'static str {
        match self {
            Dialect::Sqlite => "SQLite",
            Dialect::Postgres => "PostgreSQL",
            Dialect::MySql => "MySQL",
        }
    }

    fn quote(self, ident: &str) -> String {
        match self {
            Dialect::MySql => format!("`{ident}`"),
            Dialect::Sqlite | Dialect::Postgres => format!("\"{ident}\""),
        }
    }

    /// The expression that reads one column in the form the importer decodes: text, `i64` or
    /// bytes, whatever the column's declared type is on this database.
    fn expr(self, col: &Col) -> String {
        let q = self.quote(col.name);
        match (self, col.kind) {
            (_, Kind::Text) => q,
            (Dialect::Sqlite, Kind::Time) | (Dialect::Postgres, Kind::Time) => {
                format!("CAST({q} AS TEXT)")
            }
            (Dialect::MySql, Kind::Time) => format!("CAST({q} AS CHAR)"),
            (Dialect::Sqlite, Kind::Int) | (Dialect::Sqlite, Kind::Bool) => {
                format!("CAST({q} AS INTEGER)")
            }
            (Dialect::Postgres, Kind::Int) => format!("CAST({q} AS BIGINT)"),
            // PostgreSQL has no cast from boolean to bigint, only to integer.
            (Dialect::Postgres, Kind::Bool) => {
                format!("CAST(CAST({q} AS INTEGER) AS BIGINT)")
            }
            (Dialect::MySql, Kind::Int) | (Dialect::MySql, Kind::Bool) => {
                format!("CAST({q} AS SIGNED)")
            }
            (Dialect::Sqlite, Kind::Blob) => format!("CAST({q} AS BLOB)"),
            (Dialect::Postgres, Kind::Blob) | (Dialect::MySql, Kind::Blob) => q,
        }
    }
}

/// The `SELECT` that reads every column of a table, in the spec's order.
pub fn select_sql(spec: &TableSpec, dialect: Dialect) -> String {
    let columns: Vec<String> = spec.cols.iter().map(|c| dialect.expr(c)).collect();
    format!(
        "SELECT {} FROM {}",
        columns.join(", "),
        dialect.quote(spec.name)
    )
}

/// The `SELECT` that lists the migrations a Vaultwarden database has run. Diesel keeps them in
/// `__diesel_schema_migrations`.
pub const MIGRATIONS_SQL: &str = "SELECT version FROM __diesel_schema_migrations";

/// One Vaultwarden release's schema, pinned by a fixture database in this crate's tests.
#[derive(Clone, Copy, Debug)]
pub struct SupportedSchema {
    pub release: &'static str,
    /// The diesel version of every migration, in order.
    pub migrations: &'static [&'static str],
}

/// The releases the importer accepts on a database.
pub fn supported(dialect: Dialect) -> &'static [SupportedSchema] {
    match dialect {
        Dialect::Sqlite => &[SupportedSchema {
            release: "1.37.5",
            migrations: SQLITE_1_37_5,
        }],
        Dialect::Postgres => &[SupportedSchema {
            release: "1.37.5",
            migrations: POSTGRESQL_1_37_5,
        }],
        Dialect::MySql => &[SupportedSchema {
            release: "1.37.5",
            migrations: MYSQL_1_37_5,
        }],
    }
}

/// How a database's migrations compare with the releases the importer accepts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SchemaCheck {
    /// Exactly the migrations of this release.
    Supported(&'static str),
    /// Some migrations of a supported release have not run: a Vaultwarden older than the
    /// supported one wrote this database.
    Older {
        release: &'static str,
        missing: usize,
    },
    /// Migrations the importer doesn't know: a newer Vaultwarden, or a fork.
    Unknown { unknown: Vec<String> },
}

/// Compares the versions in `__diesel_schema_migrations` with the supported releases.
pub fn check_versions(dialect: Dialect, applied: &[String]) -> SchemaCheck {
    let mut best_older: Option<(&'static str, usize)> = None;
    for schema in supported(dialect) {
        let unknown: Vec<String> = applied
            .iter()
            .filter(|v| !schema.migrations.contains(&v.as_str()))
            .cloned()
            .collect();
        let missing = schema
            .migrations
            .iter()
            .filter(|m| !applied.iter().any(|a| a.as_str() == **m))
            .count();
        if unknown.is_empty() && missing == 0 {
            return SchemaCheck::Supported(schema.release);
        }
        if unknown.is_empty() {
            best_older = Some((schema.release, missing));
        }
    }
    match best_older {
        Some((release, missing)) => SchemaCheck::Older { release, missing },
        None => {
            let known: Vec<&str> = supported(dialect)
                .iter()
                .flat_map(|s| s.migrations.iter().copied())
                .collect();
            let unknown = applied
                .iter()
                .filter(|v| !known.contains(&v.as_str()))
                .cloned()
                .collect();
            SchemaCheck::Unknown { unknown }
        }
    }
}

/// The diesel version of a migration directory name: what comes before the first underscore,
/// without dashes (`2018-01-14-171611_create_tables` is `20180114171611`).
pub fn diesel_version(directory: &str) -> String {
    directory
        .split('_')
        .next()
        .unwrap_or_default()
        .replace('-', "")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_spec_names_its_key_columns() {
        for spec in TABLES {
            assert!(!spec.key.is_empty(), "{}", spec.name);
            assert_eq!(spec.key_indexes().len(), spec.key.len(), "{}", spec.name);
            let mut names: Vec<&str> = spec.cols.iter().map(|c| c.name).collect();
            names.sort_unstable();
            names.dedup();
            assert_eq!(
                names.len(),
                spec.cols.len(),
                "{}: repeated column",
                spec.name
            );
        }
    }

    #[test]
    fn there_are_twenty_six_tables_with_distinct_names() {
        let mut names: Vec<&str> = TABLES.iter().map(|t| t.name).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), 26);
        assert!(spec("ciphers").is_some());
        assert!(spec("nope").is_none());
    }

    #[test]
    fn selects_quote_every_name_and_cast_per_database() {
        let sqlite = select_sql(&SENDS, Dialect::Sqlite);
        assert!(sqlite.starts_with("SELECT \"uuid\""), "{sqlite}");
        assert!(sqlite.contains("CAST(\"disabled\" AS INTEGER)"));
        assert!(sqlite.contains("CAST(\"password_hash\" AS BLOB)"));
        assert!(sqlite.contains("CAST(\"creation_date\" AS TEXT)"));
        assert!(sqlite.ends_with("FROM \"sends\""));

        let pg = select_sql(&SENDS, Dialect::Postgres);
        assert!(pg.contains("CAST(CAST(\"hide_email\" AS INTEGER) AS BIGINT)"));
        assert!(pg.contains("CAST(\"access_count\" AS BIGINT)"));
        assert!(pg.contains("\"password_hash\", "), "bytea is read as it is");

        let my = select_sql(&GROUPS, Dialect::MySql);
        // `groups` is a reserved word in MySQL 8.
        assert!(my.ends_with("FROM `groups`"), "{my}");
        assert!(my.contains("CAST(`creation_date` AS CHAR)"));
        assert!(my.contains("CAST(`access_all` AS SIGNED)"));
    }

    #[test]
    fn diesel_versions_drop_dashes_and_the_name() {
        assert_eq!(
            diesel_version("2018-01-14-171611_create_tables"),
            "20180114171611"
        );
        // One migration directory has an underscore where the others have a dash.
        assert_eq!(
            diesel_version("2024-03-13_170000_sso_userscascade"),
            "20240313"
        );
    }

    #[test]
    fn the_release_lists_have_the_expected_lengths() {
        assert_eq!(SQLITE_1_37_5.len(), 58);
        assert_eq!(POSTGRESQL_1_37_5.len(), 48);
        assert_eq!(MYSQL_1_37_5.len(), 57);
    }

    #[test]
    fn versions_are_compared_with_the_supported_lists() {
        let all: Vec<String> = SQLITE_1_37_5.iter().map(|s| (*s).to_owned()).collect();
        assert_eq!(
            check_versions(Dialect::Sqlite, &all),
            SchemaCheck::Supported("1.37.5")
        );

        let older = &all[..all.len() - 2];
        assert_eq!(
            check_versions(Dialect::Sqlite, older),
            SchemaCheck::Older {
                release: "1.37.5",
                missing: 2
            }
        );

        let mut newer = all.clone();
        newer.push("29990101000000".to_owned());
        assert_eq!(
            check_versions(Dialect::Sqlite, &newer),
            SchemaCheck::Unknown {
                unknown: vec!["29990101000000".to_owned()]
            }
        );
    }
}
