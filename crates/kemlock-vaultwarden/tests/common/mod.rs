//! Builds a Vaultwarden 1.37.5 data folder for the tests: a SQLite database made by running
//! Vaultwarden's own migrations in order (the files under
//! `tests/fixtures/vaultwarden-1.37.5/migrations/sqlite`, copied from Vaultwarden, AGPL-3.0),
//! sample rows, and the files Vaultwarden keeps beside it.

#![allow(dead_code, unreachable_pub)]

use kemlock_vaultwarden::mapping::{
    FileCopy, MappedAccount, MappedAttachment, MappedCipherState, MappedFolder, MappedItem,
    MappedRsaKey,
};
use kemlock_vaultwarden::schema::diesel_version;
use kemlock_vaultwarden::settings::MappedSettings;
use kemlock_vaultwarden::sink::ImportSink;
use kemlock_vaultwarden::snapshot::{RowKey, Table};
use kemlock_vaultwarden::{Source, VaultwardenSnapshot, read_snapshot};
use sqlx::sqlite::{SqliteConnectOptions, SqliteConnection};
use sqlx::{AssertSqlSafe, ConnectOptions};
use std::convert::Infallible;
use std::path::Path;

pub const MIGRATIONS_DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../kemlock-vaultwarden/tests/fixtures/vaultwarden-1.37.5/migrations/sqlite"
);

pub const ALICE: &str = "a1111111-1111-4111-8111-111111111111";
pub const BOB: &str = "b2222222-2222-4222-8222-222222222222";
pub const ORG: &str = "c3333333-3333-4333-8333-333333333333";
pub const ORG_MEMBER_BOB: &str = "d4444444-4444-4444-8444-444444444444";
pub const COLLECTION: &str = "e5555555-5555-4555-8555-555555555555";
pub const FOLDER: &str = "f6666666-6666-4666-8666-666666666666";
pub const GROUP: &str = "96666666-7777-4777-8777-777777777777";
pub const LOGIN: &str = "11111111-aaaa-4aaa-8aaa-000000000001";
pub const NOTE: &str = "11111111-aaaa-4aaa-8aaa-000000000002";
pub const CARD: &str = "11111111-aaaa-4aaa-8aaa-000000000003";
pub const SSH: &str = "11111111-aaaa-4aaa-8aaa-000000000004";
pub const SHARED: &str = "11111111-aaaa-4aaa-8aaa-000000000005";
pub const SEND: &str = "5e000000-0000-4000-8000-000000000001";
pub const ATTACHMENT: &str = "att0000000000001";

/// Every migration's diesel version and SQL, in the order diesel runs them.
pub fn migration_scripts() -> Vec<(String, String)> {
    let mut scripts: Vec<(String, String)> = std::fs::read_dir(MIGRATIONS_DIR)
        .expect("the migrations folder")
        .map(|entry| {
            let entry = entry.expect("a migration folder");
            let name = entry.file_name().to_string_lossy().into_owned();
            let sql = std::fs::read_to_string(entry.path().join("up.sql")).expect("an up.sql");
            (diesel_version(&name), sql)
        })
        .collect();
    scripts.sort();
    scripts
}

/// Opens (and creates, if needed) `<dir>/db.sqlite3` for writing, with foreign keys off as
/// Vaultwarden runs its migrations.
pub async fn writer(dir: &Path) -> SqliteConnection {
    SqliteConnectOptions::new()
        .filename(dir.join("db.sqlite3"))
        .create_if_missing(true)
        .foreign_keys(false)
        .connect()
        .await
        .expect("opens the fixture database")
}

/// Runs one or more SQL statements.
pub async fn exec(conn: &mut SqliteConnection, sql: &str) {
    if let Err(e) = sqlx::raw_sql(AssertSqlSafe(sql.to_owned()))
        .execute(&mut *conn)
        .await
    {
        panic!("{e}\nwhile running:\n{sql}");
    }
}

/// Creates the database with Vaultwarden's schema and diesel's migration history, and nothing
/// else.
pub async fn create_schema(dir: &Path) {
    let mut conn = writer(dir).await;
    exec(
        &mut conn,
        "CREATE TABLE __diesel_schema_migrations (
            version VARCHAR(50) PRIMARY KEY NOT NULL,
            run_on TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        )",
    )
    .await;
    for (version, sql) in migration_scripts() {
        exec(&mut conn, &sql).await;
        exec(
            &mut conn,
            &format!("INSERT INTO __diesel_schema_migrations (version) VALUES ('{version}')"),
        )
        .await;
    }
    sqlx::Connection::close(conn).await.expect("closes");
}

pub const SAMPLE_ROWS: &str = r#"
INSERT INTO users (uuid, created_at, updated_at, email, name, password_hash, salt,
    password_iterations, password_hint, akey, private_key, public_key, security_stamp,
    equivalent_domains, excluded_globals, client_kdf_type, client_kdf_iter, client_kdf_memory,
    client_kdf_parallelism, api_key, avatar_color, key_id)
VALUES
 ('a1111111-1111-4111-8111-111111111111', '2023-01-02 03:04:05.123456', '2024-05-06 07:08:09',
  'alice@example.org', 'Alice', X'AABBCCDD', X'0102030405060708', 600000, 'a hint',
  '2.userkey|iv|mac', '2.private|iv|mac', 'MIIBpublic', 'stamp-alice', '[]', '[]', 0, 600000,
  NULL, NULL, 'apikey-alice', '#00ff00', NULL),
 ('b2222222-2222-4222-8222-222222222222', '2023-02-03 04:05:06', '2024-05-06 07:08:10',
  'bob@example.org', 'Bob', X'EEFF0011', X'1112131415161718', 600000, NULL,
  '2.bobkey|iv|mac', NULL, NULL, 'stamp-bob', '[[1,2]]', '[3]', 1, 3, 65536, 4, NULL, NULL,
  'key-id-bob');

INSERT INTO devices (uuid, created_at, updated_at, user_uuid, name, atype, push_token,
    refresh_token, twofactor_remember, push_uuid)
VALUES ('de000000-0000-4000-8000-000000000001', '2024-01-01 00:00:00', '2024-05-01 00:00:00',
  'a1111111-1111-4111-8111-111111111111', 'Pixel', 0, NULL, 'refresh-1', NULL, NULL);

INSERT INTO organizations (uuid, name, billing_email, private_key, public_key)
VALUES ('c3333333-3333-4333-8333-333333333333', 'Family', 'alice@example.org', '2.orgpriv|iv|mac', 'orgpub');
INSERT INTO collections (uuid, org_uuid, name, external_id)
VALUES ('e5555555-5555-4555-8555-555555555555', 'c3333333-3333-4333-8333-333333333333', '2.coll|iv|mac', NULL);
INSERT INTO users_organizations (uuid, user_uuid, org_uuid, access_all, akey, status, atype,
    invited_by_email, reset_password_key, external_id)
VALUES
 ('d0000000-0000-4000-8000-000000000001', 'a1111111-1111-4111-8111-111111111111',
  'c3333333-3333-4333-8333-333333333333', 1, '2.orgkey-a|iv|mac', 2, 0, NULL, NULL, NULL),
 ('d4444444-4444-4444-8444-444444444444', 'b2222222-2222-4222-8222-222222222222',
  'c3333333-3333-4333-8333-333333333333', 0, '2.orgkey-b|iv|mac', 2, 2, 'alice@example.org', NULL, NULL);
INSERT INTO users_collections (user_uuid, collection_uuid, read_only, hide_passwords, manage)
VALUES ('b2222222-2222-4222-8222-222222222222', 'e5555555-5555-4555-8555-555555555555', 1, 0, 0);
INSERT INTO groups (uuid, organizations_uuid, name, access_all, external_id, creation_date, revision_date)
VALUES ('96666666-7777-4777-8777-777777777777', 'c3333333-3333-4333-8333-333333333333', 'Kids', 0, NULL,
  '2024-02-01 00:00:00', '2024-02-02 00:00:00');
INSERT INTO groups_users (groups_uuid, users_organizations_uuid)
VALUES ('96666666-7777-4777-8777-777777777777', 'd4444444-4444-4444-8444-444444444444');
INSERT INTO collections_groups (collections_uuid, groups_uuid, read_only, hide_passwords, manage)
VALUES ('e5555555-5555-4555-8555-555555555555', '96666666-7777-4777-8777-777777777777', 0, 1, 0);
INSERT INTO org_policies (uuid, org_uuid, atype, enabled, data)
VALUES ('90000000-0000-4000-8000-000000000001', 'c3333333-3333-4333-8333-333333333333', 1, 1, '{}');

INSERT INTO folders (uuid, created_at, updated_at, user_uuid, name)
VALUES ('f6666666-6666-4666-8666-666666666666', '2024-03-01 00:00:00', '2024-03-02 00:00:00',
  'a1111111-1111-4111-8111-111111111111', '2.folder|iv|mac');

INSERT INTO ciphers (uuid, created_at, updated_at, user_uuid, organization_uuid, atype, name, notes,
    fields, data, password_history, deleted_at, reprompt, "key")
VALUES
 ('11111111-aaaa-4aaa-8aaa-000000000001', '2024-05-01 10:00:00.123456', '2024-05-02 11:30:00',
  'a1111111-1111-4111-8111-111111111111', NULL, 1, '2.name|iv|mac', '2.notes|iv|mac',
  '[{"Type":"1","Name":"2.fn|iv|mac","Value":"2.fv|iv|mac"},{"Name":"2.x|iv|mac"}]',
  '{"Username":"2.u|iv|mac","Password":"2.p|iv|mac","Totp":null,"Uris":[{"Uri":"2.uri1|iv|mac","Match":"1"},{"Uri":"2.uri2|iv|mac","Match":null}]}',
  '[{"Password":"2.old|iv|mac","LastUsedDate":"2023-01-01T00:00:00Z"},{"Password":null,"LastUsedDate":"x"}]',
  NULL, 1, '2.cipherkey|iv|mac'),
 ('11111111-aaaa-4aaa-8aaa-000000000002', '2024-05-03 10:00:00', '2024-05-03 10:00:00',
  'a1111111-1111-4111-8111-111111111111', NULL, 2, '2.note|iv|mac', NULL, NULL, '{"Type":0}',
  NULL, NULL, NULL, NULL),
 ('11111111-aaaa-4aaa-8aaa-000000000003', '2024-05-04 10:00:00', '2024-05-05 10:00:00',
  'a1111111-1111-4111-8111-111111111111', NULL, 3, '2.card|iv|mac', NULL, NULL,
  '{"CardholderName":"2.c|iv|mac","Number":"2.n|iv|mac"}', NULL, '2024-06-01 00:00:00', 0, NULL),
 ('11111111-aaaa-4aaa-8aaa-000000000004', '2024-05-04 10:00:00', '2024-05-05 10:00:00',
  'b2222222-2222-4222-8222-222222222222', NULL, 5, '2.ssh|iv|mac', NULL, NULL,
  '{"PrivateKey":"2.k|iv|mac"}', NULL, NULL, NULL, NULL),
 ('11111111-aaaa-4aaa-8aaa-000000000005', '2024-05-06 10:00:00', '2024-05-07 10:00:00',
  NULL, 'c3333333-3333-4333-8333-333333333333', 1, '2.shared|iv|mac', NULL, NULL,
  '{"Username":"2.su|iv|mac","Uris":[{"Uri":"2.suri|iv|mac"}]}', NULL, NULL, 0, NULL);
INSERT INTO folders_ciphers (cipher_uuid, folder_uuid)
VALUES ('11111111-aaaa-4aaa-8aaa-000000000002', 'f6666666-6666-4666-8666-666666666666');
INSERT INTO favorites (user_uuid, cipher_uuid)
VALUES ('a1111111-1111-4111-8111-111111111111', '11111111-aaaa-4aaa-8aaa-000000000002'),
       ('b2222222-2222-4222-8222-222222222222', '11111111-aaaa-4aaa-8aaa-000000000005');
INSERT INTO archives (user_uuid, cipher_uuid, archived_at)
VALUES ('a1111111-1111-4111-8111-111111111111', '11111111-aaaa-4aaa-8aaa-000000000002', '2025-01-02 03:04:05');
INSERT INTO ciphers_collections (cipher_uuid, collection_uuid)
VALUES ('11111111-aaaa-4aaa-8aaa-000000000005', 'e5555555-5555-4555-8555-555555555555');
INSERT INTO attachments (id, cipher_uuid, file_name, file_size, akey)
VALUES ('att0000000000001', '11111111-aaaa-4aaa-8aaa-000000000001', '2.file|iv|mac', 5, '2.attkey|iv|mac'),
       ('att0000000000002', '11111111-aaaa-4aaa-8aaa-000000000001', '2.gone|iv|mac', 9, NULL);

INSERT INTO sends (uuid, user_uuid, name, notes, atype, data, akey, access_count, creation_date,
    revision_date, deletion_date, disabled, hide_email)
VALUES
 ('5e000000-0000-4000-8000-000000000001', 'a1111111-1111-4111-8111-111111111111', '2.send|iv|mac', NULL, 1,
  '{"Id":"fileid1","FileName":"2.fname|iv|mac","Size":3,"SizeName":"3 bytes"}', '2.sendkey|iv|mac',
  0, '2024-04-01 00:00:00', '2024-04-01 00:00:00', '2030-01-01 00:00:00', 0, NULL),
 ('5e000000-0000-4000-8000-000000000002', 'a1111111-1111-4111-8111-111111111111', '2.text|iv|mac', NULL, 0,
  '{"Text":"2.t|iv|mac","Hidden":false}', '2.sendkey2|iv|mac', 2, '2024-04-02 00:00:00',
  '2024-04-02 00:00:00', '2030-01-01 00:00:00', 0, 0);

INSERT INTO twofactor (uuid, user_uuid, atype, enabled, data, last_used)
VALUES ('20000000-0000-4000-8000-000000000001', 'a1111111-1111-4111-8111-111111111111', 0, 1, 'JBSWY3DPEHPK3PXP', 12345),
       ('20000000-0000-4000-8000-000000000002', 'a1111111-1111-4111-8111-111111111111', 1000, 1, '{"challenge":1}', 0);
INSERT INTO emergency_access (uuid, grantor_uuid, grantee_uuid, email, key_encrypted, atype, status,
    wait_time_days, updated_at, created_at)
VALUES ('ea000000-0000-4000-8000-000000000001', 'a1111111-1111-4111-8111-111111111111',
  'b2222222-2222-4222-8222-222222222222', 'bob@example.org', '2.ek|iv|mac', 0, 2, 7,
  '2024-04-01 00:00:00', '2024-04-01 00:00:00');
INSERT INTO event (uuid, event_type, user_uuid, ip_address, event_date, device_type)
VALUES ('e0000000-0000-4000-8000-000000000001', 1000, 'a1111111-1111-4111-8111-111111111111', '192.0.2.1', '2024-05-01 00:00:00', 0);
INSERT INTO invitations (email) VALUES ('new@example.org');
INSERT INTO sso_users (user_uuid, identifier) VALUES ('a1111111-1111-4111-8111-111111111111', 'sub-123');
"#;

pub const CONFIG_JSON: &str = r#"{
  "domain": "https://vault.example.org",
  "signups_allowed": false,
  "smtp_host": "mail.example.org",
  "smtp_password": "hunter2",
  "sso_client_secret": "sso-secret",
  "push_installation_key": "push-key",
  "admin_token": "$argon2id$v=19$m=65540,t=3,p=4$abc$def",
  "enable_websocket": true
}"#;

pub const RSA_PEM: &[u8] =
    b"-----BEGIN RSA PRIVATE KEY-----\nfake-private\n-----END RSA PRIVATE KEY-----\n";
pub const RSA_PUB_PEM: &[u8] =
    b"-----BEGIN PUBLIC KEY-----\nfake-public\n-----END PUBLIC KEY-----\n";

/// A full sample data folder: schema, rows, attachment and send files, `rsa_key.pem`,
/// `config.json`.
pub async fn create_sample_folder(dir: &Path) {
    create_schema(dir).await;
    let mut conn = writer(dir).await;
    exec(&mut conn, SAMPLE_ROWS).await;
    sqlx::Connection::close(conn).await.expect("closes");

    let attachments = dir.join("attachments").join(LOGIN);
    std::fs::create_dir_all(&attachments).expect("attachments folder");
    std::fs::write(attachments.join(ATTACHMENT), b"12345").expect("attachment file");
    let sends = dir.join("sends").join(SEND);
    std::fs::create_dir_all(&sends).expect("sends folder");
    std::fs::write(sends.join("fileid1"), b"abc").expect("send file");
    std::fs::write(dir.join("rsa_key.pem"), RSA_PEM).expect("rsa key");
    std::fs::write(dir.join("rsa_key.pub.pem"), RSA_PUB_PEM).expect("rsa pub key");
    std::fs::write(dir.join("config.json"), CONFIG_JSON).expect("config.json");
}

/// Reads a data folder the way the CLI does.
pub async fn read_folder(dir: &Path) -> VaultwardenSnapshot {
    let source = Source::parse(dir.to_str().expect("a UTF-8 path"), None).expect("a source");
    read_snapshot(&source).await.expect("reads the folder")
}

/// A sink that remembers what it was given.
#[derive(Debug, Default)]
pub struct Recorder {
    pub calls: Vec<String>,
    pub accounts: Vec<MappedAccount>,
    pub items: Vec<MappedItem>,
    pub copied: Vec<String>,
    pub deleted: Vec<(String, RowKey)>,
}

impl ImportSink for Recorder {
    type Error = Infallible;

    async fn put_accounts(&mut self, accounts: &[MappedAccount]) -> Result<(), Infallible> {
        self.calls.push(format!("accounts {}", accounts.len()));
        self.accounts.extend_from_slice(accounts);
        Ok(())
    }
    async fn put_folders(&mut self, folders: &[MappedFolder]) -> Result<(), Infallible> {
        self.calls.push(format!("folders {}", folders.len()));
        Ok(())
    }
    async fn put_items(&mut self, items: &[MappedItem]) -> Result<(), Infallible> {
        self.calls.push(format!("items {}", items.len()));
        self.items.extend_from_slice(items);
        Ok(())
    }
    async fn put_cipher_states(&mut self, states: &[MappedCipherState]) -> Result<(), Infallible> {
        self.calls.push(format!("states {}", states.len()));
        Ok(())
    }
    async fn put_attachments(
        &mut self,
        attachments: &[MappedAttachment],
    ) -> Result<(), Infallible> {
        self.calls
            .push(format!("attachments {}", attachments.len()));
        Ok(())
    }
    async fn put_carried(&mut self, table: &Table) -> Result<(), Infallible> {
        self.calls
            .push(format!("carried {} {}", table.name(), table.len()));
        Ok(())
    }
    async fn put_settings(&mut self, settings: &MappedSettings) -> Result<(), Infallible> {
        self.calls
            .push(format!("settings {}", settings.values.len()));
        Ok(())
    }
    async fn put_rsa_key(&mut self, _key: &MappedRsaKey) -> Result<(), Infallible> {
        self.calls.push("rsa key".to_owned());
        Ok(())
    }
    async fn copy_file(&mut self, file: &FileCopy) -> Result<(), Infallible> {
        self.copied.push(file.storage_key.clone());
        Ok(())
    }
    async fn delete_rows(
        &mut self,
        table: &'static str,
        keys: &[RowKey],
    ) -> Result<(), Infallible> {
        for key in keys {
            self.deleted.push((table.to_owned(), key.clone()));
        }
        Ok(())
    }
    async fn finish(&mut self) -> Result<(), Infallible> {
        self.calls.push("finish".to_owned());
        Ok(())
    }
}
