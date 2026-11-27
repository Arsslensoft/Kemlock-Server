//! Reads, diffs and maps a Vaultwarden 1.37.5 data folder whose database was made by running
//! Vaultwarden's own migrations (see `common`).

mod common;

use common::*;
use kemlock_domain::{AccountMode, ItemFormat, Owner, Role};
use kemlock_vaultwarden::error::ReadError;
use kemlock_vaultwarden::{
    ApplyReport, Source, apply, diff, map_snapshot, read_snapshot, render_plan,
};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::path::Path;

fn file_names(dir: &Path) -> BTreeSet<String> {
    std::fs::read_dir(dir)
        .expect("a readable folder")
        .map(|e| {
            e.expect("an entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect()
}

fn key(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|p| (*p).to_owned()).collect()
}

#[tokio::test]
async fn reads_a_data_folder_without_touching_it() {
    let dir = tempfile::tempdir().expect("a temp folder");
    create_sample_folder(dir.path()).await;
    let db_before = std::fs::read(dir.path().join("db.sqlite3")).expect("the database");
    let names_before = file_names(dir.path());

    let snapshot = read_folder(dir.path()).await;

    // Nothing written: same bytes, and no journal or WAL files beside the database.
    assert_eq!(
        std::fs::read(dir.path().join("db.sqlite3")).expect("the database"),
        db_before
    );
    assert_eq!(file_names(dir.path()), names_before);

    assert_eq!(snapshot.meta.release, "1.37.5");
    assert_eq!(snapshot.meta.database, "SQLite");
    let counts: Vec<(&str, usize)> = snapshot
        .tables()
        .iter()
        .map(|t| (t.name(), t.len()))
        .collect();
    assert_eq!(
        counts,
        vec![
            ("users", 2),
            ("devices", 1),
            ("ciphers", 5),
            ("folders", 1),
            ("folders_ciphers", 1),
            ("favorites", 2),
            ("archives", 1),
            ("attachments", 2),
            ("organizations", 1),
            ("users_organizations", 2),
            ("collections", 1),
            ("ciphers_collections", 1),
            ("users_collections", 1),
            ("groups", 1),
            ("collections_groups", 1),
            ("groups_users", 1),
            ("org_policies", 1),
            ("organization_api_key", 0),
            ("twofactor", 2),
            ("twofactor_incomplete", 0),
            ("emergency_access", 1),
            ("sends", 2),
            ("event", 1),
            ("auth_requests", 0),
            ("sso_users", 1),
            ("invitations", 1),
        ]
    );

    // Every column is kept as stored: text, integers, booleans, blobs and dates.
    let alice = snapshot.users.get(&key(&[ALICE])).expect("alice");
    assert_eq!(alice.text("email"), Some("alice@example.org"));
    assert_eq!(alice.text("akey"), Some("2.userkey|iv|mac"));
    assert_eq!(
        alice.bytes("password_hash"),
        Some(&[0xAA_u8, 0xBB, 0xCC, 0xDD][..])
    );
    assert_eq!(alice.int("password_iterations"), Some(600_000));
    assert_eq!(alice.bool("enabled"), Some(true));
    assert_eq!(alice.text("created_at"), Some("2023-01-02 03:04:05.123456"));
    assert_eq!(alice.text("avatar_color"), Some("#00ff00"));
    assert_eq!(alice.int("client_kdf_memory"), None);
    assert_eq!(alice.text("key_id"), None);
    let bob = snapshot.users.get(&key(&[BOB])).expect("bob");
    assert_eq!(bob.int("client_kdf_memory"), Some(65536));
    assert_eq!(bob.text("equivalent_domains"), Some("[[1,2]]"));

    // The files beside it.
    assert_eq!(
        snapshot
            .files
            .attachment_files
            .get(&format!("{LOGIN}/{ATTACHMENT}")),
        Some(&5)
    );
    assert_eq!(
        snapshot.files.send_files.get(&format!("{SEND}/fileid1")),
        Some(&3)
    );
    assert_eq!(snapshot.files.rsa_key_pem.as_deref(), Some(RSA_PEM));
    assert_eq!(snapshot.files.rsa_pub_pem.as_deref(), Some(RSA_PUB_PEM));
    assert_eq!(snapshot.files.config_json.as_deref(), Some(CONFIG_JSON));
    // The private key never shows in Debug output.
    assert!(!format!("{:?}", snapshot.files).contains("fake-private"));
}

#[tokio::test]
async fn refuses_a_schema_it_does_not_know() {
    let dir = tempfile::tempdir().expect("a temp folder");
    create_schema(dir.path()).await;
    let source = Source::parse(dir.path().to_str().expect("UTF-8"), None).expect("a source");
    let mut conn = writer(dir.path()).await;

    // The newest migration has not run: a Vaultwarden older than 1.37.5 wrote this database.
    exec(
        &mut conn,
        "DELETE FROM __diesel_schema_migrations WHERE version = '20261007120000'",
    )
    .await;
    let err = read_snapshot(&source).await.expect_err("an older schema");
    assert!(
        matches!(
            err,
            ReadError::SchemaOlder {
                release: "1.37.5",
                missing: 1
            }
        ),
        "{err}"
    );

    // A migration this importer has never heard of: a newer Vaultwarden, or a fork.
    exec(
        &mut conn,
        "INSERT INTO __diesel_schema_migrations (version) VALUES ('20261007120000'), ('29990101000000')",
    )
    .await;
    let err = read_snapshot(&source).await.expect_err("an unknown schema");
    assert!(
        matches!(&err, ReadError::SchemaUnknown { unknown } if unknown == &["29990101000000".to_owned()]),
        "{err}"
    );
    assert!(err.to_string().contains("29990101000000"));
}

#[tokio::test]
async fn refuses_what_is_not_a_vaultwarden_database() {
    let dir = tempfile::tempdir().expect("a temp folder");
    let source = Source::parse(dir.path().to_str().expect("UTF-8"), None).expect("a source");
    let err = read_snapshot(&source).await.expect_err("no database yet");
    assert!(matches!(err, ReadError::NoDatabase(_)), "{err}");

    let mut conn = writer(dir.path()).await;
    exec(&mut conn, "CREATE TABLE unrelated (x INTEGER)").await;
    let err = read_snapshot(&source).await.expect_err("not Vaultwarden");
    assert!(matches!(err, ReadError::NotVaultwarden(_)), "{err}");
}

#[tokio::test]
async fn a_database_url_source_without_a_server_fails_cleanly() {
    // Nothing listens here, and the read must report it rather than hang or panic.
    let source = Source::parse("postgres://nobody:pw@127.0.0.1:1/none", None).expect("a source");
    let err = read_snapshot(&source).await.expect_err("no server");
    assert!(matches!(err, ReadError::Database(_)), "{err}");
    assert!(!err.to_string().contains(":pw@"));
}

#[tokio::test]
async fn maps_accounts_in_compatible_mode_with_their_keys() {
    let dir = tempfile::tempdir().expect("a temp folder");
    create_sample_folder(dir.path()).await;
    let mapped = map_snapshot(&read_folder(dir.path()).await).expect("maps");

    assert_eq!(mapped.accounts.len(), 2);
    let alice = mapped
        .accounts
        .iter()
        .find(|a| a.email == "alice@example.org")
        .expect("alice");
    assert_eq!(alice.id.to_string(), ALICE);
    assert_eq!(alice.mode, AccountMode::Compatible);
    assert_eq!(alice.role, Role::User);
    assert_eq!(alice.name, "Alice");
    assert_eq!(alice.bitwarden.password_hash, vec![0xAA, 0xBB, 0xCC, 0xDD]);
    assert_eq!(alice.bitwarden.salt, vec![1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(alice.bitwarden.akey, "2.userkey|iv|mac");
    assert_eq!(
        alice.bitwarden.private_key.as_deref(),
        Some("2.private|iv|mac")
    );
    assert_eq!(alice.bitwarden.security_stamp, "stamp-alice");
    assert_eq!(alice.bitwarden.client_kdf_type, 0);
    assert_eq!(alice.bitwarden.client_kdf_iter, 600_000);
    assert_eq!(alice.bitwarden.password_hint.as_deref(), Some("a hint"));
    assert_eq!(alice.bitwarden.api_key.as_deref(), Some("apikey-alice"));
    assert!(alice.bitwarden.enabled);
    // 2023-01-02 03:04:05.123456 UTC.
    assert_eq!(alice.created_at.unix_timestamp(), 1_672_628_645);
    assert_eq!(alice.created_at.microsecond(), 123_456);

    let bob = mapped
        .accounts
        .iter()
        .find(|a| a.email == "bob@example.org")
        .expect("bob");
    assert_eq!(bob.bitwarden.client_kdf_type, 1, "Argon2id stays Argon2id");
    assert_eq!(bob.bitwarden.client_kdf_iter, 3);
    assert_eq!(bob.bitwarden.client_kdf_memory, Some(65536));
    assert_eq!(bob.bitwarden.client_kdf_parallelism, Some(4));
    assert_eq!(bob.bitwarden.key_id.as_deref(), Some("key-id-bob"));
    assert_eq!(bob.bitwarden.private_key, None);

    // Password hashes stay out of Debug output.
    let printed = format!("{:?}", alice.bitwarden);
    assert!(!printed.contains("password_hash"), "{printed}");
    assert!(!printed.contains("userkey"), "{printed}");
}

#[tokio::test]
async fn maps_ciphers_to_the_json_vaultwarden_returns() {
    let dir = tempfile::tempdir().expect("a temp folder");
    create_sample_folder(dir.path()).await;
    let mapped = map_snapshot(&read_folder(dir.path()).await).expect("maps");
    assert_eq!(mapped.items.len(), 5);
    let item = |id: &str| {
        mapped
            .items
            .iter()
            .find(|i| i.id.to_string() == id)
            .unwrap_or_else(|| panic!("item {id}"))
    };

    // A login, as its owner's sync shows it.
    let login = item(LOGIN);
    assert_eq!(login.format, ItemFormat::Bw);
    assert_eq!(login.kind.as_str(), "login");
    assert_eq!(login.owner.to_string(), format!("user:{ALICE}"));
    assert_eq!(
        login.json,
        json!({
            "object": "cipherDetails",
            "id": LOGIN,
            "type": 1,
            "creationDate": "2024-05-01T10:00:00.123456Z",
            "revisionDate": "2024-05-02T11:30:00.000000Z",
            "deletedDate": null,
            "reprompt": 1,
            "organizationId": null,
            "key": "2.cipherkey|iv|mac",
            "attachments": null,
            "organizationUseTotp": true,
            "collectionIds": [],
            "name": "2.name|iv|mac",
            "notes": "2.notes|iv|mac",
            "fields": [
                {"type": 1, "name": "2.fn|iv|mac", "value": "2.fv|iv|mac"},
                {"type": 1, "name": "2.x|iv|mac"}
            ],
            "passwordHistory": [
                {"password": "2.old|iv|mac", "lastUsedDate": "2023-01-01T00:00:00.000000Z"}
            ],
            "login": {
                "username": "2.u|iv|mac",
                "password": "2.p|iv|mac",
                "totp": null,
                "uri": "2.uri1|iv|mac",
                "uris": [
                    {"uri": "2.uri1|iv|mac", "match": 1},
                    {"uri": "2.uri2|iv|mac", "match": null}
                ]
            },
            "secureNote": null,
            "card": null,
            "identity": null,
            "sshKey": null,
            "bankAccount": null,
            "driversLicense": null,
            "passport": null,
            "folderId": null,
            "favorite": false,
            "archivedDate": null,
            "edit": true,
            "viewPassword": true,
            "permissions": {"delete": true, "restore": true}
        })
    );
    // The stored payload is that JSON, compact.
    let payload: Value = serde_json::from_slice(&login.payload()).expect("JSON");
    assert_eq!(payload, login.json);

    // A secure note in a folder, a favorite, archived.
    let note = item(NOTE);
    assert_eq!(note.kind.as_str(), "secure-note");
    assert_eq!(note.json["secureNote"], json!({"type": 0}));
    assert_eq!(note.json["folderId"], FOLDER);
    assert_eq!(note.json["favorite"], true);
    assert_eq!(note.json["archivedDate"], "2025-01-02T03:04:05.000000Z");

    // A card in the trash.
    let card = item(CARD);
    assert_eq!(card.json["deletedDate"], "2024-06-01T00:00:00.000000Z");
    assert_eq!(card.json["card"]["cardholderName"], "2.c|iv|mac");
    assert_eq!(card.json["reprompt"], 0);

    // An SSH key missing its public half is null, so mobile clients don't crash on it.
    let ssh = item(SSH);
    assert_eq!(ssh.owner.to_string(), format!("user:{BOB}"));
    assert_eq!(ssh.json["sshKey"], Value::Null);

    // An organization's cipher is stored without any viewer's folder, favorite or permissions.
    let shared = item(SHARED);
    assert_eq!(shared.owner.to_string(), format!("space:{ORG}"));
    assert!(matches!(shared.owner, Owner::Space(_)));
    assert_eq!(shared.json["organizationId"], ORG);
    assert_eq!(shared.json["collectionIds"], json!([COLLECTION]));
    assert!(shared.json.get("folderId").is_none());
    assert!(shared.json.get("favorite").is_none());
    assert!(shared.json.get("edit").is_none());

    // Each user's own state is kept beside the items.
    assert_eq!(mapped.cipher_states.len(), 2);
    let note_state = mapped
        .cipher_states
        .iter()
        .find(|s| s.item.to_string() == NOTE)
        .expect("the note's state");
    assert_eq!(note_state.user.to_string(), ALICE);
    assert_eq!(
        note_state.folder.map(|f| f.to_string()).as_deref(),
        Some(FOLDER)
    );
    assert!(note_state.favorite);
    assert!(note_state.archived_at.is_some());
    let shared_state = mapped
        .cipher_states
        .iter()
        .find(|s| s.item.to_string() == SHARED)
        .expect("the shared cipher's state");
    assert_eq!(shared_state.user.to_string(), BOB);
    assert!(shared_state.favorite);
    assert_eq!(shared_state.folder, None);

    // Folders keep their encrypted names.
    assert_eq!(mapped.folders.len(), 1);
    assert_eq!(
        mapped.folders[0].json,
        json!({
            "id": FOLDER,
            "revisionDate": "2024-03-02T00:00:00.000000Z",
            "name": "2.folder|iv|mac",
            "object": "folder"
        })
    );
}

#[tokio::test]
async fn maps_files_settings_the_signing_key_and_everything_else() {
    let dir = tempfile::tempdir().expect("a temp folder");
    create_sample_folder(dir.path()).await;
    let snapshot = read_folder(dir.path()).await;
    let mapped = map_snapshot(&snapshot).expect("maps");

    // Attachments: both rows are carried, one file is found and copied as it is.
    assert_eq!(mapped.attachments.len(), 2);
    let found = mapped
        .attachments
        .iter()
        .find(|a| a.id == ATTACHMENT)
        .expect("the attachment");
    assert!(found.file_found);
    assert_eq!(
        found.storage_key,
        format!("attachments/{LOGIN}/{ATTACHMENT}")
    );
    assert_eq!(found.item.to_string(), LOGIN);
    assert_eq!(found.size, 5);
    assert_eq!(found.key.as_deref(), Some("2.attkey|iv|mac"));
    let gone = mapped
        .attachments
        .iter()
        .find(|a| a.id == "att0000000000002")
        .expect("the missing one");
    assert!(!gone.file_found);
    assert_eq!(gone.key, None);

    let copies: BTreeSet<(String, u64)> = mapped
        .files
        .iter()
        .map(|f| (f.storage_key.clone(), f.size))
        .collect();
    assert_eq!(
        copies,
        BTreeSet::from([
            (format!("attachments/{LOGIN}/{ATTACHMENT}"), 5),
            (format!("sends/{SEND}/fileid1"), 3),
        ])
    );
    assert_eq!(mapped.file_bytes(), 8);
    let attachment_copy = mapped
        .files
        .iter()
        .find(|f| f.storage_key.starts_with("attachments/"))
        .expect("an attachment copy");
    assert_eq!(
        attachment_copy.from,
        dir.path().join("attachments").join(LOGIN).join(ATTACHMENT)
    );

    // rsa_key.pem is carried, so signed-in apps keep their tokens.
    let rsa = mapped.rsa_key.as_ref().expect("the signing key");
    assert_eq!(rsa.private_pem, RSA_PEM);
    assert_eq!(rsa.public_pem.as_deref(), Some(RSA_PUB_PEM));

    // config.json: only the listed settings carried, never secrets, the admin token ignored.
    let names: Vec<&str> = mapped.settings.values.keys().map(String::as_str).collect();
    assert_eq!(names, vec!["signups_allowed", "smtp_host"]);
    assert_eq!(mapped.settings.values["signups_allowed"], json!(false));
    assert_eq!(
        mapped.settings.ignored,
        vec!["admin_token", "domain", "enable_websocket"]
    );
    assert_eq!(
        mapped.settings.secrets,
        vec![
            "push_installation_key",
            "smtp_password",
            "sso_client_secret"
        ]
    );
    let printed = format!("{mapped:?}");
    for leaked in [
        "hunter2",
        "sso-secret",
        "push-key",
        "argon2id",
        "fake-private",
    ] {
        assert!(
            !printed.contains(leaked),
            "{leaked} leaked into Debug output"
        );
    }

    // Everything else is carried row for row; two-step login challenges are left out.
    let carried: Vec<(&str, usize)> = mapped.carried.iter().map(|t| (t.name(), t.len())).collect();
    assert_eq!(
        carried,
        vec![
            ("devices", 1),
            ("organizations", 1),
            ("users_organizations", 2),
            ("collections", 1),
            ("ciphers_collections", 1),
            ("users_collections", 1),
            ("groups", 1),
            ("collections_groups", 1),
            ("groups_users", 1),
            ("org_policies", 1),
            ("organization_api_key", 0),
            ("twofactor", 1),
            ("emergency_access", 1),
            ("sends", 2),
            ("event", 1),
            ("sso_users", 1),
            ("invitations", 1),
        ]
    );

    // Warnings: the missing attachment file and each secret to enter again.
    assert!(
        mapped
            .warnings
            .iter()
            .any(|w| w.contains("att0000000000002") && w.contains("no file")),
        "{:?}",
        mapped.warnings
    );
    assert!(mapped.warnings.iter().any(|w| w.contains("smtp_password")));
    assert!(!mapped.warnings.iter().any(|w| w.contains("rsa_key")));

    // The dry-run plan says all of this without writing anything.
    let plan = render_plan(&snapshot.meta, &mapped, None);
    assert!(plan.contains("Vaultwarden 1.37.5 (SQLite)"), "{plan}");
    assert!(plan.contains("Compatible mode"), "{plan}");
    assert!(
        plan.contains("to enter again: push_installation_key, smtp_password, sso_client_secret"),
        "{plan}"
    );
    assert!(
        plan.contains(r#"not carried: "admin_token", "domain", "enable_websocket""#),
        "{plan}"
    );
}

#[tokio::test]
async fn a_second_copy_finds_what_changed_including_deletions() {
    let dir = tempfile::tempdir().expect("a temp folder");
    create_sample_folder(dir.path()).await;
    let first = read_folder(dir.path()).await;
    let first_mapped = map_snapshot(&first).expect("maps");

    // Vaultwarden kept running after the first copy: one cipher edited, one added, one deleted
    // (with its folder, favorite and archive rows), an attachment added and one removed, and a
    // setting changed.
    let new_cipher = "11111111-aaaa-4aaa-8aaa-000000000006";
    let new_attachment = "att0000000000003";
    let new_data = r#"{"Type":0}"#;
    let mut conn = writer(dir.path()).await;
    exec(
        &mut conn,
        &format!(
            "UPDATE ciphers SET name = '2.renamed|iv|mac', updated_at = '2024-06-10 12:00:00' WHERE uuid = '{LOGIN}';
             INSERT INTO ciphers (uuid, created_at, updated_at, user_uuid, atype, name, data)
               VALUES ('{new_cipher}', '2024-06-10 12:00:00', '2024-06-10 12:00:00', '{BOB}', 2, '2.new|iv|mac', '{new_data}');
             DELETE FROM archives WHERE cipher_uuid = '{NOTE}';
             DELETE FROM favorites WHERE cipher_uuid = '{NOTE}';
             DELETE FROM folders_ciphers WHERE cipher_uuid = '{NOTE}';
             DELETE FROM ciphers WHERE uuid = '{NOTE}';
             INSERT INTO attachments (id, cipher_uuid, file_name, file_size, akey)
               VALUES ('{new_attachment}', '{LOGIN}', '2.late|iv|mac', 4, NULL);
             DELETE FROM attachments WHERE id = 'att0000000000002';"
        ),
    )
    .await;
    std::fs::write(
        dir.path()
            .join("attachments")
            .join(LOGIN)
            .join(new_attachment),
        b"late",
    )
    .expect("a new attachment file");
    std::fs::write(
        dir.path().join("config.json"),
        CONFIG_JSON.replace("\"signups_allowed\": false", "\"signups_allowed\": true"),
    )
    .expect("config.json");

    let second = read_folder(dir.path()).await;
    let d = diff(&first, &second);

    // By primary key, deletions included: a deleted row leaves no date to find it by.
    let ciphers = d.table("ciphers").expect("ciphers changed");
    assert_eq!(ciphers.added, vec![key(&[new_cipher])]);
    assert_eq!(ciphers.removed, vec![key(&[NOTE])]);
    assert_eq!(ciphers.changed.len(), 1);
    assert_eq!(ciphers.changed[0].key, key(&[LOGIN]));
    assert_eq!(ciphers.changed[0].columns, vec!["updated_at", "name"]);
    assert_eq!(
        d.table("favorites").expect("favorites").removed,
        vec![key(&[ALICE, NOTE])]
    );
    assert_eq!(
        d.table("archives").expect("archives").removed,
        vec![key(&[ALICE, NOTE])]
    );
    assert_eq!(
        d.table("folders_ciphers").expect("folders_ciphers").removed,
        vec![key(&[NOTE, FOLDER])]
    );
    let attachments = d.table("attachments").expect("attachments");
    assert_eq!(attachments.added, vec![key(&[new_attachment])]);
    assert_eq!(attachments.removed, vec![key(&["att0000000000002"])]);
    assert_eq!(d.tables.len(), 5, "no other table changed: {d}");
    assert_eq!(
        d.attachment_files.added,
        vec![format!("{LOGIN}/{new_attachment}")]
    );
    assert!(d.attachment_files.removed.is_empty());
    assert!(d.send_files.is_empty());
    assert!(d.config_changed);
    assert!(!d.rsa_key_changed);
    assert!(diff(&second, &second.clone()).is_empty());

    // The second pass puts only what changed, then deletes what went away.
    let second_mapped = map_snapshot(&second).expect("maps");
    let delta = second_mapped.delta_since(&first_mapped);
    assert_eq!(delta.accounts.len(), 0);
    assert_eq!(delta.items.len(), 2, "the edited cipher and the new one");
    assert_eq!(delta.attachments.len(), 1);
    assert_eq!(delta.files.len(), 1);
    assert_eq!(
        delta.files[0].storage_key,
        format!("attachments/{LOGIN}/{new_attachment}")
    );
    assert_eq!(delta.carried_rows(), 0);
    assert_eq!(delta.settings.values["signups_allowed"], json!(true));
    assert_eq!(delta.rsa_key, None);
    let edited = delta
        .items
        .iter()
        .find(|i| i.id.to_string() == LOGIN)
        .expect("the edited cipher");
    assert_eq!(edited.json["name"], "2.renamed|iv|mac");
    assert_eq!(edited.json["revisionDate"], "2024-06-10T12:00:00.000000Z");

    let mut sink = Recorder::default();
    let report = apply(&delta, &d.deletions(), &mut sink)
        .await
        .expect("infallible");
    assert_eq!(
        sink.calls,
        vec![
            "accounts 0",
            "folders 0",
            "items 2",
            "states 0",
            "attachments 1",
            "settings 2",
            "finish"
        ]
    );
    assert_eq!(
        sink.copied,
        vec![format!("attachments/{LOGIN}/{new_attachment}")]
    );
    assert_eq!(
        sink.deleted,
        vec![
            ("attachments".to_owned(), key(&["att0000000000002"])),
            ("archives".to_owned(), key(&[ALICE, NOTE])),
            ("favorites".to_owned(), key(&[ALICE, NOTE])),
            ("folders_ciphers".to_owned(), key(&[NOTE, FOLDER])),
            ("ciphers".to_owned(), key(&[NOTE])),
        ]
    );
    assert_eq!(
        report,
        ApplyReport {
            items: 2,
            attachments: 1,
            settings: 2,
            files: 1,
            file_bytes: 4,
            deleted_rows: 5,
            ..ApplyReport::default()
        }
    );
}

#[tokio::test]
async fn the_first_pass_puts_everything() {
    let dir = tempfile::tempdir().expect("a temp folder");
    create_sample_folder(dir.path()).await;
    let mapped = map_snapshot(&read_folder(dir.path()).await).expect("maps");
    let mut sink = Recorder::default();
    let report = apply(&mapped, &[], &mut sink).await.expect("infallible");
    assert_eq!(report.accounts, 2);
    assert_eq!(report.items, 5);
    assert_eq!(report.attachments, 2);
    assert_eq!(report.files, 2);
    assert!(report.rsa_key);
    assert_eq!(report.deleted_rows, 0);
    assert_eq!(sink.accounts.len(), 2);
    assert_eq!(sink.items.len(), 5);
    assert_eq!(sink.calls.first().map(String::as_str), Some("accounts 2"));
    assert_eq!(sink.calls.last().map(String::as_str), Some("finish"));
    assert!(sink.calls.contains(&"rsa key".to_owned()));
}
