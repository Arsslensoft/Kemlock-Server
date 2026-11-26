//! The move from Vaultwarden, end to end: the sample data folder (a SQLite database made by
//! running Vaultwarden 1.37.5's own migrations, see `kemlock-vaultwarden`'s tests) is read, mapped
//! and written by `SqlImportSink` into a store, and the Bitwarden API is asked what it serves.
//! A second pass then applies what changed in Vaultwarden meanwhile: edits and deletions.
//!
//! What `/api/sync` must show for the fixture is written out below by hand from what Vaultwarden's
//! `Cipher::to_json` and `Folder::to_json` return for those rows, not taken from the importer.

mod common;
#[allow(clippy::unwrap_used)]
#[path = "../../kemlock-vaultwarden/tests/common/mod.rs"]
mod vwfix;

use common::{DOMAIN, HASH, Harness, IntoBlobs, SERVER_KEY};
use kemlock_api_bw::password::hash_password;
use kemlock_api_bw::{BlobStore, MemoryBlobStore};
use kemlock_app::admin::AdminUserRepo;
use kemlock_app::bitwarden::{BwAccountRepo, BwOrgStore};
use kemlock_app::emergency::EmergencyRepo;
use kemlock_app::ports::{DeviceRepo, ItemStore, TwoFactorMethod, TwoFactorRepo, UserRepo};
use kemlock_app::spaces::SpaceRepo;
use kemlock_crypto::seal::ServerSeal;
use kemlock_domain::spaces::{CollectionPermission, Grantee, MemberState, SpaceRole};
use kemlock_domain::{DeviceId, DeviceKind, Email, ItemId, Owner, SpaceId, UserId};
use kemlock_store_sql::{ImportOptions, SqlImportSink, SqlStore};
use kemlock_vaultwarden::{ApplyReport, Deletion, MappedImport, apply, diff, map_snapshot};
use serde_json::{Value, json};
use sqlx::ConnectOptions;
use sqlx::sqlite::{SqliteConnectOptions, SqliteConnection};
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use time::OffsetDateTime;
use uuid::Uuid;
use vwfix::{
    ALICE, ATTACHMENT, BOB, CARD, FOLDER, GROUP, LOGIN, NOTE, ORG, RSA_PEM, RSA_PUB_PEM, SEND,
    SHARED, SSH,
};

const DEVICE: &str = "de000000-0000-4000-8000-000000000001";
const NEW_NOTE: &str = "11111111-aaaa-4aaa-8aaa-000000000006";
/// The base32 secret of alice's authenticator in the sample, `JBSWY3DPEHPK3PXP`, as bytes.
const TOTP_SECRET: &[u8] = b"Hello!\xde\xad\xbe\xef";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn uuid(text: &str) -> Uuid {
    Uuid::parse_str(text).expect("a UUID")
}

/// What Vaultwarden returns for alice's login (reprompt 1, a favorite of nobody, two attachments).
/// The download links are made per request, so they are blank here and in what is compared.
fn login_json() -> Value {
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
        "attachments": [
            {
                "id": "att0000000000001", "url": "", "fileName": "2.file|iv|mac",
                "size": "5", "sizeName": "5.00 bytes", "key": "2.attkey|iv|mac",
                "object": "attachment"
            },
            {
                "id": "att0000000000002", "url": "", "fileName": "2.gone|iv|mac",
                "size": "9", "sizeName": "9.00 bytes", "key": null,
                "object": "attachment"
            }
        ],
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
}

/// A secure note in the folder, a favorite and archived.
fn note_json() -> Value {
    json!({
        "object": "cipherDetails",
        "id": NOTE,
        "type": 2,
        "creationDate": "2024-05-03T10:00:00.000000Z",
        "revisionDate": "2024-05-03T10:00:00.000000Z",
        "deletedDate": null,
        "reprompt": 0,
        "organizationId": null,
        "key": null,
        "attachments": null,
        "organizationUseTotp": true,
        "collectionIds": [],
        "name": "2.note|iv|mac",
        "notes": null,
        "fields": [],
        "passwordHistory": [],
        "login": null,
        "secureNote": {"type": 0},
        "card": null,
        "identity": null,
        "sshKey": null,
        "bankAccount": null,
        "driversLicense": null,
        "passport": null,
        "folderId": FOLDER,
        "favorite": true,
        "archivedDate": "2025-01-02T03:04:05.000000Z",
        "edit": true,
        "viewPassword": true,
        "permissions": {"delete": true, "restore": true}
    })
}

/// A card in the trash.
fn card_json() -> Value {
    json!({
        "object": "cipherDetails",
        "id": CARD,
        "type": 3,
        "creationDate": "2024-05-04T10:00:00.000000Z",
        "revisionDate": "2024-05-05T10:00:00.000000Z",
        "deletedDate": "2024-06-01T00:00:00.000000Z",
        "reprompt": 0,
        "organizationId": null,
        "key": null,
        "attachments": null,
        "organizationUseTotp": true,
        "collectionIds": [],
        "name": "2.card|iv|mac",
        "notes": null,
        "fields": [],
        "passwordHistory": [],
        "login": null,
        "secureNote": null,
        "card": {"cardholderName": "2.c|iv|mac", "number": "2.n|iv|mac"},
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
}

fn folder_json(name: &str, revision: &str) -> Value {
    json!({"id": FOLDER, "revisionDate": revision, "name": name, "object": "folder"})
}

/// Blanks the download link of every attachment (it holds a token), after checking it points at
/// this server's file route for that attachment.
fn without_links(mut cipher: Value) -> Value {
    let id = cipher["id"].as_str().expect("an id").to_owned();
    if let Some(list) = cipher["attachments"].as_array_mut() {
        for attachment in list {
            let url = attachment["url"].as_str().expect("a link").to_owned();
            let file = attachment["id"].as_str().expect("an id").to_owned();
            assert!(
                url.starts_with(&format!("{DOMAIN}/attachments/{id}/{file}?token=")),
                "{url}"
            );
            attachment["url"] = json!("");
        }
    }
    cipher
}

fn ciphers_of(sync: &Value) -> BTreeMap<String, Value> {
    sync["ciphers"]
        .as_array()
        .expect("a list of ciphers")
        .iter()
        .cloned()
        .map(|c| {
            (
                c["id"].as_str().expect("an id").to_owned(),
                without_links(c),
            )
        })
        .collect()
}

async fn sync(h: &Harness, token: &str) -> Value {
    let (status, body) = h.json("GET", "/api/sync", Some(token), None).await;
    assert_eq!(status, 200, "{body}");
    body
}

/// Opens one pass, puts `mapped` into it and deletes `deletions`, and commits.
async fn pass(
    store: &SqlStore,
    files: &Path,
    blobs: &Arc<MemoryBlobStore>,
    now: OffsetDateTime,
    retention: Option<i64>,
    mapped: &MappedImport,
    deletions: &[Deletion],
) -> ApplyReport {
    let mut options = ImportOptions::new(files, Arc::new(IntoBlobs(blobs.clone())), now);
    options.events_retention_days = retention;
    let mut sink = SqlImportSink::begin(store, ServerSeal::new(&SERVER_KEY), options)
        .await
        .expect("a pass opens");
    apply(mapped, deletions, &mut sink)
        .await
        .expect("the pass applies")
}

async fn raw(path: &Path) -> SqliteConnection {
    SqliteConnectOptions::new()
        .filename(path)
        .connect()
        .await
        .expect("opens the store's database")
}

async fn count(conn: &mut SqliteConnection, sql: &'static str) -> i64 {
    sqlx::query_scalar::<sqlx::Sqlite, i64>(sql)
        .fetch_one(&mut *conn)
        .await
        .expect("counts")
}

fn file_url(path: &Path) -> String {
    format!(
        "sqlite://{}?mode=rwc",
        path.to_string_lossy().replace('\\', "/")
    )
}

/// Makes the sample's passwords ones a client can sign in with: Vaultwarden's hashes are of a
/// client's hash, which the fixture can't know.
async fn give_alice_a_known_password(vw: &Path) {
    let mut conn = vwfix::writer(vw).await;
    let hash = hash_password(HASH.as_bytes(), &[1, 2, 3, 4, 5, 6, 7, 8], 1_000);
    vwfix::exec(
        &mut conn,
        &format!(
            "UPDATE users SET password_hash = X'{}', password_iterations = 1000 WHERE uuid = '{ALICE}';
             UPDATE devices SET refresh_token = '{}' WHERE uuid = '{DEVICE}';",
            hex(&hash),
            kemlock_app::b64url::encode(&[9u8; 64]),
        ),
    )
    .await;
    sqlx::Connection::close(conn).await.expect("closes");
}

/// A signed-in alice: she has an authenticator, so the code goes with the password.
async fn sign_in_alice(h: &Harness) -> String {
    let code = kemlock_crypto::totp::code_at(
        TOTP_SECRET,
        u64::try_from(h.env.time().unix_timestamp()).expect("a time"),
    );
    let mut fields = Harness::password_fields("alice@example.org", HASH);
    fields.push(("twoFactorProvider", "0"));
    fields.push(("twoFactorToken", code.as_str()));
    let (status, body) = h.token(&fields).await;
    assert_eq!(status, 200, "{body}");
    body["access_token"].as_str().expect("a token").to_owned()
}

#[tokio::test]
async fn a_failed_pass_leaves_nothing_behind() {
    let vw = tempfile::tempdir().expect("a temp folder");
    vwfix::create_sample_folder(vw.path()).await;
    let mut mapped = map_snapshot(&vwfix::read_folder(vw.path()).await).expect("maps");
    // The second account can't be stored; the first is written before it is found out.
    let mut bad = mapped.accounts[1].clone();
    bad.email = "not an email".to_owned();
    mapped.accounts[1] = bad;

    let dest = tempfile::tempdir().expect("a temp folder");
    let h = Harness::new().await;
    let mut sink = SqlImportSink::begin(
        &h.store,
        ServerSeal::new(&SERVER_KEY),
        ImportOptions::new(
            dest.path(),
            Arc::new(IntoBlobs(h.blobs.clone())),
            h.env.time(),
        ),
    )
    .await
    .expect("a pass opens");
    let error = apply(&mapped, &[], &mut sink)
        .await
        .expect_err("the account is refused");
    assert!(
        error.to_string().contains("not one Kemlock accepts"),
        "{error}"
    );
    drop(sink);

    let alice = Email::parse("alice@example.org").expect("an email");
    assert!(
        UserRepo::by_email(&h.store, &alice)
            .await
            .expect("reads")
            .is_none(),
        "the first account was rolled back with the pass"
    );

    // The store is free again: a good pass goes through.
    let good = map_snapshot(&vwfix::read_folder(vw.path()).await).expect("maps");
    let report = pass(
        &h.store,
        dest.path(),
        &h.blobs,
        h.env.time(),
        None,
        &good,
        &[],
    )
    .await;
    assert_eq!(report.accounts, 2);
    assert!(
        UserRepo::by_email(&h.store, &alice)
            .await
            .expect("reads")
            .is_some()
    );
}

#[tokio::test]
async fn imports_the_sample_and_serves_it_as_vaultwarden_would_then_applies_a_second_pass() {
    let vw = tempfile::tempdir().expect("a temp folder");
    vwfix::create_sample_folder(vw.path()).await;
    give_alice_a_known_password(vw.path()).await;
    let store_dir = tempfile::tempdir().expect("a temp folder");
    let db = store_dir.path().join("kemlock.db");
    let store = SqlStore::connect(&file_url(&db)).await.expect("a store");
    let h = Harness::on(store.clone(), |_| {}).await;
    let dest = tempfile::tempdir().expect("a temp folder");
    let now = h.env.time();

    // ---- The first pass: Vaultwarden running.
    let first = vwfix::read_folder(vw.path()).await;
    let first_mapped = map_snapshot(&first).expect("maps");
    let report = pass(
        &store,
        dest.path(),
        &h.blobs,
        now,
        Some(90),
        &first_mapped,
        &[],
    )
    .await;
    assert_eq!(report.accounts, 2);
    assert_eq!(report.folders, 1);
    assert_eq!(report.items, 5);
    assert_eq!(report.attachments, 2);
    assert_eq!(report.files, 2);
    assert!(report.rsa_key);

    // Files are where the Bitwarden API reads them, and the signing key is carried as it is.
    assert_eq!(
        BlobStore::get(&*h.blobs, &format!("{LOGIN}/{ATTACHMENT}")).await,
        Ok(Some(b"12345".to_vec()))
    );
    assert_eq!(
        BlobStore::get(&*h.blobs, &format!("sends/{SEND}/fileid1")).await,
        Ok(Some(b"abc".to_vec()))
    );
    // Nothing but the signing key is copied under the data folder.
    assert!(!dest.path().join("attachments").exists());
    assert!(!dest.path().join("sends").exists());
    assert_eq!(
        std::fs::read(dest.path().join("rsa_key.pem")).expect("the key"),
        RSA_PEM
    );
    assert_eq!(
        std::fs::read(dest.path().join("rsa_key.pub.pem")).expect("the public key"),
        RSA_PUB_PEM
    );

    // Alice signs in with the password and authenticator code Vaultwarden knew.
    let token = sign_in_alice(&h).await;
    let alice = UserId(uuid(ALICE));
    let account = BwAccountRepo::get(&store, alice)
        .await
        .expect("reads")
        .expect("alice's Bitwarden account");
    assert_eq!(account.akey, "2.userkey|iv|mac");
    assert_eq!(account.private_key.as_deref(), Some("2.private|iv|mac"));
    assert_eq!(account.api_key.as_deref(), Some("apikey-alice"));
    assert_eq!(account.avatar_color.as_deref(), Some("#00ff00"));
    let revision_after_first = h
        .json("GET", "/api/accounts/revision-date", Some(&token), None)
        .await
        .1
        .as_i64()
        .expect("a number");

    // ---- /api/sync: the folder, and every cipher byte for byte.
    let before = sync(&h, &token).await;
    assert_eq!(before["object"], "sync");
    assert_eq!(before["profile"]["email"], "alice@example.org");
    assert_eq!(before["profile"]["name"], "Alice");
    assert_eq!(before["profile"]["key"], "2.userkey|iv|mac");
    assert_eq!(before["profile"]["privateKey"], "2.private|iv|mac");
    assert_eq!(before["profile"]["avatarColor"], "#00ff00");
    assert_eq!(
        before["profile"]["creationDate"],
        "2023-01-02T03:04:05.123456Z"
    );
    assert_eq!(before["profile"]["twoFactorEnabled"], true);
    assert_eq!(
        before["folders"],
        json!([folder_json(
            "2.folder|iv|mac",
            "2024-03-02T00:00:00.000000Z"
        )])
    );
    let ciphers = ciphers_of(&before);
    assert_eq!(
        ciphers.keys().map(String::as_str).collect::<Vec<_>>(),
        vec![LOGIN, NOTE, CARD, SHARED],
        "alice's own ciphers and, as the Family organization's confirmed Owner with access to all, \n         its cipher, as Vaultwarden's sync gives them; bob's SSH key is not hers"
    );
    assert_eq!(ciphers[LOGIN], login_json());
    assert_eq!(ciphers[NOTE], note_json());
    assert_eq!(ciphers[CARD], card_json());

    // GET of one is the sync's entry, and the SSH key is bob's alone.
    let (status, one) = h
        .json("GET", &format!("/api/ciphers/{LOGIN}"), Some(&token), None)
        .await;
    assert_eq!(status, 200);
    assert_eq!(without_links(one), login_json());
    let (status, _) = h
        .json("GET", &format!("/api/ciphers/{SSH}"), Some(&token), None)
        .await;
    assert_ne!(status, 200);

    // A change from an app turns an imported cipher into the API's own document, and what it then
    // serves is still exactly what Vaultwarden returned.
    let (status, partial) = h
        .json(
            "PUT",
            &format!("/api/ciphers/{NOTE}/partial"),
            Some(&token),
            Some(json!({"folderId": FOLDER, "favorite": true})),
        )
        .await;
    assert_eq!(status, 200, "{partial}");
    assert_eq!(without_links(partial), note_json());
    assert_eq!(ciphers_of(&sync(&h, &token).await)[NOTE], note_json());

    // ---- The rest of what moved.
    let devices = DeviceRepo::get(&store, DeviceId(uuid(DEVICE)))
        .await
        .expect("reads")
        .expect("the device");
    assert_eq!(
        (devices.name.as_str(), devices.kind),
        ("Pixel", DeviceKind::Bitwarden)
    );
    // Its refresh token still works.
    let refresh = kemlock_app::b64url::encode(&[9u8; 64]);
    let (status, refreshed) = h
        .token(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh.as_str()),
            ("client_id", "mobile"),
        ])
        .await;
    assert_eq!(status, 200, "{refreshed}");
    assert!(refreshed["access_token"].is_string());

    let factors = TwoFactorRepo::list(&store, alice).await.expect("reads");
    assert_eq!(factors.len(), 1);
    assert_eq!(factors[0].method, TwoFactorMethod::Totp);
    assert!(factors[0].enabled);
    assert_eq!(
        // Sealed to the account, as every per-account secret is.
        ServerSeal::new(&SERVER_KEY)
            .open(
                &kemlock_app::sealed::bound_purpose("totp", alice),
                &factors[0].sealed_secret,
            )
            .expect("opens with the server key")
            .as_slice(),
        TOTP_SECRET
    );

    let space = SpaceRepo::load(&store, SpaceId(uuid(ORG)))
        .await
        .expect("reads")
        .expect("the organization is a space");
    assert_eq!(space.space.name, b"Family");
    assert_eq!(space.members.len(), 2);
    let bob = space
        .members
        .iter()
        .find(|m| m.user == UserId(uuid(BOB)))
        .expect("bob is a member");
    assert_eq!(
        (bob.role, bob.state),
        (SpaceRole::Member, MemberState::Confirmed)
    );
    assert_eq!(
        bob.sealed_space_key.as_deref(),
        Some(&b"2.orgkey-b|iv|mac"[..])
    );
    assert_eq!(bob.invited_by, alice);
    let owner = space
        .members
        .iter()
        .find(|m| m.user == alice)
        .expect("alice is a member");
    assert_eq!(owner.role, SpaceRole::Owner);
    assert_eq!(space.collections.len(), 1);
    assert_eq!(space.collections[0].name, b"2.coll|iv|mac");
    assert_eq!(space.groups.len(), 1);
    assert!(space.groups[0].members.contains(&UserId(uuid(BOB))));
    let grants: Vec<(Grantee, &str)> = space
        .grants
        .iter()
        .map(|g| (g.grantee, g.permission.as_str()))
        .collect();
    assert_eq!(grants.len(), 2);
    assert!(grants.contains(&(Grantee::Member(UserId(uuid(BOB))), "view")));
    assert!(grants.contains(&(
        Grantee::Group(kemlock_domain::spaces::GroupId(uuid(GROUP))),
        CollectionPermission::EditHidePasswords.as_str()
    )));
    // The organization's cipher is in its space and its collection, viewer-independent.
    let shared = ItemStore::get(&store, ItemId(uuid(SHARED)))
        .await
        .expect("reads")
        .expect("the shared cipher");
    assert_eq!(shared.owner, Owner::Space(SpaceId(uuid(ORG))));
    let doc: Value = serde_json::from_slice(shared.ciphertext.as_deref().expect("a body"))
        .expect("Vaultwarden's cipher JSON");
    assert_eq!(doc["organizationId"], ORG);
    assert!(doc.get("favorite").is_none());

    let grants = EmergencyRepo::grants_of_grantor(&store, alice)
        .await
        .expect("reads");
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0].grantee_email.as_str(), "bob@example.org");
    assert_eq!(grants[0].state.as_str(), "confirmed");
    assert_eq!(grants[0].kind.as_str(), "view");
    assert_eq!(grants[0].wait_days, 7);
    assert_eq!(grants[0].grantee, Some(UserId(uuid(BOB))));

    let mut conn = raw(&db).await;
    let setting = |key: &'static str| {
        sqlx::query_scalar::<sqlx::Sqlite, String>("SELECT value FROM settings WHERE key = ?")
            .bind(key)
    };
    // Only the names of the admin settings list are carried, under the key the settings code reads:
    // `domain` is not one of them.
    assert_eq!(
        count(
            &mut conn,
            "SELECT COUNT(*) FROM settings WHERE key = 'domain'"
        )
        .await,
        0
    );
    assert_eq!(
        setting("setting.smtp_host")
            .fetch_one(&mut conn)
            .await
            .expect("a setting"),
        "mail.example.org"
    );
    assert_eq!(
        setting("setting.signups_allowed")
            .fetch_one(&mut conn)
            .await
            .expect("a setting"),
        "false"
    );
    assert_eq!(
        count(
            &mut conn,
            "SELECT COUNT(*) FROM settings WHERE key = 'smtp_password'"
        )
        .await,
        0
    );
    assert_eq!(
        count(
            &mut conn,
            "SELECT COUNT(*) FROM vw_rows WHERE table_name = 'sends'"
        )
        .await,
        2
    );
    assert_eq!(
        count(
            &mut conn,
            "SELECT COUNT(*) FROM vw_rows WHERE table_name = 'org_policies'"
        )
        .await,
        1
    );
    let sealed: String = sqlx::query_scalar::<sqlx::Sqlite, String>(
        "SELECT data FROM vw_rows WHERE table_name = 'twofactor'",
    )
    .fetch_one(&mut conn)
    .await
    .expect("a sealed row");
    assert!(
        sealed.starts_with("sealed:") && !sealed.contains("JBSWY3DPEHPK3PXP"),
        "{sealed}"
    );
    assert_eq!(
        count(&mut conn, "SELECT COUNT(*) FROM bw_attachments").await,
        2
    );
    // The sample's one event is from 2024: past the 90 days of retention.
    assert_eq!(count(&mut conn, "SELECT COUNT(*) FROM events").await, 0);

    // ---- Vaultwarden changes while it is being moved: edits and deletions.
    let mut vwconn = vwfix::writer(vw.path()).await;
    vwfix::exec(
        &mut vwconn,
        &format!(
            r#"
UPDATE ciphers SET name = '2.renamed|iv|mac', updated_at = '2024-07-01 00:00:00' WHERE uuid = '{LOGIN}';
INSERT INTO favorites (user_uuid, cipher_uuid) VALUES ('{ALICE}', '{LOGIN}');
DELETE FROM archives WHERE cipher_uuid = '{NOTE}';
DELETE FROM favorites WHERE cipher_uuid = '{NOTE}';
DELETE FROM folders_ciphers WHERE cipher_uuid = '{NOTE}';
DELETE FROM ciphers WHERE uuid = '{NOTE}';
DELETE FROM attachments WHERE id = 'att0000000000002';
UPDATE folders SET name = '2.folder2|iv|mac', updated_at = '2024-07-02 00:00:00' WHERE uuid = '{FOLDER}';
INSERT INTO ciphers (uuid, created_at, updated_at, user_uuid, organization_uuid, atype, name, notes,
    fields, data, password_history, deleted_at, reprompt, "key")
VALUES ('{NEW_NOTE}', '2024-08-01 00:00:00', '2024-08-01 00:00:00', '{ALICE}', NULL, 2, '2.new|iv|mac',
    NULL, NULL, '{{"Type":0}}', NULL, NULL, 0, NULL);
DELETE FROM users_collections WHERE user_uuid = '{BOB}';
UPDATE organizations SET name = 'Family 2' WHERE uuid = '{ORG}';
DELETE FROM emergency_access;
"#
        ),
    )
    .await;
    sqlx::Connection::close(vwconn).await.expect("closes");

    // ---- The second pass: Vaultwarden stopped; only what changed is applied.
    let second = vwfix::read_folder(vw.path()).await;
    let second_mapped = map_snapshot(&second).expect("maps");
    let changes = diff(&first, &second);
    let deletions = changes.deletions();
    let tables: Vec<&str> = deletions.iter().map(|d| d.table).collect();
    for table in [
        "ciphers",
        "attachments",
        "emergency_access",
        "users_collections",
        "favorites",
    ] {
        assert!(tables.contains(&table), "{table} among {tables:?}");
    }
    let delta = second_mapped.delta_since(&first_mapped);
    assert_eq!(delta.items.len(), 2, "the renamed login and the new note");
    pass(
        &store,
        dest.path(),
        &h.blobs,
        now,
        Some(90),
        &delta,
        &deletions,
    )
    .await;

    let after = sync(&h, &token).await;
    assert_eq!(
        after["folders"],
        json!([folder_json(
            "2.folder2|iv|mac",
            "2024-07-02T00:00:00.000000Z"
        )])
    );
    let ciphers = ciphers_of(&after);
    assert_eq!(
        ciphers.keys().map(String::as_str).collect::<Vec<_>>(),
        vec![LOGIN, CARD, SHARED, NEW_NOTE],
        "the note is gone, the new one is there, and the organization's cipher stays"
    );
    let mut login = login_json();
    login["name"] = json!("2.renamed|iv|mac");
    login["revisionDate"] = json!("2024-07-01T00:00:00.000000Z");
    login["favorite"] = json!(true);
    login["attachments"] = json!([login_json()["attachments"][0].clone()]);
    assert_eq!(ciphers[LOGIN], login);
    assert_eq!(ciphers[CARD], card_json());
    assert_eq!(ciphers[NEW_NOTE]["name"], "2.new|iv|mac");
    assert_eq!(ciphers[NEW_NOTE]["secureNote"], json!({"type": 0}));
    let gone = ItemStore::get(&store, ItemId(uuid(NOTE)))
        .await
        .expect("reads")
        .expect("a tombstone stays");
    assert!(gone.is_tombstone());
    // Vaultwarden answers a cipher that is gone with its error body, a 400, not a 404.
    let (status, body) = h
        .json("GET", &format!("/api/ciphers/{NOTE}"), Some(&token), None)
        .await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["message"], "Cipher doesn't exist");

    let revision_after_second = h
        .json("GET", "/api/accounts/revision-date", Some(&token), None)
        .await
        .1
        .as_i64()
        .expect("a number");
    assert!(
        revision_after_second > revision_after_first,
        "apps are told to sync"
    );

    let space = SpaceRepo::load(&store, SpaceId(uuid(ORG)))
        .await
        .expect("reads")
        .expect("the space");
    assert_eq!(space.space.name, b"Family 2");
    assert_eq!(
        space.grants.len(),
        1,
        "bob's own grant is gone, the group's stays"
    );
    assert!(matches!(space.grants[0].grantee, Grantee::Group(_)));
    assert!(
        EmergencyRepo::grants_of_grantor(&store, alice)
            .await
            .expect("reads")
            .is_empty()
    );
    assert_eq!(
        count(&mut conn, "SELECT COUNT(*) FROM bw_attachments").await,
        1
    );
    assert_eq!(
        count(
            &mut conn,
            "SELECT COUNT(*) FROM vw_rows WHERE table_name = 'users_collections'"
        )
        .await,
        0
    );
    // The file of the attachment that went stays gone, the other stays.
    assert!(
        BlobStore::get(&*h.blobs, &format!("{LOGIN}/{ATTACHMENT}"))
            .await
            .expect("reads")
            .is_some()
    );

    // ---- Running a pass again changes nothing in the vault: no item gets a new revision.
    let owners = [Owner::User(alice)];
    let latest = ItemStore::latest(&store, &owners).await.expect("reads");
    pass(
        &store,
        dest.path(),
        &h.blobs,
        now,
        None,
        &second_mapped,
        &[],
    )
    .await;
    assert_eq!(
        ItemStore::latest(&store, &owners).await.expect("reads"),
        latest,
        "the same rows are the same items"
    );
    assert_eq!(ciphers_of(&sync(&h, &token).await), ciphers);
    // Without a retention window the event is imported too, once.
    assert_eq!(count(&mut conn, "SELECT COUNT(*) FROM events").await, 1);
    pass(
        &store,
        dest.path(),
        &h.blobs,
        now,
        None,
        &second_mapped,
        &[],
    )
    .await;
    assert_eq!(count(&mut conn, "SELECT COUNT(*) FROM events").await, 1);
}

#[tokio::test]
async fn a_user_vaultwarden_had_disabled_gets_no_session_until_an_admin_enables_it() {
    let vw = tempfile::tempdir().expect("a temp folder");
    vwfix::create_sample_folder(vw.path()).await;
    give_alice_a_known_password(vw.path()).await;
    let mut conn = vwfix::writer(vw.path()).await;
    vwfix::exec(
        &mut conn,
        &format!("UPDATE users SET enabled = 0 WHERE uuid = '{ALICE}';"),
    )
    .await;
    sqlx::Connection::close(conn).await.expect("closes");

    let h = Harness::new().await;
    let dest = tempfile::tempdir().expect("a temp folder");
    let mapped = map_snapshot(&vwfix::read_folder(vw.path()).await).expect("maps");
    pass(
        &h.store,
        dest.path(),
        &h.blobs,
        h.env.time(),
        None,
        &mapped,
        &[],
    )
    .await;
    let alice = UserId(uuid(ALICE));

    // The password and the device's refresh token, both as Vaultwarden knew them, get nothing.
    let (status, body) = h
        .token(&Harness::password_fields("alice@example.org", HASH))
        .await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["message"], "This user has been disabled");
    let refresh = kemlock_app::b64url::encode(&[9u8; 64]);
    let (status, body) = h
        .token(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh.as_str()),
            ("client_id", "mobile"),
        ])
        .await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["message"], "This user has been disabled");
    assert!(body.get("access_token").is_none());

    // Enabling the account clears the flag it came with; the password then works.
    AdminUserRepo::set_disabled(&h.store, alice, None)
        .await
        .expect("enables");
    sign_in_alice(&h).await;
}

#[tokio::test]
async fn imported_files_go_to_the_blob_store_the_bitwarden_api_reads() {
    let vw = tempfile::tempdir().expect("a temp folder");
    vwfix::create_sample_folder(vw.path()).await;
    give_alice_a_known_password(vw.path()).await;
    let h = Harness::new().await;
    let dest = tempfile::tempdir().expect("a temp folder");
    let first = vwfix::read_folder(vw.path()).await;
    let mapped = map_snapshot(&first).expect("maps");

    let options = ImportOptions::new(
        dest.path(),
        Arc::new(IntoBlobs(h.blobs.clone())),
        h.env.time(),
    );
    let mut sink = SqlImportSink::begin(&h.store, ServerSeal::new(&SERVER_KEY), options)
        .await
        .expect("a pass opens");
    apply(&mapped, &[], &mut sink)
        .await
        .expect("the pass applies");

    // Under the data folder nothing was copied: the blob store keeps the files, by the keys the
    // API uses (`<cipher>/<attachment>`, and `sends/<send>/<file>` for a Send's).
    assert!(!dest.path().join("attachments").exists());
    assert!(!dest.path().join("sends").exists());
    let key = format!("{LOGIN}/{ATTACHMENT}");
    assert_eq!(
        BlobStore::get(&*h.blobs, &key).await,
        Ok(Some(b"12345".to_vec()))
    );
    assert_eq!(
        BlobStore::get(&*h.blobs, &format!("sends/{SEND}/fileid1")).await,
        Ok(Some(b"abc".to_vec()))
    );

    // And the API finds the attachment through the link it gives.
    let token = sign_in_alice(&h).await;
    let (status, one) = h
        .json("GET", &format!("/api/ciphers/{LOGIN}"), Some(&token), None)
        .await;
    assert_eq!(status, 200, "{one}");
    let url = one["attachments"][0]["url"].as_str().expect("a link");
    let (status, _, bytes) = h
        .send(
            "GET",
            url.trim_start_matches(DOMAIN),
            &[],
            axum::body::Body::empty(),
        )
        .await;
    assert_eq!(status, 200);
    assert_eq!(bytes, b"12345");

    // A second pass that finds the attachment gone from Vaultwarden removes its file there too.
    let mut vwconn = vwfix::writer(vw.path()).await;
    vwfix::exec(
        &mut vwconn,
        &format!("DELETE FROM attachments WHERE id = '{ATTACHMENT}';"),
    )
    .await;
    sqlx::Connection::close(vwconn).await.expect("closes");
    let second = vwfix::read_folder(vw.path()).await;
    let deletions = diff(&first, &second).deletions();
    let options = ImportOptions::new(
        dest.path(),
        Arc::new(IntoBlobs(h.blobs.clone())),
        h.env.time(),
    );
    let mut sink = SqlImportSink::begin(&h.store, ServerSeal::new(&SERVER_KEY), options)
        .await
        .expect("a pass opens");
    let delta = map_snapshot(&second).expect("maps").delta_since(&mapped);
    apply(&delta, &deletions, &mut sink)
        .await
        .expect("the pass applies");
    assert_eq!(BlobStore::get(&*h.blobs, &key).await, Ok(None));
}

const SECOND_COLLECTION: &str = "e6666666-6666-4666-8666-666666666666";
const FIRST_COLLECTION: &str = "e5555555-5555-4555-8555-555555555555";

/// The sample with its organization cipher in a second collection too.
async fn sample_with_a_second_collection(vw: &Path) {
    vwfix::create_sample_folder(vw).await;
    give_alice_a_known_password(vw).await;
    let mut conn = vwfix::writer(vw).await;
    vwfix::exec(
        &mut conn,
        &format!(
            "INSERT INTO collections (uuid, org_uuid, name, external_id)
                VALUES ('{SECOND_COLLECTION}', '{ORG}', '2.coll2|iv|mac', NULL);
             INSERT INTO ciphers_collections (cipher_uuid, collection_uuid)
                VALUES ('{SHARED}', '{SECOND_COLLECTION}');"
        ),
    )
    .await;
    sqlx::Connection::close(conn).await.expect("closes");
}

async fn doc(h: &Harness, scope: &str, kind: &str, key: &str) -> Option<Value> {
    BwOrgStore::doc_get(&h.store, uuid(scope), kind, key)
        .await
        .expect("reads")
        .map(|text| serde_json::from_str(&text).expect("a JSON document"))
}

#[tokio::test]
async fn an_imported_organization_gets_the_documents_the_bitwarden_api_serves_it_from() {
    let vw = tempfile::tempdir().expect("a temp folder");
    sample_with_a_second_collection(vw.path()).await;
    let h = Harness::new().await;
    let dest = tempfile::tempdir().expect("a temp folder");
    let first = vwfix::read_folder(vw.path()).await;
    let mapped = map_snapshot(&first).expect("maps");
    pass(
        &h.store,
        dest.path(),
        &h.blobs,
        h.env.time(),
        None,
        &mapped,
        &[],
    )
    .await;

    let org = doc(&h, ORG, "org", "").await.expect("the organization");
    assert_eq!(org["billingEmail"], "alice@example.org");
    assert_eq!(org["privateKey"], "2.orgpriv|iv|mac");
    assert_eq!(org["publicKey"], "orgpub");
    let alice = doc(&h, ORG, "member", ALICE)
        .await
        .expect("alice's membership");
    assert_eq!(alice["atype"], 0);
    assert_eq!(alice["status"], 2);
    assert_eq!(alice["accessAll"], true);
    assert_eq!(alice["akey"], "2.orgkey-a|iv|mac");
    let bob = doc(&h, ORG, "member", BOB).await.expect("bob's membership");
    assert_eq!(bob["atype"], 2);
    assert_eq!(bob["accessAll"], false);
    assert_eq!(bob["invitedByEmail"], "alice@example.org");
    assert!(doc(&h, ORG, "collection", FIRST_COLLECTION).await.is_some());
    assert!(doc(&h, ORG, "group", GROUP).await.is_some());
    let policy = doc(&h, ORG, "policy", "1").await.expect("the policy");
    assert_eq!(policy["enabled"], true);
    assert_eq!(policy["data"], "{}");
    assert_eq!(policy["id"], "90000000-0000-4000-8000-000000000001");
    // Every collection the cipher is in, not only the first the space tables keep.
    assert_eq!(
        doc(&h, ORG, "cc", SHARED).await,
        Some(json!([FIRST_COLLECTION, SECOND_COLLECTION]))
    );
    // What bob had set on the cipher, kept for him.
    let pref = doc(&h, BOB, "orgpref", SHARED).await.expect("bob's state");
    assert_eq!(pref["favorite"], true);
    assert!(pref["folderId"].is_null());

    // A second pass that finds the policy and the link gone drops their documents.
    let mut vwconn = vwfix::writer(vw.path()).await;
    vwfix::exec(
        &mut vwconn,
        &format!(
            "DELETE FROM org_policies;
             DELETE FROM ciphers_collections WHERE collection_uuid = '{SECOND_COLLECTION}';
             DELETE FROM favorites WHERE user_uuid = '{BOB}';"
        ),
    )
    .await;
    sqlx::Connection::close(vwconn).await.expect("closes");
    let second = vwfix::read_folder(vw.path()).await;
    let deletions = diff(&first, &second).deletions();
    let delta = map_snapshot(&second).expect("maps").delta_since(&mapped);
    pass(
        &h.store,
        dest.path(),
        &h.blobs,
        h.env.time(),
        None,
        &delta,
        &deletions,
    )
    .await;
    assert_eq!(doc(&h, ORG, "policy", "1").await, None);
    assert_eq!(
        doc(&h, ORG, "cc", SHARED).await,
        Some(json!([FIRST_COLLECTION]))
    );
    assert_eq!(doc(&h, BOB, "orgpref", SHARED).await, None);
}

#[tokio::test]
async fn an_imported_organization_and_its_cipher_are_served_in_every_collection() {
    let vw = tempfile::tempdir().expect("a temp folder");
    sample_with_a_second_collection(vw.path()).await;
    let h = Harness::new().await;
    let dest = tempfile::tempdir().expect("a temp folder");
    let mapped = map_snapshot(&vwfix::read_folder(vw.path()).await).expect("maps");
    pass(
        &h.store,
        dest.path(),
        &h.blobs,
        h.env.time(),
        None,
        &mapped,
        &[],
    )
    .await;
    let token = sign_in_alice(&h).await;
    let body = sync(&h, &token).await;

    let organizations = body["profile"]["organizations"].as_array().expect("a list");
    assert_eq!(organizations.len(), 1, "{body}");
    assert_eq!(organizations[0]["id"], ORG);
    assert_eq!(organizations[0]["name"], "Family");
    assert_eq!(organizations[0]["key"], "2.orgkey-a|iv|mac");
    assert_eq!(organizations[0]["type"], 0);

    let collections: Vec<&str> = body["collections"]
        .as_array()
        .expect("a list")
        .iter()
        .filter_map(|c| c["id"].as_str())
        .collect();
    assert_eq!(collections.len(), 2, "{collections:?}");
    assert!(collections.contains(&FIRST_COLLECTION) && collections.contains(&SECOND_COLLECTION));
    let policies = body["policies"].as_array().expect("a list");
    assert_eq!(policies.len(), 1);
    assert_eq!(
        (
            policies[0]["type"].as_i64(),
            policies[0]["enabled"].as_bool()
        ),
        (Some(1), Some(true))
    );

    // The organization's cipher is there, in both its collections.
    let shared = body["ciphers"]
        .as_array()
        .expect("a list")
        .iter()
        .find(|c| c["id"] == SHARED)
        .expect("the organization's cipher is synced");
    assert_eq!(shared["organizationId"], ORG);
    assert_eq!(shared["name"], "2.shared|iv|mac");
    assert_eq!(
        shared["collectionIds"],
        json!([FIRST_COLLECTION, SECOND_COLLECTION])
    );
    let (status, one) = h
        .json("GET", &format!("/api/ciphers/{SHARED}"), Some(&token), None)
        .await;
    assert_eq!(status, 200, "{one}");
    assert_eq!(one["collectionIds"], shared["collectionIds"]);
}

#[tokio::test]
async fn a_rerun_leaves_the_documents_the_api_changed_and_refreshes_the_rest() {
    let vw = tempfile::tempdir().expect("a temp folder");
    sample_with_a_second_collection(vw.path()).await;
    let h = Harness::new().await;
    let dest = tempfile::tempdir().expect("a temp folder");
    let first = vwfix::read_folder(vw.path()).await;
    let mapped = map_snapshot(&first).expect("maps");
    pass(
        &h.store,
        dest.path(),
        &h.blobs,
        h.env.time(),
        None,
        &mapped,
        &[],
    )
    .await;
    assert_eq!(
        doc(&h, ORG, "policy", "1").await.expect("a policy")["enabled"],
        true
    );

    // An admin switches the policy off in an app.
    let edited = json!({
        "id": "90000000-0000-4000-8000-000000000001",
        "enabled": false,
        "data": "{}",
        "revisionDate": "2026-11-23T10:00:00.000000Z",
    });
    BwOrgStore::doc_put(&h.store, uuid(ORG), "policy", "1", &edited.to_string())
        .await
        .expect("writes");
    // The app also removes the cipher's collection links.
    BwOrgStore::doc_delete(&h.store, uuid(ORG), "cc", SHARED)
        .await
        .expect("deletes");

    // Meanwhile Vaultwarden changes the policy, the billing address and bob's access.
    let mut vwconn = vwfix::writer(vw.path()).await;
    vwfix::exec(
        &mut vwconn,
        &format!(
            "UPDATE org_policies SET data = '{{\"minLength\":8}}';
             UPDATE organizations SET billing_email = 'billing@example.org';
             UPDATE users_organizations SET access_all = 1 WHERE user_uuid = '{BOB}';"
        ),
    )
    .await;
    sqlx::Connection::close(vwconn).await.expect("closes");
    let second = vwfix::read_folder(vw.path()).await;
    let deletions = diff(&first, &second).deletions();
    let delta = map_snapshot(&second).expect("maps").delta_since(&mapped);
    pass(
        &h.store,
        dest.path(),
        &h.blobs,
        h.env.time(),
        None,
        &delta,
        &deletions,
    )
    .await;

    // What the API changed stays, whatever Vaultwarden has now.
    assert_eq!(doc(&h, ORG, "policy", "1").await, Some(edited));
    assert_eq!(doc(&h, ORG, "cc", SHARED).await, None);
    // What nobody touched follows Vaultwarden.
    assert_eq!(
        doc(&h, ORG, "org", "").await.expect("the organization")["billingEmail"],
        "billing@example.org"
    );
    assert_eq!(
        doc(&h, ORG, "member", BOB).await.expect("bob")["accessAll"],
        true
    );
}
