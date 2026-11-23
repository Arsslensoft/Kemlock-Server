//! An account as the apps' own server tests make one, and the bodies the apps send.

use crate::enc::{b64, enc, enc_bytes, random_bytes};
use crate::fixtures;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicU64, Ordering};

/// An account's key derivation, as prelogin and registration name it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Kdf {
    /// 0 PBKDF2-SHA256, 1 Argon2id.
    pub kind: u64,
    /// PBKDF2 rounds, or Argon2 passes.
    pub iterations: u64,
    /// Argon2 only: MiB.
    pub memory: Option<u64>,
    /// Argon2 only: lanes.
    pub parallelism: Option<u64>,
}

impl Kdf {
    /// PBKDF2-SHA256 with `iterations` rounds.
    pub fn pbkdf2(iterations: u64) -> Kdf {
        Kdf {
            kind: 0,
            iterations,
            memory: None,
            parallelism: None,
        }
    }

    /// Argon2id with `passes` passes, `memory` MiB and `lanes` lanes.
    pub fn argon2id(passes: u64, memory: u64, lanes: u64) -> Kdf {
        Kdf {
            kind: 1,
            iterations: passes,
            memory: Some(memory),
            parallelism: Some(lanes),
        }
    }

    /// The cheapest PBKDF2 Vaultwarden takes, so a test does not wait
    /// (`mobile/test/vaultwarden_server/server_kit.dart:49`).
    pub fn cheap_pbkdf2() -> Kdf {
        Kdf::pbkdf2(100_000)
    }

    /// A cheap Argon2id (`server_kit.dart:52`).
    pub fn cheap_argon2id() -> Kdf {
        Kdf::argon2id(2, 16, 1)
    }

    /// The `kdf`, `kdfIterations`, `kdfMemory` and `kdfParallelism` of a registration body; the
    /// two Argon2 values only for Argon2 (`BwKdf.toJson`, `mobile/lib/crypto/bitwarden.dart:79`).
    pub fn fields(&self) -> Map<String, Value> {
        let mut out = Map::new();
        out.insert("kdf".to_owned(), json!(self.kind));
        out.insert("kdfIterations".to_owned(), json!(self.iterations));
        if let Some(memory) = self.memory {
            out.insert("kdfMemory".to_owned(), json!(memory));
        }
        if let Some(parallelism) = self.parallelism {
            out.insert("kdfParallelism".to_owned(), json!(parallelism));
        }
        out
    }
}

/// A new device identifier: a UUID, as the apps make one per vault.
pub fn device_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// An account made for one test. Its keys are strings of the right shape and nothing more: the
/// server stores them and never opens them.
#[derive(Debug, Clone)]
pub struct Account {
    pub email: String,
    pub password: String,
    pub kdf: Kdf,
    /// What stands for the master password's hash: a base64 string of 32 bytes. The server hashes
    /// it again and compares, and cannot tell it from a real one.
    pub hash: String,
    /// The user key, encrypted: `Key` in the token answer and `profile.key` in the sync.
    pub user_key: String,
    pub public_key: String,
    pub private_key: String,
}

impl Account {
    /// A new account with a random address and the KDF given.
    pub fn new(kdf: Kdf) -> Account {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let stamp = b64(&random_bytes(6))
            .replace(['+', '/', '='], "x")
            .to_lowercase();
        let email = format!("contract-{}-{n}-{stamp}@example.com", std::process::id());
        let password = "correct horse battery".to_owned();
        let hash = b64(Sha256::digest(format!("{email}\n{password}")).as_ref());
        // The recorded account's RSA key pair, which is real: some servers read it.
        let fixture = fixtures::account("account-pbkdf2.json");
        let pair = &fixture["token"]["AccountKeys"]["publicKeyEncryptionKeyPair"];
        Account {
            email,
            password,
            kdf,
            hash,
            user_key: enc_bytes(&random_bytes(80)),
            public_key: pair["publicKey"].as_str().unwrap_or_default().to_owned(),
            private_key: pair["wrappedPrivateKey"]
                .as_str()
                .unwrap_or_default()
                .to_owned(),
        }
    }

    /// The body of `POST /identity/accounts/register/finish`
    /// (`server_kit.dart:75-86`), with the verification `token` of the first step.
    pub fn register_body(&self, token: &str) -> Value {
        let mut body = Map::new();
        body.insert("email".to_owned(), json!(self.email));
        body.insert("emailVerificationToken".to_owned(), json!(token));
        body.insert("masterPasswordHash".to_owned(), json!(self.hash));
        body.insert("masterPasswordHint".to_owned(), Value::Null);
        body.insert("userSymmetricKey".to_owned(), json!(self.user_key));
        body.insert(
            "userAsymmetricKeys".to_owned(),
            json!({
                "publicKey": self.public_key,
                "encryptedPrivateKey": self.private_key,
            }),
        );
        for (name, value) in self.kdf.fields() {
            body.insert(name, value);
        }
        Value::Object(body)
    }

    /// The password grant as Kemlock's app sends it (`vw_api.dart:266-282`): `client_id` `mobile`,
    /// device type 0, scope `api offline_access`.
    pub fn login_form(&self, device_id: &str) -> Vec<(String, String)> {
        let pairs = [
            ("grant_type", "password"),
            ("username", self.email.as_str()),
            ("password", self.hash.as_str()),
            ("scope", "api offline_access"),
            ("client_id", "mobile"),
            ("deviceType", "0"),
            ("deviceIdentifier", device_id),
            ("deviceName", "Kemlock contract tests"),
        ];
        pairs
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect()
    }
}

/// Replaces the value of `name` in a form, or adds it.
pub fn set_field(form: &mut Vec<(String, String)>, name: &str, value: &str) {
    match form.iter_mut().find(|(key, _)| key == name) {
        Some(pair) => pair.1 = value.to_owned(),
        None => form.push((name.to_owned(), value.to_owned())),
    }
}

/// Removes `name` from a form.
pub fn remove_field(form: &mut Vec<(String, String)>, name: &str) {
    form.retain(|(key, _)| key != name);
}

// ─── Cipher bodies ─────────────────────────────────────────────────────────

/// A Login as Kemlock writes one (`vw_codec.dart:495-510`, `api_test.dart:251-273`): the item key
/// `null`, a hidden `Kemlock` field, a URI with its checksum, `encryptedFor` set.
pub fn login_cipher(user_id: &str, name: &str) -> Value {
    json!({
        "type": 1,
        "organizationId": null,
        "folderId": null,
        "name": enc(name),
        "notes": enc("a note"),
        "favorite": false,
        "reprompt": 0,
        "key": null,
        "encryptedFor": user_id,
        "fields": [
            {"type": 1, "name": enc("Kemlock"), "value": enc("{\"v\":1}"), "linkedId": null},
            {"type": 0, "name": enc("Other app"), "value": enc("keep me"), "linkedId": null},
        ],
        "login": {
            "username": enc("me@example.com"),
            "password": enc("hunter2"),
            "totp": enc("otpauth://totp/GitHub:me?secret=JBSWY3DPEHPK3PXP"),
            "uris": [
                {"uri": enc("https://github.com"), "uriChecksum": enc("checksum"), "match": null},
            ],
        },
        "passwordHistory": null,
    })
}

/// A secure note as Kemlock writes one (`api_test.dart:315-320`).
pub fn note_cipher(user_id: &str, name: &str) -> Value {
    json!({
        "type": 2,
        "name": enc(name),
        "secureNote": {"type": 0},
        "encryptedFor": user_id,
    })
}

/// An SSH key item as Kemlock writes one (`vw_codec.dart:559-564`).
pub fn ssh_cipher(user_id: &str, name: &str) -> Value {
    json!({
        "type": 5,
        "organizationId": null,
        "folderId": null,
        "name": enc(name),
        "notes": null,
        "favorite": false,
        "reprompt": 0,
        "key": null,
        "encryptedFor": user_id,
        "fields": null,
        "passwordHistory": null,
        "sshKey": {
            "privateKey": enc("-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n"),
            "publicKey": enc("ssh-ed25519 AAAA"),
            "keyFingerprint": enc("SHA256:abc"),
        },
    })
}

/// A cipher as a sync gives it, turned into the body of a write: the server's own keys taken
/// out, `encryptedFor` set. This is how the apps send an item back
/// (`api_test.dart:282-291`: "Send it back as the server gave it").
pub fn as_write(cipher: &Value, user_id: &str) -> Value {
    let mut body = cipher.clone();
    if let Some(object) = body.as_object_mut() {
        for key in [
            "object",
            "id",
            "creationDate",
            "deletedDate",
            "edit",
            "viewPassword",
            "permissions",
            "organizationUseTotp",
            "collectionIds",
            "attachments",
        ] {
            object.remove(key);
        }
        object.insert("encryptedFor".to_owned(), json!(user_id));
    }
    body
}
