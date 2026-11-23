//! `seed`: registers the accounts, signs each in, writes its items in batches and records the
//! sync cursor, then writes the accounts file the other commands and k6 read.
//!
//! The server needs `SIGNUPS_ALLOWED=true`, and, because registration is limited to 10 an hour
//! per address, `IP_HEADER` with `KEMLOCK_TRUSTED_PROXIES` and this command's `--ip-header`.

use crate::accounts::{AccountEntry, AccountsFile, Sample, email};
use crate::device::{Device, Result, Target};
use kemlock_app::b64url;
use serde_json::{Value, json};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use uuid::Uuid;

#[derive(clap::Args, Debug)]
pub(crate) struct Args {
    /// How many accounts to make.
    #[arg(long, default_value_t = 100)]
    pub(crate) accounts: usize,
    /// Items per account, each with 2 KiB of ciphertext.
    #[arg(long, default_value_t = 500)]
    pub(crate) items: usize,
    /// Email prefix: `<prefix>-0000@example.org`.
    #[arg(long, default_value = "load")]
    pub(crate) prefix: String,
    /// Accounts seeded at once.
    #[arg(long, default_value_t = 8)]
    pub(crate) concurrency: usize,
    /// Items per `items:batch` request (the server takes up to 500 and 2 MiB of body).
    #[arg(long, default_value_t = 200)]
    pub(crate) batch: usize,
    /// Where to write the accounts file.
    #[arg(long, default_value = "loadgen-accounts.json")]
    pub(crate) out: PathBuf,
}

/// An item in `docs/crypto.md`'s wire shape with random sealed values: the server checks only
/// their lengths. 2048 bytes of ciphertext, a 60-byte wrapped item key.
fn item_json(owner: &str, id: &str) -> Value {
    json!({
        "id": id,
        "owner": format!("user:{owner}"),
        "kind": "login",
        "format": "kem1",
        "revision": 1,
        "keyVersion": 1,
        "ciphertext": b64url::encode(&kemlock_crypto::rand::bytes::<2048>()),
        "itemKey": b64url::encode(&kemlock_crypto::rand::bytes::<60>()),
        "deleted": false,
    })
}

async fn seed_one(
    http: reqwest::Client,
    target: Target,
    prefix: String,
    index: usize,
    items: usize,
    batch: usize,
) -> Result<AccountEntry> {
    let email = email(&prefix, index);
    let device = Device::new(http, target, u32::try_from(index).unwrap_or(u32::MAX));
    let status = device.register(&email, Uuid::new_v4()).await?;
    if status != 201 {
        eprintln!("{email}: register answered {status}; signing in to see if it exists");
    }
    let (tokens, _took) = device.sign_in(&email).await?;
    let user_id = tokens.user_id.clone();

    let mut item_ids = Vec::with_capacity(items);
    let mut writes = Vec::with_capacity(batch);
    for n in 0..items {
        let id = Uuid::new_v4().to_string();
        writes.push(json!({"expectedRevision": null, "item": item_json(&user_id, &id)}));
        item_ids.push(id);
        if writes.len() == batch || n + 1 == items {
            device.put_batch(&tokens.access_token, &writes).await?;
            writes.clear();
        }
    }
    let cursor = device.current_cursor(&tokens.access_token).await?;
    Ok(AccountEntry {
        index,
        email,
        user_id,
        item_ids,
        cursor,
    })
}

pub(crate) async fn run(target: Target, args: Args) -> Result<()> {
    if args.accounts == 0 || args.items == 0 || args.batch == 0 || args.concurrency == 0 {
        return Err("--accounts, --items, --batch and --concurrency must be at least 1".into());
    }
    let http = reqwest::Client::new();
    let semaphore = Arc::new(Semaphore::new(args.concurrency));
    let mut tasks = JoinSet::new();
    for index in 0..args.accounts {
        let permit = Arc::clone(&semaphore).acquire_owned().await?;
        let (http, target, prefix) = (http.clone(), target.clone(), args.prefix.clone());
        let (items, batch) = (args.items, args.batch);
        tasks.spawn(async move {
            let entry = seed_one(http, target, prefix, index, items, batch).await;
            drop(permit);
            entry
        });
    }
    let mut entries = Vec::with_capacity(args.accounts);
    while let Some(joined) = tasks.join_next().await {
        entries.push(joined??);
        eprintln!("seeded {}/{} accounts", entries.len(), args.accounts);
    }
    entries.sort_by_key(|entry| entry.index);

    let file = AccountsFile {
        base_url: target.base_url.clone(),
        domain: target.domain.clone(),
        sample: Sample {
            ciphertext: b64url::encode(&kemlock_crypto::rand::bytes::<2048>()),
            item_key: b64url::encode(&kemlock_crypto::rand::bytes::<60>()),
        },
        accounts: entries,
    };
    file.save(&args.out)?;
    println!(
        "wrote {} ({} accounts of {} items)",
        args.out.display(),
        args.accounts,
        args.items
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_item_is_2_kib_of_ciphertext_in_the_wire_shape() {
        let item = item_json("00000000-0000-0000-0000-000000000001", "i");
        assert_eq!(item["format"], "kem1");
        assert_eq!(item["revision"], 1);
        assert_eq!(item["owner"], "user:00000000-0000-0000-0000-000000000001");
        let ciphertext =
            b64url::decode(item["ciphertext"].as_str().expect("ciphertext")).expect("base64url");
        assert_eq!(ciphertext.len(), 2048);
        let key = b64url::decode(item["itemKey"].as_str().expect("itemKey")).expect("base64url");
        assert_eq!(key.len(), 60);
    }
}
