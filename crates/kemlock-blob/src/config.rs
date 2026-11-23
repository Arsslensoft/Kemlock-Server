//! Where files go: the settings, read from the environment.
//!
//! - `ATTACHMENTS_FOLDER` (Vaultwarden's name): the local folder, default
//!   `<DATA_FOLDER>/attachments`. Used unless a bucket is named.
//! - `KEMLOCK_S3_BUCKET`: names an S3-compatible bucket (MinIO, Garage, Backblaze B2, AWS) and
//!   switches to it. Then `KEMLOCK_S3_ACCESS_KEY_ID` and `KEMLOCK_S3_SECRET_ACCESS_KEY` are
//!   needed, and `KEMLOCK_S3_ENDPOINT` (for anything but AWS), `KEMLOCK_S3_REGION` (default
//!   `us-east-1`) and `KEMLOCK_S3_PATH_STYLE` (default true, which MinIO and Garage want; AWS
//!   takes either) are read. A bucket should abort incomplete multipart uploads after a day by a
//!   lifecycle rule: an upload cut off mid-way can't clean up after itself.
//! - `KEMLOCK_ATTACHMENT_MAX_SIZE`: the most bytes one file may have, default 100 MiB.
//! - `KEMLOCK_ATTACHMENT_PRESIGN` (default false): on the Kemlock API only, let clients send and
//!   fetch files straight to and from the bucket through pre-signed URLs that live
//!   `KEMLOCK_ATTACHMENT_PRESIGN_TTL` seconds (default 900). Needs a bucket the clients can
//!   reach. The Bitwarden API always streams through the server.
//!
//! A setting saved from the admin console will replace these when the console exists.

use std::path::{Path, PathBuf};
use std::time::Duration;

/// A bucket to keep files in.
#[derive(Clone, PartialEq, Eq)]
pub struct S3Config {
    /// The service's URL, such as `https://s3.example.org`; `None` for AWS itself.
    pub endpoint: Option<String>,
    pub bucket: String,
    pub region: String,
    pub access_key_id: String,
    pub secret_access_key: String,
    /// `https://host/bucket/key` rather than `https://bucket.host/key`.
    pub path_style: bool,
}

impl std::fmt::Debug for S3Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3Config")
            .field("endpoint", &self.endpoint)
            .field("bucket", &self.bucket)
            .field("region", &self.region)
            .field("path_style", &self.path_style)
            .finish_non_exhaustive()
    }
}

/// Where the bytes live.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Backend {
    Local { folder: PathBuf },
    S3(S3Config),
}

/// Every file-storage setting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlobConfig {
    pub backend: Backend,
    /// The most bytes one `KMA1` file may have.
    pub max_size: u64,
    /// Whether to hand out pre-signed bucket URLs on the Kemlock API (a bucket only).
    pub presign: bool,
    pub presign_ttl: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    #[error("{name} must be {expected}, not {value:?}")]
    Bad {
        name: &'static str,
        expected: &'static str,
        value: String,
    },
    #[error("{name} is needed when {when}")]
    Missing {
        name: &'static str,
        when: &'static str,
    },
}

/// 100 MiB.
const DEFAULT_MAX_SIZE: u64 = 100 * 1024 * 1024;
const DEFAULT_PRESIGN_TTL_SECS: u64 = 900;

fn flag(name: &'static str, value: Option<String>, default: bool) -> Result<bool, ConfigError> {
    match value.as_deref().map(str::trim) {
        None => Ok(default),
        Some(v)
            if ["1", "true", "yes", "on"]
                .iter()
                .any(|t| v.eq_ignore_ascii_case(t)) =>
        {
            Ok(true)
        }
        Some(v)
            if ["0", "false", "no", "off"]
                .iter()
                .any(|f| v.eq_ignore_ascii_case(f)) =>
        {
            Ok(false)
        }
        Some(v) => Err(ConfigError::Bad {
            name,
            expected: "true or false",
            value: v.to_owned(),
        }),
    }
}

fn number(name: &'static str, value: Option<String>, default: u64) -> Result<u64, ConfigError> {
    match value {
        None => Ok(default),
        Some(v) => match v.trim().parse::<u64>() {
            Ok(n) if n > 0 => Ok(n),
            _ => Err(ConfigError::Bad {
                name,
                expected: "a whole number above zero",
                value: v,
            }),
        },
    }
}

impl BlobConfig {
    /// Reads the settings through `get`, which returns a variable's non-empty value. Tests pass a
    /// map; the server calls [`BlobConfig::from_env`].
    pub fn from_lookup(
        data_folder: &Path,
        get: impl Fn(&str) -> Option<String>,
    ) -> Result<BlobConfig, ConfigError> {
        let backend = match get("KEMLOCK_S3_BUCKET") {
            Some(bucket) => {
                let need = |name: &'static str| {
                    get(name).ok_or(ConfigError::Missing {
                        name,
                        when: "KEMLOCK_S3_BUCKET is set",
                    })
                };
                Backend::S3(S3Config {
                    endpoint: get("KEMLOCK_S3_ENDPOINT"),
                    bucket,
                    region: get("KEMLOCK_S3_REGION").unwrap_or_else(|| "us-east-1".to_owned()),
                    access_key_id: need("KEMLOCK_S3_ACCESS_KEY_ID")?,
                    secret_access_key: need("KEMLOCK_S3_SECRET_ACCESS_KEY")?,
                    path_style: flag("KEMLOCK_S3_PATH_STYLE", get("KEMLOCK_S3_PATH_STYLE"), true)?,
                })
            }
            None => Backend::Local {
                folder: get("ATTACHMENTS_FOLDER")
                    .map_or_else(|| data_folder.join("attachments"), PathBuf::from),
            },
        };
        Ok(BlobConfig {
            backend,
            max_size: number(
                "KEMLOCK_ATTACHMENT_MAX_SIZE",
                get("KEMLOCK_ATTACHMENT_MAX_SIZE"),
                DEFAULT_MAX_SIZE,
            )?,
            presign: flag(
                "KEMLOCK_ATTACHMENT_PRESIGN",
                get("KEMLOCK_ATTACHMENT_PRESIGN"),
                false,
            )?,
            presign_ttl: Duration::from_secs(number(
                "KEMLOCK_ATTACHMENT_PRESIGN_TTL",
                get("KEMLOCK_ATTACHMENT_PRESIGN_TTL"),
                DEFAULT_PRESIGN_TTL_SECS,
            )?),
        })
    }

    /// Reads the settings from the process environment.
    pub fn from_env(data_folder: &Path) -> Result<BlobConfig, ConfigError> {
        BlobConfig::from_lookup(data_folder, |name| {
            std::env::var(name).ok().filter(|v| !v.trim().is_empty())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn config(vars: &[(&str, &str)]) -> Result<BlobConfig, ConfigError> {
        let map: HashMap<String, String> = vars
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        BlobConfig::from_lookup(Path::new("data"), |name| map.get(name).cloned())
    }

    #[test]
    fn the_default_is_a_folder_in_the_data_folder_with_a_100_mib_limit() {
        let c = config(&[]).expect("defaults");
        assert_eq!(
            c.backend,
            Backend::Local {
                folder: PathBuf::from("data").join("attachments")
            }
        );
        assert_eq!(c.max_size, 100 * 1024 * 1024);
        assert!(!c.presign);
        assert_eq!(c.presign_ttl, Duration::from_secs(900));
    }

    #[test]
    fn the_folder_and_the_limit_can_be_set() {
        let c = config(&[
            ("ATTACHMENTS_FOLDER", "/srv/files"),
            ("KEMLOCK_ATTACHMENT_MAX_SIZE", "5000"),
        ])
        .expect("valid");
        assert_eq!(
            c.backend,
            Backend::Local {
                folder: PathBuf::from("/srv/files")
            }
        );
        assert_eq!(c.max_size, 5000);
    }

    #[test]
    fn a_bucket_needs_its_keys_and_defaults_to_path_style() {
        let missing = config(&[("KEMLOCK_S3_BUCKET", "kemlock")]).expect_err("no keys");
        assert_eq!(
            missing,
            ConfigError::Missing {
                name: "KEMLOCK_S3_ACCESS_KEY_ID",
                when: "KEMLOCK_S3_BUCKET is set"
            }
        );
        let c = config(&[
            ("KEMLOCK_S3_BUCKET", "kemlock"),
            ("KEMLOCK_S3_ENDPOINT", "http://minio:9000"),
            ("KEMLOCK_S3_ACCESS_KEY_ID", "id"),
            ("KEMLOCK_S3_SECRET_ACCESS_KEY", "secret"),
        ])
        .expect("valid");
        let Backend::S3(s3) = c.backend else {
            panic!("a bucket was named");
        };
        assert_eq!(s3.bucket, "kemlock");
        assert_eq!(s3.endpoint.as_deref(), Some("http://minio:9000"));
        assert_eq!(s3.region, "us-east-1");
        assert!(s3.path_style);
    }

    #[test]
    fn the_debug_form_hides_the_secret() {
        let c = config(&[
            ("KEMLOCK_S3_BUCKET", "kemlock"),
            ("KEMLOCK_S3_ACCESS_KEY_ID", "id"),
            ("KEMLOCK_S3_SECRET_ACCESS_KEY", "hunter2"),
        ])
        .expect("valid");
        assert!(!format!("{c:?}").contains("hunter2"));
    }

    #[test]
    fn presigning_is_opt_in() {
        let c = config(&[
            ("KEMLOCK_ATTACHMENT_PRESIGN", "yes"),
            ("KEMLOCK_ATTACHMENT_PRESIGN_TTL", "60"),
        ])
        .expect("valid");
        assert!(c.presign);
        assert_eq!(c.presign_ttl, Duration::from_secs(60));
    }

    #[test]
    fn bad_values_are_named() {
        for (name, value) in [
            ("KEMLOCK_ATTACHMENT_MAX_SIZE", "lots"),
            ("KEMLOCK_ATTACHMENT_MAX_SIZE", "0"),
            ("KEMLOCK_ATTACHMENT_PRESIGN", "maybe"),
            ("KEMLOCK_ATTACHMENT_PRESIGN_TTL", "-5"),
        ] {
            let error = config(&[(name, value)]).expect_err("refused");
            assert!(
                matches!(&error, ConfigError::Bad { name: n, .. } if *n == name),
                "{name}={value}: {error}"
            );
        }
    }
}
