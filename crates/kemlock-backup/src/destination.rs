//! Where archives go: a local path (a NAS mount, say) or an S3-compatible bucket, both through the
//! `object_store` crate, so one code path stores, lists, fetches and deletes either.

use crate::error::BackupError;
use futures_util::TryStreamExt;
use object_store::aws::AmazonS3Builder;
use object_store::buffered::BufWriter;
use object_store::local::LocalFileSystem;
use object_store::memory::InMemory;
use object_store::path::Path as ObjectPath;
use object_store::{ObjectStore, ObjectStoreExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use time::OffsetDateTime;
use tokio::io::AsyncWriteExt;

/// A bucket. The secret is never printed: `Debug` leaves it out.
#[derive(Clone, PartialEq, Eq)]
pub struct S3Destination {
    /// The service's URL, such as `https://s3.example.org`; `None` for AWS itself.
    pub endpoint: Option<String>,
    pub bucket: String,
    pub region: String,
    pub access_key_id: String,
    pub secret_access_key: String,
    /// `https://host/bucket/key` rather than `https://bucket.host/key`.
    pub path_style: bool,
    /// A folder inside the bucket, without slashes at either end; empty for the bucket's root.
    pub prefix: String,
}

impl std::fmt::Debug for S3Destination {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3Destination")
            .field("endpoint", &self.endpoint)
            .field("bucket", &self.bucket)
            .field("region", &self.region)
            .field("path_style", &self.path_style)
            .field("prefix", &self.prefix)
            .finish_non_exhaustive()
    }
}

/// Where archives are kept.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DestinationConfig {
    Local { folder: PathBuf },
    S3(S3Destination),
}

impl DestinationConfig {
    /// `local` or `S3`, for the processing summary and the admin console.
    pub fn kind(&self) -> &'static str {
        match self {
            DestinationConfig::Local { .. } => "local",
            DestinationConfig::S3(_) => "S3",
        }
    }
}

/// One archive in a destination.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArchiveInfo {
    pub name: String,
    pub size: u64,
    pub modified: OffsetDateTime,
}

/// An open destination. Cloning is cheap.
#[derive(Clone, Debug)]
pub struct Destination {
    store: Arc<dyn ObjectStore>,
    prefix: String,
}

fn dest_error(what: &str, e: impl std::fmt::Display) -> BackupError {
    BackupError::Destination(format!("{what}: {e}"))
}

impl Destination {
    /// Opens the destination, making a local folder if it isn't there.
    pub fn open(config: &DestinationConfig) -> Result<Destination, BackupError> {
        match config {
            DestinationConfig::Local { folder } => {
                crate::archive::create_private_dir(folder)
                    .map_err(|e| BackupError::io(format!("can't make {}", folder.display()), e))?;
                let fs = LocalFileSystem::new_with_prefix(folder)
                    .map_err(|e| dest_error("can't open the folder", e))?;
                Ok(Destination {
                    store: Arc::new(fs),
                    prefix: String::new(),
                })
            }
            DestinationConfig::S3(s3) => {
                let mut builder = AmazonS3Builder::new()
                    .with_bucket_name(s3.bucket.as_str())
                    .with_region(s3.region.as_str())
                    .with_access_key_id(s3.access_key_id.as_str())
                    .with_secret_access_key(s3.secret_access_key.as_str())
                    .with_virtual_hosted_style_request(!s3.path_style);
                if let Some(endpoint) = &s3.endpoint {
                    builder = builder
                        .with_endpoint(endpoint.as_str())
                        .with_allow_http(endpoint.starts_with("http://"));
                }
                let store = builder
                    .build()
                    .map_err(|e| dest_error("can't open the bucket", e))?;
                Ok(Destination {
                    store: Arc::new(store),
                    prefix: s3.prefix.trim_matches('/').to_owned(),
                })
            }
        }
    }

    /// A destination in memory, for tests.
    pub fn memory() -> Destination {
        Destination {
            store: Arc::new(InMemory::new()),
            prefix: String::new(),
        }
    }

    fn path(&self, name: &str) -> ObjectPath {
        if self.prefix.is_empty() {
            ObjectPath::from(name)
        } else {
            ObjectPath::from(format!("{}/{name}", self.prefix))
        }
    }

    /// Stores the local file as `name`, streaming it so a big archive is never held in memory.
    pub async fn put_file(&self, name: &str, local: &Path) -> Result<(), BackupError> {
        let mut source = tokio::fs::File::open(local)
            .await
            .map_err(|e| BackupError::io(format!("can't read {}", local.display()), e))?;
        let mut writer = BufWriter::new(self.store.clone(), self.path(name));
        let copied = tokio::io::copy(&mut source, &mut writer).await;
        match copied {
            Ok(_) => writer
                .shutdown()
                .await
                .map_err(|e| dest_error("can't finish storing the archive", e)),
            Err(e) => {
                // Give up the parts already sent; the error is the copy's.
                if let Err(abort) = writer.abort().await {
                    tracing::warn!(error = %abort, "couldn't abort a partial upload");
                }
                Err(dest_error("can't store the archive", e))
            }
        }
    }

    /// Writes the archive `name` to the local file `to`.
    pub async fn download(&self, name: &str, to: &Path) -> Result<(), BackupError> {
        let got = self
            .store
            .get(&self.path(name))
            .await
            .map_err(|e| dest_error(&format!("can't fetch {name}"), e))?;
        let mut out = tokio::fs::File::create(to)
            .await
            .map_err(|e| BackupError::io(format!("can't write {}", to.display()), e))?;
        let mut stream = got.into_stream();
        while let Some(chunk) = stream
            .try_next()
            .await
            .map_err(|e| dest_error(&format!("can't fetch {name}"), e))?
        {
            out.write_all(&chunk)
                .await
                .map_err(|e| BackupError::io(format!("can't write {}", to.display()), e))?;
        }
        out.flush()
            .await
            .map_err(|e| BackupError::io(format!("can't write {}", to.display()), e))
    }

    /// The archives under the destination's prefix, oldest name first.
    pub async fn list(&self) -> Result<Vec<ArchiveInfo>, BackupError> {
        let prefix = (!self.prefix.is_empty()).then(|| ObjectPath::from(self.prefix.as_str()));
        let metas: Vec<_> = self
            .store
            .list(prefix.as_ref())
            .try_collect()
            .await
            .map_err(|e| dest_error("can't list the archives", e))?;
        let mut out: Vec<ArchiveInfo> = metas
            .into_iter()
            .filter_map(|meta| {
                let name = meta.location.filename()?.to_owned();
                Some(ArchiveInfo {
                    name,
                    size: meta.size,
                    modified: OffsetDateTime::from_unix_timestamp(meta.last_modified.timestamp())
                        .unwrap_or(OffsetDateTime::UNIX_EPOCH),
                })
            })
            .collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    /// Deletes an archive. One that isn't there is not an error.
    pub async fn delete(&self, name: &str) -> Result<(), BackupError> {
        match self.store.delete(&self.path(name)).await {
            Ok(()) | Err(object_store::Error::NotFound { .. }) => Ok(()),
            Err(e) => Err(dest_error(&format!("can't delete {name}"), e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn put(dest: &Destination, name: &str, bytes: &[u8]) {
        let dir = tempfile::tempdir().expect("a temp dir");
        let path = dir.path().join("source");
        std::fs::write(&path, bytes).expect("written");
        dest.put_file(name, &path).await.expect("stored");
    }

    #[tokio::test]
    async fn an_archive_goes_in_comes_out_and_is_listed_then_deleted() {
        let dest = Destination::memory();
        put(&dest, "b.age", b"second").await;
        put(&dest, "a.age", b"first archive").await;

        let listed = dest.list().await.expect("listed");
        let names: Vec<&str> = listed.iter().map(|a| a.name.as_str()).collect();
        assert_eq!(names, ["a.age", "b.age"]);
        assert_eq!(listed[0].size, 13);

        let dir = tempfile::tempdir().expect("a temp dir");
        let back = dir.path().join("back");
        dest.download("a.age", &back).await.expect("fetched");
        assert_eq!(std::fs::read(&back).expect("a file"), b"first archive");

        dest.delete("a.age").await.expect("deleted");
        dest.delete("a.age").await.expect("deleting twice is fine");
        assert_eq!(dest.list().await.expect("listed").len(), 1);
        assert!(dest.download("a.age", &back).await.is_err());
    }

    #[tokio::test]
    async fn a_local_folder_is_made_and_keeps_the_files_by_name() {
        let root = tempfile::tempdir().expect("a temp dir");
        let folder = root.path().join("nas").join("kemlock");
        let dest = Destination::open(&DestinationConfig::Local {
            folder: folder.clone(),
        })
        .expect("opens");
        put(&dest, "x.age", b"bytes").await;
        assert_eq!(
            std::fs::read(folder.join("x.age")).expect("a file"),
            b"bytes"
        );
        assert_eq!(dest.list().await.expect("listed").len(), 1);
    }

    #[tokio::test]
    async fn a_prefix_keeps_archives_apart_from_other_objects() {
        let dest = Destination {
            store: Arc::new(InMemory::new()),
            prefix: "kemlock/backups".to_owned(),
        };
        put(&dest, "one.age", b"1").await;
        // Something else in the same bucket, outside the prefix.
        dest.store
            .put(&ObjectPath::from("other/thing"), b"x".as_ref().into())
            .await
            .expect("stored");
        let listed = dest.list().await.expect("listed");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name, "one.age");
    }

    #[test]
    fn the_secret_stays_out_of_debug_output() {
        let config = DestinationConfig::S3(S3Destination {
            endpoint: Some("https://s3.example.org".to_owned()),
            bucket: "b".to_owned(),
            region: "us-east-1".to_owned(),
            access_key_id: "AKID".to_owned(),
            secret_access_key: "very-secret".to_owned(),
            path_style: true,
            prefix: String::new(),
        });
        let text = format!("{config:?}");
        assert!(!text.contains("very-secret"));
        assert!(!text.contains("AKID"));
        assert_eq!(config.kind(), "S3");
    }
}
