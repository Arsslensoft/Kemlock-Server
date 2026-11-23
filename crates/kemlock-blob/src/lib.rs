//! Kemlock Server's file storage: attachments in a local folder or an S3-compatible bucket, by
//! random blob id, and the `KMA1` header check that keeps other bytes out.
//!
//! Dependencies point inward: this adapter implements the `BlobStore` port of `kemlock-app`.
//! Blobs are named by random ids, never file names. Uploads stream with a size cap, and on a
//! bucket the Kemlock API may hand clients pre-signed URLs, behind a setting.

pub mod config;
pub mod kma1;
pub mod store;

pub use config::{Backend, BlobConfig, ConfigError, S3Config};
pub use store::{ObjectBlobStore, ObjectUpload};
