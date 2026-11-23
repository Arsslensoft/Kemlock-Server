//! `ManifestRepo` on `signed_manifests`.

use crate::convert::{to_i64, utc};
use crate::error::{StoreResult, is_unique_violation, map_db};
use crate::store::SqlStore;
use crate::tables::signed_manifests;
use kemlock_app::manifests::ManifestRepo;
use kemlock_app::ports::StoreError;
use kemlock_domain::Owner;
use kemlock_domain::manifest::SignedManifest;
use sea_orm::ActiveValue::{NotSet, Set};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};

impl ManifestRepo for SqlStore {
    async fn manifest(&self, owner: Owner) -> Result<Option<SignedManifest>, StoreError> {
        signed_manifests::Entity::find_by_id(owner.to_string())
            .one(self.reader())
            .await
            .store()?
            .map(signed_manifests::Model::into_domain)
            .transpose()
    }

    /// `UPDATE … WHERE owner = ? AND counter < ?`, then an insert for an owner with no row: of two
    /// writers racing on one counter, the statement that finds the lower stored counter (or no
    /// row) wins and the other changes nothing.
    async fn put_manifest(&self, manifest: &SignedManifest) -> Result<bool, StoreError> {
        let counter = to_i64(manifest.counter, "manifest counter")?;
        let replacement = signed_manifests::ActiveModel {
            owner: NotSet,
            counter: Set(counter),
            manifest: Set(manifest.bytes.clone()),
            signature: Set(manifest.signature.clone()),
            signer_id: Set(manifest.signer.0),
            stored_at: Set(utc(manifest.stored_at)),
        };
        let updated = signed_manifests::Entity::update_many()
            .set(replacement)
            .filter(signed_manifests::Column::Owner.eq(manifest.owner.to_string()))
            .filter(signed_manifests::Column::Counter.lt(counter))
            .exec(self.writer())
            .await
            .store()?;
        if updated.rows_affected > 0 {
            return Ok(true);
        }
        match signed_manifests::Entity::insert(signed_manifests::active(manifest)?)
            .exec(self.writer())
            .await
        {
            Ok(_) => Ok(true),
            // A row is there already, and its counter is not below this one.
            Err(err) if is_unique_violation(&err) => Ok(false),
            Err(err) => Err(map_db(err)),
        }
    }
}
