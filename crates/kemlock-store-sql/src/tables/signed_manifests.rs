//! `signed_manifests`: the latest signed manifest of each owner, as
//! `kemlock_domain::manifest::SignedManifest`.

use crate::convert::{corrupt, from_i64, to_i64, utc};
use kemlock_app::ports::StoreError;
use kemlock_domain::UserId;
use kemlock_domain::manifest::SignedManifest;
use sea_orm::ActiveValue::Set;
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "signed_manifests")]
pub struct Model {
    /// `user:<uuid>` or `space:<uuid>`.
    #[sea_orm(primary_key, auto_increment = false)]
    pub owner: String,
    pub counter: i64,
    /// The signed bytes, exactly as the writer made them.
    pub manifest: Vec<u8>,
    pub signature: Vec<u8>,
    pub signer_id: Uuid,
    pub stored_at: TimeDateTimeWithTimeZone,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

impl Model {
    pub(crate) fn into_domain(self) -> Result<SignedManifest, StoreError> {
        Ok(SignedManifest {
            owner: self.owner.parse().map_err(|_| corrupt("manifest owner"))?,
            counter: from_i64(self.counter, "manifest counter")?,
            bytes: self.manifest,
            signature: self.signature,
            signer: UserId(self.signer_id),
            stored_at: self.stored_at,
        })
    }
}

/// Every column set.
pub(crate) fn active(manifest: &SignedManifest) -> Result<ActiveModel, StoreError> {
    Ok(ActiveModel {
        owner: Set(manifest.owner.to_string()),
        counter: Set(to_i64(manifest.counter, "manifest counter")?),
        manifest: Set(manifest.bytes.clone()),
        signature: Set(manifest.signature.clone()),
        signer_id: Set(manifest.signer.0),
        stored_at: Set(utc(manifest.stored_at)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use kemlock_domain::Owner;
    use time::macros::datetime;

    #[test]
    fn a_manifest_round_trips_through_its_row() {
        let manifest = SignedManifest {
            owner: Owner::User(UserId::random()),
            counter: 7,
            bytes: vec![1; 100],
            signature: vec![2; 3373],
            signer: UserId::random(),
            stored_at: datetime!(2026-01-02 03:04:05 UTC),
        };
        let row = active(&manifest).expect("a counter in range");
        assert_eq!(row.counter, Set(7));
        let model = Model {
            owner: manifest.owner.to_string(),
            counter: 7,
            manifest: manifest.bytes.clone(),
            signature: manifest.signature.clone(),
            signer_id: manifest.signer.0,
            stored_at: manifest.stored_at,
        };
        assert_eq!(model.into_domain(), Ok(manifest));
    }

    #[test]
    fn a_corrupt_owner_or_counter_is_refused() {
        let model = |owner: &str, counter: i64| Model {
            owner: owner.to_owned(),
            counter,
            manifest: vec![],
            signature: vec![],
            signer_id: Uuid::new_v4(),
            stored_at: datetime!(2026-01-02 03:04:05 UTC),
        };
        assert!(model("toaster", 1).into_domain().is_err());
        assert!(
            model(&format!("user:{}", Uuid::new_v4()), -1)
                .into_domain()
                .is_err()
        );
    }
}
