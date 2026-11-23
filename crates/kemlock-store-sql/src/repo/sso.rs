//! The SSO ports on `sso_settings`, `sso_identities` and `verified_domains`.

use crate::convert::utc;
use crate::error::{StoreResult, is_unique_violation, map_db};
use crate::store::SqlStore;
use crate::tables::sso::{domains, identities, settings};
use kemlock_app::ports::StoreError;
use kemlock_app::sso::{
    SsoIdentity, SsoIdentityRepo, SsoSettings, SsoSettingsRepo, VerifiedDomain, VerifiedDomainRepo,
};
use kemlock_domain::UserId;
use sea_orm::ActiveValue::{NotSet, Set};
use sea_orm::sea_query::OnConflict;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder};
use time::OffsetDateTime;

impl SsoSettingsRepo for SqlStore {
    async fn sso_settings(&self) -> Result<Option<SsoSettings>, StoreError> {
        settings::Entity::find_by_id(settings::ROW_ID)
            .one(self.reader())
            .await
            .store()?
            .map(settings::Model::into_domain)
            .transpose()
    }

    async fn put_sso_settings(&self, value: &SsoSettings) -> Result<(), StoreError> {
        let conflict = OnConflict::column(settings::Column::Id)
            .update_columns([
                settings::Column::Enabled,
                settings::Column::DisplayName,
                settings::Column::Issuer,
                settings::Column::ClientId,
                settings::Column::SealedClientSecret,
                settings::Column::Scopes,
                settings::Column::AllowUnknownEmailVerification,
                settings::Column::LinkByEmail,
                settings::Column::CreateAccounts,
                settings::Column::RequireVerifiedDomain,
                settings::Column::GroupRules,
                settings::Column::UpdatedAt,
            ])
            .to_owned();
        let written = settings::Entity::insert(settings::active(value))
            .on_conflict(conflict)
            .exec(self.writer())
            .await;
        match written {
            Ok(_) => Ok(()),
            // MySQL counts a replaced row with identical values as zero rows affected.
            Err(sea_orm::DbErr::RecordNotInserted) => Ok(()),
            Err(err) if is_unique_violation(&err) => Err(StoreError::Duplicate),
            Err(err) => Err(map_db(err)),
        }
    }
}

impl SsoIdentityRepo for SqlStore {
    async fn find_identity(
        &self,
        issuer: &str,
        subject: &str,
    ) -> Result<Option<SsoIdentity>, StoreError> {
        Ok(
            identities::Entity::find_by_id((issuer.to_owned(), subject.to_owned()))
                .one(self.reader())
                .await
                .store()?
                .map(identities::Model::into_domain),
        )
    }

    async fn insert_identity(&self, identity: &SsoIdentity) -> Result<(), StoreError> {
        identities::Entity::insert(identities::active(identity))
            .exec(self.writer())
            .await
            .store()?;
        Ok(())
    }

    async fn identities_of(&self, user: UserId) -> Result<Vec<SsoIdentity>, StoreError> {
        Ok(identities::Entity::find()
            .filter(identities::Column::UserId.eq(user.0))
            .order_by_asc(identities::Column::LinkedAt)
            .order_by_asc(identities::Column::Issuer)
            .order_by_asc(identities::Column::Subject)
            .all(self.reader())
            .await
            .store()?
            .into_iter()
            .map(identities::Model::into_domain)
            .collect())
    }

    async fn touch_identity(
        &self,
        issuer: &str,
        subject: &str,
        email: &str,
        at: OffsetDateTime,
    ) -> Result<(), StoreError> {
        let row = identities::ActiveModel {
            issuer: NotSet,
            subject: NotSet,
            user_id: NotSet,
            email: Set(email.to_owned()),
            linked_at: NotSet,
            last_login_at: Set(utc(at)),
        };
        let result = identities::Entity::update_many()
            .set(row)
            .filter(identities::Column::Issuer.eq(issuer))
            .filter(identities::Column::Subject.eq(subject))
            .exec(self.writer())
            .await
            .store()?;
        if result.rows_affected == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }
}

impl VerifiedDomainRepo for SqlStore {
    async fn domain_claim(&self, domain: &str) -> Result<Option<VerifiedDomain>, StoreError> {
        Ok(domains::Entity::find_by_id(domain.to_owned())
            .one(self.reader())
            .await
            .store()?
            .map(domains::Model::into_domain))
    }

    async fn domain_claims(&self) -> Result<Vec<VerifiedDomain>, StoreError> {
        Ok(domains::Entity::find()
            .order_by_asc(domains::Column::Domain)
            .all(self.reader())
            .await
            .store()?
            .into_iter()
            .map(domains::Model::into_domain)
            .collect())
    }

    async fn put_domain_claim(&self, claim: &VerifiedDomain) -> Result<(), StoreError> {
        let conflict = OnConflict::column(domains::Column::Domain)
            .update_columns([
                domains::Column::Token,
                domains::Column::CreatedAt,
                domains::Column::VerifiedAt,
            ])
            .to_owned();
        let written = domains::Entity::insert(domains::active(claim))
            .on_conflict(conflict)
            .exec(self.writer())
            .await;
        match written {
            Ok(_) => Ok(()),
            Err(sea_orm::DbErr::RecordNotInserted) => Ok(()),
            Err(err) if is_unique_violation(&err) => Err(StoreError::Duplicate),
            Err(err) => Err(map_db(err)),
        }
    }

    async fn remove_domain_claim(&self, domain: &str) -> Result<(), StoreError> {
        domains::Entity::delete_many()
            .filter(domains::Column::Domain.eq(domain))
            .exec(self.writer())
            .await
            .store()?;
        Ok(())
    }
}
