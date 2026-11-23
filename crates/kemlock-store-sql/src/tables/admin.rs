//! The admin console's rows: events with their address, the disabled flag, invitations and
//! privacy requests.

/// `events` as the console reads and writes it: the same table as [`super::events`], with the
/// `ip` column the admin migration added. Rows written without one hold null.
pub(crate) mod event_rows {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "events")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub actor: Option<Uuid>,
        pub device: Option<Uuid>,
        pub action: String,
        pub target: Option<String>,
        pub at: TimeDateTimeWithTimeZone,
        /// The client's address cut to its /24 or /48.
        pub ip: Option<String>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

/// `admin_user_state`: one row per disabled account.
pub(crate) mod user_state {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "admin_user_state")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub user_id: Uuid,
        pub disabled_at: TimeDateTimeWithTimeZone,
        pub disabled_by: Uuid,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

/// `admin_invites`.
pub(crate) mod invites {
    use crate::convert::{corrupt, from_i64_u32, utc};
    use kemlock_app::admin::Invite;
    use kemlock_app::ports::StoreError;
    use kemlock_domain::{Email, UserId};
    use sea_orm::ActiveValue::Set;
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "admin_invites")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub email: String,
        pub invited_by: Uuid,
        pub token_hash: Vec<u8>,
        pub created_at: TimeDateTimeWithTimeZone,
        pub expires_at: TimeDateTimeWithTimeZone,
        pub last_sent_at: TimeDateTimeWithTimeZone,
        pub sent: i64,
        pub accepted_at: Option<TimeDateTimeWithTimeZone>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}

    impl Model {
        pub(crate) fn into_domain(self) -> Result<Invite, StoreError> {
            let token_hash: [u8; 32] = self
                .token_hash
                .try_into()
                .map_err(|_| corrupt("invitation token hash"))?;
            Ok(Invite {
                id: self.id,
                email: Email::parse(&self.email).map_err(|_| corrupt("invitation email"))?,
                invited_by: UserId(self.invited_by),
                token_hash,
                created_at: self.created_at,
                expires_at: self.expires_at,
                last_sent_at: self.last_sent_at,
                sent: from_i64_u32(self.sent, "invitation send count")?,
                accepted_at: self.accepted_at,
            })
        }
    }

    pub(crate) fn active(invite: &Invite) -> ActiveModel {
        ActiveModel {
            id: Set(invite.id),
            email: Set(invite.email.as_str().to_owned()),
            invited_by: Set(invite.invited_by.0),
            token_hash: Set(invite.token_hash.to_vec()),
            created_at: Set(utc(invite.created_at)),
            expires_at: Set(utc(invite.expires_at)),
            last_sent_at: Set(utc(invite.last_sent_at)),
            sent: Set(i64::from(invite.sent)),
            accepted_at: Set(invite.accepted_at.map(utc)),
        }
    }
}

/// `compliance_requests`.
pub(crate) mod requests {
    use crate::convert::{corrupt, utc};
    use kemlock_app::admin::{ComplianceRequest, RequestKind, RequestStatus};
    use kemlock_app::ports::StoreError;
    use kemlock_domain::UserId;
    use sea_orm::ActiveValue::Set;
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "compliance_requests")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub kind: String,
        pub requester: String,
        pub user_id: Option<Uuid>,
        pub received_at: TimeDateTimeWithTimeZone,
        pub due_at: TimeDateTimeWithTimeZone,
        pub extended: bool,
        pub status: String,
        pub note: Option<String>,
        pub closed_at: Option<TimeDateTimeWithTimeZone>,
        pub handled_by: Option<Uuid>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}

    impl Model {
        pub(crate) fn into_domain(self) -> Result<ComplianceRequest, StoreError> {
            Ok(ComplianceRequest {
                id: self.id,
                kind: RequestKind::parse(&self.kind).ok_or_else(|| corrupt("request kind"))?,
                requester: self.requester,
                user: self.user_id.map(UserId),
                received_at: self.received_at,
                due_at: self.due_at,
                extended: self.extended,
                status: RequestStatus::parse(&self.status)
                    .ok_or_else(|| corrupt("request status"))?,
                note: self.note,
                closed_at: self.closed_at,
                handled_by: self.handled_by.map(UserId),
            })
        }
    }

    pub(crate) fn active(request: &ComplianceRequest) -> ActiveModel {
        ActiveModel {
            id: Set(request.id),
            kind: Set(request.kind.as_str().to_owned()),
            requester: Set(request.requester.clone()),
            user_id: Set(request.user.map(|u| u.0)),
            received_at: Set(utc(request.received_at)),
            due_at: Set(utc(request.due_at)),
            extended: Set(request.extended),
            status: Set(request.status.as_str().to_owned()),
            note: Set(request.note.clone()),
            closed_at: Set(request.closed_at.map(utc)),
            handled_by: Set(request.handled_by.map(|u| u.0)),
        }
    }
}
