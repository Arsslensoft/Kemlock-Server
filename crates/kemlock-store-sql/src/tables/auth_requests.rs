//! `auth_requests`: pending and answered device approvals, as `kemlock_domain::unlock::AuthRequest`.

use crate::convert::{corrupt, utc};
use kemlock_app::ports::StoreError;
use kemlock_domain::unlock::{ApprovalId, ApprovalState, AuthRequest};
use kemlock_domain::{DeviceId, DeviceKind, UserId};
use sea_orm::ActiveValue::Set;
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "auth_requests")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub user_id: Uuid,
    pub device_id: Uuid,
    pub device_name: String,
    /// `DeviceKind` as its kebab-case name.
    pub device_kind: String,
    /// The new device's one-time `kx1` public key.
    pub public_key: Vec<u8>,
    pub jkt: String,
    /// The requester's address, already cut to its /24 or /48.
    pub ip: String,
    /// `pending`, `approved`, `denied` or `consumed`.
    pub state: String,
    pub sealed_key: Option<Vec<u8>>,
    pub answered_at: Option<TimeDateTimeWithTimeZone>,
    pub created_at: TimeDateTimeWithTimeZone,
    pub expires_at: TimeDateTimeWithTimeZone,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

pub(crate) fn state_str(state: ApprovalState) -> &'static str {
    match state {
        ApprovalState::Pending => "pending",
        ApprovalState::Approved => "approved",
        ApprovalState::Denied => "denied",
        ApprovalState::Consumed => "consumed",
    }
}

fn state_from(s: &str) -> Result<ApprovalState, StoreError> {
    match s {
        "pending" => Ok(ApprovalState::Pending),
        "approved" => Ok(ApprovalState::Approved),
        "denied" => Ok(ApprovalState::Denied),
        "consumed" => Ok(ApprovalState::Consumed),
        _ => Err(corrupt("approval state")),
    }
}

fn kind_str(kind: DeviceKind) -> &'static str {
    match kind {
        DeviceKind::KemlockAndroid => "kemlock-android",
        DeviceKind::KemlockIos => "kemlock-ios",
        DeviceKind::KemlockWeb => "kemlock-web",
        DeviceKind::KemlockBrowser => "kemlock-browser",
        DeviceKind::KemlockCli => "kemlock-cli",
        DeviceKind::Amethystora => "amethystora",
        DeviceKind::Bitwarden => "bitwarden",
        DeviceKind::Other => "other",
    }
}

fn kind_from(s: &str) -> Result<DeviceKind, StoreError> {
    match s {
        "kemlock-android" => Ok(DeviceKind::KemlockAndroid),
        "kemlock-ios" => Ok(DeviceKind::KemlockIos),
        "kemlock-web" => Ok(DeviceKind::KemlockWeb),
        "kemlock-browser" => Ok(DeviceKind::KemlockBrowser),
        "kemlock-cli" => Ok(DeviceKind::KemlockCli),
        "amethystora" => Ok(DeviceKind::Amethystora),
        "bitwarden" => Ok(DeviceKind::Bitwarden),
        "other" => Ok(DeviceKind::Other),
        _ => Err(corrupt("device kind")),
    }
}

impl Model {
    pub(crate) fn into_domain(self) -> Result<AuthRequest, StoreError> {
        Ok(AuthRequest {
            id: ApprovalId(self.id),
            user: UserId(self.user_id),
            device: DeviceId(self.device_id),
            device_name: self.device_name,
            device_kind: kind_from(&self.device_kind)?,
            public_key: self.public_key,
            jkt: self.jkt,
            ip: self.ip,
            state: state_from(&self.state)?,
            sealed_key: self.sealed_key,
            answered_at: self.answered_at,
            created_at: self.created_at,
            expires_at: self.expires_at,
        })
    }
}

/// Every column set, the id included.
pub(crate) fn active(request: &AuthRequest) -> ActiveModel {
    ActiveModel {
        id: Set(request.id.0),
        user_id: Set(request.user.0),
        device_id: Set(request.device.0),
        device_name: Set(request.device_name.clone()),
        device_kind: Set(kind_str(request.device_kind).to_owned()),
        public_key: Set(request.public_key.clone()),
        jkt: Set(request.jkt.clone()),
        ip: Set(request.ip.clone()),
        state: Set(state_str(request.state).to_owned()),
        sealed_key: Set(request.sealed_key.clone()),
        answered_at: Set(request.answered_at.map(utc)),
        created_at: Set(utc(request.created_at)),
        expires_at: Set(utc(request.expires_at)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn every_state_round_trips() {
        for state in [
            ApprovalState::Pending,
            ApprovalState::Approved,
            ApprovalState::Denied,
            ApprovalState::Consumed,
        ] {
            assert_eq!(state_from(state_str(state)), Ok(state));
        }
        assert!(state_from("lost").is_err());
    }

    #[test]
    fn every_device_kind_round_trips() {
        for kind in [
            DeviceKind::KemlockAndroid,
            DeviceKind::KemlockIos,
            DeviceKind::KemlockWeb,
            DeviceKind::KemlockBrowser,
            DeviceKind::KemlockCli,
            DeviceKind::Amethystora,
            DeviceKind::Bitwarden,
            DeviceKind::Other,
        ] {
            assert_eq!(kind_from(kind_str(kind)), Ok(kind));
        }
        // The extension and the web vault are stored apart, and the name fits the column.
        assert_eq!(kind_str(DeviceKind::KemlockBrowser), "kemlock-browser");
        assert_ne!(
            kind_str(DeviceKind::KemlockBrowser),
            kind_str(DeviceKind::KemlockWeb)
        );
        assert!(kind_from("toaster").is_err());
    }

    #[test]
    fn a_row_becomes_a_request_and_back() {
        let model = Model {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            device_id: Uuid::new_v4(),
            device_name: "Firefox".to_owned(),
            device_kind: "kemlock-web".to_owned(),
            public_key: vec![7; 1600],
            jkt: "thumb".to_owned(),
            ip: "203.0.113.0/24".to_owned(),
            state: "approved".to_owned(),
            sealed_key: Some(vec![1, 2, 3]),
            answered_at: Some(datetime!(2026-01-02 03:05:05 UTC)),
            created_at: datetime!(2026-01-02 03:04:05 UTC),
            expires_at: datetime!(2026-01-02 03:19:05 UTC),
        };
        let request = model.clone().into_domain().expect("valid row");
        assert_eq!(request.state, ApprovalState::Approved);
        assert_eq!(request.device_kind, DeviceKind::KemlockWeb);
        assert_eq!(request.sealed_key, Some(vec![1, 2, 3]));
        let active = active(&request);
        assert_eq!(active.state, Set("approved".to_owned()));
        assert_eq!(active.device_kind, Set("kemlock-web".to_owned()));
    }
}
