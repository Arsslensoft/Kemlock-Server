//! Emergency access: a contact named by the account's owner may ask for the vault and get it after
//! a wait, unless the owner refuses first. The ports are in [`ports`].

mod access;
mod approve_due;
pub mod ports;

pub use access::{ContactKeys, EmergencyAccess, EmergencyOverview, GrantView, KeyRelease};
pub use approve_due::ApproveDue;
pub use ports::{EmergencyEvent, EmergencyNotice, EmergencyNotices, EmergencyRepo};
