//! Opening the vault on a new device without the master password: device approval, trusted-device
//! key copies and signing a device out.
//!
//! The ports are in [`ports`]; the use cases are one struct each, built with a struct literal like
//! the rest of the crate's.

mod approvals;
mod bitwarden_id;
mod device_key_sign_in;
mod device_sign_in;
mod key_copy;
pub mod ports;

pub use approvals::{
    Answer, AnswerApproval, ApprovalRequestInput, ListApprovals, PendingApproval, Poll,
    PollApproval, PurgeApprovals, RequestApproval, Requested, phrase_for,
};
pub use bitwarden_id::{MAX_IDENTIFIER_LEN, bitwarden_device_id};
pub use device_key_sign_in::{DeviceKeySignIn, PURPOSE_DEVICE_KEY_CHALLENGE};
pub use device_sign_in::{DeviceSignIn, PURPOSE_DEVICE_CHALLENGE};
pub use key_copy::{EndSession, KeyCopies, SignOutDevice, UntrustDevice};
pub use ports::{
    ApprovalRepo, DeviceNotices, DevicesStore, KeyCopyRepo, LogNotices, NewDeviceNotice,
};
