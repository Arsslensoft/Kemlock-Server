//! Device approval requests: a new device asks, an open device of the account answers.

use crate::device::DeviceKind;
use crate::ids::{DeviceId, UserId};
use std::net::IpAddr;
use time::{Duration, OffsetDateTime};

uuid_id!(
    /// A device approval request.
    ApprovalId
);

/// A request lives 15 minutes (design, "Retention").
pub const REQUEST_TTL: Duration = Duration::minutes(15);
/// An account takes at most this many requests an hour from all addresses together (design,
/// "Limits"); past it a request is still stored and shown on the account's open devices, but the
/// new device is told it was held back among many and the owner is mailed about it once.
pub const HOURLY_REQUEST_LIMIT: usize = 30;
/// The most requests an account stores in an hour, whoever sent them, the count and the insert
/// made in one transaction. A request from an address the owner was answered from isn't held to
/// it. Past it a request is answered like one for an email with no account and nothing is stored.
pub const HARD_HOURLY_REQUEST_LIMIT: usize = 100;
/// One address (a /24, or a /48 for IPv6) takes at most this many requests an hour for one account,
/// so a few addresses can't use up the account's whole hour.
pub const SOURCE_HOURLY_REQUEST_LIMIT: usize = 3;
/// A `kx1` public key: ML-KEM-1024 encapsulation key (1568) and X25519 public key (32).
pub const KX1_PUBLIC_KEY_LEN: usize = 1600;
/// What a `kx1` sealed box adds to its secret: version byte (1), `kx1` ciphertext (1600), AES-GCM
/// nonce (12) and tag (16).
pub const SEALED_BOX_OVERHEAD: usize = 1 + 1600 + 12 + 16;

/// Whether a sealed box of `len` bytes can hold a key of 32 to 64 bytes: the user key or the root
/// key. The server can't open it; this only stops it storing a blob of the wrong shape.
pub fn sealed_key_len_ok(len: usize) -> bool {
    (SEALED_BOX_OVERHEAD + 32..=SEALED_BOX_OVERHEAD + 64).contains(&len)
}

/// An address cut to the part a person can be told: IPv4 to its /24, IPv6 to its /48. The full
/// address is never stored for approvals.
pub fn truncate_ip(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, c, _] = v4.octets();
            format!("{a}.{b}.{c}.0/24")
        }
        IpAddr::V6(v6) => {
            // An IPv4-mapped address is an IPv4 client behind a dual-stack socket.
            if let Some(v4) = v6.to_ipv4_mapped() {
                return truncate_ip(IpAddr::V4(v4));
            }
            let [a, b, c, ..] = v6.segments();
            format!("{a:x}:{b:x}:{c:x}::/48")
        }
    }
}

/// Where a request stands. A request past its expiry is expired whatever its state says; see
/// [`AuthRequest::is_expired`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApprovalState {
    /// Waiting for an open device.
    Pending,
    /// An open device sealed the key to the new device.
    Approved,
    /// An open device refused.
    Denied,
    /// The new device signed in with the answer; it can't be used again.
    Consumed,
}

/// Why a request can't take an answer or a sign-in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ApprovalError {
    #[error("the request has expired")]
    Expired,
    #[error("the request was already answered")]
    AlreadyAnswered,
    #[error("the request hasn't been approved")]
    NotApproved,
}

/// A pending or answered approval request (`auth_requests`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthRequest {
    pub id: ApprovalId,
    pub user: UserId,
    /// The device id the new device will sign in as.
    pub device: DeviceId,
    pub device_name: String,
    pub device_kind: DeviceKind,
    /// The new device's one-time `kx1` public key.
    pub public_key: Vec<u8>,
    /// The RFC 7638 thumbprint of the DPoP key the new device registered with the request.
    pub jkt: String,
    /// Where the request came from, cut by [`truncate_ip`].
    pub ip: String,
    pub state: ApprovalState,
    /// The root key sealed to `public_key`, once approved. Opaque to the server.
    pub sealed_key: Option<Vec<u8>>,
    pub answered_at: Option<OffsetDateTime>,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
}

impl AuthRequest {
    pub fn is_expired(&self, now: OffsetDateTime) -> bool {
        now >= self.expires_at
    }

    /// Pending and not yet expired: what an open device is shown.
    pub fn is_open(&self, now: OffsetDateTime) -> bool {
        self.state == ApprovalState::Pending && !self.is_expired(now)
    }

    /// Marks the request approved with `sealed_key`.
    pub fn approve(
        &mut self,
        sealed_key: Vec<u8>,
        now: OffsetDateTime,
    ) -> Result<(), ApprovalError> {
        self.check_answerable(now)?;
        self.state = ApprovalState::Approved;
        self.sealed_key = Some(sealed_key);
        self.answered_at = Some(now);
        Ok(())
    }

    /// Marks the request denied.
    pub fn deny(&mut self, now: OffsetDateTime) -> Result<(), ApprovalError> {
        self.check_answerable(now)?;
        self.state = ApprovalState::Denied;
        self.answered_at = Some(now);
        Ok(())
    }

    /// Marks the request used by the new device's sign-in. Only an approved, unexpired request
    /// can be.
    pub fn consume(&mut self, now: OffsetDateTime) -> Result<(), ApprovalError> {
        if self.is_expired(now) {
            return Err(ApprovalError::Expired);
        }
        if self.state != ApprovalState::Approved {
            return Err(ApprovalError::NotApproved);
        }
        self.state = ApprovalState::Consumed;
        // The new device has its key; the server needn't keep the box any longer.
        self.sealed_key = None;
        Ok(())
    }

    fn check_answerable(&self, now: OffsetDateTime) -> Result<(), ApprovalError> {
        if self.is_expired(now) {
            return Err(ApprovalError::Expired);
        }
        if self.state != ApprovalState::Pending {
            return Err(ApprovalError::AlreadyAnswered);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use time::macros::datetime;

    const NOW: OffsetDateTime = datetime!(2026-11-22 10:00:00 UTC);

    fn request() -> AuthRequest {
        AuthRequest {
            id: ApprovalId::random(),
            user: UserId::random(),
            device: DeviceId::random(),
            device_name: "Firefox on Linux".to_owned(),
            device_kind: DeviceKind::KemlockWeb,
            public_key: vec![7; KX1_PUBLIC_KEY_LEN],
            jkt: "thumb".to_owned(),
            ip: "203.0.113.0/24".to_owned(),
            state: ApprovalState::Pending,
            sealed_key: None,
            answered_at: None,
            created_at: NOW,
            expires_at: NOW + REQUEST_TTL,
        }
    }

    #[test]
    fn ipv4_keeps_its_24() {
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 77));
        assert_eq!(truncate_ip(ip), "203.0.113.0/24");
    }

    #[test]
    fn ipv6_keeps_its_48() {
        let ip: IpAddr = "2001:db8:1234:5678:9abc:def0:1234:5678"
            .parse::<Ipv6Addr>()
            .expect("valid")
            .into();
        assert_eq!(truncate_ip(ip), "2001:db8:1234::/48");
    }

    #[test]
    fn a_mapped_ipv4_address_is_cut_as_ipv4() {
        let ip: IpAddr = "::ffff:198.51.100.9".parse().expect("valid");
        assert_eq!(truncate_ip(ip), "198.51.100.0/24");
    }

    #[test]
    fn sealed_key_sizes_cover_user_and_root_keys() {
        assert!(sealed_key_len_ok(SEALED_BOX_OVERHEAD + 32));
        assert!(sealed_key_len_ok(SEALED_BOX_OVERHEAD + 64));
        assert!(!sealed_key_len_ok(SEALED_BOX_OVERHEAD + 31));
        assert!(!sealed_key_len_ok(SEALED_BOX_OVERHEAD + 65));
        assert!(!sealed_key_len_ok(0));
    }

    #[test]
    fn a_request_is_open_until_its_expiry() {
        let r = request();
        assert!(r.is_open(NOW));
        assert!(r.is_open(NOW + Duration::minutes(14)));
        assert!(!r.is_open(NOW + REQUEST_TTL));
        assert!(r.is_expired(NOW + Duration::minutes(16)));
    }

    #[test]
    fn approving_stores_the_box_once() {
        let mut r = request();
        r.approve(vec![1, 2, 3], NOW + Duration::minutes(1))
            .expect("pending");
        assert_eq!(r.state, ApprovalState::Approved);
        assert_eq!(r.sealed_key, Some(vec![1, 2, 3]));
        assert_eq!(
            r.approve(vec![9], NOW + Duration::minutes(2)),
            Err(ApprovalError::AlreadyAnswered)
        );
        assert_eq!(r.sealed_key, Some(vec![1, 2, 3]));
    }

    #[test]
    fn a_denied_request_holds_no_key_and_stays_denied() {
        let mut r = request();
        r.deny(NOW).expect("pending");
        assert_eq!(r.state, ApprovalState::Denied);
        assert_eq!(r.sealed_key, None);
        assert_eq!(r.approve(vec![1], NOW), Err(ApprovalError::AlreadyAnswered));
    }

    #[test]
    fn an_expired_request_takes_no_answer() {
        let mut r = request();
        assert_eq!(
            r.approve(vec![1], NOW + REQUEST_TTL),
            Err(ApprovalError::Expired)
        );
        assert_eq!(r.deny(NOW + REQUEST_TTL), Err(ApprovalError::Expired));
        assert_eq!(r.state, ApprovalState::Pending);
    }

    #[test]
    fn only_an_approved_request_is_consumed_and_only_once() {
        let mut r = request();
        assert_eq!(r.consume(NOW), Err(ApprovalError::NotApproved));
        r.approve(vec![1], NOW).expect("pending");
        assert_eq!(r.consume(NOW + REQUEST_TTL), Err(ApprovalError::Expired));
        r.consume(NOW + Duration::minutes(1)).expect("approved");
        assert_eq!(r.state, ApprovalState::Consumed);
        assert_eq!(r.sealed_key, None, "the box is dropped once used");
        assert_eq!(r.consume(NOW), Err(ApprovalError::NotApproved));
    }
}
