//! Settings the running server reads on every request, kept apart from the start-up
//! configuration so that a change saved in the console takes effect without a restart.
//!
//! One [`Live`] handle is made with the API and cloned into everything that reads one of these
//! values: the registration routes (sign-ups, the invitation gate), the file routes (the largest
//! file) and the Bitwarden API's registration. The server's settings watcher writes to it when
//! the effective settings change (environment, then the TOML file, then what the console saved).
//! Reads are lock-free or take a short read lock; nothing here waits on I/O.

use super::invites::InviteGate;
use kemlock_domain::Email;
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, PoisonError, RwLock};

/// What a quota holds when there is none: no number of bytes is that many.
const NO_QUOTA: u64 = u64::MAX;

fn quota(value: &AtomicU64) -> Option<u64> {
    match value.load(Ordering::Relaxed) {
        NO_QUOTA => None,
        bytes => Some(bytes),
    }
}

struct Shared {
    signups_allowed: AtomicBool,
    /// `SIGNUPS_VERIFY`: an address is proven by a mailed link before its account is made.
    signups_verify: AtomicBool,
    /// `KEMLOCK_BW_INVITES_AUTO_ACCEPT`: an invitation of the Bitwarden API to an existing account with
    /// a password counts as accepted at once, when the server doesn't mail.
    bw_invites_auto_accept: AtomicBool,
    invitations_allowed: AtomicBool,
    /// Lower-case domains; empty means no whitelist.
    signup_domains: RwLock<Vec<String>>,
    /// Bytes; 0 means the value the file routes were built with.
    max_file_size: AtomicU64,
    /// Storage quotas in bytes, [`NO_QUOTA`] for none: personal attachments, space attachments
    /// and file Sends.
    user_attachment_limit: AtomicU64,
    space_attachment_limit: AtomicU64,
    send_limit: AtomicU64,
    invites: OnceLock<Arc<dyn InviteGate>>,
}

/// The live, shared settings. Cheap to clone; every clone sees every change.
#[derive(Clone)]
pub struct Live(Arc<Shared>);

impl fmt::Debug for Live {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Live")
            .field("signups_allowed", &self.signups_allowed())
            .field("invitations_allowed", &self.invitations_allowed())
            .finish_non_exhaustive()
    }
}

/// Two handles are equal when they are the same handle.
impl PartialEq for Live {
    fn eq(&self, other: &Live) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for Live {}

impl Live {
    /// A handle with sign-ups as given, invitations on (Vaultwarden's default), no domain
    /// whitelist and the file routes' own size limit.
    pub fn new(signups_allowed: bool) -> Live {
        Live(Arc::new(Shared {
            signups_allowed: AtomicBool::new(signups_allowed),
            signups_verify: AtomicBool::new(false),
            bw_invites_auto_accept: AtomicBool::new(false),
            invitations_allowed: AtomicBool::new(true),
            signup_domains: RwLock::new(Vec::new()),
            max_file_size: AtomicU64::new(0),
            user_attachment_limit: AtomicU64::new(NO_QUOTA),
            space_attachment_limit: AtomicU64::new(NO_QUOTA),
            send_limit: AtomicU64::new(NO_QUOTA),
            invites: OnceLock::new(),
        }))
    }

    pub fn signups_allowed(&self) -> bool {
        self.0.signups_allowed.load(Ordering::Relaxed)
    }

    pub fn set_signups_allowed(&self, allowed: bool) {
        self.0.signups_allowed.store(allowed, Ordering::Relaxed);
    }

    /// Whether registration has to prove the address with a mailed link first.
    pub fn signups_verify(&self) -> bool {
        self.0.signups_verify.load(Ordering::Relaxed)
    }

    pub fn set_signups_verify(&self, verify: bool) {
        self.0.signups_verify.store(verify, Ordering::Relaxed);
    }

    /// Whether a Bitwarden invitation to an existing account is taken as accepted at once, as
    /// Vaultwarden does with its mailer off. Off by default: the invitee accepts for themselves.
    pub fn bw_invites_auto_accept(&self) -> bool {
        self.0.bw_invites_auto_accept.load(Ordering::Relaxed)
    }

    pub fn set_bw_invites_auto_accept(&self, on: bool) {
        self.0.bw_invites_auto_accept.store(on, Ordering::Relaxed);
    }

    pub fn invitations_allowed(&self) -> bool {
        self.0.invitations_allowed.load(Ordering::Relaxed)
    }

    pub fn set_invitations_allowed(&self, allowed: bool) {
        self.0.invitations_allowed.store(allowed, Ordering::Relaxed);
    }

    /// Replaces the domain whitelist; each domain is lower-cased.
    pub fn set_signup_domains<I, T>(&self, domains: I)
    where
        I: IntoIterator<Item = T>,
        T: AsRef<str>,
    {
        let domains = domains
            .into_iter()
            .map(|d| d.as_ref().trim().to_ascii_lowercase())
            .filter(|d| !d.is_empty())
            .collect();
        *self
            .0
            .signup_domains
            .write()
            .unwrap_or_else(PoisonError::into_inner) = domains;
    }

    /// Whether `email` may register without an invitation. With a domain whitelist set, only
    /// its domains may, whatever `signups_allowed` says (Vaultwarden's rule: the whitelist
    /// overrides the switch); with none, everyone may while sign-ups are on.
    pub fn signups_open_for(&self, email: &Email) -> bool {
        let domains = self
            .0
            .signup_domains
            .read()
            .unwrap_or_else(PoisonError::into_inner);
        if domains.is_empty() {
            return self.signups_allowed();
        }
        let address = email.as_str();
        address
            .rsplit_once('@')
            .is_some_and(|(_, domain)| domains.iter().any(|d| d.eq_ignore_ascii_case(domain)))
    }

    /// The largest file in bytes, when the settings set one.
    pub fn max_file_size(&self) -> Option<u64> {
        match self.0.max_file_size.load(Ordering::Relaxed) {
            0 => None,
            bytes => Some(bytes),
        }
    }

    /// Sets the largest file; 0 goes back to the value the routes were built with.
    pub fn set_max_file_size(&self, bytes: u64) {
        self.0.max_file_size.store(bytes, Ordering::Relaxed);
    }

    /// The most bytes of attachments an account may keep (Vaultwarden's `USER_ATTACHMENT_LIMIT`),
    /// `None` for no limit; `Some(0)` switches personal attachments off.
    pub fn user_attachment_limit(&self) -> Option<u64> {
        quota(&self.0.user_attachment_limit)
    }

    pub fn set_user_attachment_limit(&self, bytes: Option<u64>) {
        self.0
            .user_attachment_limit
            .store(bytes.unwrap_or(NO_QUOTA), Ordering::Relaxed);
    }

    /// The most bytes of attachments a space may keep (`ORG_ATTACHMENT_LIMIT`).
    pub fn space_attachment_limit(&self) -> Option<u64> {
        quota(&self.0.space_attachment_limit)
    }

    pub fn set_space_attachment_limit(&self, bytes: Option<u64>) {
        self.0
            .space_attachment_limit
            .store(bytes.unwrap_or(NO_QUOTA), Ordering::Relaxed);
    }

    /// The most bytes of file Sends an account may keep (`USER_SEND_LIMIT`).
    pub fn send_limit(&self) -> Option<u64> {
        quota(&self.0.send_limit)
    }

    pub fn set_send_limit(&self, bytes: Option<u64>) {
        self.0
            .send_limit
            .store(bytes.unwrap_or(NO_QUOTA), Ordering::Relaxed);
    }

    /// Hands registration the gate that checks and consumes invitation tokens. Set once, at
    /// start; a second call is ignored.
    pub fn set_invites(&self, gate: Arc<dyn InviteGate>) {
        let _ = self.0.invites.set(gate);
    }

    /// The invitation gate, once the server has set one and while invitations are allowed.
    pub fn invites(&self) -> Option<Arc<dyn InviteGate>> {
        if !self.invitations_allowed() {
            return None;
        }
        self.0.invites.get().cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn email(text: &str) -> Email {
        Email::parse(text).expect("a valid email")
    }

    #[test]
    fn a_change_is_seen_by_every_clone() {
        let live = Live::new(false);
        let other = live.clone();
        assert!(!other.signups_allowed());
        live.set_signups_allowed(true);
        assert!(other.signups_allowed());
        assert_eq!(live, other);
        assert_ne!(live, Live::new(true));
    }

    #[test]
    fn bitwarden_invitations_are_not_auto_accepted_until_set() {
        let live = Live::new(true);
        let other = live.clone();
        assert!(!other.bw_invites_auto_accept());
        live.set_bw_invites_auto_accept(true);
        assert!(other.bw_invites_auto_accept());
    }

    #[test]
    fn verifying_sign_ups_is_off_until_set_and_every_clone_sees_it() {
        let live = Live::new(true);
        let other = live.clone();
        assert!(!other.signups_verify());
        live.set_signups_verify(true);
        assert!(other.signups_verify());
        live.set_signups_verify(false);
        assert!(!other.signups_verify());
    }

    #[test]
    fn without_a_whitelist_the_switch_decides() {
        let live = Live::new(false);
        assert!(!live.signups_open_for(&email("ada@example.org")));
        live.set_signups_allowed(true);
        assert!(live.signups_open_for(&email("ada@example.org")));
    }

    #[test]
    fn a_whitelist_overrides_the_switch() {
        let live = Live::new(false);
        live.set_signup_domains(["Example.org", " corp.example.com "]);
        assert!(live.signups_open_for(&email("ada@example.org")));
        assert!(live.signups_open_for(&email("bob@CORP.example.com")));
        assert!(!live.signups_open_for(&email("eve@evil.example")));
        // Even with sign-ups on, a whitelist keeps other domains out.
        live.set_signups_allowed(true);
        assert!(!live.signups_open_for(&email("eve@evil.example")));
        live.set_signup_domains(Vec::<String>::new());
        assert!(live.signups_open_for(&email("eve@evil.example")));
    }

    #[test]
    fn the_file_limit_falls_back_when_unset() {
        let live = Live::new(false);
        assert_eq!(live.max_file_size(), None);
        live.set_max_file_size(5 << 20);
        assert_eq!(live.max_file_size(), Some(5 << 20));
        live.set_max_file_size(0);
        assert_eq!(live.max_file_size(), None);
    }

    #[test]
    fn the_quotas_are_none_until_set_and_zero_is_a_limit_of_its_own() {
        let live = Live::new(false);
        assert_eq!(live.user_attachment_limit(), None);
        assert_eq!(live.space_attachment_limit(), None);
        assert_eq!(live.send_limit(), None);
        live.set_user_attachment_limit(Some(0));
        live.set_space_attachment_limit(Some(2048));
        live.set_send_limit(Some(1));
        assert_eq!(live.user_attachment_limit(), Some(0));
        assert_eq!(live.space_attachment_limit(), Some(2048));
        assert_eq!(live.send_limit(), Some(1));
        live.set_user_attachment_limit(None);
        assert_eq!(live.user_attachment_limit(), None);
    }

    #[test]
    fn the_invitation_switch_hides_the_gate() {
        use super::super::invites::InviteTicket;
        use crate::notices::BoxFuture;

        struct Never;
        impl InviteGate for Never {
            fn accept<'a>(
                &'a self,
                _token: &'a str,
                _email: &'a Email,
            ) -> BoxFuture<'a, Result<InviteTicket, crate::AppError>> {
                Box::pin(async { Err(crate::AppError::Forbidden) })
            }
            fn consume<'a>(
                &'a self,
                _ticket: &'a InviteTicket,
            ) -> BoxFuture<'a, Result<(), crate::AppError>> {
                Box::pin(async { Ok(()) })
            }
        }

        let live = Live::new(false);
        assert!(live.invites().is_none());
        live.set_invites(Arc::new(Never));
        assert!(live.invites().is_some());
        live.set_invitations_allowed(false);
        assert!(live.invites().is_none());
    }
}
