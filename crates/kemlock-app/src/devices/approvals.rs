//! Device approval: a new device asks, open devices list and answer, the new device polls.
//!
//! The server only relays. The new device makes a one-time `kx1` key pair and posts the public key
//! with its DPoP key's thumbprint; an open device checks the five-word phrase both show, seals the
//! root key to that public key (docs/crypto.md, context `"device-approval"`) and posts the box;
//! the new device opens it. The box is opaque here: only its length is checked.

use super::ports::{ApprovalRepo, DeviceNotices, NewDeviceNotice};
use crate::authenticate::Actor;
use crate::error::AppError;
use crate::platform::{Hasher, Platform, random_uuid};
use crate::ports::{Event, EventLog, UserRepo};
use crate::session::DeviceInfo;
use kemlock_domain::unlock::{
    ApprovalError, ApprovalId, ApprovalState, AuthRequest, HOURLY_REQUEST_LIMIT,
    KX1_PUBLIC_KEY_LEN, REQUEST_TTL, phrase_from_digest, phrase_input, sealed_key_len_ok,
    truncate_ip,
};
use kemlock_domain::{Device, DeviceKind, Email, UserId};
use std::net::IpAddr;
use subtle::ConstantTimeEq;
use time::{Duration, OffsetDateTime};

/// The five-word phrase of a request's one-time public key. Every client computes the same one.
pub fn phrase_for<H: Hasher>(hasher: &H, public_key: &[u8]) -> String {
    phrase_from_digest(&hasher.sha256(&phrase_input(public_key)))
}

pub(crate) fn same(a: &str, b: &str) -> bool {
    bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}

fn answer_error(e: ApprovalError) -> AppError {
    match e {
        ApprovalError::Expired => AppError::Invalid("the request has expired"),
        ApprovalError::AlreadyAnswered | ApprovalError::NotApproved => {
            AppError::Invalid("the request was already answered")
        }
    }
}

/// What a new device says when it asks.
#[derive(Clone, Debug)]
pub struct ApprovalRequestInput {
    pub email: String,
    pub device: DeviceInfo,
    /// The one-time `kx1` public key (1,600 bytes).
    pub public_key: Vec<u8>,
    /// The thumbprint of the DPoP key that signed this request; the device signs in with it.
    pub jkt: String,
    pub ip: IpAddr,
}

/// What the new device gets back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Requested {
    pub id: ApprovalId,
    /// The phrase to show beside the one the open device shows.
    pub phrase: String,
    pub expires_at: OffsetDateTime,
}

/// A new device asks for approval.
#[derive(Debug)]
pub struct RequestApproval<U, A, N, E> {
    pub users: U,
    pub approvals: A,
    pub notices: N,
    pub env: E,
}

impl<U: UserRepo, A: ApprovalRepo, N: DeviceNotices, E: Platform> RequestApproval<U, A, N, E> {
    /// Stores the request and tells the account's owner. The answer for an email with no account
    /// looks the same as for one with an account, so this can't be used to find accounts; the
    /// request just never appears anywhere. An account takes 10 requests an hour.
    pub async fn execute(&self, input: ApprovalRequestInput) -> Result<Requested, AppError> {
        if input.public_key.len() != KX1_PUBLIC_KEY_LEN {
            return Err(AppError::Invalid(
                "the public key must be a 1600-byte kx1 key",
            ));
        }
        if input.jkt.is_empty() || input.jkt.len() > 128 {
            return Err(AppError::Invalid("the DPoP key thumbprint is missing"));
        }
        let email =
            Email::parse(&input.email).map_err(|_| AppError::Invalid("not an email address"))?;
        let now = self.env.now();
        let phrase = phrase_for(&self.env, &input.public_key);
        let expires_at = now + REQUEST_TTL;

        let Some(user) = self.users.by_email(&email).await? else {
            return Ok(Requested {
                id: ApprovalId(random_uuid(&self.env)),
                phrase,
                expires_at,
            });
        };

        let recent = self
            .approvals
            .requests_since(user.id, now - Duration::hours(1))
            .await?;
        if recent.len() >= HOURLY_REQUEST_LIMIT {
            // The next slot opens when the request that fills the last one ages out.
            let blocking = recent[recent.len() - HOURLY_REQUEST_LIMIT];
            let wait = (blocking + Duration::hours(1) - now).whole_seconds().max(1);
            return Err(AppError::SlowDown {
                retry_after_secs: u64::try_from(wait).unwrap_or(1),
            });
        }

        let device_name = Device::clean_name(&input.device.name);
        let request = AuthRequest {
            id: ApprovalId(random_uuid(&self.env)),
            user: user.id,
            device: input.device.resolve(user.id, &self.env),
            device_name: device_name.clone(),
            device_kind: input.device.kind,
            public_key: input.public_key,
            jkt: input.jkt,
            ip: truncate_ip(input.ip),
            state: ApprovalState::Pending,
            sealed_key: None,
            answered_at: None,
            created_at: now,
            expires_at,
        };
        self.approvals.insert_request(&request).await?;
        self.notices
            .new_device(NewDeviceNotice {
                to: user.email,
                device_name,
                device_kind: request.device_kind,
                ip: request.ip.clone(),
                at: now,
            })
            .await;
        Ok(Requested {
            id: request.id,
            phrase,
            expires_at,
        })
    }
}

/// A pending request as an open device shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingApproval {
    pub id: ApprovalId,
    pub device_name: String,
    pub device_kind: DeviceKind,
    /// The request's address cut to its /24 (IPv4) or /48 (IPv6).
    pub ip: String,
    /// The five words the new device shows too.
    pub phrase: String,
    /// The request's one-time `kx1` public key (1,600 bytes): the open device works the phrase out
    /// from it itself and seals the root key to it.
    pub public_key: Vec<u8>,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
}

/// The account's open requests, for the "Review request" banner.
#[derive(Debug)]
pub struct ListApprovals<A, E> {
    pub approvals: A,
    pub env: E,
}

impl<A: ApprovalRepo, E: Platform> ListApprovals<A, E> {
    /// Pending, unexpired requests, newest first.
    pub async fn execute(&self, actor: &Actor) -> Result<Vec<PendingApproval>, AppError> {
        let now = self.env.now();
        Ok(self
            .approvals
            .pending_requests(actor.user, now)
            .await?
            .into_iter()
            .filter(|r| r.is_open(now))
            .map(|r| PendingApproval {
                phrase: phrase_for(&self.env, &r.public_key),
                public_key: r.public_key,
                id: r.id,
                device_name: r.device_name,
                device_kind: r.device_kind,
                ip: r.ip,
                created_at: r.created_at,
                expires_at: r.expires_at,
            })
            .collect())
    }
}

/// An open device's answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Answer {
    /// The root key sealed to the request's public key (an opaque `kx1` sealed box).
    Approve {
        sealed_key: Vec<u8>,
    },
    Deny,
}

/// An open device answers a request.
#[derive(Debug)]
pub struct AnswerApproval<A, E, V> {
    pub approvals: A,
    pub env: E,
    pub events: V,
}

impl<A: ApprovalRepo, E: Platform, V: EventLog> AnswerApproval<A, E, V> {
    /// Only a device of the account the request names can answer, and only once, before the
    /// request expires. A request of another account is `NotFound`.
    pub async fn execute(
        &self,
        actor: &Actor,
        id: ApprovalId,
        answer: Answer,
    ) -> Result<(), AppError> {
        let now = self.env.now();
        let mut request = self
            .approvals
            .request(id)
            .await?
            .filter(|r| r.user == actor.user)
            .ok_or(AppError::NotFound)?;
        let from = request.state;
        let action = match answer {
            Answer::Approve { sealed_key } => {
                if !sealed_key_len_ok(sealed_key.len()) {
                    return Err(AppError::Invalid("the sealed key has the wrong shape"));
                }
                request.approve(sealed_key, now).map_err(answer_error)?;
                "device.approval_approved"
            }
            Answer::Deny => {
                request.deny(now).map_err(answer_error)?;
                "device.approval_denied"
            }
        };
        if !self.approvals.save_request(&request, from).await? {
            return Err(AppError::Invalid("the request was already answered"));
        }
        let event = Event {
            actor: Some(actor.user),
            device: Some(actor.device),
            action,
            target: Some(id.to_string()),
            at: now,
        };
        if let Err(e) = self.events.record(event).await {
            tracing::warn!(action, error = %e, "couldn't record an event");
        }
        Ok(())
    }
}

/// What the new device learns when it polls.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Poll {
    /// No answer yet. `expires_at` is `None` for an id the server doesn't know or that isn't this
    /// device's: those poll as pending, so polling can't be used to probe for requests.
    Pending {
        expires_at: Option<OffsetDateTime>,
    },
    /// The root key sealed to the device's one-time public key, and the account it opens. The
    /// device needs the account id to rebuild the box's aad (docs/crypto.md, `"device-approval"`);
    /// it learns it only once someone has approved, so polling never reveals whether an email has
    /// an account.
    Approved {
        sealed_key: Vec<u8>,
        account: UserId,
    },
    Denied,
    Expired,
    /// The device already signed in with this answer.
    Used,
}

/// The new device polls for the answer.
#[derive(Debug)]
pub struct PollApproval<A, E> {
    pub approvals: A,
    pub env: E,
}

impl<A: ApprovalRepo, E: Platform> PollApproval<A, E> {
    /// `jkt` is the thumbprint of the DPoP key that signed the poll: only the key that made the
    /// request can read its answer.
    pub async fn execute(&self, id: ApprovalId, jkt: &str) -> Result<Poll, AppError> {
        let now = self.env.now();
        let Some(request) = self
            .approvals
            .request(id)
            .await?
            .filter(|r| same(&r.jkt, jkt))
        else {
            return Ok(Poll::Pending { expires_at: None });
        };
        Ok(match request.state {
            ApprovalState::Pending if request.is_expired(now) => Poll::Expired,
            ApprovalState::Pending => Poll::Pending {
                expires_at: Some(request.expires_at),
            },
            ApprovalState::Approved if request.is_expired(now) => Poll::Expired,
            ApprovalState::Approved => match request.sealed_key {
                Some(sealed_key) => Poll::Approved {
                    sealed_key,
                    account: request.user,
                },
                None => Poll::Expired,
            },
            ApprovalState::Denied => Poll::Denied,
            ApprovalState::Consumed => Poll::Used,
        })
    }
}

/// A job: deletes requests a day after they expired.
#[derive(Debug)]
pub struct PurgeApprovals<A, E> {
    pub approvals: A,
    pub env: E,
}

impl<A: ApprovalRepo, E: Platform> PurgeApprovals<A, E> {
    /// Returns how many requests went. Safe to run on every replica: it only deletes what has
    /// already expired.
    pub async fn execute(&self) -> Result<u64, AppError> {
        let before = self.env.now() - Duration::days(1);
        Ok(self.approvals.purge_requests(before).await?)
    }
}
