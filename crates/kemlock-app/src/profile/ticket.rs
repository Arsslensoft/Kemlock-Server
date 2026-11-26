//! The ticket that ties an OPAQUE registration to what it is for.
//!
//! `credentials/start` answers the first message of a registration and hands out a ticket, sealed
//! under `server.key`, so the server keeps no state between the two messages. The ticket says who
//! asked, for which DPoP key, until when, which address the registration was for (none for a change
//! of password) and the SHA-256 of the credential identifier the server's half used. (A hash, so
//! that a ticket for an address that has an account and one for a free address are the same size
//! and say nothing of which is which.) The change that follows
//! (`PUT /account/password`, `POST /account/email`) must bring it back: a registration made for
//! one thing can't be spent on another, by another account, from another device or an hour later.

use super::ProfileError;
use crate::error::AppError;
use crate::ports::SecretSeal;
use kemlock_domain::UserId;
use subtle::ConstantTimeEq;
use time::OffsetDateTime;
use uuid::Uuid;

/// `SecretSeal` purpose of the ticket.
pub const PURPOSE_REGISTRATION: &str = "profile-registration";

/// What the ticket remembers.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Ticket {
    /// Unix seconds.
    pub(super) expires_at: i64,
    pub(super) user: UserId,
    /// The new address the registration was asked for, lower-cased; none for the account's own.
    pub(super) address: Option<String>,
    /// The SHA-256 of the credential identifier the OPRF was evaluated for: the address in force
    /// or the new one, or random bytes when the new address belongs to another account.
    pub(super) credential: [u8; 32],
    /// The thumbprint of the DPoP key that asked.
    pub(super) jkt: String,
}

const VERSION: u8 = 1;

fn put(out: &mut Vec<u8>, bytes: &[u8]) {
    // Values here are short (an address, a thumbprint), well inside u32.
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// The next length-prefixed value, and what follows it.
fn take(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    let (len, rest) = bytes.split_first_chunk::<4>()?;
    let len = usize::try_from(u32::from_be_bytes(*len)).ok()?;
    (rest.len() >= len).then(|| rest.split_at(len))
}

impl Ticket {
    fn encode(&self) -> Vec<u8> {
        let mut out = vec![VERSION];
        out.extend_from_slice(&self.expires_at.max(0).to_be_bytes());
        out.extend_from_slice(self.user.as_bytes());
        match &self.address {
            Some(address) => {
                out.push(1);
                put(&mut out, address.as_bytes());
            }
            None => out.push(0),
        }
        out.extend_from_slice(&self.credential);
        put(&mut out, self.jkt.as_bytes());
        out
    }

    fn decode(bytes: &[u8]) -> Option<Ticket> {
        let (&version, rest) = bytes.split_first()?;
        if version != VERSION {
            return None;
        }
        let (expires, rest) = rest.split_first_chunk::<8>()?;
        let (user, rest) = rest.split_first_chunk::<16>()?;
        let (&has_address, rest) = rest.split_first()?;
        let (address, rest) = match has_address {
            0 => (None, rest),
            1 => {
                let (address, rest) = take(rest)?;
                (Some(String::from_utf8(address.to_vec()).ok()?), rest)
            }
            _ => return None,
        };
        let (credential, rest) = rest.split_first_chunk::<32>()?;
        let (jkt, rest) = take(rest)?;
        let jkt = String::from_utf8(jkt.to_vec()).ok()?;
        rest.is_empty().then(|| Ticket {
            expires_at: i64::from_be_bytes(*expires),
            user: UserId(Uuid::from_bytes(*user)),
            address,
            credential: *credential,
            jkt,
        })
    }

    /// The sealed ticket, for the client to send back.
    pub(super) fn seal<S: SecretSeal>(&self, seal: &S) -> Vec<u8> {
        seal.seal(PURPOSE_REGISTRATION, &self.encode())
    }

    /// The ticket `sealed` holds, if it is genuine, unexpired, and was handed to `user` for the
    /// DPoP key `jkt`. Every failure is the same answer, so a bad ticket says nothing of why.
    pub(super) fn open<S: SecretSeal>(
        seal: &S,
        sealed: &[u8],
        now: OffsetDateTime,
        user: UserId,
        jkt: &str,
    ) -> Result<Ticket, ProfileError> {
        let bad = || ProfileError::from(AppError::Invalid("the registration ticket is not valid"));
        let plain = seal.open(PURPOSE_REGISTRATION, sealed).map_err(|_| bad())?;
        let ticket = Ticket::decode(&plain).ok_or_else(bad)?;
        let same_key = bool::from(ticket.jkt.as_bytes().ct_eq(jkt.as_bytes()));
        if now.unix_timestamp() >= ticket.expires_at || ticket.user != user || !same_key {
            return Err(bad());
        }
        Ok(ticket)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Ticket {
        Ticket {
            expires_at: 1_800_000_000,
            user: UserId(Uuid::from_u128(7)),
            address: Some("new@example.org".to_owned()),
            credential: [4; 32],
            jkt: "thumbprint".to_owned(),
        }
    }

    #[test]
    fn a_ticket_survives_its_encoding() {
        let with = sample();
        assert_eq!(Ticket::decode(&with.encode()), Some(with));
        let without = Ticket {
            address: None,
            ..sample()
        };
        assert_eq!(Ticket::decode(&without.encode()), Some(without));
    }

    #[test]
    fn a_ticket_cut_short_or_with_more_after_it_is_not_one() {
        let bytes = sample().encode();
        for cut in 0..bytes.len() {
            assert_eq!(Ticket::decode(&bytes[..cut]), None, "cut at {cut}");
        }
        let mut longer = bytes.clone();
        longer.push(0);
        assert_eq!(Ticket::decode(&longer), None);
        let mut other_version = bytes;
        other_version[0] = 2;
        assert_eq!(Ticket::decode(&other_version), None);
    }
}
