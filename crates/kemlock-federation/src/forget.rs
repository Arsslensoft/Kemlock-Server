//! Unpairing: asking the peer to delete what it holds.
//!
//! "Unpairing stops copying at once and asks the peer to delete what it holds. A peer run by
//! someone else can't be forced to, and the console says so." The server that unpairs signs a
//! notice, an envelope with `sig1("federation-forget", body)` by its identity key, and sends it
//! over a session ([`Request::Forget`]):
//!
//! | Key | Field |
//! | --- | --- |
//! | 0 | version `1` |
//! | 1 | from: the server that unpairs |
//! | 2 | to: the server asked to delete |
//! | 3 | issued at, Unix seconds |
//!
//! The receiver checks the signature against the key it pinned, that the notice is from the peer
//! that sent it and to this server, and that it is at most 5 minutes old. Then it deletes what it
//! holds because of that peer: the vaults the peer is the home of (their items, files, member
//! rows, federation rows) and the account copies it made, and the event log entries it sent. It
//! answers with what it says it deleted, and forgets the peer. Whether it really deleted is the
//! other operator's word: nothing here can force it.

use crate::cbor::Value;
use crate::error::{FedError, Result};
use crate::message::{Request, Response};
use crate::replicate::{Channel, FedStore, Replica};
use crate::session::unix_now;
use crate::signed::Signed;
use crate::wire::server_id;
use kemlock_app::ports::StoreError;
use kemlock_crypto::sig1;
use kemlock_domain::{BlobId, ServerId};
use std::future::{Future, ready};

type R<T> = std::result::Result<T, StoreError>;

/// The notice format version.
pub const VERSION: u64 = 1;
/// The `sig1` context of the notice.
pub const CONTEXT: &str = "federation-forget";
/// How old a notice may be, in seconds: the clock skew every check allows.
pub const MAX_AGE_SECS: u64 = 300;
/// What the console says before it unpairs, and after.
pub const CANT_FORCE: &str = "The other server was asked to delete what it holds of your vaults. \
A server run by someone else can't be forced to: if you need it gone, ask its operator.";

/// The signed request to delete.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForgetNotice {
    pub from: ServerId,
    pub to: ServerId,
    /// Unix seconds.
    pub issued_at: u64,
}

impl ForgetNotice {
    pub fn to_body(&self) -> Vec<u8> {
        Value::map(vec![
            (0, Value::Uint(VERSION)),
            (1, Value::bytes(self.from.as_bytes())),
            (2, Value::bytes(self.to.as_bytes())),
            (3, Value::Uint(self.issued_at)),
        ])
        .encode()
    }

    pub fn from_body(body: &[u8]) -> Result<ForgetNotice> {
        let value = Value::decode(body)?;
        let f = value.as_fields()?;
        f.only(&[0, 1, 2, 3])?;
        if f.uint(0)? != VERSION {
            return Err(FedError::Malformed("unknown notice version"));
        }
        Ok(ForgetNotice {
            from: server_id(f.fixed::<16>(1)?),
            to: server_id(f.fixed::<16>(2)?),
            issued_at: f.uint(3)?,
        })
    }

    /// Signs the notice with the identity key of `from`.
    pub fn sign(&self, key: &sig1::SigningKey) -> Result<Signed> {
        Signed::sign(key, CONTEXT, self.to_body())
    }
}

/// What a server deleted because of a peer.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Forgotten {
    /// Vaults (and the federation rows that went with them).
    pub vaults: u64,
    pub items: u64,
    /// Copies of accounts the peer's vaults had here.
    pub accounts: u64,
    /// Attachment files to delete from blob storage.
    pub blobs: Vec<BlobId>,
}

/// What federation needs from storage to delete what it holds because of a peer. The default does
/// nothing, so a store with nothing to delete needs only an empty `impl`.
pub trait Forgetting: Send + Sync {
    /// Deletes what this server holds because `peer` is the home of it: the vaults the peer homes
    /// (items, files' rows, member and federation rows), the account copies that came from it,
    /// and the offers it made. Never touches a vault this server is the home of.
    fn forget_peer(&self, _peer: ServerId) -> impl Future<Output = R<Forgotten>> + Send {
        ready(Ok(Forgotten::default()))
    }
}

/// What the peer said it deleted.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PeerReport {
    pub vaults: u64,
    pub items: u64,
    pub accounts: u64,
}

impl<S: FedStore> Replica<S> {
    /// Answers a notice from `peer`: deletes what it holds because of it, forgets it and says what
    /// went.
    pub(crate) async fn receive_forget(
        &self,
        peer: ServerId,
        notice: &[u8],
        now: u64,
    ) -> Result<Response> {
        let keys = self.peer_keys().await?;
        let key = keys.get(&peer).ok_or(FedError::UnknownPeer)?;
        let signed = Signed::decode(notice)?;
        signed.verify(key, CONTEXT)?;
        let n = ForgetNotice::from_body(&signed.body)?;
        if n.from != peer || n.to != self.server_id() {
            return Err(FedError::Refused(
                "the notice is not from this peer to this server",
            ));
        }
        if now.abs_diff(n.issued_at) > MAX_AGE_SECS {
            return Err(FedError::Expired("an unpairing notice"));
        }
        let gone = self.store.forget_peer(peer).await?;
        if let Some(files) = &self.files {
            for blob in &gone.blobs {
                // A file another row holds (a Send's) is not the peer's to have deleted.
                if self.blob_in_use(*blob).await? {
                    continue;
                }
                if let Err(e) = files.delete(*blob).await {
                    tracing::warn!(error = %e, "an attachment file of an unpaired peer was not deleted");
                }
            }
        }
        self.store.forget_peer_events(peer).await?;
        // The peer unpaired us: it is not a peer any more.
        self.store.remove_peer(peer).await?;
        tracing::info!(%peer, vaults = gone.vaults, items = gone.items, "an unpaired peer's data was deleted");
        Ok(Response::Forgotten {
            vaults: gone.vaults,
            items: gone.items,
            accounts: gone.accounts,
        })
    }

    /// Sends a signed notice to `peer` over `channel` and returns what it says it deleted.
    pub async fn ask_to_forget<C: Channel>(
        &self,
        channel: &mut C,
        peer: ServerId,
    ) -> Result<PeerReport> {
        let notice = ForgetNotice {
            from: self.server_id(),
            to: peer,
            issued_at: unix_now(),
        }
        .sign(&self.identity().signing)?
        .encode();
        match channel.call(&Request::Forget { notice }).await? {
            Response::Forgotten {
                vaults,
                items,
                accounts,
            } => Ok(PeerReport {
                vaults,
                items,
                accounts,
            }),
            Response::Error { detail, .. } => Err(FedError::Remote(detail)),
            _ => Err(FedError::Malformed(
                "an unexpected response to an unpairing",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::MemoryStore;
    use crate::ports::PeerRepo;
    use crate::suite::Suite;
    use crate::testing::identity;
    use std::sync::Arc;

    const NOW: u64 = 1_800_000_000;

    struct Direct<'a> {
        remote: &'a Replica<MemoryStore>,
        caller: ServerId,
        now: u64,
    }

    impl Channel for Direct<'_> {
        async fn call(&mut self, request: &Request) -> Result<Response> {
            Ok(self
                .remote
                .serve(self.caller, request, self.now)
                .await
                .response)
        }
    }

    async fn two() -> (Replica<MemoryStore>, Replica<MemoryStore>) {
        let ia = identity(1, NOW, &Suite::IMPLEMENTED);
        let ib = identity(2, NOW, &Suite::IMPLEMENTED);
        let a = Replica::new(MemoryStore::new(ia.server), Arc::new(ia.clone()));
        let b = Replica::new(MemoryStore::new(ib.server), Arc::new(ib.clone()));
        a.pin_peer(&ib.descriptor, NOW).await.expect("pin");
        b.pin_peer(&ia.descriptor, NOW).await.expect("pin");
        (a, b)
    }

    #[test]
    fn a_notice_round_trips_signed() {
        let n = ForgetNotice {
            from: ServerId::random(),
            to: ServerId::random(),
            issued_at: NOW,
        };
        assert_eq!(ForgetNotice::from_body(&n.to_body()), Ok(n.clone()));
        let key = sig1::SigningKey::from_bytes(&[3; 64]);
        let signed = n.sign(&key).expect("sign");
        let public = crate::crypto::sign_public(&key).expect("public");
        signed.verify(&public, CONTEXT).expect("verifies");
        assert!(signed.verify(&public, "federation-hello").is_err());
        let mut longer = n.to_body();
        longer.push(0);
        assert!(ForgetNotice::from_body(&longer).is_err());
    }

    #[tokio::test]
    async fn a_peer_asked_to_forget_forgets_the_asker() {
        let (a, b) = two().await;
        let mut channel = Direct {
            remote: &b,
            caller: a.server_id(),
            now: unix_now(),
        };
        let report = a
            .ask_to_forget(&mut channel, b.server_id())
            .await
            .expect("asked");
        assert_eq!(report, PeerReport::default());
        // B no longer has A as a peer; it would refuse a second ask.
        assert_eq!(b.store.get_peer(a.server_id()).await.expect("get"), None);
        assert!(a.ask_to_forget(&mut channel, b.server_id()).await.is_err());
    }

    #[tokio::test]
    async fn a_notice_that_is_not_for_this_server_or_is_old_or_forged_is_refused() {
        let (a, b) = two().await;
        let me = a.server_id();
        let sign = |n: &ForgetNotice, who: &Replica<MemoryStore>| {
            n.sign(&who.identity().signing).expect("sign").encode()
        };
        let good = ForgetNotice {
            from: me,
            to: b.server_id(),
            issued_at: unix_now(),
        };
        // Addressed to someone else.
        let elsewhere = ForgetNotice {
            to: ServerId::random(),
            ..good.clone()
        };
        // From someone else than the peer that sent it.
        let impersonated = ForgetNotice {
            from: ServerId::random(),
            ..good.clone()
        };
        // Old.
        let stale = ForgetNotice {
            issued_at: unix_now() - 3_600,
            ..good.clone()
        };
        for (n, why) in [(&elsewhere, "to"), (&impersonated, "from"), (&stale, "old")] {
            let notice = sign(n, &a);
            let served = b.serve(me, &Request::Forget { notice }, unix_now()).await;
            assert!(matches!(served.response, Response::Error { .. }), "{why}");
        }
        // Signed by another key than the one pinned for the peer.
        let other = identity(9, NOW, &Suite::IMPLEMENTED);
        let forged = good.sign(&other.signing).expect("sign").encode();
        let served = b
            .serve(me, &Request::Forget { notice: forged }, unix_now())
            .await;
        assert!(matches!(served.response, Response::Error { .. }));
        // A stranger can't ask at all.
        let notice = sign(&good, &a);
        let served = b
            .serve(ServerId::random(), &Request::Forget { notice }, unix_now())
            .await;
        assert!(matches!(served.response, Response::Error { .. }));
        // None of it unpaired anybody.
        assert!(b.store.get_peer(me).await.expect("get").is_some());
    }
}
