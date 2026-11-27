//! The event logs behind the two per-peer switches.
//!
//! Each server has two switches per peer, both off by default: "Send our logs" and "Pull their
//! logs". Logs flow from one server to another only when the sender's Send and the receiver's Pull
//! are both on ([`logs_flow`]). What flows is the event log of the federated vaults the two share:
//! the events whose actor is a member of the vault. The receiver asks only when its own Pull is on
//! (a [`Request::Events`] page after the id of the last event it holds from that peer), and the
//! sender answers only when its own Send for that peer is on; either switch off, nothing moves.
//! The receiver keeps what it got beside the vault, apart from its own log, for its admins.
//!
//! Event ids are UUID v7, so they sort by time and a page after an id is well defined.

use crate::cbor::{Fields, Value};
use crate::error::{FedError, Result};
use crate::message::{MAX_PAGE, Request, Response};
use crate::ports::logs_flow;
use crate::replicate::{Channel, FedStore, Replica};
use kemlock_app::ports::StoreError;
use kemlock_domain::{Owner, ServerId};
use std::future::{Future, ready};

type R<T> = std::result::Result<T, StoreError>;

/// The longest action a log entry carries.
pub const MAX_ACTION: usize = 64;
/// The longest target a log entry carries.
pub const MAX_TARGET: usize = 256;

/// One event of a server's log, as it travels to a peer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogEntry {
    /// A UUID v7.
    pub id: [u8; 16],
    /// Unix milliseconds.
    pub at_ms: u64,
    /// The account that did it, if any.
    pub actor: Option<[u8; 16]>,
    pub device: Option<[u8; 16]>,
    pub action: String,
    pub target: Option<String>,
}

impl LogEntry {
    pub(crate) fn to_value(&self) -> Value {
        let mut e = vec![
            (0, Value::bytes(&self.id)),
            (1, Value::Uint(self.at_ms)),
            (4, Value::text(&self.action)),
        ];
        if let Some(actor) = &self.actor {
            e.push((2, Value::bytes(actor)));
        }
        if let Some(device) = &self.device {
            e.push((3, Value::bytes(device)));
        }
        if let Some(target) = &self.target {
            e.push((5, Value::text(target)));
        }
        Value::map(e)
    }

    pub(crate) fn from_value(value: &Value) -> Result<LogEntry> {
        let f = value.as_fields()?;
        f.only(&[0, 1, 2, 3, 4, 5])?;
        let opt_id = |f: &Fields<'_>, key: u64| -> Result<Option<[u8; 16]>> {
            f.get(key)
                .map(|v| {
                    v.as_bytes().and_then(|b| {
                        <[u8; 16]>::try_from(b)
                            .map_err(|_| FedError::Malformed("an id has the wrong length"))
                    })
                })
                .transpose()
        };
        let action = f.text(4)?;
        let target = f
            .get(5)
            .map(|v| v.as_text().map(str::to_owned))
            .transpose()?;
        if action.len() > MAX_ACTION || target.as_ref().is_some_and(|t| t.len() > MAX_TARGET) {
            return Err(FedError::Malformed("a log entry is out of bounds"));
        }
        Ok(LogEntry {
            id: f.fixed::<16>(0)?,
            at_ms: f.uint(1)?,
            actor: opt_id(&f, 2)?,
            device: opt_id(&f, 3)?,
            action: action.to_owned(),
            target,
        })
    }
}

/// An event a peer sent, with who sent it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerEvent {
    pub from: ServerId,
    pub vault: Owner,
    pub entry: LogEntry,
}

/// What federation needs from storage to move event logs. Every method has a default body that
/// does nothing, so a store without an event log needs only an empty `impl`.
pub trait EventSync: Send + Sync {
    /// The events of `vault`'s members with an id after `after`, oldest first, at most `limit`.
    fn vault_events(
        &self,
        _vault: Owner,
        _after: [u8; 16],
        _limit: u32,
    ) -> impl Future<Output = R<Vec<LogEntry>>> + Send {
        ready(Ok(Vec::new()))
    }

    /// Keeps events received from `peer` for `vault`. Returns how many were new.
    fn store_peer_events(
        &self,
        _peer: ServerId,
        _vault: Owner,
        _events: &[LogEntry],
    ) -> impl Future<Output = R<usize>> + Send {
        ready(Ok(0))
    }

    /// The id of the newest event held from `peer` for `vault`; zeros before the first.
    fn peer_events_cursor(
        &self,
        _peer: ServerId,
        _vault: Owner,
    ) -> impl Future<Output = R<[u8; 16]>> + Send {
        ready(Ok([0; 16]))
    }

    /// The events held from peers for `vault`, newest first, at most `limit`.
    fn peer_events(
        &self,
        _vault: Owner,
        _limit: u32,
    ) -> impl Future<Output = R<Vec<PeerEvent>>> + Send {
        ready(Ok(Vec::new()))
    }

    /// Deletes everything held from `peer`. Returns how many events went.
    fn forget_peer_events(&self, _peer: ServerId) -> impl Future<Output = R<u64>> + Send {
        ready(Ok(0))
    }
}

impl<S: FedStore> Replica<S> {
    /// Answers a request for a page of events, if this server's Send switch for `peer` is on.
    pub(crate) async fn serve_events(
        &self,
        peer: ServerId,
        vault: Owner,
        after: [u8; 16],
        limit: u32,
    ) -> Result<Response> {
        let switches = self.store.log_switches(peer).await?;
        if !logs_flow(switches.send, true) {
            return Err(FedError::Refused("this server does not send its logs"));
        }
        let wanted = usize::try_from(limit.min(MAX_PAGE)).unwrap_or(usize::MAX);
        let mut events = self
            .store
            .vault_events(vault, after, limit.min(MAX_PAGE).saturating_add(1))
            .await?;
        let more = events.len() > wanted;
        events.truncate(wanted);
        Ok(Response::Events {
            vault,
            events,
            more,
        })
    }

    /// Pulls the events of `vault` that `peer` sends, page by page, if this server's Pull switch
    /// for `peer` is on; with it off nothing is asked. Returns how many events were new.
    pub async fn pull_events<C: Channel>(
        &self,
        channel: &mut C,
        peer: ServerId,
        vault: Owner,
    ) -> Result<usize> {
        self.authorize(peer, vault).await?;
        let switches = self.store.log_switches(peer).await?;
        if !logs_flow(true, switches.pull) {
            return Ok(0);
        }
        let mut stored = 0;
        for _ in 0..crate::message::MAX_PAGES_PER_VISIT {
            let after = self.store.peer_events_cursor(peer, vault).await?;
            let response = channel
                .call(&Request::Events {
                    vault,
                    after,
                    limit: MAX_PAGE,
                })
                .await?;
            let (events, more) = match response {
                Response::Events {
                    vault: v,
                    events,
                    more,
                } if v == vault => (events, more),
                Response::Error { detail, .. } => return Err(FedError::Remote(detail)),
                _ => return Err(FedError::Malformed("an unexpected response to events")),
            };
            if events.is_empty() {
                return Ok(stored);
            }
            let ascending = events.windows(2).all(|w| w[0].id < w[1].id);
            if !ascending || events.iter().any(|e| e.id <= after) {
                return Err(FedError::Invalid(
                    "the events are not in order after the cursor",
                ));
            }
            stored += self.store.store_peer_events(peer, vault, &events).await?;
            if !more {
                return Ok(stored);
            }
        }
        // The page limit of a visit: the rest comes at the next.
        Ok(stored)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::MemoryStore;
    use crate::ports::{LogSwitches, PeerRepo};
    use crate::suite::Suite;
    use crate::testing::identity;
    use kemlock_domain::UserId;
    use std::sync::Arc;

    const NOW: u64 = 1_800_000_000;

    fn entry(n: u8, action: &str) -> LogEntry {
        let mut id = [0u8; 16];
        id[0] = n;
        LogEntry {
            id,
            at_ms: 1_700_000_000_000 + u64::from(n),
            actor: Some([7; 16]),
            device: None,
            action: action.to_owned(),
            target: Some("item".to_owned()),
        }
    }

    #[test]
    fn an_entry_round_trips_and_bounds_hold() {
        let e = entry(1, "login");
        assert_eq!(LogEntry::from_value(&e.to_value()), Ok(e.clone()));
        let bare = LogEntry {
            actor: None,
            target: None,
            ..e.clone()
        };
        assert_eq!(LogEntry::from_value(&bare.to_value()), Ok(bare));
        let long = LogEntry {
            action: "x".repeat(MAX_ACTION + 1),
            ..e
        };
        assert!(LogEntry::from_value(&long.to_value()).is_err());
    }

    struct Direct<'a> {
        remote: &'a Replica<MemoryStore>,
        caller: ServerId,
        calls: usize,
    }

    impl Channel for Direct<'_> {
        async fn call(&mut self, request: &Request) -> Result<Response> {
            self.calls += 1;
            Ok(self.remote.serve(self.caller, request, NOW).await.response)
        }
    }

    struct Two {
        a: Replica<MemoryStore>,
        b: Replica<MemoryStore>,
        vault: Owner,
    }

    async fn two() -> Two {
        let ia = identity(1, NOW, &Suite::IMPLEMENTED);
        let ib = identity(2, NOW, &Suite::IMPLEMENTED);
        let a = Replica::new(MemoryStore::new(ia.server), Arc::new(ia.clone()));
        let b = Replica::new(MemoryStore::new(ib.server), Arc::new(ib.clone()));
        a.pin_peer(&ib.descriptor, NOW).await.expect("pin");
        b.pin_peer(&ia.descriptor, NOW).await.expect("pin");
        let vault = Owner::User(UserId::random());
        a.federate(vault, vec![ib.server]).await.expect("federate");
        b.accept_vault(vault, ia.server, vec![ib.server])
            .await
            .expect("accept");
        a.store.set_vault_events(
            vault,
            vec![
                entry(1, "login"),
                entry(2, "item.create"),
                entry(3, "logout"),
            ],
        );
        Two { a, b, vault }
    }

    async fn switches(t: &Two, a_sends: bool, b_pulls: bool) {
        t.a.store
            .set_log_switches(
                t.b.server_id(),
                LogSwitches {
                    send: a_sends,
                    pull: false,
                },
            )
            .await
            .expect("switches");
        t.b.store
            .set_log_switches(
                t.a.server_id(),
                LogSwitches {
                    send: false,
                    pull: b_pulls,
                },
            )
            .await
            .expect("switches");
    }

    #[tokio::test]
    async fn logs_flow_only_when_the_senders_send_and_the_receivers_pull_are_both_on() {
        for (a_sends, b_pulls) in [(false, false), (true, false), (false, true)] {
            let t = two().await;
            switches(&t, a_sends, b_pulls).await;
            let mut channel = Direct {
                remote: &t.a,
                caller: t.b.server_id(),
                calls: 0,
            };
            let pulled =
                t.b.pull_events(&mut channel, t.a.server_id(), t.vault)
                    .await;
            if b_pulls {
                // B asks, and A, whose Send is off, refuses.
                assert!(pulled.is_err(), "send off: {pulled:?}");
            } else {
                // B doesn't ask at all.
                assert_eq!(pulled, Ok(0));
                assert_eq!(channel.calls, 0, "pull off: nothing is requested");
            }
            assert!(
                t.b.store
                    .peer_events(t.vault, 100)
                    .await
                    .expect("events")
                    .is_empty(),
                "send {a_sends}, pull {b_pulls}"
            );
        }

        let t = two().await;
        switches(&t, true, true).await;
        let mut channel = Direct {
            remote: &t.a,
            caller: t.b.server_id(),
            calls: 0,
        };
        let pulled =
            t.b.pull_events(&mut channel, t.a.server_id(), t.vault)
                .await;
        assert_eq!(pulled, Ok(3));
        let held = t.b.store.peer_events(t.vault, 100).await.expect("events");
        assert_eq!(held.len(), 3);
        assert!(held.iter().all(|e| e.from == t.a.server_id()));
        // A second pull finds nothing new, and a new event follows.
        assert_eq!(
            t.b.pull_events(&mut channel, t.a.server_id(), t.vault)
                .await,
            Ok(0)
        );
        t.a.store.set_vault_events(
            t.vault,
            vec![
                entry(1, "login"),
                entry(2, "item.create"),
                entry(3, "logout"),
                entry(4, "login"),
            ],
        );
        assert_eq!(
            t.b.pull_events(&mut channel, t.a.server_id(), t.vault)
                .await,
            Ok(1)
        );
    }

    #[tokio::test]
    async fn a_peer_that_sends_events_out_of_order_is_refused() {
        let t = two().await;
        switches(&t, true, true).await;
        struct Shuffle<'a>(Direct<'a>);
        impl Channel for Shuffle<'_> {
            async fn call(&mut self, request: &Request) -> Result<Response> {
                let mut response = self.0.call(request).await?;
                if let Response::Events { events, .. } = &mut response {
                    events.reverse();
                }
                Ok(response)
            }
        }
        let mut channel = Shuffle(Direct {
            remote: &t.a,
            caller: t.b.server_id(),
            calls: 0,
        });
        assert!(
            t.b.pull_events(&mut channel, t.a.server_id(), t.vault)
                .await
                .is_err()
        );
        assert!(
            t.b.store
                .peer_events(t.vault, 100)
                .await
                .expect("events")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn a_peer_that_always_has_more_is_asked_for_a_bounded_number_of_pages() {
        let t = two().await;
        switches(&t, true, true).await;
        struct Endless {
            calls: usize,
        }
        impl Channel for Endless {
            async fn call(&mut self, request: &Request) -> Result<Response> {
                let Request::Events { vault, after, .. } = request else {
                    return Err(FedError::Malformed("not an events request"));
                };
                self.calls += 1;
                let mut last = [0u8; 8];
                last.copy_from_slice(&after[8..]);
                let next = u64::from_be_bytes(last) + 1;
                let mut id = [0u8; 16];
                id[8..].copy_from_slice(&next.to_be_bytes());
                Ok(Response::Events {
                    vault: *vault,
                    events: vec![LogEntry {
                        id,
                        at_ms: 1_700_000_000_000,
                        actor: None,
                        device: None,
                        action: "login".to_owned(),
                        target: None,
                    }],
                    more: true,
                })
            }
        }
        let mut channel = Endless { calls: 0 };
        let stored = t
            .b
            .pull_events(&mut channel, t.a.server_id(), t.vault)
            .await
            .expect("a bounded pull");
        assert_eq!(channel.calls, crate::message::MAX_PAGES_PER_VISIT);
        assert_eq!(stored, crate::message::MAX_PAGES_PER_VISIT);
    }
}
