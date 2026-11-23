//! Everything that tells someone something: mail, live sync and push.
//!
//! - [`mail`]: SMTP with lettre behind a [`mail::Mailer`] port, a log-only mailer and the
//!   templates (approval request, new device, emergency access, invitation, two-step code).
//!   [`mail::MailOutbox`] turns the notices the use cases raise into mails.
//! - [`fanout`]: tells every replica's open sockets that an owner's vault changed (PostgreSQL
//!   `NOTIFY` with the owner id only, MySQL polling a small table each second, in process on
//!   SQLite).
//! - [`push`]: Kemlock's push relay, a hosted service that wakes the mobile apps. The server
//!   registers once, then sends "sync now" for the push tokens of an owner's devices. The relay's
//!   HTTP contract is `docs/push-relay.md`.
//! - [`bitwarden`]: what Bitwarden's apps use: the `/notifications/hub` WebSocket in SignalR
//!   (MessagePack and JSON), and Bitwarden's own push relay with an installation id and key.
//!
//! A change reaches people through [`Notify::nudge`]: every replica's sockets hear of it through
//! the fan-out, and this replica (the one that took the write) alone pushes to the phones.

pub mod audience;
pub mod bitwarden;
pub mod fanout;
pub mod mail;
pub mod push;

#[cfg(test)]
mod testing;

use kemlock_domain::Owner;

/// What a commit calls: nudges every replica's sockets, and wakes the owner's phones through the
/// push relay when the operator opted in. Cheap to clone.
#[derive(Clone, Debug)]
pub struct Notify {
    fanout: fanout::Fanout,
    push: Option<push::PushDispatcher>,
}

impl Notify {
    pub fn new(fanout: fanout::Fanout, push: Option<push::PushDispatcher>) -> Notify {
        Notify { fanout, push }
    }

    /// An owner's vault changed. Never waits.
    pub fn nudge(&self, owner: Owner) {
        self.fanout.nudge(owner);
        if let Some(push) = &self.push {
            push.nudge(owner);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audience::UserOnly;
    use crate::fanout::{Fanout, Sink};
    use crate::push::{PushDispatcher, RelayClient};
    use crate::testing::{MemoryPush, TaggedSeal};
    use kemlock_domain::UserId;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    #[tokio::test]
    async fn a_nudge_reaches_the_sink_and_queues_a_push() {
        let heard = Arc::new(Mutex::new(Vec::new()));
        let sink = {
            let heard = heard.clone();
            Sink::new(move |owner| heard.lock().expect("lock").push(owner), || {})
        };
        let client = RelayClient::new("http://127.0.0.1:9").expect("client");
        let dispatcher = PushDispatcher::start(
            MemoryPush::default(),
            UserOnly,
            TaggedSeal,
            client,
            Duration::from_millis(10),
        );
        let notify = Notify::new(Fanout::in_process(sink), Some(dispatcher));
        let owner = Owner::User(UserId::random());
        notify.clone().nudge(owner);
        assert_eq!(*heard.lock().expect("lock"), vec![owner]);
    }

    #[tokio::test]
    async fn without_push_a_nudge_is_just_the_fan_out() {
        let heard = Arc::new(Mutex::new(Vec::new()));
        let sink = {
            let heard = heard.clone();
            Sink::new(move |owner| heard.lock().expect("lock").push(owner), || {})
        };
        let notify = Notify::new(Fanout::in_process(sink), None);
        let owner = Owner::User(UserId::random());
        notify.nudge(owner);
        assert_eq!(*heard.lock().expect("lock"), vec![owner]);
    }
}
