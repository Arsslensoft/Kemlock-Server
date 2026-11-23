//! Two servers in one process: pair with a one-time code, open sessions in both directions,
//! replicate a federated vault's items both ways, make a conflict that produces siblings and
//! resolve it, and see a replayed frame and a tampered frame refused.

use kemlock_domain::{ItemId, Owner, Revision, UserId};
use kemlock_federation::memory::MemoryStore;
use kemlock_federation::message::{Request, Response};
use kemlock_federation::pairing::{self, PairingCode, PairingInitiator};
use kemlock_federation::ports::{ReplicaStore, VaultRepo};
use kemlock_federation::replicate::Channel;
use kemlock_federation::testing::{draft, draft_with, identity};
use kemlock_federation::{
    ErasureOutbox, FedError, NonceCache, Replica, SecureChannel, SessionServer, Suite, Transport,
    VaultErasure, unix_now,
};
use std::sync::{Arc, Mutex};

type Server = Arc<Replica<MemoryStore>>;

/// Carries every message to the other server in this process: the first is the hello, the rest
/// are sealed frames. It keeps what crossed the wire and can alter the next frame.
struct Wire {
    remote: Server,
    cache: NonceCache,
    session: Option<SessionServer<MemoryStore>>,
    seen: Arc<Mutex<Vec<Vec<u8>>>>,
    tamper: Arc<Mutex<bool>>,
}

impl Transport for Wire {
    async fn exchange(&mut self, mut message: Vec<u8>) -> Result<Vec<u8>, FedError> {
        let now = unix_now();
        if self.session.is_none() {
            let (reply, session) = self.remote.accept(&mut self.cache, &message, now).await?;
            self.session = Some(SessionServer::new(self.remote.clone(), session));
            return Ok(reply);
        }
        if std::mem::take(&mut *self.tamper.lock().expect("tamper switch")) {
            let last = message.len() - 1;
            message[last] ^= 1;
        }
        self.seen.lock().expect("wire log").push(message.clone());
        match self.session.as_mut() {
            Some(session) => Ok(session.on_frame(&message, now).await?.reply),
            None => Err(FedError::Frame("no session")),
        }
    }
}

struct Link {
    channel: SecureChannel<Wire>,
    seen: Arc<Mutex<Vec<Vec<u8>>>>,
    tamper: Arc<Mutex<bool>>,
}

/// Opens a session from `from` to `to`.
async fn connect(from: &Server, to: &Server) -> Link {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let tamper = Arc::new(Mutex::new(false));
    let wire = Wire {
        remote: to.clone(),
        cache: NonceCache::new(),
        session: None,
        seen: seen.clone(),
        tamper: tamper.clone(),
    };
    let channel = from
        .connect(to.server_id(), &to.identity().descriptor, wire, unix_now())
        .await
        .expect("the handshake succeeds between paired servers");
    Link {
        channel,
        seen,
        tamper,
    }
}

fn server(seed: u8) -> Server {
    let id = identity(seed, unix_now(), &Suite::IMPLEMENTED);
    Arc::new(Replica::new(MemoryStore::new(id.server), Arc::new(id)))
}

/// Pairs two servers with a one-time code, as two admins would.
async fn pair(a: &Server, b: &Server) {
    let now = unix_now();
    let shown = PairingCode::generate();
    let typed = PairingCode::parse(&shown.display()).expect("the code reads back");
    let (initiator, first) = PairingInitiator::start(&typed, &b.identity()).expect("start");
    let (pending, second) = pairing::respond(shown, &a.identity(), &first).expect("respond");
    let (paired_b, third) = initiator
        .finish(&second, now)
        .expect("the code opens message 2");
    let paired_a = pending
        .finish(&third, now)
        .expect("the code opens message 3");
    assert_eq!(
        paired_a.fingerprint, paired_b.fingerprint,
        "both admins see the same six words"
    );
    a.pin_peer(&paired_a.descriptor, now)
        .await
        .expect("A pins B");
    b.pin_peer(&paired_b.descriptor, now)
        .await
        .expect("B pins A");
}

#[tokio::test]
async fn two_servers_replicate_a_vault_both_ways_and_refuse_a_replay_and_a_tampered_frame() {
    let a = server(1);
    let b = server(2);
    pair(&a, &b).await;

    let vault = Owner::User(UserId::random());
    a.federate(vault, vec![b.server_id()])
        .await
        .expect("federate");
    b.accept_vault(vault, a.server_id(), vec![b.server_id()])
        .await
        .expect("accept");

    // A's items reach B.
    let first = ItemId::random();
    let second = ItemId::random();
    a.store()
        .put(draft(first, vault, None, 1, 1_000))
        .expect("put");
    a.store()
        .put(draft(second, vault, None, 1, 1_100))
        .expect("put");
    let mut b_to_a = connect(&b, &a).await;
    let report = b
        .pull(&mut b_to_a.channel, a.server_id(), vault)
        .await
        .expect("B pulls from A");
    assert_eq!(report.counts.applied, 2);
    assert_eq!(b.store().len(), 2);

    // B's own item reaches A, over a session A opens.
    let third = ItemId::random();
    b.store()
        .put(draft(third, vault, None, 1, 1_200))
        .expect("put");
    let mut a_to_b = connect(&a, &b).await;
    let report = a
        .pull(&mut a_to_b.channel, b.server_id(), vault)
        .await
        .expect("A pulls from B");
    assert_eq!(report.counts.applied, 1);
    assert_eq!(a.store().len(), 3);

    // Both now hold the same versions: the summaries match.
    let in_step = b
        .reconcile(&mut b_to_a.channel, a.server_id(), vault)
        .await
        .expect("reconcile");
    assert!(in_step.in_step);

    // A replayed frame is refused by the session, and nothing changes.
    let recorded = b_to_a.seen.lock().expect("wire log")[0].clone();
    assert!(
        b_to_a
            .channel
            .transport_mut()
            .exchange(recorded)
            .await
            .is_err(),
        "a recorded frame played again must fail"
    );

    // A tampered frame is refused, and the pull it carried applies nothing.
    let fourth = ItemId::random();
    a.store()
        .put(draft(fourth, vault, None, 1, 1_300))
        .expect("put");
    let mut tampered = connect(&b, &a).await;
    *tampered.tamper.lock().expect("tamper switch") = true;
    assert!(
        b.pull(&mut tampered.channel, a.server_id(), vault)
            .await
            .is_err(),
        "a changed frame must fail"
    );
    assert!(b.store().get(fourth).is_none());
    // A fresh session still works: the attack didn't break the pairing.
    let mut again = connect(&b, &a).await;
    let report = b
        .pull(&mut again.channel, a.server_id(), vault)
        .await
        .expect("pull");
    assert_eq!(report.counts.applied, 1);

    // The sessions close cleanly.
    again.channel.close().await.expect("close");
    b_to_a.channel.close().await.ok();
}

#[tokio::test]
async fn a_conflict_makes_siblings_on_both_servers_and_a_merge_resolves_it() {
    let a = server(3);
    let b = server(4);
    pair(&a, &b).await;
    let vault = Owner::User(UserId::random());
    a.federate(vault, vec![b.server_id()])
        .await
        .expect("federate");
    b.accept_vault(vault, a.server_id(), vec![b.server_id()])
        .await
        .expect("accept");

    // One item, in step on both.
    let item = ItemId::random();
    a.store()
        .put(draft(item, vault, None, 1, 1_000))
        .expect("put");
    let mut to_a = connect(&b, &a).await;
    b.pull(&mut to_a.channel, a.server_id(), vault)
        .await
        .expect("pull");

    // Cut off from each other, both servers accept an edit to it.
    a.store()
        .put(draft_with(item, vault, Some(1), 2, 2_000, 0xA))
        .expect("A's edit");
    b.store()
        .put(draft_with(item, vault, Some(1), 2, 3_000, 0xB))
        .expect("B's edit");

    // They reconnect and pull each other's changes.
    let report = b
        .pull(&mut to_a.channel, a.server_id(), vault)
        .await
        .expect("B pulls A's edit");
    assert_eq!(report.counts.siblings, 1, "B keeps both versions");
    let mut to_b = connect(&a, &b).await;
    let report = a
        .pull(&mut to_b.channel, b.server_id(), vault)
        .await
        .expect("A pulls B's edit");
    // B's later edit takes over as head at A, and A's own edit stays as the sibling.
    assert_eq!(report.counts.applied, 1);

    // Both agree: the later clock is the head, the other edit is a sibling.
    let head_a = a.store().get(item).expect("head at A");
    let head_b = b.store().get(item).expect("head at B");
    assert_eq!(head_a.change, head_b.change);
    assert_eq!(head_a.ciphertext, Some(vec![0xB; 40]));
    let sibling_a = a
        .store()
        .siblings(vault, item)
        .await
        .expect("siblings at A");
    let sibling_b = b
        .store()
        .siblings(vault, item)
        .await
        .expect("siblings at B");
    assert_eq!(sibling_a.len(), 1);
    assert_eq!(sibling_b.len(), 1);
    assert_eq!(sibling_a[0].change, sibling_b[0].change);
    assert_eq!(sibling_a[0].ciphertext, Some(vec![0xA; 40]));

    // A device merges the two and writes a version that supersedes both. It lands on B, which
    // marks the siblings replaced, and then A picks it up.
    b.store()
        .put(draft_with(item, vault, Some(2), 3, 4_000, 0xC))
        .expect("the merged write");
    let resolved = b
        .store()
        .resolve_siblings(vault, item)
        .await
        .expect("resolve");
    assert_eq!(resolved, 1);
    let report = a
        .pull(&mut to_b.channel, b.server_id(), vault)
        .await
        .expect("A pulls the merge");
    assert_eq!(report.counts.applied, 1);
    assert!(
        a.store()
            .siblings(vault, item)
            .await
            .expect("siblings")
            .is_empty()
    );
    let merged = a.store().get(item).expect("head");
    assert_eq!(merged.revision, Revision(3));
    assert_eq!(merged.ciphertext, Some(vec![0xC; 40]));

    // A sibling that was resolved never comes back from a server that still has it.
    let mut again = connect(&b, &a).await;
    let report = b
        .pull(&mut again.channel, a.server_id(), vault)
        .await
        .expect("pull");
    assert_eq!(report.counts.siblings, 0);
    assert!(
        b.store()
            .siblings(vault, item)
            .await
            .expect("siblings")
            .is_empty()
    );
}

#[tokio::test]
async fn a_vault_that_is_not_federated_never_leaves_and_a_stranger_cannot_connect() {
    let a = server(5);
    let b = server(6);
    pair(&a, &b).await;
    let local = Owner::User(UserId::random());
    a.store()
        .put(draft(ItemId::random(), local, None, 1, 1_000))
        .expect("put");
    let mut link = connect(&b, &a).await;
    let answer = link
        .channel
        .call(&Request::Pull {
            vault: local,
            since: kemlock_domain::VersionVector::new(),
            limit: 10,
        })
        .await
        .expect("the server answers");
    assert!(matches!(answer, Response::Error { .. }), "{answer:?}");
    assert!(
        b.pull(&mut link.channel, a.server_id(), local)
            .await
            .is_err()
    );
    assert_eq!(b.store().len(), 0);

    // A server A never paired with can read A's public descriptor and pin it, but A refuses it.
    let stranger = server(7);
    stranger
        .pin_peer(&a.identity().descriptor, unix_now())
        .await
        .expect("pin");
    let wire = Wire {
        remote: a.clone(),
        cache: NonceCache::new(),
        session: None,
        seen: Arc::new(Mutex::new(Vec::new())),
        tamper: Arc::new(Mutex::new(false)),
    };
    let result = stranger
        .connect(a.server_id(), &a.identity().descriptor, wire, unix_now())
        .await;
    assert!(matches!(result, Err(FedError::UnknownPeer)));
}

#[tokio::test]
async fn an_erasure_at_the_home_reaches_the_replicas_copy_and_only_the_home_may_ask() {
    let a = server(8);
    let b = server(9);
    pair(&a, &b).await;
    let vault = Owner::User(UserId::random());
    a.federate(vault, vec![b.server_id()])
        .await
        .expect("federate");
    b.accept_vault(vault, a.server_id(), vec![b.server_id()])
        .await
        .expect("accept");
    for n in 0..3 {
        a.store()
            .put(draft(ItemId::random(), vault, None, 1, 1_000 + n))
            .expect("put");
    }
    let mut b_to_a = connect(&b, &a).await;
    b.pull(&mut b_to_a.channel, a.server_id(), vault)
        .await
        .expect("B pulls from A");
    assert_eq!(b.store().len(), 3);

    // The replica may not erase its home's vault: only the home may ask.
    let refused = b_to_a
        .channel
        .call(&Request::Erase { vault })
        .await
        .expect("A answers");
    assert!(matches!(refused, Response::Error { .. }), "{refused:?}");
    assert_eq!(a.store().len(), 3, "A still holds its vault");

    // A erases the vault: its store deletes it, queues the erasure for B and forgets the vault's
    // settings. The replication job sends it in the next session.
    a.store().erase_vault(vault).await.expect("A erases");
    a.store().queue_erasure(b.server_id(), vault, unix_now());
    assert_eq!(a.store().len(), 0);
    assert_eq!(
        a.store()
            .pending_erasures(b.server_id())
            .await
            .expect("pending")
            .len(),
        1
    );
    let mut a_to_b = connect(&a, &b).await;
    let sent = a
        .forward_erasures(&mut a_to_b.channel, b.server_id())
        .await
        .expect("A tells B");
    assert_eq!(sent, 1);

    assert_eq!(b.store().len(), 0, "B's copy is gone");
    assert_eq!(b.store().get_vault(vault).await, Ok(None));
    assert!(
        a.store()
            .pending_erasures(b.server_id())
            .await
            .expect("pending")
            .is_empty(),
        "an acknowledged erasure is done"
    );
    // Told again (a lost acknowledgement), B acknowledges: it holds nothing.
    let again = a_to_b
        .channel
        .call(&Request::Erase { vault })
        .await
        .expect("B answers");
    assert_eq!(again, Response::Ack);
}

#[tokio::test]
async fn an_erasure_from_a_server_that_is_not_the_home_is_refused_and_stays_queued() {
    let a = server(10);
    let b = server(11);
    let c = server(12);
    pair(&b, &c).await;
    pair(&a, &c).await;
    // The vault's home is B and C holds a copy; A is paired with C but has nothing to do with it.
    let vault = Owner::User(UserId::random());
    b.federate(vault, vec![c.server_id()])
        .await
        .expect("federate");
    c.accept_vault(vault, b.server_id(), vec![c.server_id()])
        .await
        .expect("accept");
    c.store()
        .put(draft(ItemId::random(), vault, None, 1, 1_000))
        .expect("put");

    a.store().queue_erasure(c.server_id(), vault, unix_now());
    let mut a_to_c = connect(&a, &c).await;
    let sent = a
        .forward_erasures(&mut a_to_c.channel, c.server_id())
        .await
        .expect("the session itself works");

    assert_eq!(sent, 0, "C refuses: A is not the vault's home");
    assert_eq!(c.store().len(), 1, "C still holds its copy");
    assert_eq!(
        a.store()
            .pending_erasures(c.server_id())
            .await
            .expect("pending")
            .len(),
        1,
        "left queued for the next session"
    );
}
