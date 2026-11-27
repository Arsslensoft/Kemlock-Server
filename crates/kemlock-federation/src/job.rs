//! The replication job: one session per paired peer, under a lease, that brings this server's
//! copy of every vault it shares with the peer up to date.
//!
//! One run of [`PeerRunner::run_peer`] for a peer:
//!
//! 1. takes the lease `fed-peer-<peer id>`, so of several processes sharing one database only one
//!    talks to that peer at a time;
//! 2. opens a session through the [`Connector`] (the WebSocket client in [`crate::net`], or an
//!    in-process one in tests);
//! 3. for each federated vault both servers hold: as the home, offers it to a replica that hasn't
//!    answered yet and publishes the members' account records; then pulls the peer's changes
//!    since the cursor, pulls its home records (applying members under the epoch fence), copies
//!    attachments, compares hash trees (hourly, and the first time after the peer was away), and
//!    nudges the peer when this server has changes it hasn't been told of;
//! 4. announces to the peer any promotion this server made, and tells it of the vaults this server
//!    erased that it holds a copy of ([`Replica::forward_erasures`]);
//! 5. ends the session and gives the lease back.
//!
//! [`PeerRunner::run`] ticks every few seconds and starts a run for a peer when there is a reason:
//! never run, a local change to tell it of, a nudge from it, the last run failed (retried with a
//! growing delay), or a few minutes passed. Nothing here is needed for correctness: a peer that
//! is down just misses its turn, and the hash-tree comparison finds anything a missed nudge left.

use crate::error::{FedError, Result};
use crate::extra::Leases;
use crate::health::{HealthConfig, HealthStatus, PeerHealth, random_bits};
use crate::home::{Policy, VaultFederation};
use crate::message::OfferState;
use crate::ports::{Peer, PeerState};
use crate::replicate::{Channel, Counts, FedStore, Replica};
use crate::session::unix_now;
use kemlock_domain::{Owner, ServerId, VersionVector};
use std::collections::{HashMap, HashSet};
use std::future::{Future, ready};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

/// How long a lease on a peer lasts: well beyond one run, and a crashed holder only blocks that
/// long.
pub const LEASE_SECS: u64 = 5 * 60;
/// The longest one run for one peer may take once it is connected. A peer that answers slowly, or
/// keeps saying there is more, is cut off here, so it holds its own lease for no longer than it
/// lasts; what was left is taken at the next run, and the run still counts as a success: it ends
/// with what it did and a note on the vaults it didn't reach. A third of it is kept for moving
/// files, which come last.
pub const VISIT_DEADLINE: Duration = Duration::from_secs(4 * 60);
const _: () = assert!(VISIT_DEADLINE.as_secs() < LEASE_SECS);
/// The hash trees of a vault are compared this often.
pub const RECONCILE_EVERY_SECS: u64 = 60 * 60;
/// A peer is visited at least this often, whether or not anything changed.
pub const VISIT_EVERY_SECS: u64 = 5 * 60;
/// How often the loop looks for a peer that is due.
pub const TICK: Duration = Duration::from_secs(5);
/// After a failed run, the peer is left alone for 15 seconds, doubling to a ceiling of 5 minutes.
const RETRY_FIRST_SECS: u64 = 15;
const RETRY_CEILING_SECS: u64 = 5 * 60;

/// Opens sessions to peers.
pub trait Connector: Send + Sync {
    type Chan: Channel;

    /// Opens a session to `peer`: finds a reachable address, checks its descriptor against the
    /// pinned key and runs the handshake.
    fn connect(&self, peer: &Peer) -> impl Future<Output = Result<Self::Chan>> + Send;

    /// Ends a session cleanly.
    fn close(&self, channel: Self::Chan) -> impl Future<Output = Result<()>> + Send;

    /// Asks whether `peer` answers, and is the peer: an error says why not. The default opens a
    /// session and closes it; a transport with something cheaper (the signed descriptor over
    /// HTTP) overrides it.
    fn probe(&self, peer: &Peer) -> impl Future<Output = Result<()>> + Send {
        async move {
            let channel = self.connect(peer).await?;
            self.close(channel).await
        }
    }

    /// Delivers a signed key record (a rotation or a revocation of an identity key) to `peer` over
    /// plain HTTP: after a rotation the peer can't open a session until it has the record. The
    /// default can't deliver.
    fn send_key_record(
        &self,
        _peer: &Peer,
        _record: Vec<u8>,
    ) -> impl Future<Output = Result<()>> + Send {
        ready(Err(FedError::Remote(
            "this connector can't deliver key records".to_owned(),
        )))
    }
}

/// Where one vault stands with one peer after a run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultStatus {
    pub vault: Owner,
    /// Unix seconds of the run.
    pub at: u64,
    /// What the peer said of our offer, when this server is the home and the peer a replica.
    pub offer: Option<OfferState>,
    /// What pulling the items did.
    pub pulled: Counts,
    /// Home records applied and quarantined.
    pub home_applied: usize,
    pub home_quarantined: usize,
    /// A promotion was missed: the peer's home records are of a newer epoch than ours.
    pub behind: bool,
    /// Files copied and files left for their first use.
    pub files_fetched: usize,
    pub files_deferred: usize,
    /// Sends copied or brought up to date.
    pub sends_copied: usize,
    /// Event log entries taken from the peer, when both switches are on.
    pub events_pulled: usize,
    /// Items that got duplicate tags from the peer, where server matching is on.
    pub tags_pulled: usize,
    /// Hash trees were compared this run, and matched.
    pub in_step: Option<bool>,
    /// Why the vault wasn't (fully) synced, if it wasn't.
    pub note: Option<String>,
}

impl VaultStatus {
    fn new(vault: Owner, at: u64) -> VaultStatus {
        VaultStatus {
            vault,
            at,
            offer: None,
            pulled: Counts::default(),
            home_applied: 0,
            home_quarantined: 0,
            behind: false,
            files_fetched: 0,
            files_deferred: 0,
            sends_copied: 0,
            events_pulled: 0,
            tags_pulled: 0,
            in_step: None,
            note: None,
        }
    }
}

/// What the console shows of a peer.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PeerStatus {
    pub last_attempt: Option<u64>,
    pub last_success: Option<u64>,
    /// Since when the peer has been unreachable, if it is.
    pub down_since: Option<u64>,
    pub last_error: Option<String>,
    /// The identity key the peer offered when it wasn't the pinned one: "Possible man in the
    /// middle".
    pub key_mismatch: Option<Vec<u8>>,
    pub consecutive_failures: u32,
    pub vaults: Vec<VaultStatus>,
}

/// The result of one run for a peer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RunOutcome {
    /// Another process holds the lease on this peer.
    Leased,
    /// The peer isn't paired (any more).
    NotPaired,
    /// The run completed (individual vaults may carry a note).
    Done(Vec<VaultStatus>),
}

/// What a run's vault is at, while the phases of a visit go through the vaults.
struct VaultRun {
    vault: VaultFederation,
    status: VaultStatus,
    /// False once the vault's work was stopped: not accepted yet, a missed promotion, a failure.
    active: bool,
    /// Records the pull left out for now.
    pull_retry: usize,
    /// The comparison found items this server holds that the peer lacks: it is nudged to pull.
    push: bool,
}

/// The note on a vault a visit didn't reach before its time ran out.
const CUT_SHORT_NOTE: &str = "the visit's time ran out: the rest comes at the next visit";

/// A peer's run is in progress while this is held.
struct RunningGuard<'a> {
    state: &'a Mutex<RunnerState>,
    peer: ServerId,
}

impl<'a> RunningGuard<'a> {
    fn take(state: &'a Mutex<RunnerState>, peer: ServerId) -> Option<RunningGuard<'a>> {
        let mut held = state.lock().unwrap_or_else(PoisonError::into_inner);
        held.running
            .insert(peer)
            .then_some(RunningGuard { state, peer })
    }
}

impl Drop for RunningGuard<'_> {
    fn drop(&mut self) {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .running
            .remove(&self.peer);
    }
}

#[derive(Debug, Default)]
struct RunnerState {
    peers: HashMap<ServerId, PeerStatus>,
    /// When each vault was last compared by hash tree with each peer, Unix seconds.
    reconciled: HashMap<(ServerId, Owner), u64>,
    /// The vector this server last told each peer it holds, per vault.
    told: HashMap<(ServerId, Owner), VersionVector>,
    /// Promotions already announced: (peer, vault, epoch).
    announced: HashSet<(ServerId, Owner, u64)>,
    /// Peers that nudged us since the last run.
    dirty: HashSet<ServerId>,
    /// Key records already delivered: (peer, the server the record is about, kind, issued at).
    told_keys: HashSet<(ServerId, ServerId, String, u64)>,
    /// What the probes and visits found of each peer.
    health: HashMap<ServerId, PeerHealth>,
    /// Peers a run is in progress for in this process: a peer never runs twice at once.
    running: HashSet<ServerId>,
    /// How many visits each peer has had, to rotate which vault goes first.
    turns: HashMap<ServerId, usize>,
}

/// Runs replication for every paired peer.
pub struct PeerRunner<S, C> {
    replica: Arc<Replica<S>>,
    connector: C,
    holder: String,
    state: Mutex<RunnerState>,
    health_config: HealthConfig,
    visit_deadline: Duration,
}

impl<S, C> std::fmt::Debug for PeerRunner<S, C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerRunner").finish_non_exhaustive()
    }
}

/// The lease name for a peer.
pub fn lease_name(peer: ServerId) -> String {
    format!("fed-peer-{peer}")
}

fn is_unknown_vault(e: &FedError) -> bool {
    matches!(e, FedError::Remote(detail) if detail == "unknown vault")
        || matches!(e, FedError::UnknownVault)
}

impl<S: FedStore + Leases, C: Connector> PeerRunner<S, C> {
    /// `holder` names this process in the leases; it must differ between processes.
    pub fn new(replica: Arc<Replica<S>>, connector: C, holder: String) -> PeerRunner<S, C> {
        PeerRunner {
            replica,
            connector,
            holder,
            state: Mutex::new(RunnerState::default()),
            health_config: HealthConfig::default(),
            visit_deadline: VISIT_DEADLINE,
        }
    }

    /// Sets how long one run for one peer may take (the default is [`VISIT_DEADLINE`]).
    pub fn with_visit_deadline(mut self, deadline: Duration) -> PeerRunner<S, C> {
        self.visit_deadline = deadline;
        self
    }

    /// Sets how the peers are probed (the default is [`HealthConfig::default`]).
    pub fn with_health(mut self, config: HealthConfig) -> PeerRunner<S, C> {
        self.health_config = config;
        self
    }

    pub fn health_config(&self) -> &HealthConfig {
        &self.health_config
    }

    /// What the probes and visits found of each peer so far.
    pub fn health(&self) -> HashMap<ServerId, PeerHealth> {
        self.state().health.clone()
    }

    pub fn health_of(&self, peer: ServerId) -> Option<PeerHealth> {
        self.state().health.get(&peer).cloned()
    }

    /// Whether `peer` answers, at `now`: `Unknown` for a peer nothing has been tried with.
    pub fn health_status(&self, peer: ServerId, now: u64) -> HealthStatus {
        self.state()
            .health
            .get(&peer)
            .map_or(HealthStatus::Unknown, |h| {
                h.status(now, &self.health_config)
            })
    }

    /// Probes `peer` now: one call with a timeout, recorded in its health. Returns whether it
    /// answered. A peer that isn't paired is not probed.
    pub async fn probe_peer(&self, peer: ServerId, now: u64) -> Option<bool> {
        let stored = self
            .replica
            .store()
            .get_peer(peer)
            .await
            .ok()
            .flatten()
            .filter(|p| p.state == PeerState::Paired)?;
        let started = Instant::now();
        let result =
            match tokio::time::timeout(self.health_config.timeout(), self.connector.probe(&stored))
                .await
            {
                Ok(result) => result,
                Err(_) => Err(FedError::Remote(
                    "the peer did not answer in time".to_owned(),
                )),
            };
        let latency = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let answered = result.is_ok();
        let mut state = self.state();
        let health = state.health.entry(peer).or_default();
        match result {
            Ok(()) => health.record_answer(now, Some(latency)),
            Err(e @ FedError::KeyMismatch { .. }) => health.record_key_mismatch(now, e.to_string()),
            Err(e) => health.record_failure(now, e.to_string()),
        }
        health.schedule(now, &self.health_config, random_bits());
        Some(answered)
    }

    /// Probes every paired peer whose probe is due. Returns the peers probed and whether each
    /// answered. Does nothing when the probes are off.
    pub async fn probe_tick(&self, now: u64) -> Vec<(ServerId, bool)> {
        if !self.health_config.enabled() {
            return Vec::new();
        }
        let peers = match self.replica.store().list_peers().await {
            Ok(peers) => peers,
            Err(e) => {
                tracing::warn!(error = %e, "couldn't list the federation peers to probe");
                return Vec::new();
            }
        };
        let mut out = Vec::new();
        for peer in peers.into_iter().filter(|p| p.state == PeerState::Paired) {
            let due = self.state().health.get(&peer.id).is_none_or(|h| h.due(now));
            if due && let Some(answered) = self.probe_peer(peer.id, now).await {
                out.push((peer.id, answered));
            }
        }
        out
    }

    /// Probes the peers that are due, every few seconds, until the task is dropped or aborted.
    pub async fn run_probes(self: Arc<Self>)
    where
        S: 'static,
        C: 'static,
    {
        if !self.health_config.enabled() {
            return;
        }
        let mut every = tokio::time::interval(TICK);
        every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            every.tick().await;
            for (peer, answered) in self.probe_tick(unix_now()).await {
                if !answered {
                    tracing::info!(%peer, "a peer did not answer its probe");
                }
            }
        }
    }

    pub fn replica(&self) -> &Arc<Replica<S>> {
        &self.replica
    }

    /// The connector sessions are opened with.
    pub fn connector(&self) -> &C {
        &self.connector
    }

    fn state(&self) -> MutexGuard<'_, RunnerState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// What the console shows for each peer that has been visited.
    pub fn status(&self) -> HashMap<ServerId, PeerStatus> {
        self.state().peers.clone()
    }

    pub fn status_of(&self, peer: ServerId) -> Option<PeerStatus> {
        self.state().peers.get(&peer).cloned()
    }

    /// Asks for the hash trees of `vault` to be compared with `peer` at the next visit, and for
    /// that visit to come soon: what a resume needs, to offer the withheld versions again.
    pub fn reconcile_soon(&self, peer: ServerId, vault: Owner) {
        let mut state = self.state();
        state.reconciled.remove(&(peer, vault));
        state.dirty.insert(peer);
    }

    /// A peer showed it has more of a vault: visit it soon.
    pub fn mark_dirty(&self, peer: ServerId) {
        self.state().dirty.insert(peer);
    }

    /// Forgets what is known of a peer (after it is removed).
    pub fn forget(&self, peer: ServerId) {
        let mut state = self.state();
        state.peers.remove(&peer);
        state.dirty.remove(&peer);
        state.reconciled.retain(|(p, _), _| *p != peer);
        state.told_keys.retain(|(p, _, _, _)| *p != peer);
        state.told.retain(|(p, _), _| *p != peer);
        state.health.remove(&peer);
        state.announced.retain(|(p, _, _)| *p != peer);
        state.turns.remove(&peer);
    }

    /// The vaults this server and `peer` both hold as a federated set.
    async fn shared_vaults(&self, peer: ServerId) -> Result<Vec<VaultFederation>> {
        let me = self.replica.server_id();
        Ok(self
            .replica
            .store()
            .list_vaults()
            .await?
            .into_iter()
            .filter(|v| v.policy == Policy::Federated && v.holds(me) && v.holds(peer))
            .collect())
    }

    /// Whether `peer` is due a visit at `now`.
    async fn due(&self, peer: &Peer, now: u64) -> bool {
        let (status, dirty) = {
            let state = self.state();
            (
                state.peers.get(&peer.id).cloned(),
                state.dirty.contains(&peer.id),
            )
        };
        let Some(status) = status else { return true };
        if let Some(last) = status.last_attempt {
            if status.consecutive_failures > 0 {
                let shift = status.consecutive_failures.saturating_sub(1).min(5);
                let delay = (RETRY_FIRST_SECS << shift).min(RETRY_CEILING_SECS);
                return now >= last.saturating_add(delay);
            }
            if now >= last.saturating_add(VISIT_EVERY_SECS) {
                return true;
            }
        } else {
            return true;
        }
        if dirty {
            return true;
        }
        // A vault this server erased since the last visit, whose copy at the peer must go. One the
        // peer refused is left to the regular visits, so it is not asked again every tick.
        let since = status.last_attempt.unwrap_or(0);
        if self
            .replica
            .store()
            .pending_erasures(peer.id)
            .await
            .is_ok_and(|pending| pending.iter().any(|p| p.queued_at >= since))
        {
            return true;
        }
        // A change of ours the peer hasn't been told of.
        let Ok(vaults) = self.shared_vaults(peer.id).await else {
            return false;
        };
        for vault in vaults {
            let Ok(latest) = self.replica.store().latest(vault.owner).await else {
                continue;
            };
            let told = self.state().told.get(&(peer.id, vault.owner)).cloned();
            if told.as_ref() != Some(&latest) {
                return true;
            }
        }
        false
    }

    /// Starts a run for every paired peer that is due and returns the peers it started, without
    /// waiting for them: each run is its own task under its own deadline, so one slow or hostile
    /// peer can't slow the visits to the others, and a peer whose run is still going is not started
    /// again. What a run did is logged when it ends.
    pub async fn tick(self: &Arc<Self>, now: u64) -> Vec<ServerId>
    where
        S: 'static,
        C: 'static,
    {
        let peers = match self.replica.store().list_peers().await {
            Ok(peers) => peers,
            Err(e) => {
                tracing::warn!(error = %e, "couldn't list the federation peers");
                return Vec::new();
            }
        };
        let mut started = Vec::new();
        for peer in peers.into_iter().filter(|p| p.state == PeerState::Paired) {
            if self.state().running.contains(&peer.id) || !self.due(&peer, now).await {
                continue;
            }
            started.push(peer.id);
            let runner = self.clone();
            let id = peer.id;
            tokio::spawn(async move {
                match runner.run_peer(id, now).await {
                    Ok(RunOutcome::Done(vaults)) => {
                        tracing::debug!(peer = %id, vaults = vaults.len(), "replicated with a peer");
                    }
                    Ok(_) => {}
                    Err(e) => {
                        tracing::info!(peer = %id, error = %e, "replication with a peer failed")
                    }
                }
            });
        }
        started
    }

    /// Ticks until the task is dropped or aborted.
    pub async fn run(self: Arc<Self>)
    where
        S: 'static,
        C: 'static,
    {
        let mut every = tokio::time::interval(TICK);
        every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            every.tick().await;
            self.tick(unix_now()).await;
        }
    }

    fn record_attempt(&self, peer: ServerId, now: u64) {
        self.state().peers.entry(peer).or_default().last_attempt = Some(now);
    }

    fn record_failure(&self, peer: ServerId, now: u64, error: &FedError) {
        let mut state = self.state();
        let status = state.peers.entry(peer).or_default();
        status.consecutive_failures = status.consecutive_failures.saturating_add(1);
        status.down_since.get_or_insert(now);
        status.last_error = Some(error.to_string());
        if let FedError::KeyMismatch { offered } = error {
            status.key_mismatch = Some(offered.clone());
        }
    }

    /// One run for `peer`, if no other process (or task of this one) is running one.
    pub async fn run_peer(&self, peer: ServerId, now: u64) -> Result<RunOutcome> {
        let Some(_running) = RunningGuard::take(&self.state, peer) else {
            return Ok(RunOutcome::Leased);
        };
        let store = self.replica.store();
        let Some(stored) = store
            .get_peer(peer)
            .await?
            .filter(|p| p.state == PeerState::Paired)
        else {
            return Ok(RunOutcome::NotPaired);
        };
        let lease = lease_name(peer);
        if !store
            .acquire_lease(&lease, &self.holder, LEASE_SECS)
            .await?
        {
            return Ok(RunOutcome::Leased);
        }
        self.record_attempt(peer, now);
        self.state().dirty.remove(&peer);
        let result = self.visit(&stored, now).await;
        if let Err(e) = store.drop_lease(&lease, &self.holder).await {
            tracing::warn!(error = %e, "couldn't give back a peer lease");
        }
        match result {
            Ok(vaults) => Ok(RunOutcome::Done(vaults)),
            Err(e) => {
                self.record_failure(peer, now, &e);
                Err(e)
            }
        }
    }

    async fn visit(&self, peer: &Peer, now: u64) -> Result<Vec<VaultStatus>> {
        // A rotated key can't open a session until the peer has the record, so it goes first.
        self.deliver_key_records(peer).await;
        let started = Instant::now();
        let mut channel = match self.connector.connect(peer).await {
            Ok(channel) => channel,
            Err(e) => {
                let mut state = self.state();
                let health = state.health.entry(peer.id).or_default();
                if matches!(e, FedError::KeyMismatch { .. }) {
                    health.record_key_mismatch(now, e.to_string());
                } else {
                    health.record_failure(now, e.to_string());
                }
                drop(state);
                return Err(e);
            }
        };
        let latency = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.state()
            .health
            .entry(peer.id)
            .or_default()
            .record_answer(now, Some(latency));
        let returned = {
            let mut state = self.state();
            let status = state.peers.entry(peer.id).or_default();
            let was_down = status.down_since.take().is_some();
            status.consecutive_failures = 0;
            status.last_error = None;
            status.key_mismatch = None;
            was_down || status.last_success.is_none()
        };
        let mut runs = self.vault_runs(peer, now).await?;
        // The time limit is not a failure: what the run did is kept, the vaults it didn't reach
        // carry a note, and the peer is visited again at once for the rest.
        let hard = Instant::now() + self.visit_deadline;
        let finished = tokio::time::timeout(
            self.visit_deadline,
            self.sync_all(&mut channel, peer, returned, now, hard, &mut runs),
        )
        .await;
        let (outcome, incomplete, timed_out) = match finished {
            Ok(Ok(complete)) => (Ok(()), !complete, false),
            Ok(Err(e)) => (Err(e), false, false),
            Err(_) => (Ok(()), true, true),
        };
        // A session cut off in the middle of a call is dropped, not closed: it can't answer.
        if !timed_out {
            // A failed close after a good run is not a failed run.
            if let Err(e) = self.connector.close(channel).await {
                tracing::debug!(error = %e, "a peer session did not close cleanly");
            }
        }
        let mut statuses: Vec<VaultStatus> = runs.into_iter().map(|run| run.status).collect();
        outcome?;
        let cut_short = incomplete;
        if cut_short {
            self.state().dirty.insert(peer.id);
            for status in &mut statuses {
                if status.note.is_none() {
                    status.note = Some(CUT_SHORT_NOTE.to_owned());
                }
            }
        }
        let store = self.replica.store();
        if let Err(e) = store.touch_peer(peer.id, now).await {
            tracing::debug!(error = %e, "couldn't record the visit to a peer");
        }
        let mut state = self.state();
        let status = state.peers.entry(peer.id).or_default();
        status.last_success = Some(now);
        status.vaults = statuses.clone();
        Ok(statuses)
    }

    /// Gives `peer` the key records this server holds (its own, and those it was given to pass on)
    /// that it hasn't had. A failure is tried again at the next run.
    async fn deliver_key_records(&self, peer: &Peer) {
        let records = match self.replica.store().key_records().await {
            Ok(records) => records,
            Err(e) => {
                tracing::debug!(error = %e, "couldn't read the key records to deliver");
                return;
            }
        };
        for record in records {
            if record.server == peer.id {
                continue;
            }
            let told = (
                peer.id,
                record.server,
                record.kind.clone(),
                record.issued_at,
            );
            if self.state().told_keys.contains(&told) {
                continue;
            }
            match self
                .connector
                .send_key_record(peer, record.envelope.clone())
                .await
            {
                Ok(()) => {
                    self.state().told_keys.insert(told);
                }
                Err(e) => {
                    tracing::debug!(peer = %peer.id, error = %e, "a key record was not delivered")
                }
            }
        }
    }

    /// One visit's work, in the order that matters when time runs out:
    ///
    /// 1. **Control**, for every vault: the offer, the home's records (members, keys, policies),
    ///    the erasures owed to the peer, the promotions announced to it, and a nudge when it hasn't
    ///    been told what this server holds.
    /// 2. **Items**: pull, duplicate tags and event logs.
    /// 3. **Comparison**: the hash trees.
    /// 4. **Files**, last, with a third of the visit to themselves: attachments and Sends.
    ///
    /// The vaults go in a different order at each visit, so the first one can't use up the visit
    /// every time. Returns whether everything was reached.
    async fn sync_all(
        &self,
        channel: &mut C::Chan,
        peer: &Peer,
        returned: bool,
        now: u64,
        hard: Instant,
        runs: &mut [VaultRun],
    ) -> Result<bool> {
        let files_budget = self.visit_deadline / 3;
        let soft = hard.checked_sub(files_budget).unwrap_or(hard);
        let mut complete = true;

        // 1. Control.
        for run in runs.iter_mut() {
            self.control_vault(channel, peer, run, now).await;
        }
        // Vaults this server erased, whose copies at the peer must go too. A failure leaves the
        // erasure queued for the next session; it never fails the run.
        if let Err(e) = self.replica.forward_erasures(channel, peer.id).await {
            tracing::info!(peer = %peer.id, error = %e, "couldn't tell a peer about erased vaults");
        }
        if let Err(e) = self.announce_promotions(channel, peer.id).await {
            tracing::info!(peer = %peer.id, error = %e, "couldn't announce a promotion to a peer");
        }
        for run in runs.iter_mut().filter(|r| r.active) {
            self.nudge_vault(channel, peer, run, false).await;
        }

        // 2. Items.
        for run in runs.iter_mut().filter(|r| r.active) {
            if Instant::now() >= soft {
                complete = false;
                break;
            }
            self.items_vault(channel, peer, run).await;
        }

        // 3. Comparison.
        for run in runs.iter_mut().filter(|r| r.active) {
            if Instant::now() >= soft {
                complete = false;
                break;
            }
            self.reconcile_vault(channel, peer, run, returned, now)
                .await;
        }
        // What the comparison found that the peer lacks, and what the pull brought in.
        for run in runs.iter_mut().filter(|r| r.active) {
            self.nudge_vault(channel, peer, run, true).await;
        }

        // 4. Files.
        let files_until = (Instant::now() + files_budget).min(hard);
        for run in runs.iter_mut().filter(|r| r.active) {
            if Instant::now() >= files_until {
                complete = false;
                break;
            }
            if !self.files_vault(channel, peer, run, files_until).await {
                complete = false;
            }
        }
        Ok(complete)
    }

    /// The vaults this server and `peer` share, as the runs of a visit, in an order that turns by
    /// one at each visit: the first vault can't use up every visit.
    async fn vault_runs(&self, peer: &Peer, now: u64) -> Result<Vec<VaultRun>> {
        let mut vaults = self.shared_vaults(peer.id).await?;
        if !vaults.is_empty() {
            let turn = {
                let mut state = self.state();
                let turn = state.turns.entry(peer.id).or_insert(0);
                let current = *turn;
                *turn = turn.wrapping_add(1);
                current
            };
            let count = vaults.len();
            vaults.rotate_left(turn % count);
        }
        Ok(vaults
            .into_iter()
            .map(|vault| VaultRun {
                status: VaultStatus::new(vault.owner, now),
                vault,
                active: true,
                pull_retry: 0,
                push: false,
            })
            .collect())
    }

    /// Sets the note a failure of one vault's work leaves: the peer may simply not hold the vault
    /// yet. The vault's later steps are left out of this visit.
    fn vault_failed(&self, peer: &Peer, run: &mut VaultRun, error: &FedError) {
        if is_unknown_vault(error) {
            run.status.note = Some("the peer doesn't hold this vault yet".to_owned());
        } else {
            tracing::info!(peer = %peer.id, vault = ?run.vault.owner, error = %error, "a vault didn't sync");
            run.status.note = Some(error.to_string());
        }
        run.active = false;
    }

    async fn control_vault(
        &self,
        channel: &mut C::Chan,
        peer: &Peer,
        run: &mut VaultRun,
        now: u64,
    ) {
        if let Err(e) = self.control_vault_inner(channel, peer, run, now).await {
            self.vault_failed(peer, run, &e);
        }
    }

    async fn control_vault_inner(
        &self,
        channel: &mut C::Chan,
        peer: &Peer,
        run: &mut VaultRun,
        _now: u64,
    ) -> Result<()> {
        let replica = &self.replica;
        let owner = run.vault.owner;
        if run.vault.home == replica.server_id() && run.vault.replicas.contains(&peer.id) {
            let offer = replica.offer_vault(channel, peer.id, owner).await?;
            run.status.offer = Some(offer);
            // The space's own records first: a replica applies a member's account only once it
            // knows the member belongs to the space.
            replica.publish_space_state(owner).await?;
            replica.publish_members(owner).await?;
            replica.publish_signed_writes(owner).await?;
            if offer != OfferState::Accepted {
                run.status.note = Some(
                    match offer {
                        OfferState::Pending => "waiting for the peer's admin to accept the vault",
                        _ => "the peer's admin declined the vault",
                    }
                    .to_owned(),
                );
                run.active = false;
                return Ok(());
            }
        }

        // The keys of servers of this vault we aren't paired with, which this peer vouches for: the
        // changes it relays from them are checked against them.
        match replica.learn_origin_keys(channel, peer.id, owner).await {
            Ok(0) => {}
            Ok(n) => {
                tracing::debug!(peer = %peer.id, keys = n, "learned the keys of other servers of a vault")
            }
            Err(e) => tracing::info!(error = %e, "origin keys didn't sync"),
        }

        let sync = replica.pull_home_records(channel, peer.id, owner).await?;
        run.status.home_applied = sync.applied;
        run.status.home_quarantined = sync.quarantined;
        if sync.behind {
            // A promotion was missed: nothing more of this vault until its record arrives (the
            // new home announces it when it visits).
            run.status.behind = true;
            run.status.note =
                Some("the peer is at a newer home epoch: a promotion was missed".to_owned());
            run.active = false;
        }
        Ok(())
    }

    /// Tells the peer what this server holds, when it hasn't been told: before the work (`after`
    /// false) so a peer that is behind starts pulling at once, and after it (`after` true), when the
    /// pull and the comparison changed what is held or found something the peer lacks.
    async fn nudge_vault(
        &self,
        channel: &mut C::Chan,
        peer: &Peer,
        run: &mut VaultRun,
        after: bool,
    ) {
        let owner = run.vault.owner;
        let result: Result<()> = async {
            let latest = self.replica.store().latest(owner).await?;
            let told = self.state().told.get(&(peer.id, owner)).cloned();
            let push = after && run.push;
            if push || told.as_ref() != Some(&latest) {
                self.replica.nudge(channel, owner).await?;
                self.state().told.insert((peer.id, owner), latest);
            }
            Ok(())
        }
        .await;
        if let Err(e) = result {
            self.vault_failed(peer, run, &e);
        }
    }

    async fn items_vault(&self, channel: &mut C::Chan, peer: &Peer, run: &mut VaultRun) {
        let replica = &self.replica;
        let owner = run.vault.owner;
        let report = match replica.pull(channel, peer.id, owner).await {
            Ok(report) => report,
            Err(e) => {
                self.vault_failed(peer, run, &e);
                return;
            }
        };
        run.pull_retry = report.counts.retry;
        if report.pages >= crate::message::MAX_PAGES_PER_VISIT {
            // Stopped at the page limit: the rest is taken at the next visit, soon.
            self.state().dirty.insert(peer.id);
        }
        run.status.pulled = report.counts;

        // Duplicate tags follow the revisions just pulled, where server matching is on.
        match replica.pull_tags(channel, peer.id, owner).await {
            Ok(n) => run.status.tags_pulled = n,
            Err(e) => tracing::info!(error = %e, "duplicate tags didn't sync"),
        }

        // The peer's event log, when its Send and our Pull for it are both on.
        match replica.pull_events(channel, peer.id, owner).await {
            Ok(n) => run.status.events_pulled = n,
            Err(e) => tracing::info!(error = %e, "event logs didn't sync"),
        }
    }

    async fn reconcile_vault(
        &self,
        channel: &mut C::Chan,
        peer: &Peer,
        run: &mut VaultRun,
        returned: bool,
        now: u64,
    ) {
        let owner = run.vault.owner;
        let due = {
            let state = self.state();
            let last = state.reconciled.get(&(peer.id, owner)).copied();
            // A pull that left records out for now (a writer's keys not here yet, an origin over its
            // quota) compares at once: the comparison fetches them again. One it refused for good
            // waits for the regular comparison, or every visit would fetch it again.
            returned
                || run.pull_retry > 0
                || last.is_none_or(|t| now >= t.saturating_add(RECONCILE_EVERY_SECS))
        };
        if !due {
            return;
        }
        match self.replica.reconcile(channel, peer.id, owner).await {
            Ok(reconciled) => {
                run.status.in_step = Some(reconciled.in_step);
                run.push = !reconciled.to_push.is_empty();
                self.state().reconciled.insert((peer.id, owner), now);
            }
            Err(e) if is_unknown_vault(&e) => self.vault_failed(peer, run, &e),
            Err(e @ (FedError::Refused(_) | FedError::Remote(_))) => {
                // The peer (or this server) turned the comparison down, as it does when a vault
                // was compared too often in the hour: a note, and the next one is a regular
                // interval away. The visit goes on.
                tracing::info!(peer = %peer.id, error = %e, "a comparison was turned down");
                run.status.note = Some(format!("comparison turned down: {e}"));
                self.state().reconciled.insert((peer.id, owner), now);
            }
            Err(e) => self.vault_failed(peer, run, &e),
        }
    }

    /// Attachments and Sends of one vault, until `until`. False when it stopped for time.
    async fn files_vault(
        &self,
        channel: &mut C::Chan,
        peer: &Peer,
        run: &mut VaultRun,
        until: Instant,
    ) -> bool {
        let replica = &self.replica;
        let owner = run.vault.owner;
        let mut finished = true;
        if replica.files.is_some() {
            match replica
                .sync_blobs_until(channel, peer.id, owner, until)
                .await
            {
                Ok(files) => {
                    run.status.files_fetched = files.fetched;
                    run.status.files_deferred = files.deferred;
                    finished = !files.unfinished;
                }
                Err(e) => tracing::info!(error = %e, "attachments didn't sync"),
            }
        }
        // Notes copy without file storage; only a file Send needs it (see `sync_sends`). Asked
        // only of a peer that says it answers: an older one drops the session on a request it
        // doesn't know, and the vaults after this one would not sync.
        if peer.advertises(crate::sendsync::SENDS_CAPABILITY) {
            match replica.sync_sends(channel, peer.id, owner).await {
                Ok(sends) => {
                    run.status.sends_copied = sends.rows + sends.updated;
                    run.status.files_fetched += sends.fetched;
                    run.status.files_deferred += sends.deferred;
                }
                Err(e) => tracing::info!(error = %e, "Sends didn't sync"),
            }
        }
        finished
    }

    /// Tells `peer` of every promotion this server made, once per run of this process. A peer that
    /// refuses (it already applied it, or it is not in the set) is not an error.
    async fn announce_promotions(&self, channel: &mut C::Chan, peer: ServerId) -> Result<()> {
        let me = self.replica.server_id();
        for vault in self.shared_vaults(peer).await? {
            let Some(record) = vault.promotion.clone() else {
                continue;
            };
            if vault.home != me {
                continue;
            }
            let key = (peer, vault.owner, vault.epoch);
            if self.state().announced.contains(&key) {
                continue;
            }
            match self.replica.announce(channel, record).await {
                Ok(()) => {}
                Err(FedError::Remote(detail)) => {
                    tracing::debug!(%detail, "a peer didn't take a promotion (already applied?)");
                }
                Err(e) => return Err(e),
            }
            self.state().announced.insert(key);
        }
        Ok(())
    }
}

/// Brings one file from the first peer that holds it, for [`crate::blobs::OnDemandBlobs`].
pub struct PeerBlobFetcher<S, C> {
    runner: Arc<PeerRunner<S, C>>,
}

impl<S, C> std::fmt::Debug for PeerBlobFetcher<S, C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerBlobFetcher").finish_non_exhaustive()
    }
}

impl<S, C> PeerBlobFetcher<S, C> {
    pub fn new(runner: Arc<PeerRunner<S, C>>) -> PeerBlobFetcher<S, C> {
        PeerBlobFetcher { runner }
    }
}

impl<S, C> crate::blobs::BlobFetcher for PeerBlobFetcher<S, C>
where
    S: FedStore + Leases + 'static,
    C: Connector + 'static,
{
    fn fetch(
        &self,
        blob: kemlock_domain::BlobId,
    ) -> kemlock_app::federation_view::BoxFut<
        '_,
        std::result::Result<(), kemlock_app::files::BlobError>,
    > {
        Box::pin(async move {
            use kemlock_app::files::BlobError;
            let replica = &self.runner.replica;
            let backend = |e: &dyn std::fmt::Display| BlobError::Backend(e.to_string());
            // An attachment's file, or the file of a Send (which a Bitwarden app may have made in
            // a format storage can't check).
            let (file_owner, file_size, raw) = match replica
                .store()
                .attachment_of_blob(blob)
                .await
                .map_err(|e| backend(&e))?
            {
                Some(attachment) => (attachment.owner, attachment.size, false),
                None => {
                    let send = replica
                        .store()
                        .send_of_blob(blob)
                        .await
                        .map_err(|e| backend(&e))?
                        .ok_or(BlobError::NotFound)?;
                    let file = send.file.ok_or(BlobError::NotFound)?;
                    (
                        Owner::User(send.owner),
                        file.size,
                        file.format == kemlock_domain::sends::SendFileFormat::Opaque,
                    )
                }
            };
            let vault = replica
                .store()
                .get_vault(file_owner)
                .await
                .map_err(|e| backend(&e))?
                .filter(|v| v.policy == Policy::Federated)
                .ok_or(BlobError::NotFound)?;
            // The home first, then the replicas in order.
            for server in vault.order() {
                if server == replica.server_id() {
                    continue;
                }
                let Some(peer) = replica
                    .store()
                    .get_peer(server)
                    .await
                    .map_err(|e| backend(&e))?
                    .filter(|p| p.state == PeerState::Paired)
                else {
                    continue;
                };
                let mut channel = match self.runner.connector.connect(&peer).await {
                    Ok(channel) => channel,
                    Err(e) => {
                        tracing::info!(peer = %server, error = %e, "can't reach a peer for a file");
                        continue;
                    }
                };
                let fetched = replica
                    .fetch_file(&mut channel, file_owner, blob, file_size, raw)
                    .await;
                if let Err(e) = self.runner.connector.close(channel).await {
                    tracing::debug!(error = %e, "a peer session did not close cleanly");
                }
                match fetched {
                    Ok(()) => return Ok(()),
                    Err(e) => {
                        tracing::info!(peer = %server, error = %e, "a peer couldn't give a file")
                    }
                }
            }
            Err(BlobError::NotFound)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_lease_is_named_for_its_peer() {
        let peer = ServerId::random();
        assert_eq!(lease_name(peer), format!("fed-peer-{peer}"));
        assert_ne!(lease_name(peer), lease_name(ServerId::random()));
    }

    #[test]
    fn only_an_unknown_vault_answer_is_expected() {
        assert!(is_unknown_vault(&FedError::UnknownVault));
        assert!(is_unknown_vault(&FedError::Remote(
            "unknown vault".to_owned()
        )));
        assert!(!is_unknown_vault(&FedError::Remote("refused".to_owned())));
        assert!(!is_unknown_vault(&FedError::Pairing));
    }

    #[test]
    fn a_new_status_has_no_history() {
        let status = PeerStatus::default();
        assert_eq!(status.consecutive_failures, 0);
        assert!(status.last_success.is_none() && status.down_since.is_none());
        let vault = VaultStatus::new(Owner::User(kemlock_domain::UserId::random()), 5);
        assert_eq!((vault.at, vault.behind, vault.note), (5, false, None));
    }

    #[test]
    fn the_retry_delay_doubles_to_its_ceiling() {
        let delay = |failures: u32| {
            let shift = failures.saturating_sub(1).min(5);
            (RETRY_FIRST_SECS << shift).min(RETRY_CEILING_SECS)
        };
        assert_eq!(delay(1), 15);
        assert_eq!(delay(2), 30);
        assert_eq!(delay(5), 240);
        assert_eq!(delay(6), 300);
        assert_eq!(delay(50), 300);
    }
}
