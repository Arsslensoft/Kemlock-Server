//! What the admin console does with federation, as one facade over the engine: the peer list with
//! its fingerprints, lag and health, the two log switches, revoking a peer, each vault's policy and
//! the replica order, consent to a vault a home offers, and promotion; the vaults that may be
//! federated; reaching every peer or comparing hash trees now; what is known of a peer's
//! descriptor and KEM key; this server's own keys, suites and descriptor; and a peer that offered
//! an identity key other than the pinned one.
//!
//! `kemlock-api-fed` puts HTTP routes (`/admin/v1/federation`) over it; the console and the CLI
//! are its other users. Pairing is in [`crate::hub`].

use crate::addr::{self, Trust};
use crate::descriptor::{Descriptor, KEM_ROTATION_SECS, SignedDescriptor, kem_key_id};
use crate::error::{FedError, Result};
use crate::eventsync::PeerEvent;
use crate::extra::{Acknowledgement, Leases, StoredOffer};
use crate::forget::{CANT_FORCE, PeerReport};
use crate::health::{HealthStatus, PeerHealth};
use crate::home::{MAX_REPLICAS, Policy, PromotionRecord, VaultFederation};
use crate::hub::Pairings;
use crate::insight::{MismatchRecord, PeerSecurityRecord, VaultInfo};
use crate::job::{Connector, LEASE_SECS, PeerRunner, PeerStatus, RunOutcome, lease_name};
use crate::keyrecs::{IdentityRotator, PendingAddresses, revocation_record, rotation_record};
use crate::net::Http;
use crate::pairing::Fingerprint;
use crate::ports::{HomeStatus, LogSwitches, Peer, PeerState, StoredHomeRecord};
use crate::replicate::{FedStore, Replica};
use crate::session::unix_now;
use crate::suite::Suite;
use kemlock_app::federation_view::BoxFut;
use kemlock_domain::{Owner, ServerId};
use std::collections::HashSet;
use std::sync::Arc;

/// Who holds the lease while the console compares hash trees by hand.
const CONSOLE_HOLDER: &str = "admin-console";
/// The most events read of a vault to see whether a peer sends its logs.
const EVENTS_LOOKED_AT: u32 = 200;

/// Where the console reads a peer's published descriptor from. The network in production; the
/// tests give it fixed ones.
pub trait DescriptorSource: Send + Sync {
    /// The descriptor published at `address`, parsed but not checked, reached as `trust` allows.
    fn fetch<'a>(
        &'a self,
        address: &'a str,
        trust: Trust,
    ) -> BoxFut<'a, Result<SignedDescriptor>>;
}

/// [`DescriptorSource`] over `GET /fed/v1/descriptor`.
#[derive(Debug, Default)]
struct HttpDescriptors;

impl DescriptorSource for HttpDescriptors {
    fn fetch<'a>(
        &'a self,
        address: &'a str,
        trust: Trust,
    ) -> BoxFut<'a, Result<SignedDescriptor>> {
        Box::pin(async move { Http::new()?.descriptor(address, trust).await })
    }
}

/// What the console says of this server beyond its descriptor, set by the process that runs it.
/// A descriptor carries neither, and the wire format is fixed, so nothing of the kind is known of
/// a peer.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ServerProfile {
    /// A name for the console; the host of the first address when unset.
    pub name: Option<String>,
    /// The kind of database, such as `postgres` or `sqlite`.
    pub database: Option<String>,
    /// The country the server runs in.
    pub country: Option<String>,
}

/// How far behind a peer is, as far as this server can tell.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PeerActivity {
    /// Versions of the vaults shared with the peer that this server holds and that its last pull
    /// from the peer did not cover: what it may still be waiting for. Counted to
    /// [`WAITING_LIMIT`](crate::outbox::WAITING_LIMIT) per vault.
    pub lag_changes: u64,
    /// The age of the oldest of those versions, `None` when no vault is shared with the peer.
    pub lag_seconds: Option<u64>,
    /// When the peer last wrote a change to a shared vault, Unix seconds.
    pub last_change_at: Option<u64>,
    pub last_change_vault: Option<Owner>,
}

/// What a vault is waiting to send, as far as this server can tell.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Waiting {
    pub changes: u64,
    /// The count stopped at the limit.
    pub at_least: bool,
    /// When the oldest waiting version was written, Unix seconds.
    pub oldest_at: Option<u64>,
}

/// A peer as the console lists it.
#[derive(Clone, Debug)]
pub struct PeerView {
    pub peer: Peer,
    /// The six words of the pairing, as both admins compared them.
    pub fingerprint: String,
    pub switches: LogSwitches,
    pub acknowledgement: Option<Acknowledgement>,
    /// What the last runs found, if the peer has been visited since the server started.
    pub status: Option<PeerStatus>,
    /// Whether the peer answers, as the probes and visits found: `unknown` until the first.
    pub health: HealthStatus,
    /// What those found: when it last answered, how long that took, why it last failed.
    pub probe: Option<PeerHealth>,
    pub activity: PeerActivity,
    /// Whether this server holds event-log entries the peer sent: it takes our Pull switch and the
    /// peer's Send switch both being on for any to arrive. The peer's switch itself isn't ours to
    /// read.
    pub they_send_logs: bool,
}

/// A vault as the console lists it.
#[derive(Clone, Debug)]
pub struct VaultView {
    pub settings: VaultFederation,
    /// Whether this server is the vault's home.
    pub is_home: bool,
    /// Owner, members and size, when this server holds the vault.
    pub info: Option<VaultInfo>,
    /// What is waiting to reach the vault's other servers: the most of any one of them.
    pub waiting: Waiting,
}

/// What unpairing a peer did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnpairReport {
    /// The peer was asked to delete, and answered.
    pub asked: bool,
    /// What the peer says it deleted: its word, nothing more.
    pub peer_report: Option<PeerReport>,
    /// Why the peer couldn't be asked, if it couldn't (it was down, or had revoked us).
    pub detail: Option<String>,
    /// What the console says: a peer run by someone else can't be forced to delete.
    pub notice: &'static str,
}

/// What changing this server's identity key did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyChange {
    /// `"rotation"` or `"revocation"`.
    pub kind: &'static str,
    /// The `sig1` public key the server has now.
    pub new_identity_key: Vec<u8>,
    /// How many paired peers will be told.
    pub peers: usize,
}

/// How a visit to a peer went.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reach {
    /// A session opened and the run finished.
    Reached,
    /// Another process is running this peer now.
    Busy,
    /// The peer isn't paired (any more).
    NotPaired,
    /// No vault is shared with the peer, so there was nothing to compare.
    NothingShared,
    /// The peer offered an identity key other than the pinned one.
    KeyMismatch,
    /// The peer could not be reached, or refused.
    Unreachable,
}

impl Reach {
    pub fn as_str(self) -> &'static str {
        match self {
            Reach::Reached => "reached",
            Reach::Busy => "busy",
            Reach::NotPaired => "not-paired",
            Reach::NothingShared => "nothing-shared",
            Reach::KeyMismatch => "key-mismatch",
            Reach::Unreachable => "unreachable",
        }
    }
}

/// What reaching a peer now found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerCheck {
    pub peer: ServerId,
    pub reach: Reach,
    /// Why it could not be reached, in words fit for the console.
    pub detail: Option<String>,
}

/// One vault's hash trees, compared with a peer's.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultComparison {
    pub vault: Owner,
    /// The roots matched; `None` when the comparison didn't run.
    pub in_step: Option<bool>,
    pub detail: Option<String>,
}

/// What comparing hash trees with a peer now found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerConsistency {
    pub peer: ServerId,
    pub reach: Reach,
    pub vaults: Vec<VaultComparison>,
    pub detail: Option<String>,
}

/// One suite in the comparison of this server's and a peer's lists.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SuiteRow {
    pub name: String,
    /// Its place in the peer's list, from 1; `None` when the peer doesn't list it.
    pub theirs: Option<u32>,
    /// Its place in this server's list, from 1.
    pub ours: Option<u32>,
    /// The suite a session between the two would use.
    pub in_use: bool,
}

/// What is known of a peer's keys and descriptor.
#[derive(Clone, Debug)]
pub struct PeerSecurityView {
    pub peer: Peer,
    /// The descriptor's identity key is the pinned one, and no run met another.
    pub keys_match: bool,
    /// The descriptor's signature holds under its own identity key and it is inside its window.
    pub signature_ok: bool,
    pub descriptor: Option<Descriptor>,
    /// The signed descriptor as the peer served it.
    pub descriptor_bytes: Option<Vec<u8>>,
    /// When the descriptor shown was read, Unix seconds. This call reads it afresh when it can.
    pub fetched_at: Option<u64>,
    /// Why a fresh read failed, when it did and an older copy is shown.
    pub fetch_error: Option<String>,
    /// When this server first saw the peer's current KEM key. A KEM key's creation time is not in
    /// the descriptor, so this is the nearest it can say of the key's age.
    pub kem_first_seen: Option<u64>,
    /// First 8 bytes of SHA-256 of the KEM key, as four groups of hex.
    pub kem_fingerprint: Option<String>,
    pub suites: Vec<SuiteRow>,
    /// The last session that opened with the peer, Unix seconds.
    pub last_handshake_at: Option<u64>,
}

/// One suite of this server's setting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SuiteSetting {
    pub suite: Suite,
    pub on: bool,
    /// This build can run it.
    pub available: bool,
}

/// This server's own federation identity, for the console.
#[derive(Clone, Debug)]
pub struct SelfView {
    pub server: ServerId,
    pub operator: String,
    pub addresses: Vec<String>,
    pub identity_key: Vec<u8>,
    /// First 16 bytes of SHA-256 of the identity key, as eight groups of hex.
    pub identity_fingerprint: String,
    /// The signed descriptor this server publishes.
    pub descriptor: Vec<u8>,
    pub valid_from: u64,
    pub valid_to: u64,
    /// When the current KEM key was made, if the keeper of the identity knows.
    pub kem_made_at: Option<u64>,
    pub kem_next_rotation_at: Option<u64>,
    /// The suites in this server's order, then the ones left off.
    pub suites: Vec<SuiteSetting>,
    pub profile: ServerProfile,
}

/// A vault paused because a peer's key does not match.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PausedVault {
    pub vault: Owner,
    pub info: Option<VaultInfo>,
    pub waiting: Waiting,
}

/// A peer that offered an identity key other than the pinned one, as the console shows it.
#[derive(Clone, Debug)]
pub struct MismatchView {
    pub peer: Peer,
    pub pinned_key: Vec<u8>,
    /// When the key was pinned: the pairing's time.
    pub pinned_at: u64,
    pub record: MismatchRecord,
    /// The offered key was offered before the latest attempt.
    pub seen_before: bool,
    /// The addresses the peer is known by: where it usually is.
    pub usual_addresses: Vec<String>,
    /// The vaults shared with the peer, which can't sync while the mismatch stands.
    pub paused: Vec<PausedVault>,
    /// How many vaults are homed here and not federated.
    pub local_vaults: u64,
}

fn grouped_hex(bytes: &[u8]) -> String {
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    hex.as_bytes()
        .chunks(4)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect::<Vec<_>>()
        .join(" ")
}

/// Why a call failed, in words that tell an admin something and leak nothing.
fn reason(error: &FedError) -> String {
    match error {
        FedError::Remote(detail) => detail.clone(),
        FedError::Expired(what) => (*what).to_owned(),
        FedError::NoCommonSuite => "the two servers share no cipher suite".to_owned(),
        FedError::KeyMismatch { .. } => "the peer offered another identity key".to_owned(),
        _ => "the call failed".to_owned(),
    }
}

/// The federation admin facade.
pub struct Federation<S, C> {
    replica: Arc<Replica<S>>,
    runner: Arc<PeerRunner<S, C>>,
    pairings: Arc<Pairings<S>>,
    rotator: Option<Arc<dyn IdentityRotator>>,
    profile: ServerProfile,
    descriptors: Arc<dyn DescriptorSource>,
}

impl<S, C> std::fmt::Debug for Federation<S, C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Federation").finish_non_exhaustive()
    }
}

impl<S, C> Clone for Federation<S, C> {
    fn clone(&self) -> Self {
        Federation {
            replica: self.replica.clone(),
            runner: self.runner.clone(),
            pairings: self.pairings.clone(),
            rotator: self.rotator.clone(),
            profile: self.profile.clone(),
            descriptors: self.descriptors.clone(),
        }
    }
}

impl<S: FedStore + Leases, C: Connector> Federation<S, C> {
    pub fn new(
        replica: Arc<Replica<S>>,
        runner: Arc<PeerRunner<S, C>>,
        pairings: Arc<Pairings<S>>,
    ) -> Federation<S, C> {
        Federation {
            replica,
            runner,
            pairings,
            rotator: None,
            profile: ServerProfile::default(),
            descriptors: Arc::new(HttpDescriptors),
        }
    }

    /// What the console says of this server beyond its descriptor.
    pub fn with_profile(mut self, profile: ServerProfile) -> Federation<S, C> {
        self.profile = profile;
        self
    }

    /// Reads a peer's descriptor from `source` instead of the network.
    pub fn with_descriptors(mut self, source: Arc<dyn DescriptorSource>) -> Federation<S, C> {
        self.descriptors = source;
        self
    }

    pub fn profile(&self) -> &ServerProfile {
        &self.profile
    }

    /// Lets this facade change the server's identity key, with `rotator` making and keeping the new
    /// one (see [`rotate_identity`](Self::rotate_identity)).
    pub fn with_rotator(mut self, rotator: Arc<dyn IdentityRotator>) -> Federation<S, C> {
        self.rotator = Some(rotator);
        self
    }

    pub fn replica(&self) -> &Arc<Replica<S>> {
        &self.replica
    }

    pub fn runner(&self) -> &Arc<PeerRunner<S, C>> {
        &self.runner
    }

    pub fn pairings(&self) -> &Arc<Pairings<S>> {
        &self.pairings
    }

    fn me(&self) -> ServerId {
        self.replica.server_id()
    }

    /// Every peer, paired or revoked.
    pub async fn peers(&self) -> Result<Vec<PeerView>> {
        let now = unix_now();
        let identity = self.replica.identity();
        let mut out = Vec::new();
        for peer in self.replica.store().list_peers().await? {
            let fingerprint = peer
                .key()
                .map(|key| Fingerprint::of((identity.server, &identity.public), (peer.id, &key)))
                .map(|f| f.to_string())
                .unwrap_or_default();
            let switches = self.replica.store().log_switches(peer.id).await?;
            let (activity, they_send_logs) = if peer.state == PeerState::Paired {
                self.activity(&peer, switches, now).await?
            } else {
                (PeerActivity::default(), false)
            };
            out.push(PeerView {
                switches,
                acknowledgement: self.replica.store().acknowledgement(peer.id).await?,
                status: self.runner.status_of(peer.id),
                health: self.runner.health_status(peer.id, unix_now()),
                probe: self.runner.health_of(peer.id),
                fingerprint,
                activity,
                they_send_logs,
                peer,
            });
        }
        Ok(out)
    }

    /// Sets the two event-log switches of a peer. Both are off until an admin turns them on;
    /// logs flow only when the sender's Send and the receiver's Pull are both on.
    pub async fn set_log_switches(&self, peer: ServerId, switches: LogSwitches) -> Result<()> {
        self.replica
            .store()
            .get_peer(peer)
            .await?
            .ok_or(FedError::UnknownPeer)?;
        self.replica
            .store()
            .set_log_switches(peer, switches)
            .await?;
        Ok(())
    }

    /// Stops trusting a peer: no session is accepted from it or opened to it. Its copies of our
    /// vaults stay where they are (the console says so: a peer run by someone else can't be forced
    /// to delete them).
    pub async fn revoke_peer(&self, peer: ServerId) -> Result<()> {
        self.replica
            .store()
            .set_peer_state(peer, PeerState::Revoked)
            .await?;
        Ok(())
    }

    /// Unpairs a peer: stops copying at once, asks it to delete what it holds of our vaults, and
    /// forgets it. The ask is a signed notice over a session and is best effort: a peer that is
    /// down, or that doesn't answer, is unpaired all the same. A peer run by someone else can't be
    /// forced to delete, which [`UnpairReport::notice`] says.
    ///
    /// Our vaults that had the peer as a replica lose it from their replica order (a vault with no
    /// replica left is Local again). A vault the peer is the home of stays: its admin can promote
    /// this server.
    pub async fn unpair(&self, peer: ServerId) -> Result<UnpairReport> {
        let stored = self
            .replica
            .store()
            .get_peer(peer)
            .await?
            .ok_or(FedError::UnknownPeer)?;
        let mut report = UnpairReport {
            asked: false,
            peer_report: None,
            detail: None,
            notice: CANT_FORCE,
        };
        if stored.state == PeerState::Paired {
            match self.ask_to_forget(&stored).await {
                Ok(peer_report) => {
                    report.asked = true;
                    report.peer_report = Some(peer_report);
                }
                Err(e) => report.detail = Some(e.to_string()),
            }
        }
        let me = self.me();
        for vault in self.replica.store().list_vaults().await? {
            if vault.home == me && vault.replicas.contains(&peer) {
                let mut next = vault.clone();
                next.replicas.retain(|r| *r != peer);
                if next.replicas.is_empty() {
                    next.policy = Policy::Local;
                }
                self.replica.store().put_vault(&next).await?;
            }
        }
        self.replica.store().remove_peer(peer).await?;
        self.runner.forget(peer);
        Ok(report)
    }

    async fn ask_to_forget(&self, peer: &Peer) -> Result<PeerReport> {
        let connector = self.runner.connector();
        let mut channel = connector.connect(peer).await?;
        let asked = self.replica.ask_to_forget(&mut channel, peer.id).await;
        if let Err(e) = connector.close(channel).await {
            tracing::debug!(error = %e, "a session did not close cleanly after an unpairing");
        }
        asked
    }

    /// Replaces this server's identity key with a new one, through a rotation signed with the old
    /// key. The record reaches each peer before the next session (peers accept the new key only
    /// through it), and each peer passes it on to its own peers. The caller has checked the admin
    /// with a fresh passkey or password.
    pub async fn rotate_identity(&self, now: u64) -> Result<KeyChange> {
        let rotator = self.rotator()?;
        let old = self.replica.identity();
        let new = rotator.rotate(&old, now)?;
        let (record, signed) = rotation_record(&old, &new, now)?;
        let key = new.public.as_bytes().to_vec();
        self.replica
            .install_rotated_identity(Arc::new(new), &record, signed.encode())
            .await?;
        Ok(KeyChange {
            kind: "rotation",
            new_identity_key: key,
            peers: self.tell_peers().await?,
        })
    }

    /// Declares this server's identity key stolen: signs a revocation with it, sends it to every
    /// peer (which stop trusting the key and pass the record on) and takes a new key. Every peer
    /// must be paired again with a new code, since each now has this server revoked. The caller has
    /// checked the admin with a fresh passkey or password.
    pub async fn revoke_identity(&self, now: u64) -> Result<KeyChange> {
        let rotator = self.rotator()?;
        let old = self.replica.identity();
        let new = rotator.rotate(&old, now)?;
        let (record, signed) = revocation_record(&old, now)?;
        let key = new.public.as_bytes().to_vec();
        self.replica
            .install_rotated_identity(Arc::new(new), &record, signed.encode())
            .await?;
        Ok(KeyChange {
            kind: "revocation",
            new_identity_key: key,
            peers: self.tell_peers().await?,
        })
    }

    fn rotator(&self) -> Result<&Arc<dyn IdentityRotator>> {
        self.rotator.as_ref().ok_or(FedError::Refused(
            "this server can\x27t change its identity key",
        ))
    }

    /// Visits every paired peer soon, which delivers the key record. Returns how many.
    async fn tell_peers(&self) -> Result<usize> {
        let mut told = 0;
        for peer in self.replica.store().list_peers().await? {
            if peer.state == PeerState::Paired {
                self.runner.mark_dirty(peer.id);
                told += 1;
            }
        }
        Ok(told)
    }

    /// Removes a peer with its cursors and switches.
    pub async fn remove_peer(&self, peer: ServerId) -> Result<bool> {
        let removed = self.replica.store().remove_peer(peer).await?;
        self.replica.store().forget_withheld(peer).await?;
        self.runner.forget(peer);
        Ok(removed)
    }

    /// The vaults federation knows of here: every one with a federation row.
    pub async fn vaults(&self) -> Result<Vec<VaultView>> {
        let me = self.me();
        let mut out = Vec::new();
        for settings in self.replica.store().list_vaults().await? {
            let info = self.replica.store().vault_info(settings.owner).await?;
            let waiting = self.waiting_of(&settings).await?;
            out.push(VaultView {
                is_home: settings.home == me,
                settings,
                info,
                waiting,
            });
        }
        Ok(out)
    }

    /// What `peer` may still be waiting for in `vault`: the versions this server holds that its
    /// last pull from the peer did not cover, counted to a limit. Not exact, since what the peer
    /// holds is only known as of that pull, but it falls to nothing once the peer has caught up.
    async fn waiting_for(&self, peer: ServerId, vault: Owner) -> Result<Waiting> {
        self.replica.waiting_for(peer, vault).await
    }

    /// The most waiting for any other server of a federated vault this server holds.
    async fn waiting_of(&self, settings: &VaultFederation) -> Result<Waiting> {
        let me = self.me();
        let mut worst = Waiting::default();
        if settings.policy != Policy::Federated || !settings.holds(me) {
            return Ok(worst);
        }
        for server in settings.order() {
            if server == me {
                continue;
            }
            let waiting = self.waiting_for(server, settings.owner).await?;
            if waiting.changes >= worst.changes {
                worst = Waiting {
                    oldest_at: match (worst.oldest_at, waiting.oldest_at) {
                        (Some(a), Some(b)) => Some(a.min(b)),
                        (a, b) => a.or(b),
                    },
                    ..waiting
                };
            }
        }
        Ok(worst)
    }

    /// Lag and last change for `peer` over the vaults shared with it, and whether it sends us its
    /// logs.
    async fn activity(
        &self,
        peer: &Peer,
        switches: LogSwitches,
        now: u64,
    ) -> Result<(PeerActivity, bool)> {
        let me = self.me();
        let store = self.replica.store();
        let mut activity = PeerActivity::default();
        let mut they_send_logs = false;
        for vault in store.list_vaults().await? {
            if vault.policy != Policy::Federated || !vault.holds(me) || !vault.holds(peer.id) {
                continue;
            }
            let waiting = self.waiting_for(peer.id, vault.owner).await?;
            activity.lag_changes = activity.lag_changes.saturating_add(waiting.changes);
            let age = waiting.oldest_at.map_or(0, |at| now.saturating_sub(at));
            activity.lag_seconds = Some(activity.lag_seconds.map_or(age, |seen| seen.max(age)));
            if let Some(at) = store.newest_change_from(vault.owner, peer.id).await?
                && activity.last_change_at.is_none_or(|seen| at > seen)
            {
                activity.last_change_at = Some(at);
                activity.last_change_vault = Some(vault.owner);
            }
            if switches.pull && !they_send_logs {
                they_send_logs = store
                    .peer_events(vault.owner, EVENTS_LOOKED_AT)
                    .await?
                    .iter()
                    .any(|e| e.from == peer.id);
            }
        }
        Ok((activity, they_send_logs))
    }

    /// The vaults an admin may federate: those homed here that no peer holds yet (a vault with a
    /// Local policy row counts: it never left). A vault's name is ciphertext, so each is named by
    /// its owner's email when it has one.
    pub async fn shareable(&self) -> Result<Vec<VaultInfo>> {
        let federated: HashSet<Owner> = self
            .replica
            .store()
            .list_vaults()
            .await?
            .into_iter()
            .filter(|v| v.policy == Policy::Federated)
            .map(|v| v.owner)
            .collect();
        Ok(self
            .replica
            .store()
            .local_vaults()
            .await?
            .into_iter()
            .filter(|v| !federated.contains(&v.vault))
            .collect())
    }

    /// The offers other homes made, answered or not.
    pub async fn offers(&self) -> Result<Vec<StoredOffer>> {
        Ok(self.replica.store().list_offers().await?)
    }

    /// Sets a vault's policy at its home, and for a federated one the replicas in the order
    /// devices fail over to them. Each replica's admin must accept the vault before anything is
    /// copied. A vault is Local until an admin says otherwise; making it Local again stops copying
    /// at once but can't take back what a replica already holds.
    pub async fn set_policy(
        &self,
        owner: Owner,
        policy: Policy,
        replicas: Vec<ServerId>,
    ) -> Result<VaultFederation> {
        let me = self.me();
        let existing = self.replica.store().get_vault(owner).await?;
        match &existing {
            Some(v) if v.home != me => {
                return Err(FedError::Refused("only a vault's home changes its policy"));
            }
            Some(_) => {}
            None => {
                if !self.replica.store().owns_vault(owner).await? {
                    return Err(FedError::UnknownVault);
                }
            }
        }
        let epoch = existing.as_ref().map_or(1, |v| v.epoch);
        let promotion = existing.as_ref().and_then(|v| v.promotion.clone());
        let home_history = existing
            .as_ref()
            .map(|v| v.home_history.clone())
            .unwrap_or_default();
        let vault = match policy {
            Policy::Local => VaultFederation {
                owner,
                policy: Policy::Local,
                home: me,
                epoch,
                replicas: Vec::new(),
                promotion,
                // A changed set no longer fits a held demotion's record, so it goes.
                held_demotion: None,
                home_history,
            },
            Policy::Federated => {
                if replicas.is_empty() || replicas.len() > MAX_REPLICAS {
                    return Err(FedError::Refused(
                        "a federated vault needs 1 to 32 replicas",
                    ));
                }
                let mut seen = HashSet::new();
                for replica in &replicas {
                    if *replica == me || !seen.insert(*replica) {
                        return Err(FedError::Refused(
                            "the replicas must be other servers, each named once",
                        ));
                    }
                    let paired = self
                        .replica
                        .store()
                        .get_peer(*replica)
                        .await?
                        .is_some_and(|p| p.state == PeerState::Paired);
                    if !paired {
                        return Err(FedError::UnknownPeer);
                    }
                }
                VaultFederation {
                    owner,
                    policy: Policy::Federated,
                    home: me,
                    epoch,
                    replicas,
                    promotion,
                    // A changed set no longer fits a held demotion's record, so it goes.
                    held_demotion: None,
                    home_history,
                }
            }
        };
        self.replica.store().put_vault(&vault).await?;
        for peer in vault.replicas.iter() {
            self.runner.mark_dirty(*peer);
        }
        Ok(vault)
    }

    /// The admin of a replica accepts the vault a home offered: it is copied here from now on.
    pub async fn accept_offer(&self, vault: Owner) -> Result<VaultFederation> {
        let accepted = self.replica.accept_offer(vault).await?;
        self.runner.mark_dirty(accepted.home);
        Ok(accepted)
    }

    pub async fn decline_offer(&self, vault: Owner) -> Result<()> {
        self.replica.decline_offer(vault).await
    }

    /// Makes this server the home of `vault`, which it must hold as a replica: raises the epoch,
    /// signs the promotion record and puts this server first. The caller has checked the admin
    /// with a fresh passkey or password first. The record reaches the other servers at the next
    /// run for each (the old home gets it when it returns, and is fenced from then on). Returns
    /// the signed record.
    pub async fn promote(&self, vault: Owner, now: u64) -> Result<Vec<u8>> {
        let record = self.replica.promote(vault, now).await?;
        if let Some(settings) = self.replica.store().get_vault(vault).await? {
            for server in settings.order() {
                if server != self.me() {
                    self.runner.mark_dirty(server);
                }
            }
        }
        Ok(record)
    }

    /// Lets another server become the home of `vault`, which this server is the home of, by
    /// applying the promotion it sent ([`VaultFederation::held_demotion`]). The caller has checked
    /// the admin with a fresh passkey or password first. This server becomes the last replica.
    pub async fn accept_demotion(&self, vault: Owner) -> Result<VaultFederation> {
        let next = self.replica.accept_demotion(vault).await?;
        for server in next.order() {
            if server != self.me() {
                self.runner.mark_dirty(server);
            }
        }
        Ok(next)
    }

    /// Drops the promotion held for `vault` ([`VaultFederation::held_demotion`]) without applying
    /// it. The caller has checked the admin with a fresh passkey or password first.
    pub async fn refuse_demotion(&self, vault: Owner) -> Result<VaultFederation> {
        self.replica.refuse_demotion(vault).await
    }

    /// Every promotion held for this server's admin: the vault and what the record says.
    pub async fn held_promotions(&self) -> Result<Vec<(Owner, PromotionRecord)>> {
        self.replica.held_promotions().await
    }

    /// The address changes that came with peers' key rotations and wait for this server's admin.
    pub async fn pending_address_changes(&self) -> Result<Vec<PendingAddresses>> {
        self.replica.pending_address_changes().await
    }

    /// Accepts the address change that came with `peer`'s rotation: this server dials the new
    /// addresses from now on. The caller has checked the admin with a step-up token.
    pub async fn approve_address_change(&self, peer: ServerId) -> Result<()> {
        self.replica.approve_address_change(peer).await?;
        self.runner.mark_dirty(peer);
        Ok(())
    }

    /// Refuses the address change that came with `peer`'s rotation: the addresses stay.
    pub async fn refuse_address_change(&self, peer: ServerId) -> Result<()> {
        self.replica.refuse_address_change(peer).await
    }

    /// The event log entries peers sent for `vault`, newest first: what the switches allowed.
    pub async fn peer_events(&self, vault: Owner, limit: u32) -> Result<Vec<PeerEvent>> {
        Ok(self
            .replica
            .store()
            .peer_events(vault, limit.clamp(1, 500))
            .await?)
    }

    /// The home records of a vault that were made under an older epoch and not applied, for the
    /// vault's admins to redo or drop.
    pub async fn quarantined(&self, vault: Owner) -> Result<Vec<StoredHomeRecord>> {
        let mut records = self.replica.store().quarantined(vault).await?;
        records.retain(|r| r.status == HomeStatus::Quarantined);
        Ok(records)
    }

    // ---- reaching peers now ----

    /// Visits every paired peer now, as the replication job would, and says how each went. A peer
    /// another process is visiting is `Busy`.
    pub async fn check(&self, now: u64) -> Result<Vec<PeerCheck>> {
        let mut out = Vec::new();
        for peer in self.replica.store().list_peers().await? {
            if peer.state != PeerState::Paired {
                continue;
            }
            let (reach, detail) = match self.runner.run_peer(peer.id, now).await {
                Ok(RunOutcome::Done(_)) => (Reach::Reached, None),
                Ok(RunOutcome::Leased) => (Reach::Busy, None),
                Ok(RunOutcome::NotPaired) => (Reach::NotPaired, None),
                Err(FedError::KeyMismatch { .. }) => (Reach::KeyMismatch, None),
                Err(e) => (Reach::Unreachable, Some(reason(&e))),
            };
            out.push(PeerCheck {
                peer: peer.id,
                reach,
                detail,
            });
        }
        Ok(out)
    }

    /// Compares the hash trees of every vault shared with each paired peer now, whatever the hourly
    /// schedule says, and fetches what differs. A peer that is out of step is visited soon, which
    /// pushes what it lacks.
    pub async fn consistency(&self, now: u64) -> Result<Vec<PeerConsistency>> {
        let me = self.me();
        let store = self.replica.store();
        let vaults: Vec<VaultFederation> = store
            .list_vaults()
            .await?
            .into_iter()
            .filter(|v| v.policy == Policy::Federated && v.holds(me))
            .collect();
        let mut out = Vec::new();
        for peer in store.list_peers().await? {
            if peer.state != PeerState::Paired {
                continue;
            }
            let shared: Vec<Owner> = vaults
                .iter()
                .filter(|v| v.holds(peer.id))
                .map(|v| v.owner)
                .collect();
            let mut entry = PeerConsistency {
                peer: peer.id,
                reach: Reach::Reached,
                vaults: Vec::new(),
                detail: None,
            };
            if shared.is_empty() {
                entry.reach = Reach::NothingShared;
                out.push(entry);
                continue;
            }
            let lease = lease_name(peer.id);
            if !store
                .acquire_lease(&lease, CONSOLE_HOLDER, LEASE_SECS)
                .await?
            {
                entry.reach = Reach::Busy;
                out.push(entry);
                continue;
            }
            let connector = self.runner.connector();
            match connector.connect(&peer).await {
                Ok(mut channel) => {
                    let mut out_of_step = false;
                    for owner in shared {
                        match self.replica.reconcile(&mut channel, peer.id, owner).await {
                            Ok(report) => {
                                out_of_step |= !report.in_step;
                                entry.vaults.push(VaultComparison {
                                    vault: owner,
                                    in_step: Some(report.in_step),
                                    detail: None,
                                });
                            }
                            Err(e) => entry.vaults.push(VaultComparison {
                                vault: owner,
                                in_step: None,
                                detail: Some(reason(&e)),
                            }),
                        }
                    }
                    if let Err(e) = connector.close(channel).await {
                        tracing::debug!(error = %e, "a session did not close cleanly after a comparison");
                    }
                    if out_of_step {
                        self.runner.mark_dirty(peer.id);
                    }
                }
                Err(FedError::KeyMismatch { offered }) => {
                    entry.reach = Reach::KeyMismatch;
                    if let Err(e) = self.note_mismatch(&peer, &offered, None, now).await {
                        tracing::warn!(error = %e, "couldn't record a key mismatch");
                    }
                }
                Err(e) => {
                    entry.reach = Reach::Unreachable;
                    entry.detail = Some(reason(&e));
                }
            }
            if let Err(e) = store.drop_lease(&lease, CONSOLE_HOLDER).await {
                tracing::warn!(error = %e, "couldn't give back a peer lease");
            }
            out.push(entry);
        }
        Ok(out)
    }

    // ---- a peer's keys and descriptor ----

    /// The descriptor published by `peer`, read from the first of its addresses that answers.
    async fn fetch_descriptor(&self, peer: &Peer) -> Result<SignedDescriptor> {
        let mut last = FedError::Remote("the peer has no address".to_owned());
        let trusted = self
            .replica
            .store()
            .trusted_addresses(peer.id)
            .await
            .unwrap_or_default();
        for address in &peer.addresses {
            let trust = if trusted.iter().any(|t| addr::same_address(t, address)) {
                Trust::Admin
            } else {
                Trust::Descriptor
            };
            match self.descriptors.fetch(address, trust).await {
                Ok(descriptor) => return Ok(descriptor),
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    /// What is known of a peer's keys and descriptor. The descriptor is read from the peer afresh
    /// when it can be; one that verifies under the pinned key is kept (with when its KEM key was
    /// first seen), and when the peer can't be reached the last kept one is shown.
    pub async fn peer_security(&self, id: ServerId, now: u64) -> Result<PeerSecurityView> {
        let store = self.replica.store();
        let peer = store.get_peer(id).await?.ok_or(FedError::UnknownPeer)?;
        let pinned = peer.key()?;
        let kept = store.peer_security(id).await?;

        let mut fetch_error = None;
        let mut fetched_at = kept.as_ref().map(|k| k.fetched_at);
        let mut kem_first_seen = kept.as_ref().map(|k| k.kem_first_seen);
        let kept_key_id = kept.as_ref().map(|k| k.kem_key_id.clone());
        let descriptor = match self.fetch_descriptor(&peer).await {
            Ok(signed) => {
                fetched_at = Some(now);
                if signed.descriptor.identity_key != pinned {
                    let offered = signed.descriptor.identity_key.as_bytes().to_vec();
                    self.note_mismatch(&peer, &offered, None, now).await?;
                    kem_first_seen = None;
                } else if signed.verify(now, Some(&pinned)).is_ok() {
                    let key_id = kem_key_id(&signed.descriptor.kem_key);
                    let first_seen = if kept_key_id.as_deref() == Some(key_id.as_slice()) {
                        kem_first_seen.unwrap_or(now)
                    } else {
                        now
                    };
                    kem_first_seen = Some(first_seen);
                    store
                        .put_peer_security(&PeerSecurityRecord {
                            peer: id,
                            descriptor: signed.to_bytes(),
                            fetched_at: now,
                            kem_key_id: key_id.to_vec(),
                            kem_first_seen: first_seen,
                            suite: kept.as_ref().and_then(|k| k.suite.clone()),
                        })
                        .await?;
                } else {
                    kem_first_seen = None;
                }
                Some(signed)
            }
            Err(e) => {
                fetch_error = Some(reason(&e));
                kept.as_ref()
                    .and_then(|k| SignedDescriptor::parse(&k.descriptor).ok())
            }
        };

        let (descriptor_keys_match, signature_ok) = match &descriptor {
            Some(d) => (
                d.descriptor.identity_key == pinned,
                d.verify(now, None).is_ok(),
            ),
            None => (true, false),
        };
        let no_run_mismatch = self
            .runner
            .status_of(id)
            .is_none_or(|s| s.key_mismatch.is_none());

        let identity = self.replica.identity();
        let ours = identity.descriptor.descriptor.suites.clone();
        let theirs = descriptor
            .as_ref()
            .map_or_else(|| peer.suites.clone(), |d| d.descriptor.suites.clone());
        let in_use = crate::suite::negotiate(&theirs, &identity.suites())
            .ok()
            .map(|s| s.name().to_owned());
        let mut names: Vec<String> = theirs.clone();
        for name in ours
            .iter()
            .cloned()
            .chain(Suite::ALL.iter().map(|s| s.name().to_owned()))
        {
            if !names.contains(&name) {
                names.push(name);
            }
        }
        let place = |list: &[String], name: &str| {
            list.iter()
                .position(|n| n == name)
                .and_then(|i| u32::try_from(i + 1).ok())
        };
        let suites = names
            .iter()
            .map(|name| SuiteRow {
                theirs: place(&theirs, name),
                ours: place(&ours, name),
                in_use: in_use.as_deref() == Some(name.as_str()),
                name: name.clone(),
            })
            .collect();

        Ok(PeerSecurityView {
            keys_match: descriptor_keys_match && no_run_mismatch,
            signature_ok,
            kem_fingerprint: descriptor
                .as_ref()
                .map(|d| grouped_hex(&crate::crypto::sha256(d.descriptor.kem_key.as_bytes())[..8])),
            descriptor_bytes: descriptor.as_ref().map(SignedDescriptor::to_bytes),
            descriptor: descriptor.map(|d| d.descriptor),
            fetched_at,
            fetch_error,
            kem_first_seen,
            suites,
            last_handshake_at: peer.last_seen,
            peer,
        })
    }

    // ---- a key that is not the pinned one ----

    /// Keeps the record of a peer's key mismatch: a new key starts a record, the same key again
    /// adds an attempt (or takes the count `seen_attempts` of a run that kept its own).
    async fn note_mismatch(
        &self,
        peer: &Peer,
        offered: &[u8],
        seen_attempts: Option<u64>,
        at: u64,
    ) -> Result<MismatchRecord> {
        let store = self.replica.store();
        let held = store.mismatch(peer.id).await?;
        let source = peer.addresses.first().cloned().unwrap_or_default();
        let record = match &held {
            Some(h) if h.offered_key == offered => MismatchRecord {
                attempts: seen_attempts.map_or(h.attempts.saturating_add(1), |n| n.max(h.attempts)),
                last_at: at.max(h.last_at),
                source,
                ..h.clone()
            },
            _ => MismatchRecord {
                peer: peer.id,
                offered_key: offered.to_vec(),
                first_at: at,
                last_at: at,
                attempts: seen_attempts.unwrap_or(1).max(1),
                source,
                kept_blocking_at: None,
                kept_blocking_by: None,
            },
        };
        if held.as_ref() != Some(&record) {
            store.put_mismatch(&record).await?;
        }
        Ok(record)
    }

    /// The key a peer offered that was not the pinned one, when, and from where; `None` when the
    /// peer has not done so, or a later run got through with the pinned key. The key is only ever
    /// met by this server dialling the peer, so "from where" is the address dialled; a session a
    /// peer opens to this server is refused before it says which peer it is.
    pub async fn mismatch(&self, id: ServerId, now: u64) -> Result<Option<MismatchView>> {
        let store = self.replica.store();
        let peer = store.get_peer(id).await?.ok_or(FedError::UnknownPeer)?;
        let status = self.runner.status_of(id);
        let live = status
            .as_ref()
            .and_then(|s| s.key_mismatch.as_ref().map(|key| (s, key)));
        let record = if let Some((status, offered)) = live {
            let attempts = u64::from(status.consecutive_failures);
            self.note_mismatch(
                &peer,
                offered,
                Some(attempts),
                status.last_attempt.unwrap_or(now),
            )
            .await?
        } else {
            let Some(held) = store.mismatch(id).await? else {
                return Ok(None);
            };
            let got_through = status
                .as_ref()
                .and_then(|s| s.last_success)
                .is_some_and(|at| at >= held.last_at);
            if got_through {
                return Ok(None);
            }
            held
        };

        let me = self.me();
        let mut paused = Vec::new();
        for vault in store.list_vaults().await? {
            if vault.policy == Policy::Federated && vault.holds(me) && vault.holds(id) {
                paused.push(PausedVault {
                    vault: vault.owner,
                    info: store.vault_info(vault.owner).await?,
                    waiting: self.waiting_for(id, vault.owner).await?,
                });
            }
        }
        Ok(Some(MismatchView {
            pinned_key: peer.identity_key.clone(),
            pinned_at: peer.paired_at,
            seen_before: record.first_at < record.last_at,
            usual_addresses: peer.addresses.clone(),
            paused,
            local_vaults: self.shareable().await?.len() as u64,
            record,
            peer,
        }))
    }

    /// Records that an admin looked at the mismatch and chose to go on refusing the key. The
    /// pinned key stays and so does the refusal: this keeps the decision, who made it and when.
    pub async fn keep_blocking(&self, id: ServerId, by: &str, now: u64) -> Result<MismatchRecord> {
        let Some(view) = self.mismatch(id, now).await? else {
            return Err(FedError::UnknownPeer);
        };
        let mut record = view.record;
        record.kept_blocking_at = Some(now);
        record.kept_blocking_by = Some(by.chars().take(128).collect());
        self.replica.store().put_mismatch(&record).await?;
        Ok(record)
    }

    // ---- this server's own keys ----

    /// This server's identity, keys, descriptor and suites, as the console shows them.
    pub fn self_view(&self) -> SelfView {
        let identity = self.replica.identity();
        let d = &identity.descriptor.descriptor;
        let kem_made_at = self.rotator.as_ref().and_then(|r| r.kem_made_at());
        let ours = identity.suites();
        let mut suites: Vec<SuiteSetting> = ours
            .iter()
            .map(|s| SuiteSetting {
                suite: *s,
                on: true,
                available: s.available(),
            })
            .collect();
        for suite in Suite::ALL {
            if !ours.contains(&suite) {
                suites.push(SuiteSetting {
                    suite,
                    on: false,
                    available: suite.available(),
                });
            }
        }
        SelfView {
            server: identity.server,
            operator: d.operator.clone(),
            addresses: d.addresses.clone(),
            identity_key: identity.public.as_bytes().to_vec(),
            identity_fingerprint: grouped_hex(
                &crate::crypto::sha256(identity.public.as_bytes())[..16],
            ),
            descriptor: identity.descriptor.to_bytes(),
            valid_from: d.not_before,
            valid_to: d.not_after,
            kem_made_at,
            kem_next_rotation_at: kem_made_at.map(|t| t.saturating_add(KEM_ROTATION_SECS)),
            suites,
            profile: self.profile.clone(),
        }
    }

    /// Replaces the KEM key now, rather than at 30 days. The identity key and every pairing stay;
    /// the descriptor is signed afresh, and the old KEM key still opens a hello for the overlap.
    pub fn rotate_kem(&self, now: u64) -> Result<SelfView> {
        let rotator = self.rotator()?;
        let current = self.replica.identity();
        let replaced = rotator.rotate_kem(&current, now)?;
        self.replica.replace_identity(Arc::new(replaced))?;
        Ok(self.self_view())
    }

    /// Signs the descriptor afresh with `suites`, most preferred first. At least one must be a
    /// suite this build can run, and each is named once.
    pub fn choose_suites(&self, suites: &[Suite], now: u64) -> Result<SelfView> {
        if !suites.iter().any(|s| s.available()) {
            return Err(FedError::Refused(
                "keep at least one suite this build can run",
            ));
        }
        let mut seen = HashSet::new();
        if !suites.iter().all(|s| seen.insert(*s)) {
            return Err(FedError::Refused("name each suite once"));
        }
        let rotator = self.rotator()?;
        let current = self.replica.identity();
        let changed = rotator.set_suites(&current, suites, now)?;
        self.replica.replace_identity(Arc::new(changed))?;
        Ok(self.self_view())
    }
}
