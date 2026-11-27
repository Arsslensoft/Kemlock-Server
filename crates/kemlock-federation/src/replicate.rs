//! Replication: what a server does when a peer asks (`serve`), and what it does to catch up with
//! a peer (`pull`, `reconcile`, `pull_home_records`, `nudge`, `announce`).
//!
//! It is written over the storage ports and a [`Channel`], so it runs the same over a real
//! session or an in-process one in the tests.
//!
//! - Items replicate from any server holding the vault: a peer pulls the versions its cursor
//!   doesn't cover, every record verified against its origin's signature before it is applied.
//! - Home-only records (members, roles, keys, policies) are fenced by the vault's epoch.
//! - A peer may only read or write a vault if it is in the vault's set (its home and replicas).

use crate::blobs::BlobFiles;
use crate::change::{self, ChangeRecord};
use crate::conflict::Rank;
use crate::descriptor::SignedDescriptor;
use crate::error::{FedError, Result};
use crate::eventsync::EventSync;
use crate::extra::{
    BlobSync, ErasureOutbox, FedAdminRepo, MemberStore, PromotionMode, VaultErasure,
};
use crate::forget::Forgetting;
use crate::frame::Padding;
use crate::hashtree::{self, Tree};
use crate::home::{self, HomeRecord, Policy, PromotionRecord, VaultFederation, Verdict};
use crate::identity::LocalIdentity;
use crate::keyrecs::KeyStore;
use crate::message::{MAX_LEAVES, MAX_PAGE, MAX_PAGES_PER_VISIT, Request, Response, code};
use crate::outbox::Withholding;
use crate::ports::{
    ApplyOutcome, Exported, HomeStatus, Peer, PeerRepo, PeerState, ReplicaStore, StoredHomeRecord,
    VaultRepo,
};
use crate::quota::{Admission, Meter, Quota, WorkLimits, WorkMeter};
use crate::relay::OriginKeys;
use crate::sendsync::SendSync;
use crate::signed::Signed;
use crate::spaces::SpaceMirror;
use crate::tagsync::TagSync;
use crate::writes;
use kemlock_app::ports::StoreError;
use kemlock_crypto::sig1;
use kemlock_domain::{ItemId, Owner, ServerId, VersionVector};
use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, PoisonError, RwLock};

/// Everything federation needs from storage.
pub trait FedStore:
    ReplicaStore
    + VaultRepo
    + PeerRepo
    + FedAdminRepo
    + MemberStore
    + BlobSync
    + ErasureOutbox
    + VaultErasure
    + SpaceMirror
    + EventSync
    + Forgetting
    + KeyStore
    + OriginKeys
    + TagSync
    + SendSync
    + Withholding
{
}
impl<
    T: ReplicaStore
        + VaultRepo
        + PeerRepo
        + FedAdminRepo
        + MemberStore
        + BlobSync
        + ErasureOutbox
        + VaultErasure
        + SpaceMirror
        + EventSync
        + Forgetting
        + KeyStore
        + OriginKeys
        + TagSync
        + SendSync
        + Withholding,
> FedStore for T
{
}

/// A pull page stops growing past this many bytes, so a frame stays far below its cap.
const PAGE_BYTES: usize = 1_500_000;
/// How many items one fetch asks for.
const FETCH_CHUNK: usize = 256;
/// The most quarantined home records one vault keeps; a stale-epoch record past it is dropped.
const MAX_QUARANTINED: usize = 256;
/// The most of them one signer may hold when who was the home of the record's epoch isn't known
/// (a missed promotion): any member of the set could sign such records, so one can't fill the
/// quarantine and push out the others'.
const MAX_QUARANTINED_PER_SIGNER: usize = 32;

/// Sends a request to a peer and returns its response.
pub trait Channel: Send {
    fn call(&mut self, request: &Request) -> impl Future<Output = Result<Response>> + Send;
}

/// How many records of each outcome a pull or fetch applied.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    /// Records that became the head of their item.
    pub applied: usize,
    /// Records kept beside a head: conflicts.
    pub siblings: usize,
    /// Records already held or replaced.
    pub duplicates: usize,
    /// Records left out: an item id another owner holds, a change from the future, a record whose
    /// origin signature no key of the origin's verifies, a writer signature that is missing or
    /// doesn't verify, an origin over its quota, and a rollback.
    pub refused: usize,
    /// Of the refused, the ones a later comparison may apply: a change from the future or past an
    /// origin's quota, an origin whose key hasn't arrived, a writer whose keys or space membership
    /// haven't arrived. The rest (a bad
    /// signature, an unsigned change for a signed-only owner, a rollback) will be refused again, so
    /// a pull that left only those has nothing to compare.
    pub retry: usize,
}

impl Counts {
    pub fn add(&mut self, other: &Counts) {
        self.applied += other.applied;
        self.siblings += other.siblings;
        self.duplicates += other.duplicates;
        self.refused += other.refused;
        self.retry += other.retry;
    }
}

/// The outcome of [`Replica::pull`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PullReport {
    pub counts: Counts,
    pub pages: usize,
}

/// The outcome of [`Replica::reconcile`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReconcileReport {
    /// The roots matched: nothing to do.
    pub in_step: bool,
    /// What fetching the differing items applied.
    pub fetched: Counts,
    /// Items we hold that the peer lacks or holds differently: nudge it to pull.
    pub to_push: Vec<ItemId>,
}

/// The outcome of [`Replica::pull_home_records`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HomeSync {
    pub applied: usize,
    pub quarantined: usize,
    /// Records left out: an index that doesn't belong to its epoch, a stale-epoch record from a
    /// server that wasn't the home of that epoch, one that collides with another server's record
    /// at the same index, and ones past the quarantine cap.
    pub refused: usize,
    /// A record came from a newer epoch than ours: a promotion was missed.
    pub behind: bool,
}

/// The answer to a request, and a vault to pull if the request showed the peer has more.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Served {
    pub response: Response,
    pub pull: Option<Owner>,
}

/// This server's federation engine over a store.
pub struct Replica<S> {
    pub(crate) store: S,
    identity: RwLock<Arc<LocalIdentity>>,
    pub(crate) padding: Padding,
    pub(crate) files: Option<Arc<dyn BlobFiles>>,
    quota: Quota,
    meter: Meter,
    pub(crate) work: WorkMeter,
    pub(crate) work_limits: WorkLimits,
}

impl<S> std::fmt::Debug for Replica<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Replica").finish_non_exhaustive()
    }
}

fn error_response(e: &FedError) -> Response {
    match e {
        FedError::UnknownVault => Response::error(code::UNKNOWN_VAULT, "unknown vault"),
        FedError::Refused(why) => Response::error(code::REFUSED, why),
        FedError::UnknownPeer => Response::error(code::REFUSED, "unknown peer"),
        FedError::Malformed(why) | FedError::Invalid(why) => {
            Response::error(code::BAD_REQUEST, why)
        }
        other => {
            tracing::warn!(error = %other, "a federation request failed");
            Response::error(code::INTERNAL, "internal error")
        }
    }
}

fn expect_changes(response: Response, vault: Owner) -> Result<(Vec<Vec<u8>>, VersionVector, bool)> {
    match response {
        Response::Changes {
            vault: v,
            records,
            next,
            more,
        } if v == vault => Ok((records, next, more)),
        Response::Error { detail, .. } => Err(FedError::Remote(detail)),
        _ => Err(FedError::Malformed("an unexpected response")),
    }
}

impl<S: FedStore> Replica<S> {
    pub fn new(store: S, identity: Arc<LocalIdentity>) -> Replica<S> {
        Replica {
            store,
            identity: RwLock::new(identity),
            padding: Padding::Step4096,
            files: None,
            quota: Quota::default(),
            meter: Meter::default(),
            work: WorkMeter::default(),
            work_limits: WorkLimits::default(),
        }
    }

    /// Gives the engine this server's file storage, so it serves and fetches attachments.
    pub fn with_blob_files(mut self, files: Arc<dyn BlobFiles>) -> Replica<S> {
        self.files = Some(files);
        self
    }

    /// Sets what one origin may write to this server (docs/federation.md, "Per-origin quotas").
    pub fn with_quota(mut self, quota: Quota) -> Replica<S> {
        self.quota = quota;
        self
    }

    /// Sets what one peer may make this server read or scan (docs/federation.md, "Amplification").
    pub fn with_work_limits(mut self, limits: WorkLimits) -> Replica<S> {
        self.work_limits = limits;
        self
    }

    /// Turns frame padding off or on (on by default).
    pub fn with_padding(mut self, padding: Padding) -> Replica<S> {
        self.padding = padding;
        self
    }

    pub fn store(&self) -> &S {
        &self.store
    }

    /// This server's identity as it is now: a refresh replaces it (see
    /// [`replace_identity`](Self::replace_identity)), so callers hold the `Arc` only for as long as
    /// they use it.
    pub fn identity(&self) -> Arc<LocalIdentity> {
        self.identity
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Swaps in a refreshed identity: a descriptor signed afresh, or a new KEM key. The server id
    /// and the identity key must not change (a new key means pairing again).
    pub fn replace_identity(&self, identity: Arc<LocalIdentity>) -> Result<()> {
        let mut current = self
            .identity
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        if current.server != identity.server || current.public != identity.public {
            return Err(FedError::Invalid(
                "a refresh must keep the server id and the identity key",
            ));
        }
        *current = identity;
        Ok(())
    }

    /// Installs an identity with a new signing key, after a rotation or a revocation made its
    /// record. [`replace_identity`](Self::replace_identity) refuses such a change.
    pub(crate) fn set_identity(&self, identity: Arc<LocalIdentity>) {
        *self
            .identity
            .write()
            .unwrap_or_else(PoisonError::into_inner) = identity;
    }

    pub fn server_id(&self) -> ServerId {
        self.identity().server
    }

    /// Whether every paired server of `vault`'s set, this one aside, says in its descriptor that it
    /// understands `capability`. A vault nobody else holds has no one to disagree.
    pub async fn vault_advertises(&self, vault: Owner, capability: &str) -> Result<bool> {
        let Some(settings) = self.store.get_vault(vault).await? else {
            return Ok(true);
        };
        let me = self.server_id();
        Ok(self.store.list_peers().await?.iter().all(|peer| {
            peer.id == me
                || peer.state != PeerState::Paired
                || !settings.holds(peer.id)
                || peer.advertises(capability)
        }))
    }

    /// The identity keys of the peers we are paired with: who may open a session.
    pub(crate) async fn peer_keys(&self) -> Result<HashMap<ServerId, sig1::PublicKey>> {
        let mut keys = HashMap::new();
        for peer in self.store.list_peers().await? {
            if peer.state == PeerState::Paired {
                keys.insert(peer.id, peer.key()?);
            }
        }
        Ok(keys)
    }

    /// Pins a peer after pairing: stores its identity key and what its descriptor says.
    pub async fn pin_peer(&self, descriptor: &SignedDescriptor, now: u64) -> Result<Peer> {
        let d = &descriptor.descriptor;
        if d.server == self.server_id() {
            return Err(FedError::Refused("a server can't pair with itself"));
        }
        let peer = Peer {
            id: d.server,
            operator: d.operator.clone(),
            identity_key: d.identity_key.as_bytes().to_vec(),
            addresses: d.addresses.clone(),
            suites: d.suites.clone(),
            state: PeerState::Paired,
            paired_at: now,
            last_seen: None,
        };
        self.store.insert_peer(&peer).await?;
        Ok(peer)
    }

    /// Federates one of this server's own vaults to `replicas`, in that order. This server is
    /// the home. Each replica's admin must accept it with [`accept_vault`](Self::accept_vault).
    pub async fn federate(&self, owner: Owner, replicas: Vec<ServerId>) -> Result<VaultFederation> {
        let vault = VaultFederation::federated(owner, self.server_id(), replicas);
        self.store.put_vault(&vault).await?;
        Ok(vault)
    }

    /// Accepts holding a replica of a vault whose home is `home`: this server's admin consents to
    /// the storage, the metadata and the responsibility.
    pub async fn accept_vault(
        &self,
        owner: Owner,
        home: ServerId,
        replicas: Vec<ServerId>,
    ) -> Result<VaultFederation> {
        let vault = VaultFederation::federated(owner, home, replicas);
        if !vault.holds(self.server_id()) {
            return Err(FedError::Refused("this server is not in the vault's set"));
        }
        self.store.put_vault(&vault).await?;
        Ok(vault)
    }

    /// The vault's settings if this server federates it and `peer` is paired and in its set.
    pub(crate) async fn authorize(&self, peer: ServerId, vault: Owner) -> Result<VaultFederation> {
        let settings = self
            .store
            .get_vault(vault)
            .await?
            .filter(|v| v.policy == Policy::Federated && v.holds(self.server_id()))
            .ok_or(FedError::UnknownVault)?;
        let paired = self
            .store
            .get_peer(peer)
            .await?
            .is_some_and(|p| p.state == PeerState::Paired);
        if !paired {
            return Err(FedError::UnknownPeer);
        }
        if !settings.holds(peer) {
            return Err(FedError::Refused("the peer is not in the vault's set"));
        }
        Ok(settings)
    }

    // ---- serving ----

    /// Answers one request from `peer`.
    pub async fn serve(&self, peer: ServerId, request: &Request, now: u64) -> Served {
        match self.serve_inner(peer, request, now).await {
            Ok(served) => served,
            Err(e) => Served {
                response: error_response(&e),
                pull: None,
            },
        }
    }

    async fn serve_inner(&self, peer: ServerId, request: &Request, now: u64) -> Result<Served> {
        let answer = |response: Response| Served {
            response,
            pull: None,
        };
        match request {
            Request::Pull {
                vault,
                since,
                limit,
            } => {
                self.authorize(peer, *vault).await?;
                let page = self
                    .store
                    .export_since(*vault, since, (*limit).min(MAX_PAGE))
                    .await?;
                let mut next = since.clone();
                let mut records = Vec::new();
                let mut bytes = 0usize;
                let mut cut = false;
                // Versions this server was told not to send this peer (see `outbox`) are passed
                // over: the cursor moves past them, so the peer doesn't ask for them again.
                let withheld = self.store.withheld(peer, *vault).await?;
                for entry in &page.entries {
                    if withheld
                        .as_ref()
                        .is_some_and(|w| w.covers(&entry.item.change))
                    {
                        next.observe(&entry.item.change);
                        continue;
                    }
                    let envelope = self.signed_record(entry).await?;
                    if !records.is_empty() && bytes + envelope.len() > PAGE_BYTES {
                        cut = true;
                        break;
                    }
                    bytes += envelope.len();
                    next.observe(&entry.item.change);
                    records.push(envelope);
                }
                Ok(answer(Response::Changes {
                    vault: *vault,
                    records,
                    next,
                    more: page.more || cut,
                }))
            }
            Request::Nudge { vault, latest } => {
                self.authorize(peer, *vault).await?;
                let ours = self.store.latest(*vault).await?;
                Ok(Served {
                    response: Response::Ack,
                    pull: (!ours.dominates(latest)).then_some(*vault),
                })
            }
            Request::Summary { vault } => {
                self.authorize(peer, *vault).await?;
                self.admit_scan(peer, *vault, now)?;
                let tree = Tree::build(&self.store.leaves(*vault).await?);
                Ok(answer(Response::Summary {
                    vault: *vault,
                    root: tree.root,
                    buckets: tree.buckets,
                }))
            }
            Request::Leaves { vault, buckets } => {
                self.authorize(peer, *vault).await?;
                self.admit_scan(peer, *vault, now)?;
                let leaves: Vec<_> = self
                    .store
                    .leaves(*vault)
                    .await?
                    .into_iter()
                    .filter(|l| buckets.contains(&hashtree::bucket_of(l.item)))
                    .collect();
                if leaves.len() > MAX_LEAVES {
                    return Err(FedError::Refused("too many leaves: ask for fewer buckets"));
                }
                Ok(answer(Response::Leaves {
                    vault: *vault,
                    leaves,
                }))
            }
            Request::Fetch { vault, items } => {
                self.authorize(peer, *vault).await?;
                let mut records = Vec::new();
                let mut bytes = 0usize;
                let mut cut = false;
                let withheld = self.store.withheld(peer, *vault).await?;
                for entry in self.store.export_items(*vault, items).await? {
                    if withheld
                        .as_ref()
                        .is_some_and(|w| w.covers(&entry.item.change))
                    {
                        continue;
                    }
                    let envelope = self.signed_record(&entry).await?;
                    // A page stops growing at the same size a pull's does; what is left is asked
                    // for again (the answer says there is more).
                    if !records.is_empty() && bytes + envelope.len() > PAGE_BYTES {
                        cut = true;
                        break;
                    }
                    bytes += envelope.len();
                    records.push(envelope);
                }
                Ok(answer(Response::Changes {
                    vault: *vault,
                    records,
                    next: VersionVector::new(),
                    more: cut,
                }))
            }
            Request::HomeRecords {
                vault,
                after,
                limit,
            } => {
                self.authorize(peer, *vault).await?;
                let wanted = (*limit).min(MAX_PAGE);
                let mut stored = self
                    .store
                    .home_records(*vault, *after, wanted.saturating_add(1))
                    .await?;
                let more = stored.len() > usize::try_from(wanted).unwrap_or(usize::MAX);
                stored.truncate(usize::try_from(wanted).unwrap_or(usize::MAX));
                // Quarantined records stay with the vault's admins; peers get the applied ones.
                let records = stored
                    .into_iter()
                    .filter(|r| r.status == HomeStatus::Applied)
                    .map(|r| r.signed)
                    .collect();
                Ok(answer(Response::HomeRecords {
                    vault: *vault,
                    records,
                    more,
                }))
            }
            Request::Promote { record } => {
                let keys = self.directory().await?;
                let promotion = home::open_promotion(record, &keys)?;
                let current = self
                    .store
                    .get_vault(promotion.vault)
                    .await?
                    .ok_or(FedError::UnknownVault)?;
                if !current.holds(peer) {
                    return Err(FedError::Refused("the peer is not in the vault's set"));
                }
                let mut next = home::apply_promotion(&current, &promotion)?;
                // A promotion that takes the home away from this server waits for this server's
                // admin. Applied at once, any replica (or anyone holding its key) could make
                // itself the home of every vault it holds, and then, as the home, erase this
                // server's copy.
                // Every other replica holds it too, unless the setting `federation_promotion` says
                // `auto`: a replica that signs a promotion unasked (or whose key was stolen)
                // would otherwise become the home of the vault here at once, and "first to
                // arrive wins" would let it win.
                let is_home = current.home == self.server_id();
                if is_home || self.store.promotion_mode().await? == PromotionMode::Hold {
                    // One promotion is held for each server that would become the home. A later
                    // one from the same server replaces its own, never another's, so repeating an
                    // announcement can't push the legitimate one out; one that no longer fits the
                    // vault (an epoch already passed) is dropped.
                    let mut held = current.held_demotion.clone();
                    held.retain(|r| {
                        home::peek_promotion(r).is_ok_and(|p| {
                            p.new_home != promotion.new_home
                                && home::apply_promotion(&current, &p).is_ok()
                        })
                    });
                    held.push(record.clone());
                    if held != current.held_demotion {
                        let held = VaultFederation {
                            held_demotion: held,
                            ..current
                        };
                        self.store.put_vault(&held).await?;
                    }
                    return Err(FedError::Refused(if is_home {
                        "this server is the vault's home: its admin must accept the promotion"
                    } else {
                        "this server's admin must accept the promotion"
                    }));
                }
                next.promotion = Some(record.clone());
                self.store.put_vault(&next).await?;
                Ok(answer(Response::Ack))
            }
            Request::Bye => Ok(answer(Response::Ack)),
            Request::Offer {
                vault,
                home,
                epoch,
                replicas,
            } => {
                let state = self
                    .receive_offer(peer, *vault, *home, *epoch, replicas, now)
                    .await?;
                Ok(answer(Response::OfferStatus {
                    vault: *vault,
                    state,
                }))
            }
            Request::Blobs {
                vault,
                after,
                limit,
            } => {
                self.authorize(peer, *vault).await?;
                Ok(answer(self.serve_blob_list(*vault, *after, *limit).await?))
            }
            Request::Blob {
                vault,
                blob,
                offset,
                len,
            } => {
                self.authorize(peer, *vault).await?;
                Ok(answer(
                    self.serve_blob_chunk(peer, *vault, *blob, *offset, *len, now)
                        .await?,
                ))
            }
            Request::Erase { vault } => {
                self.receive_erasure(peer, *vault).await?;
                Ok(answer(Response::Ack))
            }
            Request::Events {
                vault,
                after,
                limit,
            } => {
                self.authorize(peer, *vault).await?;
                Ok(answer(
                    self.serve_events(peer, *vault, *after, *limit).await?,
                ))
            }
            Request::Forget { notice } => Ok(answer(self.receive_forget(peer, notice, now).await?)),
            Request::OriginKeys { vault } => {
                Ok(answer(self.serve_origin_keys(peer, *vault).await?))
            }
            Request::Tags { vault, items } => {
                self.authorize(peer, *vault).await?;
                Ok(answer(self.serve_tags(peer, *vault, items).await?))
            }
            Request::Sends {
                vault,
                after,
                limit,
            } => {
                self.authorize(peer, *vault).await?;
                Ok(answer(
                    self.serve_sends(peer, *vault, *after, *limit).await?,
                ))
            }
        }
    }

    /// Counts one scan of `vault` for `peer`: a summary or a list of leaves reads every item of the
    /// vault, so one peer may ask for only so many in a window.
    fn admit_scan(&self, peer: ServerId, vault: Owner, now: u64) -> Result<()> {
        if self.work.allow_scan(&self.work_limits, peer, vault, now) {
            Ok(())
        } else {
            Err(FedError::Refused("too many comparisons of this vault: try later"))
        }
    }

    /// The signed envelope of a stored version, signing it first if this server accepted it and
    /// hasn't sent it before.
    async fn signed_record(&self, entry: &Exported) -> Result<Vec<u8>> {
        let record = ChangeRecord::from_item(&entry.item, entry.lineage.clone())
            .in_collection(entry.collection);
        let signature = match &entry.signature {
            Some(signature) => signature.clone(),
            None => {
                if record.change.origin != self.server_id() {
                    return Err(FedError::Refused(
                        "a replicated change is held without its origin's signature",
                    ));
                }
                let signed = record.sign(&self.identity().signing)?;
                self.store
                    .store_signature(record.key(), &record.lineage, &signed.signature)
                    .await?;
                signed.signature
            }
        };
        Ok(Signed {
            body: record.to_body(),
            signature,
        }
        .encode())
    }

    // ---- catching up ----

    /// How this server ranks the versions of `vault`: by revision from the first time every server
    /// of its set advertises it, and by revision from then on.
    pub(crate) async fn rank_of(&self, vault: Owner) -> Result<Rank> {
        if self.store.revision_ranked(vault).await? {
            return Ok(Rank::Revision);
        }
        if self
            .vault_advertises(vault, writes::SIGNED_WRITES_CAPABILITY)
            .await?
        {
            self.store.pin_revision_ranking(vault).await?;
            return Ok(Rank::Revision);
        }
        Ok(Rank::Clock)
    }

    /// Opens a record: the origin's signature checked with the key we hold for it, or with one it
    /// used before and replaced, for a record dated up to then. `None` when no key verifies it (an
    /// origin whose key we don't hold, a revoked or unpaired one, a forgery, garbage), with whether a
    /// later comparison may apply it once the origin's key arrives.
    async fn open_envelope(
        &self,
        envelope: &[u8],
        keys: &HashMap<ServerId, sig1::PublicKey>,
    ) -> Result<std::result::Result<ChangeRecord, bool>> {
        let failure = match change::open(envelope, keys) {
            Ok(record) => return Ok(Ok(record)),
            Err(e) => e,
        };
        let Ok(origin) = change::claimed_origin(envelope) else {
            tracing::warn!(error = %failure, "a change that does not parse was left out");
            return Ok(Err(false));
        };
        let past: Vec<(Vec<u8>, u64)> = self
            .store
            .past_keys(origin)
            .await?
            .into_iter()
            .map(|past| (past.key, past.replaced_at))
            .collect();
        if !past.is_empty()
            && let Ok(record) = change::open_with_past_keys(envelope, &past)
        {
            return Ok(Ok(record));
        }
        tracing::warn!(%origin, error = %failure, "a change that can't be verified was left out");
        // An origin whose key may still arrive (a peer vouches for it) is worth asking for again.
        Ok(Err(!keys.contains_key(&origin)))
    }

    /// Verifies and applies records of `vault`. A record that no key of its origin verifies is left
    /// out and counted, and the rest of the batch goes on: one record that can never be checked
    /// (signed by a key since replaced or revoked) must not hold the cursor, and every replica
    /// behind it, still.
    pub(crate) async fn apply_envelopes(
        &self,
        from: ServerId,
        vault: Owner,
        envelopes: &[Vec<u8>],
    ) -> Result<Counts> {
        let keys = self.directory().await?;
        let direct = self.peer_keys().await?;
        let settings = self
            .store
            .get_vault(vault)
            .await?
            .ok_or(FedError::UnknownVault)?;
        let me = self.server_id();
        let now_ms = crate::session::unix_now().saturating_mul(1000);
        // The head is chosen by revision first once every server of the vault says it ranks so
        // (`x-kemlock-signed-writes1`): servers must agree on the head, and one that ranks by clock
        // alone would pick another. Once on it stays on for the vault: a server of the set that
        // later leaves the capability out of its own descriptor must not turn rollback protection
        // off for the rest.
        let rank = self.rank_of(vault).await?;
        let mut counts = Counts::default();
        for envelope in envelopes {
            let record = match self.open_envelope(envelope, &keys).await? {
                Ok(record) => record,
                Err(retry) => {
                    counts.refused += 1;
                    counts.retry += usize::from(retry);
                    continue;
                }
            };
            if record.owner != vault {
                return Err(FedError::Invalid("a record for another vault"));
            }
            // A time far ahead of our clock would raise it with the record. The record is left
            // out and the rest of the batch goes on, so one bad record doesn't stop the sync; a
            // later comparison fetches it again, once the clock has caught up.
            if change::check_not_future(&record, now_ms).is_err() {
                tracing::warn!(origin = %record.change.origin, "a change with a time far ahead of this server's clock was refused");
                counts.refused += 1;
                counts.retry += 1;
                continue;
            }
            // A relayed change is accepted from an origin we are paired with or one in the vault's
            // set (whose key a peer vouched for), and from no other.
            let origin = record.change.origin;
            if origin != me && !direct.contains_key(&origin) && !settings.holds(origin) {
                return Err(FedError::Refused(
                    "a change from an origin outside the vault's set",
                ));
            }
            // A change is applied once: one already held costs nothing, so a peer that sends the
            // same records again (a comparison fetches whatever differs) can't use up the quota of
            // the origin it relays, which would keep that origin's new changes out.
            if self.store.holds_change(record.key()).await? {
                counts.duplicates += 1;
                continue;
            }
            // What one origin may write through the server that sent it, before the expensive
            // checks: a flood is cut off here, and what one peer relays doesn't spend what another
            // does.
            match self
                .meter
                .admit(&self.quota, from, origin, envelope.len(), now_ms / 1000)
            {
                Admission::Admitted => {}
                over => {
                    tracing::warn!(%origin, ?over, "a change past the origin's quota was refused");
                    counts.refused += 1;
                    counts.retry += 1;
                    continue;
                }
            }
            // The writing account's signature: the origin's signature says which server accepted
            // the write, this says who made it.
            match writes::judge(&self.store, &record).await? {
                writes::Verdict::Accept => {}
                writes::Verdict::Refuse(why) => {
                    tracing::warn!(%origin, why, "a change was refused");
                    counts.refused += 1;
                    continue;
                }
                writes::Verdict::Defer(why) => {
                    tracing::warn!(%origin, why, "a change was left out for now");
                    counts.refused += 1;
                    counts.retry += 1;
                    continue;
                }
            }
            let signature = Signed::decode(envelope)?.signature;
            match self.store.apply_ranked(&record, &signature, rank).await {
                Ok(ApplyOutcome::Applied) => counts.applied += 1,
                Ok(ApplyOutcome::Sibling) => counts.siblings += 1,
                Ok(ApplyOutcome::Duplicate) => counts.duplicates += 1,
                Ok(ApplyOutcome::Refused) => counts.refused += 1,
                Err(StoreError::Duplicate) => counts.refused += 1,
                Err(e) => return Err(e.into()),
            }
        }
        Ok(counts)
    }

    /// Pulls everything `peer` holds of `vault` that we haven't seen, page by page, and moves our
    /// cursor for that peer after each page.
    pub async fn pull<C: Channel>(
        &self,
        channel: &mut C,
        peer: ServerId,
        vault: Owner,
    ) -> Result<PullReport> {
        self.authorize(peer, vault).await?;
        let mut report = PullReport {
            counts: Counts::default(),
            pages: 0,
        };
        loop {
            let since = self.store.peer_cursor(peer, vault).await?;
            let response = channel
                .call(&Request::Pull {
                    vault,
                    since: since.clone(),
                    limit: MAX_PAGE,
                })
                .await?;
            let (records, next, more) = expect_changes(response, vault)?;
            let counts = self.apply_envelopes(peer, vault, &records).await?;
            report.counts.add(&counts);
            let mut cursor = since.clone();
            cursor.merge(&next);
            self.store.set_peer_cursor(peer, vault, &cursor).await?;
            report.pages += 1;
            if !more {
                return Ok(report);
            }
            if report.pages >= MAX_PAGES_PER_VISIT {
                // Enough for one visit: the rest comes at the next, and the cursor is kept.
                tracing::info!(%peer, pages = report.pages, "a pull stopped at its page limit");
                return Ok(report);
            }
            if cursor == since {
                return Err(FedError::Refused("the peer has more but sent nothing new"));
            }
        }
    }

    /// Tells `peer` what we hold of `vault`, so it pulls.
    pub async fn nudge<C: Channel>(&self, channel: &mut C, vault: Owner) -> Result<()> {
        let latest = self.store.latest(vault).await?;
        match channel.call(&Request::Nudge { vault, latest }).await? {
            Response::Ack => Ok(()),
            Response::Error { detail, .. } => Err(FedError::Remote(detail)),
            _ => Err(FedError::Malformed("an unexpected response to a nudge")),
        }
    }

    /// Compares hash-tree summaries of `vault` with `peer`'s and fetches the items that differ.
    pub async fn reconcile<C: Channel>(
        &self,
        channel: &mut C,
        peer: ServerId,
        vault: Owner,
    ) -> Result<ReconcileReport> {
        self.authorize(peer, vault).await?;
        let local = self.store.leaves(vault).await?;
        let tree = Tree::build(&local);
        let (root, buckets) = match channel.call(&Request::Summary { vault }).await? {
            Response::Summary {
                vault: v,
                root,
                buckets,
            } if v == vault => (root, buckets),
            Response::Error { detail, .. } => return Err(FedError::Remote(detail)),
            _ => return Err(FedError::Malformed("an unexpected response to a summary")),
        };
        if root == tree.root {
            return Ok(ReconcileReport {
                in_step: true,
                fetched: Counts::default(),
                to_push: Vec::new(),
            });
        }
        let differing = hashtree::differing_buckets(&tree.buckets, &buckets);
        let remote = match channel
            .call(&Request::Leaves {
                vault,
                buckets: differing.clone(),
            })
            .await?
        {
            Response::Leaves { vault: v, leaves } if v == vault => leaves,
            Response::Error { detail, .. } => return Err(FedError::Remote(detail)),
            _ => return Err(FedError::Malformed("an unexpected response to leaves")),
        };
        // Only the leaves of the buckets we asked about are comparable.
        let local_in_buckets: Vec<_> = local
            .into_iter()
            .filter(|l| differing.contains(&hashtree::bucket_of(l.item)))
            .collect();
        let remote: Vec<_> = remote
            .into_iter()
            .filter(|l| differing.contains(&hashtree::bucket_of(l.item)))
            .collect();
        let diff = hashtree::diff(&local_in_buckets, &remote);

        let mut fetched = Counts::default();
        for chunk in diff.fetch.chunks(FETCH_CHUNK) {
            let response = channel
                .call(&Request::Fetch {
                    vault,
                    items: chunk.to_vec(),
                })
                .await?;
            let (records, _, more) = expect_changes(response, vault)?;
            fetched.add(&self.apply_envelopes(peer, vault, &records).await?);
            if more {
                // The peer cut the answer short: what it left out is asked for at the next
                // comparison, which comes soon.
                fetched.retry += 1;
            }
        }
        Ok(ReconcileReport {
            in_step: false,
            fetched,
            to_push: diff.push,
        })
    }

    /// Pulls the home records of `vault` from `peer` and judges each by its epoch: records of the
    /// current epoch from the home are stored as applied, older ones are quarantined, and a newer
    /// one stops the sync with `behind` set.
    ///
    /// The cursor is the highest index among the records we hold that `peer` signed. An index
    /// carries its epoch, so a record the old home made after it was replaced sorts before the
    /// records of the new epoch we already hold; asking after our highest index would never find
    /// it, while asking after the peer's own last record does.
    pub async fn pull_home_records<C: Channel>(
        &self,
        channel: &mut C,
        peer: ServerId,
        vault: Owner,
    ) -> Result<HomeSync> {
        self.authorize(peer, vault).await?;
        let mut sync = HomeSync {
            applied: 0,
            quarantined: 0,
            refused: 0,
            behind: false,
        };
        let mut after = self
            .store
            .home_records(vault, 0, u32::MAX)
            .await?
            .iter()
            .filter(|r| r.record.signer == peer)
            .map(|r| r.record.index)
            .max()
            .unwrap_or(0);
        loop {
            let response = channel
                .call(&Request::HomeRecords {
                    vault,
                    after,
                    limit: MAX_PAGE,
                })
                .await?;
            let (envelopes, more) = match response {
                Response::HomeRecords {
                    vault: v,
                    records,
                    more,
                } if v == vault => (records, more),
                Response::Error { detail, .. } => return Err(FedError::Remote(detail)),
                _ => {
                    return Err(FedError::Malformed(
                        "an unexpected response to home records",
                    ));
                }
            };
            let keys = self.directory().await?;
            let page_start = after;
            for envelope in envelopes {
                let record: HomeRecord = home::open_home_record(&envelope, &keys)?;
                if record.vault != vault {
                    return Err(FedError::Invalid("a home record for another vault"));
                }
                after = after.max(record.index);
                // An index carries the epoch it was made under. A record whose index lies in
                // another epoch's range would sit where a later home's record belongs and keep
                // that one from being stored.
                if home::index_epoch(record.index) != record.epoch {
                    tracing::warn!(%peer, index = record.index, epoch = record.epoch, "a home record whose index is not of its epoch was refused");
                    sync.refused += 1;
                    continue;
                }
                let current = self
                    .store
                    .get_vault(vault)
                    .await?
                    .ok_or(FedError::UnknownVault)?;
                let status = match home::judge(&current, &record)? {
                    Verdict::Apply => HomeStatus::Applied,
                    Verdict::Quarantine => {
                        // Only the server that was the home of that epoch could have made it.
                        if current
                            .epoch_home(record.epoch)
                            .is_some_and(|home| home != record.signer)
                        {
                            tracing::warn!(%peer, epoch = record.epoch, "a stale home record from a server that was not the home of its epoch was refused");
                            sync.refused += 1;
                            continue;
                        }
                        let held = self.store.quarantined(vault).await?;
                        if held.len() >= MAX_QUARANTINED {
                            tracing::warn!(%peer, "the vault's quarantine is full: a stale home record was dropped");
                            sync.refused += 1;
                            continue;
                        }
                        if current.epoch_home(record.epoch).is_none()
                            && held
                                .iter()
                                .filter(|r| r.record.signer == record.signer)
                                .count()
                                >= MAX_QUARANTINED_PER_SIGNER
                        {
                            tracing::warn!(%peer, "a signer holds its share of the quarantine: a stale home record was dropped");
                            sync.refused += 1;
                            continue;
                        }
                        HomeStatus::Quarantined
                    }
                    Verdict::Behind => {
                        sync.behind = true;
                        return Ok(sync);
                    }
                };
                // Two servers' records at one index can't both be kept: the first stays, and the
                // second is refused out loud instead of being dropped without a word.
                if let Some(held) = self
                    .store
                    .home_records(vault, record.index - 1, 1)
                    .await?
                    .first()
                    .filter(|held| held.record.index == record.index)
                {
                    if held.record.signer != record.signer {
                        tracing::warn!(%peer, index = record.index, "a home record collides with another server's record at its index: refused");
                        sync.refused += 1;
                    }
                    continue;
                }
                let stored = StoredHomeRecord {
                    signed: envelope,
                    record,
                    status,
                };
                if self.store.put_home_record(&stored).await? {
                    match status {
                        HomeStatus::Applied => {
                            self.apply_home_record(&stored.record).await;
                            sync.applied += 1;
                        }
                        HomeStatus::Quarantined => sync.quarantined += 1,
                    }
                }
            }
            // A page of records we already held still moves the cursor on; a page that doesn't
            // is the end, whatever the peer says.
            if !more || after == page_start {
                return Ok(sync);
            }
        }
    }

    // ---- promotion ----

    /// Makes this server the home of `vault` (it must be a replica), after the admin's fresh
    /// check. Returns the signed promotion record to announce to the other servers.
    pub async fn promote(&self, vault: Owner, now: u64) -> Result<Vec<u8>> {
        let current = self
            .store
            .get_vault(vault)
            .await?
            .ok_or(FedError::UnknownVault)?;
        let record = PromotionRecord::build(&current, self.server_id(), now)?;
        let signed = record.sign(&self.identity().signing)?.encode();
        let mut next = home::apply_promotion(&current, &record)?;
        next.promotion = Some(signed.clone());
        self.store.put_vault(&next).await?;
        Ok(signed)
    }

    /// Applies the promotion held for `vault` (see [`VaultFederation::held_demotion`]): another
    /// server becomes its home and this one a replica, last in the order. The caller has checked
    /// the admin with a fresh passkey or password. The record is checked again as it was when it
    /// arrived: signed by the new home, for the next epoch, from this server as the home.
    pub async fn accept_demotion(&self, vault: Owner) -> Result<VaultFederation> {
        self.accept_promotion_of(vault, None).await
    }

    /// [`accept_demotion`](Self::accept_demotion) for the promotion of `new_home`. `None` names it
    /// only when exactly one waits.
    pub async fn accept_promotion_of(
        &self,
        vault: Owner,
        new_home: Option<ServerId>,
    ) -> Result<VaultFederation> {
        let current = self
            .store
            .get_vault(vault)
            .await?
            .ok_or(FedError::UnknownVault)?;
        let record = pick_held(&current, new_home)?;
        let keys = self.directory().await?;
        let promotion = home::open_promotion(&record, &keys)?;
        let mut next = home::apply_promotion(&current, &promotion)?;
        next.promotion = Some(record);
        self.store.put_vault(&next).await?;
        Ok(next)
    }

    /// The admin refuses the promotion held for `vault`: it is dropped and nothing changes. The
    /// server that signed it announces it again at its next run of this process, and it is held
    /// again; the way to stop that is to unpair it, or to take it out of the vault's set.
    pub async fn refuse_demotion(&self, vault: Owner) -> Result<VaultFederation> {
        self.refuse_promotion_of(vault, None).await
    }

    /// [`refuse_demotion`](Self::refuse_demotion) for the promotion of `new_home`. `None` names it
    /// only when exactly one waits.
    pub async fn refuse_promotion_of(
        &self,
        vault: Owner,
        new_home: Option<ServerId>,
    ) -> Result<VaultFederation> {
        let current = self
            .store
            .get_vault(vault)
            .await?
            .ok_or(FedError::UnknownVault)?;
        let record = pick_held(&current, new_home)?;
        let next = VaultFederation {
            held_demotion: current
                .held_demotion
                .iter()
                .filter(|r| **r != record)
                .cloned()
                .collect(),
            ..current
        };
        self.store.put_vault(&next).await?;
        Ok(next)
    }

    /// The vaults that hold a promotion for this server's admin, with the promotion's fields.
    pub async fn held_promotions(&self) -> Result<Vec<(Owner, PromotionRecord)>> {
        let mut out = Vec::new();
        for vault in self.store.list_vaults().await? {
            for record in &vault.held_demotion {
                if let Ok(promotion) = home::peek_promotion(record) {
                    out.push((vault.owner, promotion));
                }
            }
        }
        Ok(out)
    }

    /// Sends a signed promotion record to a peer.
    pub async fn announce<C: Channel>(&self, channel: &mut C, record: Vec<u8>) -> Result<()> {
        match channel.call(&Request::Promote { record }).await? {
            Response::Ack => Ok(()),
            Response::Error { detail, .. } => Err(FedError::Remote(detail)),
            _ => Err(FedError::Malformed("an unexpected response to a promotion")),
        }
    }
}

/// The held promotion `new_home` signed, or the only one held when none is named.
fn pick_held(vault: &VaultFederation, new_home: Option<ServerId>) -> Result<Vec<u8>> {
    let mut found = vault.held_demotion.iter().filter(|record| {
        new_home
            .is_none_or(|wanted| home::peek_promotion(record).is_ok_and(|p| p.new_home == wanted))
    });
    match (found.next(), found.next()) {
        (Some(record), None) => Ok(record.clone()),
        (None, _) => Err(FedError::Refused("no promotion waits for this vault")),
        (Some(_), Some(_)) => Err(FedError::Refused(
            "several promotions wait for this vault: name the server",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::MemoryStore;
    use crate::testing::{draft, identity};
    use kemlock_domain::UserId;

    /// A channel that calls another replica directly, as a session would after the frames.
    struct Direct<'a, S: FedStore> {
        remote: &'a Replica<S>,
        caller: ServerId,
    }

    impl<S: FedStore + Sync> Channel for Direct<'_, S> {
        async fn call(&mut self, request: &Request) -> Result<Response> {
            Ok(self.remote.serve(self.caller, request, 0).await.response)
        }
    }

    const NOW: u64 = 1_800_000_000;

    struct Two {
        a: Replica<MemoryStore>,
        b: Replica<MemoryStore>,
        vault: Owner,
    }

    async fn two() -> Two {
        let ia = identity(1, NOW, &crate::suite::Suite::IMPLEMENTED);
        let ib = identity(2, NOW, &crate::suite::Suite::IMPLEMENTED);
        let a = Replica::new(MemoryStore::new(ia.server), Arc::new(ia.clone()));
        let b = Replica::new(MemoryStore::new(ib.server), Arc::new(ib.clone()));
        a.pin_peer(&ib.descriptor, NOW).await.expect("pin");
        b.pin_peer(&ia.descriptor, NOW).await.expect("pin");
        let vault = Owner::User(UserId::random());
        a.federate(vault, vec![ib.server]).await.expect("federate");
        b.accept_vault(vault, ia.server, vec![ib.server])
            .await
            .expect("accept");
        Two { a, b, vault }
    }

    #[tokio::test]
    async fn ranking_by_revision_stays_on_once_every_server_says_it_does() {
        let t = two().await;
        let a = t.a.server_id();
        let address = vec!["https://a.example.org".to_owned()];
        let capable = vec![writes::SIGNED_WRITES_CAPABILITY.to_owned()];
        let set = |suites: Vec<String>| {
            let b = &t.b;
            let address = address.clone();
            async move {
                b.store
                    .update_peer_descriptor(a, "A", &address, &suites)
                    .await
                    .expect("update");
            }
        };
        // A server of the set that doesn't say it ranks by revision keeps the vault on the clock.
        set(Vec::new()).await;
        assert_eq!(t.b.rank_of(t.vault).await.expect("rank"), Rank::Clock);
        set(capable).await;
        assert_eq!(t.b.rank_of(t.vault).await.expect("rank"), Rank::Revision);
        // It can't turn rollback protection off again by leaving the capability out.
        set(Vec::new()).await;
        assert_eq!(t.b.rank_of(t.vault).await.expect("rank"), Rank::Revision);
    }

    #[tokio::test]
    async fn a_pull_copies_items_and_a_second_pull_finds_nothing() {
        let t = two().await;
        for n in 0..3 {
            t.a.store
                .put(draft(ItemId::random(), t.vault, None, 1, 1_000 + n))
                .expect("put");
        }
        let mut channel = Direct {
            remote: &t.a,
            caller: t.b.server_id(),
        };
        let report =
            t.b.pull(&mut channel, t.a.server_id(), t.vault)
                .await
                .expect("pull");
        assert_eq!(report.counts.applied, 3);
        assert_eq!(t.b.store.len(), 3);
        let again =
            t.b.pull(&mut channel, t.a.server_id(), t.vault)
                .await
                .expect("pull");
        assert_eq!(again.counts, Counts::default());
        // The change records carry the origin's id: A's, not B's.
        let leaves_a = t.a.store.leaves(t.vault).await.expect("leaves");
        let leaves_b = t.b.store.leaves(t.vault).await.expect("leaves");
        assert_eq!(leaves_a, leaves_b);
    }

    #[tokio::test]
    async fn a_peer_outside_the_set_or_a_local_vault_is_refused() {
        let t = two().await;
        let local_vault = Owner::User(UserId::random());
        t.a.store
            .put(draft(ItemId::random(), local_vault, None, 1, 1_000))
            .expect("put");
        let served =
            t.a.serve(
                t.b.server_id(),
                &Request::Pull {
                    vault: local_vault,
                    since: VersionVector::new(),
                    limit: 10,
                },
                NOW,
            )
            .await;
        assert_eq!(
            served.response,
            Response::error(code::UNKNOWN_VAULT, "unknown vault")
        );
        let served =
            t.a.serve(
                ServerId::random(),
                &Request::Pull {
                    vault: t.vault,
                    since: VersionVector::new(),
                    limit: 10,
                },
                NOW,
            )
            .await;
        assert!(matches!(served.response, Response::Error { code: 1, .. }));
    }

    #[tokio::test]
    async fn a_peer_that_always_has_more_is_pulled_from_for_a_bounded_number_of_pages() {
        use kemlock_domain::{ChangeId, Hlc};
        let t = two().await;
        struct Endless {
            calls: u64,
            origin: ServerId,
        }
        impl Channel for Endless {
            async fn call(&mut self, request: &Request) -> Result<Response> {
                let Request::Pull { vault, since, .. } = request else {
                    return Err(FedError::Malformed("not a pull"));
                };
                self.calls += 1;
                // Nothing to apply, but the cursor moves each time and there is always more.
                let mut next = since.clone();
                next.observe(&ChangeId {
                    origin: self.origin,
                    seq: self.calls,
                    hlc: Hlc(1),
                });
                Ok(Response::Changes {
                    vault: *vault,
                    records: Vec::new(),
                    next,
                    more: true,
                })
            }
        }
        let mut channel = Endless {
            calls: 0,
            origin: ServerId::random(),
        };
        let report =
            t.b.pull(&mut channel, t.a.server_id(), t.vault)
                .await
                .expect("a bounded pull");
        assert_eq!(report.pages, MAX_PAGES_PER_VISIT);
        assert_eq!(channel.calls, MAX_PAGES_PER_VISIT as u64);
    }

    #[tokio::test]
    async fn a_forged_record_is_left_out_and_the_cursor_still_moves() {
        let t = two().await;
        t.a.store
            .put(draft(ItemId::random(), t.vault, None, 1, 1_000))
            .expect("put");
        // A channel that alters the ciphertext of what the peer sends.
        struct Tamper<'a>(Direct<'a, MemoryStore>);
        impl Channel for Tamper<'_> {
            async fn call(&mut self, request: &Request) -> Result<Response> {
                let response = self.0.call(request).await?;
                if let Response::Changes {
                    vault,
                    mut records,
                    next,
                    more,
                } = response
                {
                    for r in &mut records {
                        let n = r.len();
                        r[n - 1] ^= 1;
                    }
                    return Ok(Response::Changes {
                        vault,
                        records,
                        next,
                        more,
                    });
                }
                Ok(response)
            }
        }
        let mut channel = Tamper(Direct {
            remote: &t.a,
            caller: t.b.server_id(),
        });
        // The record is counted and left out, and the pull goes on: one record nobody can check
        // must not hold the cursor, and every replica behind it, still.
        let report =
            t.b.pull(&mut channel, t.a.server_id(), t.vault)
                .await
                .expect("pull");
        assert_eq!(
            (report.counts.applied, report.counts.refused, report.counts.retry),
            (0, 1, 0)
        );
        assert_eq!(t.b.store.len(), 0);
        assert!(
            !t.b.store
                .peer_cursor(t.a.server_id(), t.vault)
                .await
                .expect("cursor")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn changes_signed_before_the_origin_rotated_still_verify_and_later_ones_do_not() {
        let t = two().await;
        let a = t.a.server_id();
        let now = crate::session::unix_now();
        t.a.store
            .put(draft(ItemId::random(), t.vault, None, 1, 1_000))
            .expect("put");
        // A signed that change with its old key. B learns that A rotated a while ago.
        let old = t.a.identity().public.as_bytes().to_vec();
        let new = crate::crypto::sign_public(&sig1::SigningKey::from_bytes(&[9; 64]))
            .expect("a key");
        t.b.store
            .set_peer_identity(a, new.as_bytes())
            .await
            .expect("pinned");
        t.b.store
            .push_past_key(a, &old, now - 10_000)
            .await
            .expect("kept");
        let mut channel = Direct {
            remote: &t.a,
            caller: t.b.server_id(),
        };
        let report =
            t.b.pull(&mut channel, a, t.vault)
                .await
                .expect("pull");
        assert_eq!((report.counts.applied, report.counts.refused), (1, 0));

        // The old key does not sign what is dated after it was replaced.
        t.a.store
            .put(draft(
                ItemId::random(),
                t.vault,
                None,
                1,
                (now - 5_000) * 1000,
            ))
            .expect("put");
        let report =
            t.b.pull(&mut channel, a, t.vault)
                .await
                .expect("pull");
        assert_eq!((report.counts.applied, report.counts.refused), (0, 1));
        assert_eq!(t.b.store.len(), 1);
    }

    #[tokio::test]
    async fn a_change_from_far_in_the_future_is_left_out_and_the_rest_still_sync() {
        let t = two().await;
        let ahead = crate::session::unix_now() * 1000 + 3_600_000;
        t.a.store
            .put(draft(ItemId::random(), t.vault, None, 1, 1_000))
            .expect("put");
        t.a.store
            .put(draft(ItemId::random(), t.vault, None, 1, ahead))
            .expect("put");
        let mut channel = Direct {
            remote: &t.a,
            caller: t.b.server_id(),
        };
        let report =
            t.b.pull(&mut channel, t.a.server_id(), t.vault)
                .await
                .expect("pull");
        assert_eq!((report.counts.applied, report.counts.refused), (1, 1));
        assert_eq!(t.b.store.len(), 1);
        // B's clock was not raised with it, so B's next write gets an ordinary time.
        let written =
            t.b.store
                .put(draft(ItemId::random(), t.vault, None, 1, 2_000))
                .expect("put");
        assert!(written.change.hlc.millis() < ahead);
    }

    #[tokio::test]
    async fn reconcile_finds_what_a_pull_missed() {
        let t = two().await;
        let id = ItemId::random();
        t.a.store
            .put(draft(id, t.vault, None, 1, 1_000))
            .expect("put");
        t.b.store
            .put(draft(ItemId::random(), t.vault, None, 1, 1_000))
            .expect("put");
        let mut channel = Direct {
            remote: &t.a,
            caller: t.b.server_id(),
        };
        let report =
            t.b.reconcile(&mut channel, t.a.server_id(), t.vault)
                .await
                .expect("reconcile");
        assert!(!report.in_step);
        assert_eq!(report.fetched.applied, 1);
        assert_eq!(report.to_push.len(), 1, "B holds an item A lacks");
        assert!(t.b.store.get(id).is_some());
        // Once A has pulled B's item too, the roots match.
        let mut back = Direct {
            remote: &t.b,
            caller: t.a.server_id(),
        };
        t.a.pull(&mut back, t.b.server_id(), t.vault)
            .await
            .expect("pull");
        let report =
            t.b.reconcile(&mut channel, t.a.server_id(), t.vault)
                .await
                .expect("reconcile");
        assert!(report.in_step);
    }

    #[tokio::test]
    async fn a_nudge_asks_the_receiver_to_pull_only_when_it_is_behind() {
        let t = two().await;
        t.a.store
            .put(draft(ItemId::random(), t.vault, None, 1, 1_000))
            .expect("put");
        let latest = t.a.store.latest(t.vault).await.expect("latest");
        let served =
            t.b.serve(
                t.a.server_id(),
                &Request::Nudge {
                    vault: t.vault,
                    latest: latest.clone(),
                },
                NOW,
            )
            .await;
        assert_eq!(served.response, Response::Ack);
        assert_eq!(served.pull, Some(t.vault));
        let mut channel = Direct {
            remote: &t.a,
            caller: t.b.server_id(),
        };
        t.b.pull(&mut channel, t.a.server_id(), t.vault)
            .await
            .expect("pull");
        let served =
            t.b.serve(
                t.a.server_id(),
                &Request::Nudge {
                    vault: t.vault,
                    latest,
                },
                NOW,
            )
            .await;
        assert_eq!(served.pull, None);
    }

    #[tokio::test]
    async fn home_records_replicate_and_old_epochs_are_quarantined() {
        let t = two().await;
        // The home (A) writes a home record under epoch 1.
        let record = HomeRecord {
            vault: t.vault,
            index: home::home_index(1, 1),
            epoch: 1,
            kind: "member-added".to_owned(),
            payload: vec![1],
            signer: t.a.server_id(),
        };
        let signed = record.sign(&t.a.identity().signing).expect("sign").encode();
        t.a.store
            .put_home_record(&StoredHomeRecord {
                signed,
                record: record.clone(),
                status: HomeStatus::Applied,
            })
            .await
            .expect("put");
        let mut channel = Direct {
            remote: &t.a,
            caller: t.b.server_id(),
        };
        let sync =
            t.b.pull_home_records(&mut channel, t.a.server_id(), t.vault)
                .await
                .expect("sync");
        assert_eq!((sync.applied, sync.quarantined, sync.behind), (1, 0, false));

        // B is promoted (epoch 2) and tells A.
        let promotion = t.b.promote(t.vault, NOW).await.expect("promote");
        let mut to_a = Direct {
            remote: &t.a,
            caller: t.b.server_id(),
        };
        // A is the home it would take the vault from: it holds the promotion for its admin.
        t.b.announce(&mut to_a, promotion)
            .await
            .expect_err("held, not applied");
        t.a.accept_demotion(t.vault)
            .await
            .expect("A's admin accepts");
        let at_a =
            t.a.store
                .get_vault(t.vault)
                .await
                .expect("get")
                .expect("vault");
        assert_eq!(at_a.home, t.b.server_id());
        assert_eq!(at_a.epoch, 2);
        // A late epoch-1 write by the old home, arriving at B, is quarantined, not applied.
        let late = HomeRecord {
            index: home::home_index(1, 2),
            payload: vec![2],
            ..record
        };
        let signed = late.sign(&t.a.identity().signing).expect("sign").encode();
        t.a.store
            .put_home_record(&StoredHomeRecord {
                signed,
                record: late,
                status: HomeStatus::Applied,
            })
            .await
            .expect("put");
        let sync =
            t.b.pull_home_records(
                &mut Direct {
                    remote: &t.a,
                    caller: t.b.server_id(),
                },
                t.a.server_id(),
                t.vault,
            )
            .await
            .expect("sync");
        assert_eq!((sync.applied, sync.quarantined), (0, 1));
        let held = t.b.store.quarantined(t.vault).await.expect("quarantined");
        assert_eq!(held.len(), 1);
        assert_eq!(held[0].record.index, home::home_index(1, 2));
    }

    #[tokio::test]
    async fn a_replica_that_promotes_itself_cant_take_the_vault_or_erase_the_homes_copy() {
        let t = two().await;
        let a_id = t.a.server_id();
        let b_id = t.b.server_id();
        // B signs a promotion that makes it the home, as a compromised replica could, unasked.
        let promotion = t.b.promote(t.vault, NOW).await.expect("promote");
        let mut to_a = Direct {
            remote: &t.a,
            caller: b_id,
        };
        let refused = t.b.announce(&mut to_a, promotion.clone()).await;
        assert!(
            matches!(&refused, Err(FedError::Remote(d)) if d.contains("admin must accept")),
            "{refused:?}"
        );
        // A is still the home, at epoch 1, and holds the record for its admin.
        let at_a =
            t.a.store
                .get_vault(t.vault)
                .await
                .expect("get")
                .expect("vault");
        assert_eq!((at_a.home, at_a.epoch), (a_id, 1));
        assert_eq!(at_a.held_demotion, vec![promotion.clone()]);
        // So B, not A's home, can't have A erase its copy.
        let answer = to_a
            .call(&Request::Erase { vault: t.vault })
            .await
            .expect("an answer");
        assert!(matches!(answer, Response::Error { .. }), "{answer:?}");
        assert!(
            t.a.store.get_vault(t.vault).await.expect("get").is_some(),
            "A's copy stays"
        );
        // The same record again changes nothing.
        let again = t.b.announce(&mut to_a, promotion).await;
        assert!(again.is_err());
        let at_a =
            t.a.store
                .get_vault(t.vault)
                .await
                .expect("get")
                .expect("vault");
        assert_eq!(at_a.home, a_id);
    }

    #[tokio::test]
    async fn accepting_a_demotion_needs_one_held_and_checks_it_again() {
        let t = two().await;
        // Nothing held: nothing to accept.
        assert!(t.a.accept_demotion(t.vault).await.is_err());
        // A held record that was tampered with fails its signature when accepted.
        let promotion = t.b.promote(t.vault, NOW).await.expect("promote");
        let mut to_a = Direct {
            remote: &t.a,
            caller: t.b.server_id(),
        };
        t.b.announce(&mut to_a, promotion.clone())
            .await
            .expect_err("held");
        let mut tampered =
            t.a.store
                .get_vault(t.vault)
                .await
                .expect("get")
                .expect("vault");
        let mut bad = promotion.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        tampered.held_demotion = vec![bad];
        t.a.store.put_vault(&tampered).await.expect("put");
        assert!(t.a.accept_demotion(t.vault).await.is_err());
        let at_a =
            t.a.store
                .get_vault(t.vault)
                .await
                .expect("get")
                .expect("vault");
        assert_eq!(at_a.home, t.a.server_id(), "still the home");
    }

    #[tokio::test]
    async fn home_records_made_apart_in_two_epochs_do_not_collide() {
        use crate::cbor::Value;
        let entity =
            |n: u8| Value::map(vec![(0, Value::Uint(1)), (1, Value::bytes(&[n; 16]))]).encode();
        let t = two().await;
        let a_id = t.a.server_id();
        let b_id = t.b.server_id();
        // The home (A) makes a record, and B has it.
        assert_eq!(
            t.a.publish_home_record(t.vault, "k", entity(1))
                .await
                .expect("publish"),
            Some(true)
        );
        let mut from_a = Direct {
            remote: &t.a,
            caller: b_id,
        };
        let sync =
            t.b.pull_home_records(&mut from_a, a_id, t.vault)
                .await
                .expect("sync");
        assert_eq!(sync.applied, 1);

        // B is promoted and A, cut off, still makes a record under epoch 1. B's first record of
        // epoch 2 would have had the same count as A's second one.
        let promotion = t.b.promote(t.vault, NOW).await.expect("promote");
        assert_eq!(
            t.a.publish_home_record(t.vault, "k", entity(2))
                .await
                .expect("publish"),
            Some(true)
        );
        assert_eq!(
            t.b.publish_home_record(t.vault, "k", entity(3))
                .await
                .expect("publish"),
            Some(true)
        );
        // A learns of the promotion and its admin accepts it. It can no longer make records.
        t.b.announce(&mut from_a, promotion)
            .await
            .expect_err("held for A's admin");
        t.a.accept_demotion(t.vault)
            .await
            .expect("A's admin accepts");
        assert_eq!(
            t.a.publish_home_record(t.vault, "k", entity(4))
                .await
                .expect("publish"),
            None
        );

        // B takes A's stale record into quarantine, and A takes B's new one.
        let sync =
            t.b.pull_home_records(&mut from_a, a_id, t.vault)
                .await
                .expect("sync");
        assert_eq!((sync.applied, sync.quarantined), (0, 1));
        let mut from_b = Direct {
            remote: &t.b,
            caller: a_id,
        };
        let sync =
            t.a.pull_home_records(&mut from_b, b_id, t.vault)
                .await
                .expect("sync");
        assert_eq!((sync.applied, sync.quarantined), (1, 0));

        let held =
            t.b.store
                .home_records(t.vault, 0, 100)
                .await
                .expect("records");
        let mut indexes: Vec<u64> = held.iter().map(|r| r.record.index).collect();
        assert_eq!(indexes.len(), 3, "{indexes:?}");
        indexes.dedup();
        assert_eq!(indexes.len(), 3, "no two records share an index");
        let stale = t.b.store.quarantined(t.vault).await.expect("quarantined");
        assert_eq!(stale.len(), 1);
        assert_eq!(stale[0].record.epoch, 1);
        assert_eq!(home::index_epoch(stale[0].record.index), 1);
        let at_a =
            t.a.store
                .home_records(t.vault, 0, 100)
                .await
                .expect("records");
        assert!(
            at_a.iter()
                .any(|r| r.record.epoch == 2 && r.status == HomeStatus::Applied),
            "A holds the new home's record"
        );
    }

    /// A home `a` and a replica `b` that both hold a vault at epoch 2 (who was the home of epoch 1
    /// is not known), with a third server `ic` in its set.
    async fn stale_world() -> (
        Replica<MemoryStore>,
        Replica<MemoryStore>,
        LocalIdentity,
        Owner,
    ) {
        let ia = identity(1, NOW, &crate::suite::Suite::IMPLEMENTED);
        let ib = identity(2, NOW, &crate::suite::Suite::IMPLEMENTED);
        let ic = identity(3, NOW, &crate::suite::Suite::IMPLEMENTED);
        let a = Replica::new(MemoryStore::new(ia.server), Arc::new(ia.clone()));
        let b = Replica::new(MemoryStore::new(ib.server), Arc::new(ib.clone()));
        a.pin_peer(&ib.descriptor, NOW).await.expect("pin");
        b.pin_peer(&ia.descriptor, NOW).await.expect("pin");
        let vault = Owner::User(UserId::random());
        let settings = VaultFederation {
            epoch: 2,
            ..VaultFederation::federated(vault, ia.server, vec![ib.server, ic.server])
        };
        a.store.put_vault(&settings).await.expect("put");
        b.store.put_vault(&settings).await.expect("put");
        (a, b, ic, vault)
    }

    async fn keep(
        replica: &Replica<MemoryStore>,
        key: &LocalIdentity,
        record: &HomeRecord,
        status: HomeStatus,
    ) {
        let signed = record.sign(&key.signing).expect("sign").encode();
        replica
            .store
            .put_home_record(&StoredHomeRecord {
                signed,
                record: record.clone(),
                status,
            })
            .await
            .expect("put");
    }

    fn stale(vault: Owner, signer: ServerId, index: u64, epoch: u64) -> HomeRecord {
        HomeRecord {
            vault,
            index,
            epoch,
            kind: "k".to_owned(),
            payload: vec![index as u8],
            signer,
        }
    }

    #[tokio::test]
    async fn a_record_squatting_a_future_index_or_colliding_with_another_servers_is_refused() {
        let (a, b, ic, vault) = stale_world().await;
        let a_id = a.server_id();
        // A stale-epoch record that claims an index in epoch 7's range would sit where the home
        // of epoch 7 will put its first record.
        keep(
            &a,
            &a.identity(),
            &stale(vault, a_id, home::home_index(7, 1), 1),
            HomeStatus::Applied,
        )
        .await;
        let mut channel = Direct {
            remote: &a,
            caller: b.server_id(),
        };
        let sync = b
            .pull_home_records(&mut channel, a_id, vault)
            .await
            .expect("sync");
        assert_eq!((sync.applied, sync.quarantined, sync.refused), (0, 0, 1));
        assert!(
            b.store
                .home_records(vault, 0, 10)
                .await
                .expect("held")
                .is_empty(),
            "the squatted index stays free"
        );

        // Another server's record already holds an index (epoch 1's history isn't known here):
        // a second one at that index is refused, not dropped without a word.
        let at = home::home_index(1, 1);
        keep(
            &b,
            &ic,
            &stale(vault, ic.server, at, 1),
            HomeStatus::Quarantined,
        )
        .await;
        keep(
            &a,
            &a.identity(),
            &stale(vault, a_id, at, 1),
            HomeStatus::Applied,
        )
        .await;
        let sync = b
            .pull_home_records(&mut channel, a_id, vault)
            .await
            .expect("sync");
        assert_eq!((sync.applied, sync.quarantined, sync.refused), (0, 0, 2));
        let held = b.store.home_records(vault, 0, 10).await.expect("held");
        assert_eq!(held.len(), 1);
        assert_eq!(held[0].record.signer, ic.server, "the first one stays");
    }

    #[tokio::test]
    async fn a_stale_record_must_come_from_the_server_that_was_the_home_of_its_epoch() {
        let (a, b, ic, vault) = stale_world().await;
        let a_id = a.server_id();
        // B now knows that A was the home of epoch 1.
        let mut settings = b.store.get_vault(vault).await.expect("get").expect("vault");
        settings.home_history = vec![(1, a_id)];
        b.store.put_vault(&settings).await.expect("put");
        a.store.put_vault(&settings).await.expect("put");
        // A relays a stale record that C signed: C was never the home of epoch 1.
        let forged = stale(vault, ic.server, home::home_index(1, 1), 1);
        let signed = forged.sign(&ic.signing).expect("sign").encode();
        a.store
            .put_home_record(&StoredHomeRecord {
                signed,
                record: forged,
                status: HomeStatus::Applied,
            })
            .await
            .expect("put");
        let mut channel = Direct {
            remote: &a,
            caller: b.server_id(),
        };
        // C's key isn't in B's directory, so the relayed record can't even be opened; give B the
        // key the way a pairing would.
        b.pin_peer(&ic.descriptor, NOW).await.expect("pin");
        let sync = b
            .pull_home_records(&mut channel, a_id, vault)
            .await
            .expect("sync");
        assert_eq!((sync.quarantined, sync.refused), (0, 1));
        assert!(b.store.quarantined(vault).await.expect("held").is_empty());
    }

    #[tokio::test]
    async fn one_signer_cannot_fill_the_quarantine_when_the_epochs_home_is_unknown() {
        let (a, b, _ic, vault) = stale_world().await;
        let a_id = a.server_id();
        // A already holds its share of stale records at B (B never saw who was home in epoch 1).
        for n in 1..=MAX_QUARANTINED_PER_SIGNER as u64 {
            keep(
                &b,
                &a.identity(),
                &stale(vault, a_id, home::home_index(1, n), 1),
                HomeStatus::Quarantined,
            )
            .await;
        }
        let over = MAX_QUARANTINED_PER_SIGNER as u64 + 1;
        keep(
            &a,
            &a.identity(),
            &stale(vault, a_id, home::home_index(1, over), 1),
            HomeStatus::Applied,
        )
        .await;
        let mut channel = Direct {
            remote: &a,
            caller: b.server_id(),
        };
        let sync = b
            .pull_home_records(&mut channel, a_id, vault)
            .await
            .expect("sync");
        assert_eq!((sync.quarantined, sync.refused), (0, 1));
        assert_eq!(
            b.store.quarantined(vault).await.expect("held").len(),
            MAX_QUARANTINED_PER_SIGNER,
            "the room left is for the others"
        );
    }

    #[tokio::test]
    async fn a_vault_keeps_a_bounded_quarantine() {
        let (a, b, _ic, vault) = stale_world().await;
        let a_id = a.server_id();
        // Records of many members of the set, so the per-signer share isn't what stops this one.
        let signers: Vec<ServerId> = (0..MAX_QUARANTINED / MAX_QUARANTINED_PER_SIGNER)
            .map(|_| ServerId::random())
            .collect();
        for n in 1..=MAX_QUARANTINED as u64 {
            let signer = signers[(n as usize - 1) / MAX_QUARANTINED_PER_SIGNER];
            keep(
                &b,
                &a.identity(),
                &stale(vault, signer, home::home_index(1, n), 1),
                HomeStatus::Quarantined,
            )
            .await;
        }
        let over = MAX_QUARANTINED as u64 + 1;
        keep(
            &a,
            &a.identity(),
            &stale(vault, a_id, home::home_index(1, over), 1),
            HomeStatus::Applied,
        )
        .await;
        let mut channel = Direct {
            remote: &a,
            caller: b.server_id(),
        };
        let sync = b
            .pull_home_records(&mut channel, a_id, vault)
            .await
            .expect("sync");
        assert_eq!((sync.quarantined, sync.refused), (0, 1));
        assert_eq!(
            b.store.quarantined(vault).await.expect("held").len(),
            MAX_QUARANTINED
        );
    }

    #[tokio::test]
    async fn a_replica_holds_a_promotion_it_didnt_ask_for_unless_the_setting_is_auto() {
        use crate::extra::PromotionMode;
        let ia = identity(1, NOW, &crate::suite::Suite::IMPLEMENTED);
        let ib = identity(2, NOW, &crate::suite::Suite::IMPLEMENTED);
        let ic = identity(3, NOW, &crate::suite::Suite::IMPLEMENTED);
        let b = Replica::new(MemoryStore::new(ib.server), Arc::new(ib.clone()));
        let c = Replica::new(MemoryStore::new(ic.server), Arc::new(ic.clone()));
        c.pin_peer(&ib.descriptor, NOW).await.expect("pin");
        let make = || {
            let vault = Owner::User(UserId::random());
            VaultFederation::federated(vault, ia.server, vec![ib.server, ic.server])
        };
        let held_vault = make();
        let auto_vault = make();
        for settings in [&held_vault, &auto_vault] {
            b.store.put_vault(settings).await.expect("put");
            c.store.put_vault(settings).await.expect("put");
        }

        // B promotes itself and tells C. C holds the record for its admin.
        let promotion = b.promote(held_vault.owner, NOW).await.expect("promote");
        let mut to_c = Direct {
            remote: &c,
            caller: ib.server,
        };
        let refused = b.announce(&mut to_c, promotion.clone()).await;
        assert!(
            matches!(&refused, Err(FedError::Remote(d)) if d.contains("admin must accept")),
            "{refused:?}"
        );
        let at_c = c
            .store
            .get_vault(held_vault.owner)
            .await
            .expect("get")
            .expect("vault");
        assert_eq!(
            (at_c.home, at_c.epoch),
            (ia.server, 1),
            "the vault stays where it was"
        );
        assert_eq!(at_c.held_demotion, vec![promotion.clone()]);
        let held = c.held_promotions().await.expect("held");
        assert_eq!(held.len(), 1);
        assert_eq!(
            (held[0].0, held[0].1.new_home),
            (held_vault.owner, ib.server)
        );

        // The admin refuses it: gone, and nothing changed.
        c.refuse_demotion(held_vault.owner).await.expect("refused");
        assert!(c.held_promotions().await.expect("held").is_empty());
        assert!(
            c.refuse_demotion(held_vault.owner).await.is_err(),
            "nothing left to refuse"
        );
        let at_c = c
            .store
            .get_vault(held_vault.owner)
            .await
            .expect("get")
            .expect("vault");
        assert_eq!((at_c.home, at_c.epoch), (ia.server, 1));

        // Announced again and accepted this time.
        b.announce(&mut to_c, promotion)
            .await
            .expect_err("held again");
        let next = c.accept_demotion(held_vault.owner).await.expect("accepted");
        assert_eq!((next.home, next.epoch), (ib.server, 2));
        assert!(next.held_demotion.is_empty());

        // With the setting on auto, the same announcement applies at once.
        c.store.set_promotion_mode(PromotionMode::Auto);
        let promotion = b.promote(auto_vault.owner, NOW).await.expect("promote");
        b.announce(&mut to_c, promotion).await.expect("applied");
        let at_c = c
            .store
            .get_vault(auto_vault.owner)
            .await
            .expect("get")
            .expect("vault");
        assert_eq!((at_c.home, at_c.epoch), (ib.server, 2));
        assert!(at_c.held_demotion.is_empty());
    }

    #[tokio::test]
    async fn a_vault_holds_one_promotion_for_each_server_that_announced_one() {
        let ia = identity(1, NOW, &crate::suite::Suite::IMPLEMENTED);
        let ib = identity(2, NOW, &crate::suite::Suite::IMPLEMENTED);
        let ic = identity(3, NOW, &crate::suite::Suite::IMPLEMENTED);
        let id = identity(4, NOW, &crate::suite::Suite::IMPLEMENTED);
        let b = Replica::new(MemoryStore::new(ib.server), Arc::new(ib.clone()));
        let c = Replica::new(MemoryStore::new(ic.server), Arc::new(ic.clone()));
        let d = Replica::new(MemoryStore::new(id.server), Arc::new(id.clone()));
        d.pin_peer(&ib.descriptor, NOW).await.expect("pin");
        d.pin_peer(&ic.descriptor, NOW).await.expect("pin");
        let vault = Owner::User(UserId::random());
        let settings =
            VaultFederation::federated(vault, ia.server, vec![ib.server, ic.server, id.server]);
        for replica in [&b, &c, &d] {
            replica.store.put_vault(&settings).await.expect("put");
        }
        // Two replicas each sign a promotion for themselves, and a replica announces them.
        let by_b = b.promote(vault, NOW).await.expect("promote");
        let by_c = c.promote(vault, NOW).await.expect("promote");
        let mut from_b = Direct {
            remote: &d,
            caller: ib.server,
        };
        let mut from_c = Direct {
            remote: &d,
            caller: ic.server,
        };
        b.announce(&mut from_b, by_b.clone())
            .await
            .expect_err("held");
        c.announce(&mut from_c, by_c.clone())
            .await
            .expect_err("held");
        // The same one again, and again: it can't push the other out, or pile up.
        for _ in 0..3 {
            b.announce(&mut from_b, by_b.clone())
                .await
                .expect_err("held");
        }
        let held = d.store.get_vault(vault).await.expect("get").expect("vault");
        assert_eq!(held.held_demotion.len(), 2, "one for each server");
        assert!(held.held_demotion.contains(&by_b) && held.held_demotion.contains(&by_c));
        assert_eq!(d.held_promotions().await.expect("list").len(), 2);

        // Naming none is ambiguous; naming one picks it.
        assert!(d.refuse_demotion(vault).await.is_err());
        assert!(d.accept_demotion(vault).await.is_err());
        d.refuse_promotion_of(vault, Some(ib.server))
            .await
            .expect("refused");
        let left = d.store.get_vault(vault).await.expect("get").expect("vault");
        assert_eq!(left.held_demotion, vec![by_c]);
        let next = d
            .accept_promotion_of(vault, Some(ic.server))
            .await
            .expect("accepted");
        assert_eq!((next.home, next.epoch), (ic.server, 2));
        assert!(next.held_demotion.is_empty());
    }

    #[tokio::test]
    async fn a_revoked_peer_is_refused() {
        let t = two().await;
        t.a.store
            .set_peer_state(t.b.server_id(), PeerState::Revoked)
            .await
            .expect("revoke");
        let served =
            t.a.serve(t.b.server_id(), &Request::Summary { vault: t.vault }, NOW)
                .await;
        assert!(matches!(served.response, Response::Error { .. }));
    }

    #[tokio::test]
    async fn pairing_with_oneself_is_refused() {
        let t = two().await;
        assert!(t.a.pin_peer(&t.a.identity().descriptor, NOW).await.is_err());
        assert!(
            t.b.accept_vault(t.vault, ServerId::random(), vec![ServerId::random()])
                .await
                .is_err()
        );
    }
}
