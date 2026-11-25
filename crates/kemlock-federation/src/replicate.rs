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
use crate::descriptor::SignedDescriptor;
use crate::error::{FedError, Result};
use crate::eventsync::EventSync;
use crate::extra::{BlobSync, ErasureOutbox, FedAdminRepo, MemberStore, VaultErasure};
use crate::forget::Forgetting;
use crate::frame::Padding;
use crate::hashtree::{self, Tree};
use crate::home::{self, HomeRecord, Policy, PromotionRecord, VaultFederation, Verdict};
use crate::identity::LocalIdentity;
use crate::keyrecs::KeyStore;
use crate::message::{MAX_LEAVES, MAX_PAGE, Request, Response, code};
use crate::ports::{
    ApplyOutcome, Exported, HomeStatus, Peer, PeerRepo, PeerState, ReplicaStore, StoredHomeRecord,
    VaultRepo,
};
use crate::relay::OriginKeys;
use crate::sendsync::SendSync;
use crate::signed::Signed;
use crate::spaces::SpaceMirror;
use crate::tagsync::TagSync;
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
        + SendSync,
> FedStore for T
{
}

/// A pull page stops growing past this many bytes, so a frame stays far below its cap.
const PAGE_BYTES: usize = 1_500_000;
/// How many items one fetch asks for.
const FETCH_CHUNK: usize = 256;

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
    /// Records for an item id another owner holds.
    pub refused: usize,
}

impl Counts {
    pub fn add(&mut self, other: &Counts) {
        self.applied += other.applied;
        self.siblings += other.siblings;
        self.duplicates += other.duplicates;
        self.refused += other.refused;
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
        }
    }

    /// Gives the engine this server's file storage, so it serves and fetches attachments.
    pub fn with_blob_files(mut self, files: Arc<dyn BlobFiles>) -> Replica<S> {
        self.files = Some(files);
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
                for entry in &page.entries {
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
                let tree = Tree::build(&self.store.leaves(*vault).await?);
                Ok(answer(Response::Summary {
                    vault: *vault,
                    root: tree.root,
                    buckets: tree.buckets,
                }))
            }
            Request::Leaves { vault, buckets } => {
                self.authorize(peer, *vault).await?;
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
                for entry in self.store.export_items(*vault, items).await? {
                    records.push(self.signed_record(&entry).await?);
                }
                Ok(answer(Response::Changes {
                    vault: *vault,
                    records,
                    next: VersionVector::new(),
                    more: false,
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
                if current.home == self.server_id() {
                    if current.held_demotion.as_deref() != Some(record.as_slice()) {
                        let held = VaultFederation {
                            held_demotion: Some(record.clone()),
                            ..current
                        };
                        self.store.put_vault(&held).await?;
                    }
                    return Err(FedError::Refused(
                        "this server is the vault's home: its admin must accept the promotion",
                    ));
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
                    self.serve_blob_chunk(*vault, *blob, *offset, *len).await?,
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
                Ok(answer(self.serve_sends(*vault, *after, *limit).await?))
            }
        }
    }

    /// The signed envelope of a stored version, signing it first if this server accepted it and
    /// hasn't sent it before.
    async fn signed_record(&self, entry: &Exported) -> Result<Vec<u8>> {
        let record = ChangeRecord::from_item(&entry.item, entry.lineage.clone());
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

    /// Verifies and applies records of `vault`. A record from an origin whose key we don't hold,
    /// or whose signature fails, fails the whole batch: nothing past it is applied.
    pub(crate) async fn apply_envelopes(
        &self,
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
        let mut counts = Counts::default();
        for envelope in envelopes {
            let record = change::open(envelope, &keys)?;
            if record.owner != vault {
                return Err(FedError::Invalid("a record for another vault"));
            }
            // A relayed change is accepted from an origin we are paired with or one in the vault's
            // set (whose key a peer vouched for), and from no other.
            let origin = record.change.origin;
            if origin != me && !direct.contains_key(&origin) && !settings.holds(origin) {
                return Err(FedError::Refused(
                    "a change from an origin outside the vault's set",
                ));
            }
            let signature = Signed::decode(envelope)?.signature;
            match self.store.apply(&record, &signature).await {
                Ok(ApplyOutcome::Applied) => counts.applied += 1,
                Ok(ApplyOutcome::Sibling) => counts.siblings += 1,
                Ok(ApplyOutcome::Duplicate) => counts.duplicates += 1,
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
            let counts = self.apply_envelopes(vault, &records).await?;
            report.counts.add(&counts);
            let mut cursor = since.clone();
            cursor.merge(&next);
            self.store.set_peer_cursor(peer, vault, &cursor).await?;
            report.pages += 1;
            if !more {
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
            let (records, _, _) = expect_changes(response, vault)?;
            fetched.add(&self.apply_envelopes(vault, &records).await?);
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
                let current = self
                    .store
                    .get_vault(vault)
                    .await?
                    .ok_or(FedError::UnknownVault)?;
                let status = match home::judge(&current, &record)? {
                    Verdict::Apply => HomeStatus::Applied,
                    Verdict::Quarantine => HomeStatus::Quarantined,
                    Verdict::Behind => {
                        sync.behind = true;
                        return Ok(sync);
                    }
                };
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
        let current = self
            .store
            .get_vault(vault)
            .await?
            .ok_or(FedError::UnknownVault)?;
        let record = current
            .held_demotion
            .clone()
            .ok_or(FedError::Refused("no promotion waits for this vault"))?;
        let keys = self.directory().await?;
        let promotion = home::open_promotion(&record, &keys)?;
        let mut next = home::apply_promotion(&current, &promotion)?;
        next.promotion = Some(record);
        self.store.put_vault(&next).await?;
        Ok(next)
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
    async fn a_forged_record_fails_the_pull_and_moves_no_cursor() {
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
        assert!(
            t.b.pull(&mut channel, t.a.server_id(), t.vault)
                .await
                .is_err()
        );
        assert_eq!(t.b.store.len(), 0);
        assert!(
            t.b.store
                .peer_cursor(t.a.server_id(), t.vault)
                .await
                .expect("cursor")
                .is_empty()
        );
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
            index: 1,
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
            index: 2,
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
        assert_eq!(held[0].record.index, 2);
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
        assert_eq!(at_a.held_demotion.as_deref(), Some(promotion.as_slice()));
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
        tampered.held_demotion = Some(bad);
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
