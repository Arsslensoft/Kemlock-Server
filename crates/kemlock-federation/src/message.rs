//! The messages inside sealed frames: one request, one response.
//!
//! The requester (the server that opened the session) sends a request in a frame; the responder
//! sends the response in its next frame. Every message is deterministic CBOR, a map whose key 0 is
//! its type. The types and fields are in `docs/federation.md`.

use crate::cbor::{Fields, Value};
use crate::error::{FedError, Result};
use crate::eventsync::LogEntry;
use crate::hashtree::{BUCKETS, Leaf};
use crate::tagsync::ItemTags;
use crate::wire::{item_id, owner, server_id};
use kemlock_domain::sends::SendRecord;
use kemlock_domain::{AttachmentId, BlobId, ItemId, Owner, ServerId, VersionVector};

/// The most item ids one request names.
pub const MAX_ITEMS: usize = 4096;
/// The most records one response carries.
pub const MAX_RECORDS: usize = 1024;
/// The most items a pull page may ask for.
pub const MAX_PAGE: u32 = 500;
/// The most leaves one response carries.
pub const MAX_LEAVES: usize = 16_384;
/// The longest error detail.
pub const MAX_DETAIL: usize = 256;

/// Error codes of [`Response::Error`].
pub mod code {
    /// The peer is not allowed this: not in the vault's set, or not paired for it.
    pub const REFUSED: u64 = 1;
    /// The request does not make sense.
    pub const BAD_REQUEST: u64 = 2;
    /// This server failed.
    pub const INTERNAL: u64 = 3;
    /// This server does not federate that vault.
    pub const UNKNOWN_VAULT: u64 = 4;
}

/// What a peer asks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request {
    /// The changes to `vault` that `since` doesn't cover.
    Pull {
        vault: Owner,
        since: VersionVector,
        limit: u32,
    },
    /// "I have more": the sender's latest version vector for the vault. The receiver pulls.
    Nudge { vault: Owner, latest: VersionVector },
    /// The hash-tree summary of the vault.
    Summary { vault: Owner },
    /// The leaves of these buckets.
    Leaves { vault: Owner, buckets: Vec<u8> },
    /// The change records of these items (every version held).
    Fetch { vault: Owner, items: Vec<ItemId> },
    /// The home records after index `after`.
    HomeRecords {
        vault: Owner,
        after: u64,
        limit: u32,
    },
    /// A signed promotion record.
    Promote { record: Vec<u8> },
    /// Ends the session.
    Bye,
    /// The home offers a replica of `vault`: the home, the epoch and the replicas in order. The
    /// peer's admin accepts or declines; the answer says where that stands.
    Offer {
        vault: Owner,
        home: ServerId,
        epoch: u64,
        replicas: Vec<ServerId>,
    },
    /// The attachments of `vault` after the attachment id `after` (all zeros for the first page),
    /// in attachment id order.
    Blobs {
        vault: Owner,
        after: [u8; 16],
        limit: u32,
    },
    /// `len` bytes of the attachment file stored as `blob`, from `offset`.
    Blob {
        vault: Owner,
        blob: BlobId,
        offset: u64,
        len: u32,
    },
    /// The home tells a replica the vault was erased (its account was deleted, or its space was):
    /// delete the copy, and the files and copied accounts that went with it. Only the vault's
    /// home may ask; a replica that holds nothing of the vault acknowledges it all the same.
    Erase { vault: Owner },
    /// The event log entries of the vault's members with an id after `after` (all zeros for the
    /// first page), oldest first. Answered only when the responder's Send switch for the
    /// requester is on.
    Events {
        vault: Owner,
        after: [u8; 16],
        limit: u32,
    },
    /// A signed notice that the sender unpairs: delete what you hold because of it. See `forget`.
    Forget { notice: Vec<u8> },
    /// The identity keys of the other servers that hold `vault`, vouched for by the responder: one
    /// signed attestation each. See `relay`.
    OriginKeys { vault: Owner },
    /// The tags the responder holds for these items at their current revision (at most 256 items),
    /// when server matching is on for the vault there. See `tagsync`.
    Tags { vault: Owner, items: Vec<ItemId> },
    /// The Sends of a personal vault with an id after `after` (all zeros for the first page), in
    /// id order, at most `limit` (the responder serves at most 50 a page). See `sendsync`.
    Sends {
        vault: Owner,
        after: [u8; 16],
        limit: u32,
    },
}

/// Where an offer of a vault stands at the peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OfferState {
    /// Waiting for the admin.
    Pending,
    Accepted,
    Declined,
}

impl OfferState {
    fn code(self) -> u64 {
        match self {
            OfferState::Pending => 0,
            OfferState::Accepted => 1,
            OfferState::Declined => 2,
        }
    }

    fn from_code(code: u64) -> Result<OfferState> {
        match code {
            0 => Ok(OfferState::Pending),
            1 => Ok(OfferState::Accepted),
            2 => Ok(OfferState::Declined),
            _ => Err(FedError::Malformed("an unknown offer state")),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            OfferState::Pending => "pending",
            OfferState::Accepted => "accepted",
            OfferState::Declined => "declined",
        }
    }

    pub fn parse(s: &str) -> Option<OfferState> {
        match s {
            "pending" => Some(OfferState::Pending),
            "accepted" => Some(OfferState::Accepted),
            "declined" => Some(OfferState::Declined),
            _ => None,
        }
    }
}

/// One attachment of a vault, as a peer lists it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlobEntry {
    pub attachment: AttachmentId,
    pub item: ItemId,
    pub blob: BlobId,
    /// The size of the `KMA1` file in bytes.
    pub size: u64,
}

/// The longest chunk of a file one `Blob` request asks for or one `BlobChunk` carries.
pub const MAX_CHUNK: u32 = 2 * 1024 * 1024;
/// The most entries one `Blobs` response carries.
pub const MAX_BLOB_ENTRIES: usize = 500;
const BLOB_ENTRY_LEN: usize = 56;

/// What a peer answers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Response {
    /// Signed change records, and the cursor after them.
    Changes {
        vault: Owner,
        records: Vec<Vec<u8>>,
        next: VersionVector,
        more: bool,
    },
    Ack,
    Summary {
        vault: Owner,
        root: [u8; 32],
        buckets: Vec<[u8; 32]>,
    },
    Leaves {
        vault: Owner,
        leaves: Vec<Leaf>,
    },
    /// Signed home records.
    HomeRecords {
        vault: Owner,
        records: Vec<Vec<u8>>,
        more: bool,
    },
    Error {
        code: u64,
        detail: String,
    },
    /// Where an offered vault stands at this server.
    OfferStatus {
        vault: Owner,
        state: OfferState,
    },
    /// A page of a vault's attachments.
    Blobs {
        vault: Owner,
        entries: Vec<BlobEntry>,
        more: bool,
    },
    /// A chunk of an attachment file; `size` is the whole file's size.
    BlobChunk {
        vault: Owner,
        blob: BlobId,
        size: u64,
        offset: u64,
        data: Vec<u8>,
    },
    /// A page of event log entries, oldest first.
    Events {
        vault: Owner,
        events: Vec<LogEntry>,
        more: bool,
    },
    /// What the responder says it deleted because the requester unpaired.
    Forgotten {
        vaults: u64,
        items: u64,
        accounts: u64,
    },
    /// Signed attestations of the identity keys of a vault's other servers.
    OriginKeys {
        vault: Owner,
        records: Vec<Vec<u8>>,
    },
    /// The tags of some items, each for the revision it was made for.
    Tags {
        vault: Owner,
        entries: Vec<ItemTags>,
    },
    /// A page of the Sends of a personal vault, in id order. Only Sends whose bytes are held.
    Sends {
        vault: Owner,
        entries: Vec<SendRecord>,
        more: bool,
    },
}

fn vault(f: &Fields<'_>) -> Result<Owner> {
    owner(f.fixed::<17>(1)?)
}

fn cursor(f: &Fields<'_>, key: u64) -> Result<VersionVector> {
    VersionVector::from_cursor_bytes(f.bytes(key)?)
        .map_err(|_| FedError::Malformed("a cursor is not valid"))
}

fn limit(f: &Fields<'_>, key: u64) -> Result<u32> {
    let n = u32::try_from(f.uint(key)?).map_err(|_| FedError::Malformed("a limit is too large"))?;
    if n == 0 || n > MAX_PAGE {
        return Err(FedError::Malformed("a limit is out of range"));
    }
    Ok(n)
}

fn blobs(f: &Fields<'_>, key: u64, max: usize) -> Result<Vec<Vec<u8>>> {
    let items = f.array(key)?;
    if items.len() > max {
        return Err(FedError::Malformed("too many records"));
    }
    items
        .iter()
        .map(|v| v.as_bytes().map(<[u8]>::to_vec))
        .collect()
}

fn blob_array(items: &[Vec<u8>]) -> Value {
    Value::Array(items.iter().map(|b| Value::bytes(b)).collect())
}

impl Request {
    pub fn encode(&self) -> Vec<u8> {
        let entries = match self {
            Request::Pull {
                vault,
                since,
                limit,
            } => vec![
                (0, Value::Uint(1)),
                (1, Value::bytes(&vault.to_bytes())),
                (2, Value::Bytes(since.to_cursor_bytes())),
                (3, Value::Uint(u64::from(*limit))),
            ],
            Request::Nudge { vault, latest } => vec![
                (0, Value::Uint(2)),
                (1, Value::bytes(&vault.to_bytes())),
                (2, Value::Bytes(latest.to_cursor_bytes())),
            ],
            Request::Summary { vault } => {
                vec![(0, Value::Uint(3)), (1, Value::bytes(&vault.to_bytes()))]
            }
            Request::Leaves { vault, buckets } => vec![
                (0, Value::Uint(4)),
                (1, Value::bytes(&vault.to_bytes())),
                (2, Value::bytes(buckets)),
            ],
            Request::Fetch { vault, items } => vec![
                (0, Value::Uint(5)),
                (1, Value::bytes(&vault.to_bytes())),
                (
                    2,
                    Value::Array(items.iter().map(|i| Value::bytes(i.as_bytes())).collect()),
                ),
            ],
            Request::HomeRecords {
                vault,
                after,
                limit,
            } => vec![
                (0, Value::Uint(6)),
                (1, Value::bytes(&vault.to_bytes())),
                (2, Value::Uint(*after)),
                (3, Value::Uint(u64::from(*limit))),
            ],
            Request::Promote { record } => vec![(0, Value::Uint(7)), (1, Value::bytes(record))],
            Request::Bye => vec![(0, Value::Uint(8))],
            Request::Offer {
                vault,
                home,
                epoch,
                replicas,
            } => vec![
                (0, Value::Uint(9)),
                (1, Value::bytes(&vault.to_bytes())),
                (2, Value::bytes(home.as_bytes())),
                (3, Value::Uint(*epoch)),
                (
                    4,
                    Value::Array(
                        replicas
                            .iter()
                            .map(|r| Value::bytes(r.as_bytes()))
                            .collect(),
                    ),
                ),
            ],
            Request::Blobs {
                vault,
                after,
                limit,
            } => vec![
                (0, Value::Uint(10)),
                (1, Value::bytes(&vault.to_bytes())),
                (2, Value::bytes(after)),
                (3, Value::Uint(u64::from(*limit))),
            ],
            Request::Blob {
                vault,
                blob,
                offset,
                len,
            } => vec![
                (0, Value::Uint(11)),
                (1, Value::bytes(&vault.to_bytes())),
                (2, Value::bytes(blob.as_bytes())),
                (3, Value::Uint(*offset)),
                (4, Value::Uint(u64::from(*len))),
            ],
            Request::Events {
                vault,
                after,
                limit,
            } => vec![
                (0, Value::Uint(12)),
                (1, Value::bytes(&vault.to_bytes())),
                (2, Value::bytes(after)),
                (3, Value::Uint(u64::from(*limit))),
            ],
            Request::Forget { notice } => vec![(0, Value::Uint(13)), (1, Value::bytes(notice))],
            Request::OriginKeys { vault } => {
                vec![(0, Value::Uint(14)), (1, Value::bytes(&vault.to_bytes()))]
            }
            Request::Tags { vault, items } => vec![
                (0, Value::Uint(15)),
                (1, Value::bytes(&vault.to_bytes())),
                (
                    2,
                    Value::Array(items.iter().map(|i| Value::bytes(i.as_bytes())).collect()),
                ),
            ],
            Request::Erase { vault } => {
                vec![(0, Value::Uint(16)), (1, Value::bytes(&vault.to_bytes()))]
            }
            Request::Sends {
                vault,
                after,
                limit,
            } => vec![
                (0, Value::Uint(17)),
                (1, Value::bytes(&vault.to_bytes())),
                (2, Value::bytes(after)),
                (3, Value::Uint(u64::from(*limit))),
            ],
        };
        Value::map(entries).encode()
    }

    pub fn decode(bytes: &[u8]) -> Result<Request> {
        let value = Value::decode(bytes)?;
        let f = value.as_fields()?;
        match f.uint(0)? {
            1 => {
                f.only(&[0, 1, 2, 3])?;
                Ok(Request::Pull {
                    vault: vault(&f)?,
                    since: cursor(&f, 2)?,
                    limit: limit(&f, 3)?,
                })
            }
            2 => {
                f.only(&[0, 1, 2])?;
                Ok(Request::Nudge {
                    vault: vault(&f)?,
                    latest: cursor(&f, 2)?,
                })
            }
            3 => {
                f.only(&[0, 1])?;
                Ok(Request::Summary { vault: vault(&f)? })
            }
            4 => {
                f.only(&[0, 1, 2])?;
                let buckets = f.bytes(2)?;
                if buckets.len() > BUCKETS {
                    return Err(FedError::Malformed("too many buckets"));
                }
                Ok(Request::Leaves {
                    vault: vault(&f)?,
                    buckets: buckets.to_vec(),
                })
            }
            5 => {
                f.only(&[0, 1, 2])?;
                let ids = f.array(2)?;
                if ids.len() > MAX_ITEMS {
                    return Err(FedError::Malformed("too many items"));
                }
                let items =
                    ids.iter()
                        .map(|v| -> Result<ItemId> {
                            let b: [u8; 16] = v.as_bytes()?.try_into().map_err(|_| {
                                FedError::Malformed("an item id has the wrong length")
                            })?;
                            Ok(item_id(b))
                        })
                        .collect::<Result<Vec<ItemId>>>()?;
                Ok(Request::Fetch {
                    vault: vault(&f)?,
                    items,
                })
            }
            6 => {
                f.only(&[0, 1, 2, 3])?;
                Ok(Request::HomeRecords {
                    vault: vault(&f)?,
                    after: f.uint(2)?,
                    limit: limit(&f, 3)?,
                })
            }
            7 => {
                f.only(&[0, 1])?;
                Ok(Request::Promote {
                    record: f.bytes(1)?.to_vec(),
                })
            }
            8 => {
                f.only(&[0])?;
                Ok(Request::Bye)
            }
            9 => {
                f.only(&[0, 1, 2, 3, 4])?;
                let items = f.array(4)?;
                if items.len() > crate::home::MAX_REPLICAS {
                    return Err(FedError::Malformed("too many replicas"));
                }
                let replicas = items
                    .iter()
                    .map(|v| -> Result<ServerId> {
                        let b: [u8; 16] = v
                            .as_bytes()?
                            .try_into()
                            .map_err(|_| FedError::Malformed("a server id has the wrong length"))?;
                        Ok(server_id(b))
                    })
                    .collect::<Result<Vec<ServerId>>>()?;
                Ok(Request::Offer {
                    vault: vault(&f)?,
                    home: server_id(f.fixed::<16>(2)?),
                    epoch: f.uint(3)?,
                    replicas,
                })
            }
            10 => {
                f.only(&[0, 1, 2, 3])?;
                let limit = u32::try_from(f.uint(3)?)
                    .map_err(|_| FedError::Malformed("a limit is too large"))?;
                if limit == 0 || limit as usize > MAX_BLOB_ENTRIES {
                    return Err(FedError::Malformed("a limit is out of range"));
                }
                Ok(Request::Blobs {
                    vault: vault(&f)?,
                    after: f.fixed::<16>(2)?,
                    limit,
                })
            }
            11 => {
                f.only(&[0, 1, 2, 3, 4])?;
                let len = u32::try_from(f.uint(4)?)
                    .map_err(|_| FedError::Malformed("a length is too large"))?;
                if len == 0 || len > MAX_CHUNK {
                    return Err(FedError::Malformed("a length is out of range"));
                }
                Ok(Request::Blob {
                    vault: vault(&f)?,
                    blob: BlobId::from_bytes(f.fixed::<16>(2)?),
                    offset: f.uint(3)?,
                    len,
                })
            }
            12 => {
                f.only(&[0, 1, 2, 3])?;
                Ok(Request::Events {
                    vault: vault(&f)?,
                    after: f.fixed::<16>(2)?,
                    limit: limit(&f, 3)?,
                })
            }
            13 => {
                f.only(&[0, 1])?;
                Ok(Request::Forget {
                    notice: f.bytes(1)?.to_vec(),
                })
            }
            14 => {
                f.only(&[0, 1])?;
                Ok(Request::OriginKeys { vault: vault(&f)? })
            }
            15 => {
                f.only(&[0, 1, 2])?;
                let ids = f.array(2)?;
                if ids.len() > crate::tagsync::CHUNK as usize {
                    return Err(FedError::Malformed("too many items"));
                }
                let items =
                    ids.iter()
                        .map(|v| -> Result<ItemId> {
                            let b: [u8; 16] = v.as_bytes()?.try_into().map_err(|_| {
                                FedError::Malformed("an item id has the wrong length")
                            })?;
                            Ok(item_id(b))
                        })
                        .collect::<Result<Vec<ItemId>>>()?;
                Ok(Request::Tags {
                    vault: vault(&f)?,
                    items,
                })
            }
            16 => {
                f.only(&[0, 1])?;
                Ok(Request::Erase { vault: vault(&f)? })
            }
            17 => {
                f.only(&[0, 1, 2, 3])?;
                Ok(Request::Sends {
                    vault: vault(&f)?,
                    after: f.fixed::<16>(2)?,
                    limit: limit(&f, 3)?,
                })
            }
            _ => Err(FedError::Malformed("unknown request type")),
        }
    }
}

impl Response {
    pub fn encode(&self) -> Vec<u8> {
        let entries = match self {
            Response::Changes {
                vault,
                records,
                next,
                more,
            } => vec![
                (0, Value::Uint(101)),
                (1, Value::bytes(&vault.to_bytes())),
                (2, blob_array(records)),
                (3, Value::Bytes(next.to_cursor_bytes())),
                (4, Value::flag(*more)),
            ],
            Response::Ack => vec![(0, Value::Uint(102))],
            Response::Summary {
                vault,
                root,
                buckets,
            } => vec![
                (0, Value::Uint(103)),
                (1, Value::bytes(&vault.to_bytes())),
                (2, Value::bytes(root)),
                (3, Value::Bytes(buckets.concat())),
            ],
            Response::Leaves { vault, leaves } => {
                let mut packed = Vec::with_capacity(leaves.len() * 48);
                for leaf in leaves {
                    packed.extend_from_slice(leaf.item.as_bytes());
                    packed.extend_from_slice(&leaf.digest);
                }
                vec![
                    (0, Value::Uint(104)),
                    (1, Value::bytes(&vault.to_bytes())),
                    (2, Value::Bytes(packed)),
                ]
            }
            Response::HomeRecords {
                vault,
                records,
                more,
            } => vec![
                (0, Value::Uint(105)),
                (1, Value::bytes(&vault.to_bytes())),
                (2, blob_array(records)),
                (3, Value::flag(*more)),
            ],
            Response::Error { code, detail } => vec![
                (0, Value::Uint(199)),
                (1, Value::Uint(*code)),
                (2, Value::text(detail)),
            ],
            Response::OfferStatus { vault, state } => vec![
                (0, Value::Uint(106)),
                (1, Value::bytes(&vault.to_bytes())),
                (2, Value::Uint(state.code())),
            ],
            Response::Blobs {
                vault,
                entries,
                more,
            } => {
                let mut packed = Vec::with_capacity(entries.len() * BLOB_ENTRY_LEN);
                for e in entries {
                    packed.extend_from_slice(e.attachment.0.as_bytes());
                    packed.extend_from_slice(e.item.as_bytes());
                    packed.extend_from_slice(e.blob.as_bytes());
                    packed.extend_from_slice(&e.size.to_be_bytes());
                }
                vec![
                    (0, Value::Uint(107)),
                    (1, Value::bytes(&vault.to_bytes())),
                    (2, Value::Bytes(packed)),
                    (3, Value::flag(*more)),
                ]
            }
            Response::BlobChunk {
                vault,
                blob,
                size,
                offset,
                data,
            } => vec![
                (0, Value::Uint(108)),
                (1, Value::bytes(&vault.to_bytes())),
                (2, Value::bytes(blob.as_bytes())),
                (3, Value::Uint(*size)),
                (4, Value::Uint(*offset)),
                (5, Value::bytes(data)),
            ],
            Response::Events {
                vault,
                events,
                more,
            } => vec![
                (0, Value::Uint(109)),
                (1, Value::bytes(&vault.to_bytes())),
                (
                    2,
                    Value::Array(events.iter().map(LogEntry::to_value).collect()),
                ),
                (3, Value::flag(*more)),
            ],
            Response::Forgotten {
                vaults,
                items,
                accounts,
            } => vec![
                (0, Value::Uint(110)),
                (1, Value::Uint(*vaults)),
                (2, Value::Uint(*items)),
                (3, Value::Uint(*accounts)),
            ],
            Response::OriginKeys { vault, records } => vec![
                (0, Value::Uint(111)),
                (1, Value::bytes(&vault.to_bytes())),
                (2, blob_array(records)),
            ],
            Response::Tags { vault, entries } => vec![
                (0, Value::Uint(112)),
                (1, Value::bytes(&vault.to_bytes())),
                (
                    2,
                    Value::Array(entries.iter().map(ItemTags::to_value).collect()),
                ),
            ],
            Response::Sends {
                vault,
                entries,
                more,
            } => vec![
                (0, Value::Uint(113)),
                (1, Value::bytes(&vault.to_bytes())),
                (
                    2,
                    Value::Array(entries.iter().map(crate::sendsync::send_to_value).collect()),
                ),
                (3, Value::flag(*more)),
            ],
        };
        Value::map(entries).encode()
    }

    pub fn decode(bytes: &[u8]) -> Result<Response> {
        let value = Value::decode(bytes)?;
        let f = value.as_fields()?;
        match f.uint(0)? {
            101 => {
                f.only(&[0, 1, 2, 3, 4])?;
                Ok(Response::Changes {
                    vault: vault(&f)?,
                    records: blobs(&f, 2, MAX_RECORDS)?,
                    next: cursor(&f, 3)?,
                    more: f.flag(4)?,
                })
            }
            102 => {
                f.only(&[0])?;
                Ok(Response::Ack)
            }
            103 => {
                f.only(&[0, 1, 2, 3])?;
                let packed = f.bytes(3)?;
                if packed.len() != BUCKETS * 32 {
                    return Err(FedError::Malformed("a summary holds 256 buckets"));
                }
                let buckets = packed
                    .as_chunks::<32>()
                    .0
                    .iter()
                    .map(|c| {
                        let mut d = [0u8; 32];
                        d.copy_from_slice(c);
                        d
                    })
                    .collect();
                Ok(Response::Summary {
                    vault: vault(&f)?,
                    root: f.fixed::<32>(2)?,
                    buckets,
                })
            }
            104 => {
                f.only(&[0, 1, 2])?;
                let packed = f.bytes(2)?;
                if packed.len() % 48 != 0 || packed.len() / 48 > MAX_LEAVES {
                    return Err(FedError::Malformed("the leaves are not a whole number"));
                }
                let leaves = packed
                    .as_chunks::<48>()
                    .0
                    .iter()
                    .map(|c| {
                        let mut id = [0u8; 16];
                        id.copy_from_slice(&c[..16]);
                        let mut digest = [0u8; 32];
                        digest.copy_from_slice(&c[16..]);
                        Leaf {
                            item: item_id(id),
                            digest,
                        }
                    })
                    .collect();
                Ok(Response::Leaves {
                    vault: vault(&f)?,
                    leaves,
                })
            }
            105 => {
                f.only(&[0, 1, 2, 3])?;
                Ok(Response::HomeRecords {
                    vault: vault(&f)?,
                    records: blobs(&f, 2, MAX_RECORDS)?,
                    more: f.flag(3)?,
                })
            }
            199 => {
                f.only(&[0, 1, 2])?;
                let detail = f.text(2)?;
                if detail.len() > MAX_DETAIL {
                    return Err(FedError::Malformed("an error detail is too long"));
                }
                Ok(Response::Error {
                    code: f.uint(1)?,
                    detail: detail.to_owned(),
                })
            }
            106 => {
                f.only(&[0, 1, 2])?;
                Ok(Response::OfferStatus {
                    vault: vault(&f)?,
                    state: OfferState::from_code(f.uint(2)?)?,
                })
            }
            107 => {
                f.only(&[0, 1, 2, 3])?;
                let packed = f.bytes(2)?;
                if packed.len() % BLOB_ENTRY_LEN != 0
                    || packed.len() / BLOB_ENTRY_LEN > MAX_BLOB_ENTRIES
                {
                    return Err(FedError::Malformed(
                        "the attachments are not a whole number",
                    ));
                }
                let entries = packed
                    .as_chunks::<BLOB_ENTRY_LEN>()
                    .0
                    .iter()
                    .map(|c| {
                        let mut attachment = [0u8; 16];
                        attachment.copy_from_slice(&c[..16]);
                        let mut item = [0u8; 16];
                        item.copy_from_slice(&c[16..32]);
                        let mut blob = [0u8; 16];
                        blob.copy_from_slice(&c[32..48]);
                        let mut size = [0u8; 8];
                        size.copy_from_slice(&c[48..]);
                        BlobEntry {
                            attachment: AttachmentId(uuid::Uuid::from_bytes(attachment)),
                            item: item_id(item),
                            blob: BlobId::from_bytes(blob),
                            size: u64::from_be_bytes(size),
                        }
                    })
                    .collect();
                Ok(Response::Blobs {
                    vault: vault(&f)?,
                    entries,
                    more: f.flag(3)?,
                })
            }
            108 => {
                f.only(&[0, 1, 2, 3, 4, 5])?;
                let data = f.bytes(5)?;
                if data.len() > MAX_CHUNK as usize {
                    return Err(FedError::Malformed("a chunk is too long"));
                }
                Ok(Response::BlobChunk {
                    vault: vault(&f)?,
                    blob: BlobId::from_bytes(f.fixed::<16>(2)?),
                    size: f.uint(3)?,
                    offset: f.uint(4)?,
                    data: data.to_vec(),
                })
            }
            109 => {
                f.only(&[0, 1, 2, 3])?;
                let items = f.array(2)?;
                if items.len() > MAX_RECORDS {
                    return Err(FedError::Malformed("too many events"));
                }
                Ok(Response::Events {
                    vault: vault(&f)?,
                    events: items
                        .iter()
                        .map(LogEntry::from_value)
                        .collect::<Result<Vec<LogEntry>>>()?,
                    more: f.flag(3)?,
                })
            }
            110 => {
                f.only(&[0, 1, 2, 3])?;
                Ok(Response::Forgotten {
                    vaults: f.uint(1)?,
                    items: f.uint(2)?,
                    accounts: f.uint(3)?,
                })
            }
            111 => {
                f.only(&[0, 1, 2])?;
                Ok(Response::OriginKeys {
                    vault: vault(&f)?,
                    records: blobs(&f, 2, crate::home::MAX_REPLICAS)?,
                })
            }
            112 => {
                f.only(&[0, 1, 2])?;
                let items = f.array(2)?;
                if items.len() > crate::tagsync::CHUNK as usize {
                    return Err(FedError::Malformed("too many tag entries"));
                }
                Ok(Response::Tags {
                    vault: vault(&f)?,
                    entries: items
                        .iter()
                        .map(ItemTags::from_value)
                        .collect::<Result<Vec<ItemTags>>>()?,
                })
            }
            113 => {
                f.only(&[0, 1, 2, 3])?;
                let Owner::User(owner) = vault(&f)? else {
                    return Err(FedError::Malformed("a space has no Sends"));
                };
                let items = f.array(2)?;
                if items.len() > crate::sendsync::MAX_SEND_ENTRIES as usize {
                    return Err(FedError::Malformed("too many Sends"));
                }
                Ok(Response::Sends {
                    vault: Owner::User(owner),
                    entries: items
                        .iter()
                        .map(|v| crate::sendsync::send_from_value(v, owner))
                        .collect::<Result<Vec<SendRecord>>>()?,
                    more: f.flag(3)?,
                })
            }
            _ => Err(FedError::Malformed("unknown response type")),
        }
    }

    /// An error response.
    pub fn error(code: u64, detail: &str) -> Response {
        let mut end = detail.len().min(MAX_DETAIL);
        while !detail.is_char_boundary(end) {
            end -= 1;
        }
        Response::Error {
            code,
            detail: detail[..end].to_owned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::ChangeKey;
    use kemlock_domain::{ChangeId, Hlc, ServerId, UserId};

    fn vault() -> Owner {
        Owner::User(UserId::random())
    }

    fn cursor() -> VersionVector {
        let mut v = VersionVector::new();
        v.observe(&ChangeId {
            origin: ServerId::random(),
            seq: 9,
            hlc: Hlc(1),
        });
        v
    }

    #[test]
    fn every_request_round_trips() {
        let requests = vec![
            Request::Pull {
                vault: vault(),
                since: cursor(),
                limit: 100,
            },
            Request::Pull {
                vault: vault(),
                since: VersionVector::new(),
                limit: 1,
            },
            Request::Nudge {
                vault: vault(),
                latest: cursor(),
            },
            Request::Summary { vault: vault() },
            Request::Leaves {
                vault: vault(),
                buckets: vec![0, 7, 255],
            },
            Request::Fetch {
                vault: vault(),
                items: vec![ItemId::random(), ItemId::random()],
            },
            Request::HomeRecords {
                vault: vault(),
                after: 4,
                limit: 50,
            },
            Request::Promote {
                record: vec![1, 2, 3],
            },
            Request::Bye,
            Request::Offer {
                vault: vault(),
                home: ServerId::random(),
                epoch: 3,
                replicas: vec![ServerId::random(), ServerId::random()],
            },
            Request::Blobs {
                vault: vault(),
                after: [0; 16],
                limit: 500,
            },
            Request::Blob {
                vault: vault(),
                blob: BlobId::random(),
                offset: 4_194_304,
                len: MAX_CHUNK,
            },
            Request::Erase { vault: vault() },
            Request::Events {
                vault: vault(),
                after: [5; 16],
                limit: 500,
            },
            Request::Forget {
                notice: vec![1; 40],
            },
            Request::OriginKeys { vault: vault() },
            Request::Tags {
                vault: vault(),
                items: vec![ItemId::random(), ItemId::random()],
            },
        ];
        for r in requests {
            assert_eq!(Request::decode(&r.encode()), Ok(r.clone()), "{r:?}");
        }
    }

    #[test]
    fn every_response_round_trips() {
        let responses = vec![
            Response::Changes {
                vault: vault(),
                records: vec![vec![1; 10], vec![2; 20]],
                next: cursor(),
                more: true,
            },
            Response::Ack,
            Response::Summary {
                vault: vault(),
                root: [7; 32],
                buckets: vec![[3; 32]; BUCKETS],
            },
            Response::Leaves {
                vault: vault(),
                leaves: vec![
                    Leaf {
                        item: ItemId::random(),
                        digest: [5; 32],
                    },
                    Leaf {
                        item: ItemId::random(),
                        digest: [6; 32],
                    },
                ],
            },
            Response::Leaves {
                vault: vault(),
                leaves: vec![],
            },
            Response::HomeRecords {
                vault: vault(),
                records: vec![vec![9]],
                more: false,
            },
            Response::error(code::REFUSED, "not in the vault's set"),
            Response::OfferStatus {
                vault: vault(),
                state: OfferState::Pending,
            },
            Response::Blobs {
                vault: vault(),
                entries: vec![BlobEntry {
                    attachment: AttachmentId::random(),
                    item: ItemId::random(),
                    blob: BlobId::random(),
                    size: 52_428_801,
                }],
                more: true,
            },
            Response::BlobChunk {
                vault: vault(),
                blob: BlobId::random(),
                size: 100,
                offset: 50,
                data: vec![8; 50],
            },
            Response::Events {
                vault: vault(),
                events: vec![
                    LogEntry {
                        id: [1; 16],
                        at_ms: 1_700_000_000_000,
                        actor: Some([2; 16]),
                        device: None,
                        action: "login".to_owned(),
                        target: Some("x".to_owned()),
                    },
                    LogEntry {
                        id: [3; 16],
                        at_ms: 1_700_000_000_500,
                        actor: None,
                        device: Some([4; 16]),
                        action: "logout".to_owned(),
                        target: None,
                    },
                ],
                more: true,
            },
            Response::Events {
                vault: vault(),
                events: vec![],
                more: false,
            },
            Response::Forgotten {
                vaults: 1,
                items: 20,
                accounts: 3,
            },
            Response::OriginKeys {
                vault: vault(),
                records: vec![vec![1; 30], vec![2; 40]],
            },
            Response::Tags {
                vault: vault(),
                entries: vec![ItemTags {
                    item: ItemId::random(),
                    revision: 4,
                    version: 2,
                    tags: vec![[1; 32], [2; 32]],
                }],
            },
        ];
        for r in responses {
            assert_eq!(Response::decode(&r.encode()), Ok(r.clone()), "{r:?}");
        }
    }

    #[test]
    fn malformed_requests_are_refused() {
        let v = vault();
        let good = Request::Pull {
            vault: v,
            since: cursor(),
            limit: 10,
        };
        // A limit of zero or above the page cap.
        for limit in [0, MAX_PAGE + 1] {
            let bad = Request::Pull {
                vault: v,
                since: VersionVector::new(),
                limit,
            };
            assert!(Request::decode(&bad.encode()).is_err());
        }
        // Unknown type, an extra field, an unreadable cursor, an unknown owner type.
        assert!(Request::decode(&Value::map(vec![(0, Value::Uint(99))]).encode()).is_err());
        let mut value = Value::decode(&good.encode()).expect("decode");
        if let Value::Map(entries) = &mut value {
            entries.push((9, Value::Uint(1)));
        }
        assert!(Request::decode(&value.encode()).is_err());
        let bad_cursor = Value::map(vec![
            (0, Value::Uint(2)),
            (1, Value::bytes(&v.to_bytes())),
            (2, Value::bytes(&[9, 9])),
        ]);
        assert!(Request::decode(&bad_cursor.encode()).is_err());
        let mut bytes = v.to_bytes();
        bytes[0] = 9;
        let bad_owner = Value::map(vec![(0, Value::Uint(3)), (1, Value::bytes(&bytes))]);
        assert!(Request::decode(&bad_owner.encode()).is_err());
        // Too many buckets or items.
        let many = Request::Leaves {
            vault: v,
            buckets: vec![0; BUCKETS + 1],
        };
        assert!(Request::decode(&many.encode()).is_err());
        let many = Request::Fetch {
            vault: v,
            items: vec![ItemId::random(); MAX_ITEMS + 1],
        };
        assert!(Request::decode(&many.encode()).is_err());
        assert!(Request::decode(&[]).is_err());
    }

    #[test]
    fn an_erase_request_carries_only_its_vault() {
        let v = vault();
        let extra = Value::map(vec![
            (0, Value::Uint(16)),
            (1, Value::bytes(&v.to_bytes())),
            (2, Value::Uint(1)),
        ]);
        assert!(Request::decode(&extra.encode()).is_err());
        assert!(Request::decode(&Value::map(vec![(0, Value::Uint(16))]).encode()).is_err());
    }

    #[test]
    fn malformed_responses_are_refused() {
        let v = vault();
        let short_summary = Value::map(vec![
            (0, Value::Uint(103)),
            (1, Value::bytes(&v.to_bytes())),
            (2, Value::bytes(&[0; 32])),
            (3, Value::bytes(&[0; 100])),
        ]);
        assert!(Response::decode(&short_summary.encode()).is_err());
        let ragged_leaves = Value::map(vec![
            (0, Value::Uint(104)),
            (1, Value::bytes(&v.to_bytes())),
            (2, Value::bytes(&[0; 47])),
        ]);
        assert!(Response::decode(&ragged_leaves.encode()).is_err());
        let long_error = Value::map(vec![
            (0, Value::Uint(199)),
            (1, Value::Uint(1)),
            (2, Value::text(&"x".repeat(MAX_DETAIL + 1))),
        ]);
        assert!(Response::decode(&long_error.encode()).is_err());
        assert!(Response::decode(&Value::map(vec![(0, Value::Uint(1))]).encode()).is_err());
    }

    #[test]
    fn error_details_are_cut_on_a_character_boundary() {
        let long = "é".repeat(MAX_DETAIL);
        match Response::error(code::INTERNAL, &long) {
            Response::Error { detail, .. } => {
                assert!(detail.len() <= MAX_DETAIL);
                assert!(detail.chars().all(|c| c == 'é'));
            }
            other => panic!("{other:?}"),
        }
        let _ = ChangeKey::LEN;
    }
}
