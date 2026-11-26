# Kemlock federation formats, version 1

This file fixes the bytes two Kemlock Servers agree on when they federate: the signed descriptor,
the post-quantum session handshake, sealed frames, pairing, and the records that replicate vaults.
`kemlock-federation` implements it, and `test-vectors/federation-*.json` (CC0) pin each format with
generated vectors. Change a format here only with a new version label: released bytes never change.

The design behind it is "Kemlock Server: design and architecture", Federation and replication, and
its Decisions table: federation is open to any operator, every vault is Local by default, files over
50 MB are fetched on first use, the two event-log switches (Send and Pull) are off by default,
padding is on by default, and servers never share `rsa_key.pem`.

## Conventions

- `‖` is concatenation. `u8`, `u16be`, `u32be`, `u64be` are unsigned big-endian integers.
- `lp(x)` is `u32be(len(x)) ‖ x`, as in `docs/crypto.md`. Labels are ASCII strings in double quotes,
  used as bytes with no terminator.
- UUIDs (server ids, item ids) are their 16 raw bytes. An owner is `u8(type) ‖ uuid`, 17 bytes, as in
  `docs/crypto.md` (`0x01` user, `0x02` space).
- Times are Unix seconds, except a change record's write time, which is Unix milliseconds, and HLC
  times, which are `u64`: milliseconds in the high 48 bits and a logical counter in the low 16.
- HKDF is HKDF-SHA256 (RFC 5869). Every expansion here asks for at most 32 bytes, so
  `HKDF-Expand(prk, info, L)` is the first `L` bytes of `HMAC-SHA256(prk, info ‖ 0x01)`, and
  `HKDF-Extract(salt, ikm)` is `HMAC-SHA256(salt, ikm)`.
- `kx1` and `sig1` are the suites of `docs/crypto.md`: ML-KEM-1024 + X25519 and ML-DSA-65 + Ed25519.
  `sig1(ctx, m)` is a signature over `"kemlock/v1/sig1" ‖ lp(ctx) ‖ lp(m)`, 3373 bytes.
- A decoder checks every length before it decrypts or verifies anything, and refuses unknown
  versions, unknown fields and trailing bytes.

### Deterministic CBOR, and why

Every structured message is deterministic CBOR (RFC 8949 section 4.2.1) restricted to unsigned
integers, byte strings, text strings, arrays and maps whose keys are unsigned integers. There are
no floats, tags, simple values (booleans are the integers 0 and 1), negative numbers or indefinite
lengths. The encoder writes the shortest head for every integer and length and sorts map keys
ascending; a decoder refuses a longer head, an unsorted or repeated key, a nesting deeper than 6, a
count larger than the bytes left, text that is not UTF-8 and trailing bytes.

Why CBOR rather than canonical JSON (RFC 8785): the messages carry kilobytes of binary (keys of 1600
and 1984 bytes, signatures of 3373 bytes, ciphertexts) that JSON would have to base64 and a verifier
would then have to re-serialise to check a signature. With CBOR every signed object is a byte string
inside an envelope and the signature covers those exact bytes, so nothing is ever re-encoded;
integer keys give one ordering with no locale or Unicode-normalisation questions; and the subset's
parser is about 150 lines, which is what a fuzz target wants. A decoder still re-encodes what it
parsed and compares, so one record has exactly one encoding.

### The signed envelope

```
envelope = CBOR { 0: body (bytes), 1: signature (bytes, 3373) }
signature = sig1(context, body)
```

Which `sig1` context and which key sign a body is fixed per object (below). The reply of the
handshake is the one exception: its signature covers the transcript hash, not the body.

## Suites

A suite is named by an ASCII string. Descriptors and hellos carry names, so a name this build has
never heard of can be carried, hashed into the transcript and skipped.

| Suite | Exchange | Frames | Signatures | Preferred by |
| --- | --- | --- | --- | --- |
| `kfed1-mlkem1024x25519-aes256gcm` | ML-KEM-1024 + X25519 (`kx1`) | AES-256-GCM | ML-DSA-65 + Ed25519 (`sig1`) | Servers with AES instructions |
| `kfed1-mlkem1024x25519-chacha20poly1305` | `kx1` | ChaCha20-Poly1305 | `sig1` | Servers without them (Raspberry Pi 4) |
| `kfed1-mlkem1024p384-aes256gcm` | ML-KEM-1024 + ECDH P-384 | AES-256-GCM | ML-DSA-65 + ECDSA P-384 | FIPS images |

Every suite is post-quantum and authenticated; nothing weaker exists to fall back to.

**Choosing.** The connecting server reads the other's descriptor and takes the first suite in that
list that it also supports and that its build implements. A name it doesn't know is skipped, never
approximated. With no match the connection fails, and the error says whether a known suite was
refused only because it isn't implemented. The responder repeats the choice from the two lists in
the hello and refuses a hello that picked another.

**The FIPS suite is defined and refused.** The id is reserved so descriptors can list it, but this
build does not implement it: the P-384 hybrid exchange key and the ECDSA P-384 signatures have no
encoding or code yet. The ML-KEM seed is not the obstacle: `kemlock-crypto` expands it on
RustCrypto's `ml-kem` for that one step on every backend, and a FIPS build runs ML-DSA on
RustCrypto too, outside the FIPS module ("Crypto library" in `crypto.md`). A server
whose only common suite is this one fails with "not available in this build". It will get its own
exchange-key and signature encodings (P-384 points, ECDSA) when it is implemented; no byte of the
suites above changes.

## The descriptor

Published at `GET /fed/v1/descriptor` and `GET /.well-known/kemlock-federation` as an envelope
(media type `application/vnd.kemlock.federation-descriptor+cbor`). The body is:

| Key | Field | Value |
| --- | --- | --- |
| 0 | version | `1` |
| 1 | server id | 16 bytes |
| 2 | identity key | `sig1` public key, 1984 bytes. Pinned by every peer at pairing |
| 3 | KEM key | `kx1` public key, 1600 bytes. Replaced every 30 days |
| 4 | suites | array of at most 16 texts of at most 64 bytes, most preferred first |
| 5 | addresses | array of at most 8 texts of at most 256 bytes, base URLs |
| 6 | operator | text of at most 128 bytes, shown in the peer's console |
| 7 | not before | Unix seconds |
| 8 | not after | Unix seconds |

- The signature is `sig1("federation-descriptor", body)` by the identity key in field 2: a
  descriptor is self-signed, and a verifier compares field 2 with the key it pinned.
- Valid when `not_before - 300 <= now <= not_after` and `not_after - not_before <= 37 days` (the
  30-day KEM rotation plus a week of overlap). 300 seconds is the clock skew every check allows.
- `kem key id = SHA-256("kemlock/v1/fed/kem-key" ‖ kem key)`, 32 bytes. A hello names the KEM key
  it encapsulates to by this id, so a server holding the old and the new key during a rotation knows
  which to use.
- A different identity key from the pinned one is a key mismatch (below), never a rotation.

**Addresses.** An address is a plain base URL: `http` or `https`, a host, optionally a port and a path
prefix, and no user name, password, query or fragment (a request path is joined to the URL as a path,
so no address can reach a different URL than the one asked for). A descriptor's addresses are chosen
by the peer, and this server connects to them (a probe every minute, a visit, the peer's page in the
console, key records, the session), so they are checked before each connection:

- The addresses the admin chose, which are the one typed at pairing and any approved later
  (`peer_trusted_addresses`), may be `http` and may name a private network. The addresses a peer's
  descriptor lists are the peer's say, even at pairing and on the side that only showed the code.
- Any address of a peer that is refused by these rules puts the peer's addresses in the admin's list
  of address changes (the one a rotation's new addresses wait in), and approving it there trusts
  them. Peers paired before this rule start with none trusted, so a peer on a private network is
  listed the first time it is dialled.
- Any other address, one a later descriptor lists or a rotation brings, must be `https` and must resolve
  to public addresses only: loopback, private, link-local (the cloud metadata address included),
  carrier-grade NAT, documentation, multicast, reserved ranges and IPv6 addresses that carry one of
  them are refused, and one private answer refuses the whole name. The connection then goes to
  exactly the addresses that were checked, so a second lookup can't answer differently.
- Answers are read with a running cap (128 KiB for a descriptor or a pairing message), redirects are
  not followed, and the proxy variables of the environment are not used (a proxy resolves names
  itself, past the addresses checked).

## The handshake

Server A (the initiator) has fetched B's descriptor and checked it against B's pinned key.

### Hello (A to B)

An envelope signed by A's identity key with context `"federation-hello"`. The body:

| Key | Field | Value |
| --- | --- | --- |
| 0 | version | `1` |
| 1 | initiator id | 16 bytes |
| 2 | responder id | 16 bytes |
| 3 | responder KEM key id | 32 bytes |
| 4 | ephemeral key | `kx1` public key, 1600 bytes, fresh |
| 5 | encapsulation to B's KEM key | `kx1` ciphertext, 1600 bytes; its secret is `ss_B` |
| 6 | initiator suites | A's list, as in A's descriptor |
| 7 | responder suites | B's list, as in the descriptor A read |
| 8 | chosen suite | a name |
| 9 | nonce | 32 random bytes |
| 10 | timestamp | Unix seconds |
| 11 | initiator descriptor | A's signed descriptor, the envelope bytes |

B checks, in this order and before any KEM work: the message is at most 64 KiB and parses; it is
addressed to B; A's descriptor is A's (field 1) and verifies against the identity key B pinned for A
(a different key is a key mismatch, an unknown server is refused); the hello's signature verifies
under that key; the timestamp is within 300 seconds of B's clock; field 7 equals B's current list and
field 6 equals A's descriptor's list; and the chosen suite is what the rule above gives for those two
lists. Then it decapsulates field 5 with the KEM key field 3 names, and only then records the nonce:
a nonce seen in the last 5 minutes is a replay.

### Reply (B to A)

An envelope whose body is below and whose signature is
`sig1("federation-reply", th)` by B's identity key, where `th` is the transcript hash.

| Key | Field | Value |
| --- | --- | --- |
| 0 | version | `1` |
| 1 | responder id | 16 bytes |
| 2 | initiator id | 16 bytes |
| 3 | session id | 16 random bytes |
| 4 | encapsulation to A's ephemeral key | 1600 bytes; its secret is `ss_E` |
| 5 | encapsulation to A's KEM key | to the KEM key in A's descriptor, 1600 bytes; `ss_A` |
| 6 | suite | the chosen suite |
| 7 | nonce | 32 random bytes |
| 8 | timestamp | Unix seconds |
| 9 | hello hash | `SHA-256(hello envelope bytes)` |

### Transcript and keys

```
th  = SHA-256("kemlock/v1/fed/transcript" ‖ lp(hello envelope bytes) ‖ lp(reply body))
prk = HKDF-Extract(salt = th, ikm = ss_B ‖ ss_E ‖ ss_A)                        (96 bytes in)
```

A checks the reply (names, suite, hello hash, timestamp within 300 seconds, signature under B's
pinned key), decapsulates fields 4 and 5 with its ephemeral and KEM private keys and derives the
same `prk`. Both signatures cover the transcript, so both suite lists, both descriptors, the
nonces and the KEM choices are authenticated, and a downgrade needs a signature to forge.

| Label | Derives |
| --- | --- |
| `"kemlock/v1/fed/chain" ‖ u8(dir)` | A direction's first chain key from `prk` (32 bytes). `dir` 1 is initiator to responder, 2 is responder to initiator |
| `"kemlock/v1/fed/frame-key"` | The AEAD key of the chain's epoch (32 bytes) |
| `"kemlock/v1/fed/frame-iv"` | The epoch's IV (the first 12 bytes of the block) |
| `"kemlock/v1/fed/ratchet"` | The next epoch's chain key (32 bytes) |

All four are `HKDF-Expand` from the chain key (the first from `prk`). Forward secrecy comes from
the ephemeral key, post-quantum secrecy from ML-KEM-1024 in all three secrets, and none of it
depends on TLS.

## Frames

After the handshake each direction is a stream of sealed frames:

```
frame  = header (29) ‖ AEAD(key, nonce, padded payload, aad)
header = session id (16) ‖ u32be(epoch) ‖ u64be(counter) ‖ u8(flags)
aad    = "kemlock/v1/fed/frame" ‖ header
nonce  = iv, with u64be(counter) XORed into its last 8 bytes
```

- The AEAD is the suite's: AES-256-GCM or ChaCha20-Poly1305, 12-byte nonce, 16-byte tag.
- **Counter.** Starts at 0 for each direction and counts every frame of that direction across
  rekeys. A reader accepts only the next one, so a repeated, dropped or reordered frame fails, and
  a failed frame doesn't move the reader.
- **Flags.** Bit 0 marks the last frame; other bits must be 0. A frame after the last is refused,
  and a stream that ends without it was cut short. The header is in the AAD, so the flag can't be
  set or cleared on the wire.
- **Padding.** The plaintext is `payload ‖ 0x80 ‖ zeros`, padded to a multiple of 4096 bytes (at
  least one byte of padding). A receiver strips trailing zeros and then the `0x80`; anything else is
  refused. A sender may turn padding off; the format stays the same.
- **Rekey.** A direction rekeys, before sealing, when 3600 seconds have passed since its epoch
  began or the epoch has sent 2^30 bytes: the epoch number goes up by one and the chain key
  ratchets one way (`ratchet` label), which the sender then discards. A reader accepts the current
  epoch or the next and never an earlier one.
- **Limits.** A payload is at most 4 MiB; a frame at most `29 + 4 MiB + 4096 + 16 + 1` bytes; a
  server also caps frames per peer per minute.

## Messages

A frame carries one message: the requester (the server that opened the session) sends a request,
the responder answers in its next frame. Every message is a CBOR map whose key 0 is its type; key 1
is the vault (an owner, 17 bytes) where there is one. A vault is served only when it is federated,
both servers hold it and the peer is in its set (the home and the replicas); anything else is an
error response that does not say whether the vault exists.

| Type | Request | Fields |
| --- | --- | --- |
| 1 | Pull | 1 vault, 2 since (a version-vector cursor), 3 limit (1 to 500) |
| 2 | Nudge | 1 vault, 2 latest (a cursor): "I have more" |
| 3 | Summary | 1 vault |
| 4 | Leaves | 1 vault, 2 buckets (bytes, at most 256) |
| 5 | Fetch | 1 vault, 2 item ids (array of at most 4096 16-byte ids) |
| 6 | Home records | 1 vault, 2 after (index), 3 limit |
| 7 | Promote | 1 signed promotion record |
| 8 | Bye | sent with the last frame |
| 9 | Offer | 1 vault, 2 home (16 bytes), 3 epoch, 4 replicas (array of server ids, in the home's order) |
| 10 | Blobs | 1 vault, 2 after (an attachment id, all zeros for the first page), 3 limit (1 to 500) |
| 11 | Blob | 1 vault, 2 blob id (16 bytes), 3 offset, 4 length (1 to 2 MiB) |
| 12 | Events | 1 vault, 2 after (an event id, 16 bytes, all zeros for the first page), 3 limit (1 to 500) |
| 13 | Forget | 1 signed notice (see "Unpairing") |
| 14 | Origin keys | 1 vault |
| 15 | Tags | 1 vault, 2 item ids (array of at most 256 16-byte ids) |
| 16 | Erase | 1 vault: the home tells a replica its vault was erased, so the replica deletes its copy (answered with an Ack) |
| 17 | Sends | 1 vault (a personal vault), 2 after (a Send id, 16 bytes, all zeros for the first page), 3 limit (1 to 500; the responder serves at most 50) |

| Type | Response | Fields |
| --- | --- | --- |
| 101 | Changes | 1 vault, 2 records (at most 1024 signed change records), 3 next cursor, 4 more (0 or 1) |
| 102 | Ack | |
| 103 | Summary | 1 vault, 2 root, 3 buckets (256 × 32 bytes) |
| 104 | Leaves | 1 vault, 2 leaves (packed `item id (16) ‖ digest (32)`) |
| 105 | Home records | 1 vault, 2 records (signed), 3 more |
| 106 | Offer status | 1 vault, 2 state (0 pending, 1 accepted, 2 declined) |
| 107 | Blobs | 1 vault, 2 entries (packed `attachment id (16) ‖ item id (16) ‖ blob id (16) ‖ u64be(size)`, at most 500), 3 more |
| 108 | Blob chunk | 1 vault, 2 blob id, 3 size of the whole file, 4 offset, 5 data (at most 2 MiB) |
| 109 | Events | 1 vault, 2 events (array of maps `{0: id, 1: Unix milliseconds, 2: actor (absent when none), 3: device (absent when none), 4: action (at most 64 bytes), 5: target (absent when none, at most 256 bytes)}`, oldest first), 3 more |
| 110 | Forgotten | 1 vaults, 2 items, 3 accounts: what the responder says it deleted |
| 111 | Origin keys | 1 vault, 2 attestations (array of at most 32 signed envelopes) |
| 112 | Tags | 1 vault, 2 entries (array of at most 256 maps `{0: item id, 1: revision, 2: dedup key version, 3: the tags, 32 bytes each, packed, sorted, at most 64}`) |
| 113 | Sends | 1 vault, 2 entries (array of at most 50 maps, see "Sends" below), 3 more |
| 199 | Error | 1 code (1 refused, 2 bad request, 3 internal, 4 unknown vault), 2 detail (at most 256 bytes) |

A peer's cursor is the opaque version-vector form of `kemlock-domain`, one per vault (a device's
own cursor holds one per owner, "Sync cursor" in docs/crypto.md; a vault is one such owner):
`u8(1) ‖ u16be(n) ‖ n × (server id (16) ‖ u64be(seq))`, origins ascending. A pull page stops growing
past about 1.5 MB. A peer pulls with its own cursor per vault and moves it only after a whole page
verified and applied.

### Hash-tree summaries

Every hour, and when a peer comes back, servers compare a summary per vault and fetch what differs:

```
leaf(item)   = SHA-256("kemlock/v1/fed/leaf" ‖ item id ‖ n × (origin (16) ‖ u64be(seq) ‖ u64be(revision)))
bucket(b)    = SHA-256("kemlock/v1/fed/bucket" ‖ u8(b) ‖ for each leaf with item id[0] = b, by item id: item id ‖ leaf)
root         = SHA-256("kemlock/v1/fed/root" ‖ bucket(0) ‖ … ‖ bucket(255))
```

The versions of a leaf are the item's head and its siblings, sorted by change key. Equal roots mean
the vault is in step; otherwise the buckets that differ are asked for as Leaves, the items whose
digests differ or are missing are fetched, and the merge below decides what to keep.

## Change records and origin signatures

Each change record is signed by the server that accepted the write: an envelope signed with
`sig1("federation-change", body)` by that server's identity key. A peer that relays a record can
pass it on but can't alter or invent one. A receiver holds no key for an origin it hasn't paired
with and refuses such a record, unless a peer vouched for the origin's key ("Relaying across a
chain" below): a vault's servers need only form a chain of pairings.

| Key | Field | Value |
| --- | --- | --- |
| 0 | version | `1` |
| 1 | origin | server id, 16 bytes |
| 2 | sequence | the origin's sequence number, from 1 |
| 3 | HLC time | `u64` |
| 4 | item id | 16 bytes |
| 5 | owner | 17 bytes |
| 6 | kind | text (`[a-z0-9_-]`, 1 to 64) |
| 7 | format | `"kem1"` or `"bw"` |
| 8 | revision | from 1 |
| 9 | key version | |
| 10 | ciphertext | bytes; absent on a tombstone |
| 11 | item key | bytes; absent on a tombstone |
| 12 | deleted | 0 or 1 |
| 13 | written at | Unix milliseconds; a tombstone's deletion time too |
| 14 | lineage | up to 64 change keys, packed, nearest ancestor first |

A change key is `origin (16) ‖ u64be(seq)` (24 bytes). A record is refused when it has a zero
sequence or revision, a tombstone with ciphertext, a live item without it, or a lineage that names
the record itself. The ciphertext and item key are exactly as stored and servers can't read them.

**HLC times are bounded.** A receiver leaves out a record whose HLC time (the milliseconds in its
high 48 bits) is more than 300 seconds ahead of its own clock, the skew every check here allows;
the rest of the page is applied, the cursor moves on, and a later comparison fetches the record
again, when it is accepted if the clock has caught up. Old times are normal and never refused.
Without the bound one record could carry a server's clock to the top of its range, where every
later local write would fail. A server's own writes are held to a tighter bound: the time a device puts on an item pulls the
clock forward only as far as 60 seconds past the server's own, so a wrong or hostile device clock
can't pin it, and a record made on a clock that runs a little fast stays well inside what peers
accept. A server's own clock also stops at `2^63 - 1` instead of overflowing,
and at start-up it sets a stored clock more than a day ahead of the wall clock back to it (and logs
that it did), which repairs a server a record already damaged. The repair moves the clock, not the
changes already stamped with a far time: an HLC time is part of the record its origin signed and
that peers already hold, so a peer's change can't be re-stamped, and re-stamping a local one would
invalidate a signature peers may have taken. They stay as they are; such an item keeps winning the
head against older versions until a write that names it in its lineage replaces it.

### Lineage, versions and siblings

The **lineage** of a version is the versions it replaced. The origin works it out once, for a
change it accepted, as every earlier change of the item in its change log except the versions it
holds as siblings at that moment, and signs it with the record. A version that is in another's
lineage is **replaced**.

Servers can't merge items, so they keep every version that nothing replaced. Of those, the **head**
is the one with the latest HLC time, then the higher origin id, then the higher sequence number. It
is what devices sync and what Bitwarden apps see. The others are **siblings**, kept until a write
supersedes them; the next Kemlock app to sync merges them with its field-level merge and writes a
version whose lineage names every one. The rule depends only on the set of versions, so servers
that hold the same set choose the same head whatever order the versions arrived in.

Every change is applied once: a change already in the log, held or replaced, is a duplicate, so a
resolved sibling can't come back from a server that still sends it. A lineage is cut at 64
ancestors, which can only keep a sibling that could have been dropped, never lose a version. A
write that merges siblings must name them in its lineage before it is first sent to a peer.

## Home epochs, promotion and the fence

Items are written at any server holding the vault. Members, roles, policies, space keys and key
rotation are **home-only**: the vault's home orders them. Each change of home raises the vault's
**epoch** by one (a vault starts at epoch 1).

**Home record** (a home-only write on its way to the replicas), an envelope signed with
`sig1("federation-home-record", body)` by the server that made it:

| Key | Field |
| --- | --- |
| 0 | version `1` |
| 1 | vault (owner) |
| 2 | index: `(epoch << 32) + n`, where `n` counts the records made under that epoch, from 1, so a home that was replaced and the one that replaced it never make two records with one index; a peer pulls after the highest index among the records it holds that the other signed |
| 3 | epoch the write was made under, from 1 |
| 4 | kind (text, 1 to 64 bytes) |
| 5 | payload (bytes, at most 256 KiB), for the code that wrote it |
| 6 | signer (server id) |

A receiver judges a record from a server in the vault's set against the epoch it knows: the same
epoch, from the home, is applied; an older epoch is **quarantined** for the vault's admins to redo or
drop and applies nothing; a newer epoch means a promotion was missed and stops the sync; a record
from outside the set, or of the current epoch from a server that isn't the home, is refused.

A home record's index must belong to its epoch (`index >> 32 == epoch`): a record whose index lies in
another epoch's range is refused, so a server can't claim the indexes a later home will use. A
stale-epoch record is kept for the admins only when its signer was the home of that epoch, as far as
the receiver knows (each promotion adds the home it replaced to the vault's history, and an epoch the
receiver never saw is not checked), and a vault keeps at most 256 quarantined records; a later one is
dropped and logged. For an epoch whose home the receiver never saw, one signer may hold at most 32 of
them, so one member of the set can't fill the quarantine and push out the others'. Two records by
different servers at one index are not both kept: the first
stays and the second is refused and logged.

**Promotion record**, an envelope signed with `sig1("federation-promotion", body)` by the *new*
home:

| Key | Field |
| --- | --- |
| 0 | version `1` |
| 1 | vault (owner) |
| 2 | the new epoch |
| 3 | new home |
| 4 | previous home |
| 5 | issued at (Unix seconds) |
| 6 | replicas after the promotion: the others in their order, the old home last |

A peer applies it only if it is for a federated vault it holds, its epoch is the next one, its
previous home is the home the peer knows, its signer is a replica the peer already knows, and it
keeps exactly the servers the peer knows. Two replicas that promote themselves at once both make a
record for the next epoch; the first one a peer takes wins and the other fails the previous-home
check, which is why an admin does it, after a fresh passkey or password check.

**A promotion nobody asked for is held, at every server.** What a server does with a promotion
another server announces is the admin setting `federation_promotion` (environment
`KEMLOCK_FEDERATION_PROMOTION`): `hold`, the default, or `auto`.

- With `hold`, a replica checks the record as above, keeps it beside the vault's settings
  (`held_demotion`, one for each server that announced one: a later announcement replaces its
  server's own, never another's, so repeating one can't push the legitimate one out) and answers the announcement with a refusal that says so. Until its admin
  accepts it, the vault stays at this server's epoch, the other side's newer home records stop the
  sync as a missed promotion does, and nothing the other server sends as the home is taken.
  Without this, any replica, or anyone holding a replica's identity key, could make itself the home
  of every vault it holds, at every server at once, and then, as the home, `Erase` the old home's
  copy.
- With `auto`, a replica applies it at once, as before ("the first to arrive wins").
- A peer that is the vault's home by what it knows holds it whatever the setting says: it is the
  server a promotion takes the vault from.

The admin sees the held promotions at `GET /admin/v1/federation/promotions` (and as `heldPromotions`
beside each vault), accepts one with `POST /admin/v1/federation/vaults/{owner}/demotion` (after a
fresh passkey or password check) and refuses it with `DELETE` on the same path (with a step-up
token), naming the server with `?newHome=<server id>` when more than one waits; the console shows both beside the vault. Accepting checks the record again and applies it
as above; refusing drops it, and the other server announces it again when it restarts. A changed
set of servers drops a held promotion, which no longer fits it.

## Pairing

Two admins pair their servers once. One console shows a one-time code; the other admin types it.

**The code** is 12 characters of Crockford's base32 (`0-9 A-Z` without `I L O U`; 60 bits),
shown as `XXXX-XXXX-XXXX`. When typed, dashes and spaces are ignored, case doesn't matter and
`O`, `I`, `L` read as `0`, `1`, `1`. It is good for one attempt and 10 minutes; the responder takes
it by value, so one run uses it up.

**CPace** (draft-irtf-cfrg-cpace) with the ristretto255 + SHA-512 suite (domain separator
`CPaceRistretto255`), initiator-responder mode, through the `pakery-cpace` 0.6 crate, which is
validated against the draft's ristretto255 vectors. `pakery-cpace` is MIT or Apache-2.0. It is
young; the file `test-vectors/federation-pairing.json` pins this use of it (password, channel
identifier, session id, both shares, the session key) so a second implementation can check itself.

| Input | Value |
| --- | --- |
| password (PRS) | the 12 code characters, upper case, no dashes |
| channel identifier (CI) | `"kemlock/v1/fed/pair"` |
| session id | 16 random bytes chosen by the initiator, sent in message 1 |
| ADa, ADb | the initiator's and the responder's server ids |

A wrong code gives the other side a different session key, and a man in the middle gets one guess
per run.

**Messages** (the initiator is the admin who typed the code):

| Message | Body |
| --- | --- |
| 1, initiator to responder | `{0: 1, 1: session id, 2: Ya, 3: initiator id}` |
| 2, responder to initiator | `{0: Yb, 1: sealed responder descriptor, 2: responder id}` |
| 3, initiator to responder | `{0: sealed initiator descriptor}` |

```
prk             = HKDF-Extract(salt = session id, ikm = ISK)                   (ISK is 64 bytes)
responder key   = HKDF-Expand(prk, "kemlock/v1/fed/pair/responder", 32)
initiator key   = HKDF-Expand(prk, "kemlock/v1/fed/pair/initiator", 32)
binding         = "kemlock/v1/fed/pair" ‖ lp(session id) ‖ lp(Ya) ‖ lp(Yb) ‖ lp(initiator id) ‖ lp(responder id)
sealed          = nonce (12, random) ‖ AES-256-GCM(key, nonce, descriptor envelope bytes, aad = binding)
```

The initiator opens message 2 with the responder key; with the wrong code that fails and nothing
more is sent, so the other server learns nothing about the guess. The responder opens message 3
with the initiator key. Each side then checks that the descriptor is the peer's (its server id),
verifies it (there is no pinned key yet: the PAKE is what authenticated it) and pins its identity
key.

**The fingerprint.** Both admins also compare six words. Instead of a word list (which would need
a licence and a table) the words are proquints, Daniel Wilkerson's pronounceable encoding of 16 bits:
`consonant vowel consonant vowel consonant` from `bdfghjklmnprstvz` and `aiou`, 4, 2, 4, 2 and 4
bits from the high end (`0x7f00` is `lusab`, `0x0001` is `babad`, `0x3f54` is `gutih`).

```
fingerprint = SHA-512("kemlock/v1/fed/fingerprint" ‖ lp(id₁) ‖ lp(key₁) ‖ lp(id₂) ‖ lp(key₂))
words       = the first 12 bytes as six big-endian u16, each as a proquint, joined by "-"
```

`id₁` and its identity key are those of the server with the lower id, so both sides get the same
words. That is 96 bits.

## Replay, time and what stops each attack

- **Handshake.** Fresh ephemeral keys, nonces and timestamps: a hello or reply more than 300
  seconds from the receiver's clock is refused, and the responder keeps the nonces of the last
  5 minutes (only authenticated peers add to the cache, and it is capped).
- **Frames.** Per-direction counters and the header in the AAD, as above.
- **Changes.** Each change id is applied once; origin signatures cover the record and its lineage.
- **Unknown servers.** Only a peer paired for the vault gets past the first message; everything
  before it is cheap (length checks, a signature) and the KEM work comes after.
- **A key that doesn't match.** Nothing is accepted silently, and there is no trust on first use
  after pairing. A known server that offers another identity key is refused with the key it offered
  (`KeyMismatch`), both consoles show "Possible man in the middle", and the event is logged. A new
  identity key is accepted only through a rotation signed by the old key or by pairing again.
- **Malformed input.** One strict parser per format, fuzzed with `cargo fuzz`
  (`crates/kemlock-federation/fuzz`): CBOR, descriptors, hello and reply bodies, frames, messages,
  change records, promotions and home records, the first pairing message, and the first message of a
  session.

## Test vectors

`test-vectors/federation-*.json` are generated by `cargo run -p kemlock-federation --features
vectors --bin kemlock-fed-vectors -- --out test-vectors` from fixed keys and a seeded random source
(the RustCrypto backend, whose ML-DSA signatures and ML-KEM encapsulations are reproducible), and
checked by CI to regenerate byte for byte. Each file is `{"format", "version", "description",
"cases", …}` with bytes as lower-case hex, like the vectors of `docs/crypto.md`;
`federation-SHA256SUMS` lists them.

| File | Pins |
| --- | --- |
| `federation-descriptor.json` | Descriptor bodies and envelopes, the KEM key id, and descriptors that must be refused |
| `federation-handshake.json` | Hello, reply, transcript hash, the three shared secrets, the master secret, per-direction keys and the first frames, for both implemented suites; hellos that must be refused |
| `federation-frames.json` | Frames of both suites with and without padding, the rekey, the key schedule, and streams that must fail (replayed, dropped, reordered, flipped last flag, truncated, after the last) |
| `federation-pairing.json` | CPace with its two random draws, the ISK, the derived keys, the binding and sealed descriptors; the fingerprint; proquints; code normalisation |
| `federation-change.json` | Signed change records (live, tombstone, Bitwarden format, with and without lineage), a promotion and a home record, the epoch verdicts |
| `federation-hashtree.json` | Leaf digests, bucket digests and the root |

A verifier rebuilds every value from the inputs a file lists: derives public keys from seeds,
decapsulates with the listed private keys, recomputes the keys and frames, and opens what was
sealed. ML-DSA signatures here are deterministic; hedged ones verify the same.

## Offers, files and member accounts

These are additions to version 1: no byte of an earlier type or field changes.

**Offers.** A vault is `Local` until its home's admin federates it with an ordered list of
replicas, and a replica holds it only after its own admin accepts. The home sends each replica an
`Offer` at every session until the answer is `accepted` (a replica's admin may also decline). Only
the vault's home may offer it, the offer must name the receiver as a replica, and a server that
already holds the vault under another home or epoch, or whose account or space it is, answers
`pending` like any other offer and keeps nothing, so an offer can't tell a peer which ids exist
here. An accepted vault takes a new replica
order the home sends under the same epoch; nothing is copied to a replica that hasn't accepted.

**Files.** `Blobs` pages through the ready attachments of a vault in attachment id order; a replica
adds a row for each it lacks and, for a file of at most 50 MiB, fetches it with `Blob` requests of
at most 2 MiB each and stores it (the blob store checks it is a `KMA1` file as it does for an
upload). A larger file gets its row only, and its bytes are fetched from a peer the first time it
is downloaded. A peer serves a blob only of a vault it may read, and the file's owner must be that
vault. A replica leaves out an entry whose item it doesn't hold in that vault, or whose file
another row (an attachment, or a Send's file) already holds, and never deletes a file another row
holds when an erasure or an unpairing removes the rows of a vault.

**Sends.** A Send of a personal vault (a space has none) travels with the vault, as ciphertext,
so a Send link keeps working when the vault fails over to a replica. `Sends` pages through the
Sends of the vault's owner in Send id order, 50 a page and about 1.5 MB at most; only a note, or a
file Send whose bytes have arrived, is listed. An entry is a deterministic CBOR map: 0 Send id (16
bytes, the access id of the link), 1 kind (0 note, 1 file), 2 meta, 3 sealed key, 4 payload (the
sealed parts of `docs/crypto.md`, opaque here, at most 1 MiB each and 256 bytes for the key), 5 file
(absent for a note: `{0: blob id, 1: size in bytes, 2: "kma1" or "opaque"}`), 6 password (absent
when none: `{0: salt, 1: hash}`, 32 bytes each), 7 view limit (absent for none), 8 view count,
9 hide email, 10 disabled, 11 expires at (absent for none), 12 deletion at, 13 created at, 14
revised at; times are Unix milliseconds. A receiver checks every length, that a file Send has a
file and a note has none, and refuses unknown fields.

A replica adds a row for each Send it lacks, with the same id and so the same link, and copies a
file as it copies an attachment: `Blob` requests of at most 2 MiB (the responder serves the blob of
a Send of the vault's owner whose bytes have arrived), only up to 50 MiB, and a larger file gets its
row only and is fetched from a peer the first time someone opens the Send. A file of more than 512
MiB is not taken. A `kma1` file is stored through the blob store's `KMA1` check, as an upload is; an
`opaque` file (a Bitwarden app's own format, which the server can't read) is held to the announced
size alone. A file that can't be fetched or fails its check leaves its Send out until the next
visit, and the other Sends go on. A row already held takes the larger of the two view counts from any server in the vault's set, so
a view limit used up at one server stays used up at the others. It takes a newer revision (the
options and the password, never the owner, key or file) only from the server the copy came from or
from the vault's current home, which a promotion moves. Any other server's revision, or any
revision of a Send made here by a server that isn't its home, changes nothing: a server in the
vault's set can't clear a password or end a Send it didn't make. At a visit to the Send's home, a replica
deletes the copies it made that the home no longer holds (the owner deleted the Send there) and
their files; a Send made at the replica itself is never deleted this way (table
`federation_replicated_sends` records which rows are copies).
A server lists only the Sends made on it, plus the copies it holds of other servers' Sends: never a
copy to the server it came from, so a Send deleted at its origin can't come back. A copy is deleted
when the server it came from no longer lists it, whether or not another Send's file could be copied.
A copy never takes a file another Send or an attachment already holds, and deleting one never
deletes a file another row holds. Notes copy where file storage isn't configured; a file Send is
left out there. `Sends` is asked only of a peer whose descriptor lists `x-kemlock-sends1` among its
suites (an unknown suite name is skipped by negotiation, so older servers ignore it and are never
sent a request type they would drop the session on).

A Send with a view limit (`maxAccess`) is opened at its vault's home only. Each server counts views
on its own, and the copies take the larger count, but two servers counting apart would each allow
the whole limit, so a replica answers 503 (`send-home-unavailable`, with the home's address and
"try again when the home server is back") for it, for the note and for the file's download. A Send
with no limit is opened at any server that holds it. Its deletion and expiry dates apply everywhere.


**Member accounts.** The home publishes one home record of kind `member-account` per member of the
vault (for a personal vault, its account; for a space, its confirmed members) whenever the account
changes. The payload is deterministic CBOR (`kemlock-federation`, `members.rs`): the user id, email,
name, mode, KDF settings, the root key wrapped by the password, the public-key bundle and its
signature, the private keys sealed under the user key, the key version, the creation and update
times and the device registrations (id, name, kind, the thumbprint of the DPoP key, creation time).
There is no OPAQUE record, security stamp, role, two-step method or token in it, so no password
secret is shared, and a copy signs in only with a registered device key
(`POST /kem/v1/auth/device-key/challenge` and `/verify`). A replica applies a record only when it is
of the vault's current epoch and signed by its home; a copy never replaces an account that lives on
the replica (same id or email: refused and logged). A record is applied only for an account that
belongs to its vault: the owner of a personal vault, or a confirmed member of a space as the
replica already knows it (so the home publishes a space's own records before its members'
accounts), and a copy follows the one server it came from: another home's record for it is
refused. A member whose account record came before the member's own record is not lost: when the
replica applies the member record it applies that account record again, and a space's home makes
an account record once more for a member whose latest one is older than the member's first record
(homes made them in that order before). The home of an account's personal vault speaks for the
account: it replaces a copy that came in through a space, and a space's home may not publish an
account whose personal vault the replica federates. The copy's public-key bundle must verify under its own `sig1` key (an account with no
keys yet has an empty one), as it must where the account lives: a record whose bundle doesn't is
refused. A stale-epoch record is quarantined like any home-only write.

**Space roles, policies and keys.** The home of a space also publishes the rest of what only it may
change, one home record per entity whenever the entity changes, and a record saying it is gone when
it was removed (`kemlock-federation`, `spaces.rs`, has the payloads): kind `space` (the space row
with its key version), `space-member` (the confirmed member's role, custom permissions, state, sealed
space key and confirmation), `space-group`, `space-collection` (with its grants and key version),
`space-keys` (the collection keys sealed to one member), `space-policies` and `space-held` (the ids of
the live items a key replacement left held, the whole set each time: a replica replaces its own set
with it, so it keeps the same held state and never serves a held item as live; made only for a
space that has held items or had them). From the release that signs key boxes (docs/crypto.md,
"Signed key boxes"), a `space-member` record may carry field 12 (who sealed the space key, and their
signature) and each key copy of a `space-keys` record a fourth part (the same for that copy); both
are left out when nobody signed the copy. A peer that predates it refuses a record with either as
malformed, so **upgrade every replica before its home**: a home that signs boxes sends the new fields
to every peer, and an older replica then refuses those records and stops applying that space. A
revoked or removed
member is a "gone" record, which takes their grants, group seats and key copies out of the replica
too. A replica applies them only when they are of the vault's current epoch and signed by its home;
a stale-epoch one is quarantined like the rest and shows in the vault's quarantine list for its
admins to redo or drop. A space's home may only change that space's own entities: a record that names a collection or group (as its own id, a parent, the group of a grant, the collection of a key copy, or one that is gone) that already exists in another space at the replica is refused and logged, and the records after it still apply. Writes to the home-only parts of a federated space
(`/kem/v1/spaces/{id}/` `members`, `collections`, `groups`, `grants`, `key-replacement`, `reseal` and
`policies`) are refused at a server that is not the home with `409`, a
`urn:kemlock:problem:home-only` problem that names the home (`home.server`, `home.address`) and the
`X-Kemlock-Home` header; at the home, a write that succeeded makes the home records at once and
nudges the replicas.

**Event logs.** Each server has two switches per peer, both off by default: Send ("send our logs")
and Pull ("pull their logs"). Logs flow from one server to another only when the sender's Send and
the receiver's Pull are both on. What flows is the event log of the federated vaults the two share:
the events whose actor is a member of the vault. A server with Pull on for a peer asks
`Events` for each shared vault after the id of the newest event it holds from that peer (event ids
are UUID v7, so they sort by time); a server answers only while its Send for that peer is on, and
refuses otherwise. A server with Pull off never asks. The receiver keeps what it got beside the vault,
apart from its own log, for its admins (`GET /admin/v1/federation/vaults/{owner}/events`); an event
not in id order after the cursor fails the pull. Nothing else of the log (addresses, sign-in log)
travels.

**Unpairing.** An admin unpairs a peer (`POST /admin/v1/federation/peers/{id}/unpair`): copying
stops at once, and the server asks the peer to delete what it holds. The ask is a notice, an
envelope signed with `sig1("federation-forget", body)` by the unpairing server, sent over a session
as `Forget`:

| Key | Field |
| --- | --- |
| 0 | version `1` |
| 1 | from: the server that unpairs |
| 2 | to: the server asked to delete |
| 3 | issued at (Unix seconds) |

The receiver checks the signature against the key it pinned, that the notice is from the peer that
sent it and to itself, and that it is at most 5 minutes old. It then deletes what it holds because of
that peer, and forgets the peer: the vaults the peer is the home of (a space with everything in it;
for a personal vault the account copy, its items, devices and sessions), the account copies that
came from the peer, the attachment files of those vaults, the offers the peer made and the event log
entries it sent. A vault or an account that lives on the receiver is never touched. It answers
`Forgotten` with the counts. The unpairing server removes the peer from the replica order of its
vaults (a vault left with no replica is Local again), forgets it, and the answer of the route says
whether the peer was asked and what it said it deleted. **The peer can't be forced to:** a peer that
is down, that refuses or that is run by someone else keeps what it has, and the answer's `notice`,
which the console shows before and after, says so.

**Identity key rotation and revocation.** A new identity key is accepted only through a rotation
signed by the old key (or by pairing again), and a stolen key is revoked with a record that goes to
every peer. Both are envelopes whose body is deterministic CBOR:

| Key | Field |
| --- | --- |
| 0 | version `1` |
| 1 | kind: `1` rotation, `2` revocation |
| 2 | server id |
| 3 | the key being replaced (rotation) or revoked (revocation), 1984 bytes |
| 4 | issued at (Unix seconds) |
| 5 | rotation only: the new descriptor, its envelope bytes, self-signed by the new key |

A **rotation** is signed with `sig1("federation-key-rotation", body)` by the *old* key. The receiver
accepts it only when the old key is the one it holds for that server, `issued at` is not more than
300 seconds ahead of its clock (nor older than a descriptor lives, 37 days), and the new descriptor
is for the same server, verifies under its own key and carries another key; it then pins the new
key and remembers the old one, with when it replaced it. A rotation that keeps the server's
addresses takes the descriptor's operator and suites at once. One that **brings other addresses**
does not: this server keeps dialling the addresses it knew, and the new addresses, operator and
suites wait for its admin (`GET /admin/v1/federation/address-changes`; `POST` on
`/admin/v1/federation/peers/{id}/address-change` follows the server, `DELETE` keeps the old
addresses, both with a step-up token). The key that signed a rotation may be a stolen one, and the
addresses decide where this server connects.

A **revocation** is signed with `sig1("federation-key-revocation", body)` by the key it revokes. A
receiver that holds that key stops trusting the server (`revoked`) until it is paired again with a
new code. A revocation also counts when it is signed by a key the receiver **replaced** in the last
30 days: that is how the owner of a stolen key answers a thief who rotated it away. A rotation
signed by a key that turns out to be stolen can't be told from the thief's, and a copy of an old
key that leaks within 30 days of an honest rotation can sign the same revocation, so the server is
not revoked but **contested** (peer state `contested`): no session is accepted from it or opened to
it, so nothing syncs either way, nothing it sent or holds is deleted, and the console shows it in a
card of its own. Its admin settles it: unpair it and pair again with a new code, or, knowing the
rotation was honest, trust it again (`DELETE /admin/v1/federation/peers/{id}/contest`, with a
step-up token). A revocation signed by the key the receiver holds still revokes outright. A revocation of any other key (one never held, or replaced longer
ago) does nothing, and so does the same record twice. The history of a peer's keys goes when the
peer is unpaired.

Records are posted to `POST /fed/v1/keys` (204, or a bare 400), not sent over a session, because
after a rotation the new key's sessions are refused until the record is applied: a server delivers
its pending records to a peer before it opens a session to it. Each server keeps the newest record of
each kind for each server and passes them on to its other peers, so a revocation reaches peers the
revoked server isn't paired with. The admin console rotates with
`POST /admin/v1/federation/identity/rotate` and revokes with `.../identity/revoke`, both after a
fresh passkey or password check; a revoking server takes a new key and every peer must pair with it
again.

**Relaying across a chain.** A vault's home and replicas need only form a connected chain of
pairings. A server that is paired with the next one in the chain still checks the origin signature
of a change made by a server it never paired with, so it needs that server's identity key, which it
learns from a peer that holds the vault. `Origin keys` (type 14) asks a peer for the keys of the
other servers in a vault's set, and the peer answers with one **attestation** for each key it holds
(pinned at pairing, or learned itself), an envelope signed with `sig1("federation-key-attestation",
body)` by its identity key:

| Key | Field |
| --- | --- |
| 0 | version `1` |
| 1 | vault (an owner, 17 bytes) |
| 2 | server id: the server whose key it is |
| 3 | its identity key, 1984 bytes |
| 4 | attester: the server that signs, the peer that answers |
| 5 | issued at (Unix seconds) |

The receiver trusts the attester as it trusts the pairings of the chain: it checks the signature
under the key it pinned for the attester, that the attester is the peer that answered, that the
record is for this vault and names a server in the vault's set, and that it isn't about itself. A key
learned this way is kept and used only for servers the receiver isn't paired with: a key from
pairing always wins, a different key from another attester than the first is refused, and a
rotation or revocation of the server's key (above) updates or drops it. A change from an origin
that is neither paired nor in the vault's set is refused whatever key signed it. The replication
job asks at each visit, before it pulls.

**Duplicate tags.** Where server matching is on for an owner, the device uploads the duplicate tags of
each item revision it writes (`docs/crypto.md`, "Duplicate tags"), and a tag is valid only for the
revision it was made for. The tags travel with their revision: after a replica pulls a vault it asks
the peer for the tags of the items it holds without any at their current revision (`Tags`), and keeps
those made for the revision it holds. A replica where matching is off for the owner asks for
nothing, a server where it is off answers with nothing, and a tag for another revision does nothing,
so a vault that never turned matching on sends no tag anywhere. Tags are not in the origin-signed
change record, which is signed once and before the device uploads the tags of its revision: they are
hints (a tag says two items might be equal, and the device compares the values before it shows a
group) that arrive over an authenticated session from a peer that holds the vault.

## Erasure reaches replicas

When a home erases a vault (a person deleted their account, or a space went with its last owner),
each replica holds a copy that has to go too. The home queues the erasure for each replica of the
vault in the same transaction that deletes the vault, because the vault's federation settings are
deleted with it. The replication job sends a queued erasure as an `Erase` request (type 16) in the
peer's next session, soon after it is queued, and completes it when the peer answers `Ack`; a peer
that is down keeps it queued, and one that refuses (the sender is not the vault's home) leaves it
queued too, to be tried at the regular visits.

A replica accepts `Erase` only from a paired peer that is the vault's home by the settings it holds
(or by the offer, for a vault its admin never accepted). It then deletes, in one transaction, the
vault's items and every version of them, the change log, attachment rows, home records, cursors,
the offer and the federation settings, and, for a personal vault, the copied account with its
devices; then it deletes the attachment files. A personal vault whose account lives on the
replica (is not a copy) is never erased by a peer: the replica refuses, with the detail "this server
holds that vault's account itself", and deletes nothing, however the sender came to be taken for
its home. The home takes that answer as final: it drops the queued erasure and logs it, instead of
asking at every visit. A replica that holds nothing of the vault answers `Ack` too, so a repeated erasure (a lost
acknowledgement) is harmless. Both servers log it, and each writes an event
(`federation.erasure_forwarded` at the home, `federation.vault_erased` at the replica) that names
the vault and the peer and holds no name or email.

## Pairing over HTTP

The three pairing messages travel between the two servers as plain HTTP bodies, authenticated by
the code alone: `POST /fed/v1/pair/start` (message 1 in, message 2 out) and
`POST /fed/v1/pair/finish?initiator=<server id>` (message 3 in). The code is good for one attempt
and 10 minutes, kept in memory. A message 1 that is malformed (not the CBOR map of the table above, a missing field, a version
other than 1, the receiver's own id as the initiator) is refused without using the code up; one
that is well formed uses it, right or wrong, so a stranger able to send one can still use the code up. The two routes answer 429 past 20 requests a minute
from one source address (the address the server's request layer settled, which honours a trusted
proxy; an IPv6 address counts by its /64) and past 300 a minute from all of them together, so one
host can't use up the limit of the admin who is pairing. After a successful exchange each side holds the other's verified
descriptor and the fingerprint but pins nothing: its admin compares the six words and confirms
(`POST /admin/v1/federation/pairings/{peer}/confirm`), and for a peer whose operator is not this
server's the admin also acknowledges the three points of "Peers run by other organisations", which
the server keeps as the record of the data sharing.

## The replication job

One run per paired peer, under the lease `fed-peer-<peer id>` in `job_leases`: open a session (read
the descriptor from each address of the peer, check it against the pinned key, connect
`/fed/v1/session` as a WebSocket, handshake); for each federated vault both servers hold, offer it
(home to replica), publish member records (home), pull items since the peer cursor, pull home
records, copy files, compare hash trees (hourly, and the first time after the peer was away), and
nudge the peer with this server's latest vector when it changed; announce any promotion this server
made; end the session. A peer is visited when it has never been, when it nudged us, when this
server has a change it hasn't told it of, every 5 minutes, and after a failed run with a delay of
15 seconds doubling to 5 minutes.

The descriptor is signed afresh a week after it was issued (so peers always read a window with at
least 30 days left) and the KEM key is replaced at 30 days, both while the server runs; the old KEM
key stays until the last descriptor that names it has expired.

## Failover on the Kemlock API

`GET /kem/v1/config?vault=user:<uuid>` (repeatable, `space:<uuid>` too) answers, for each federated
vault this server holds, the epoch, the servers in failover order (the home first; each with its
base URL, its identity key and its role) and the signed promotion record of the current epoch.
`GET /kem/v1/sync` lists, beside the items, the versions held beside an item's head (`siblings`); a
device merges them with the head, writes the result as the next revision and calls
`POST /kem/v1/items/{id}/siblings/resolve`, which names the siblings in the new head's lineage and
drops them (it is refused once the head has been sent to a peer).

## What the console reads beyond the rows

The federation screens of the web vault read more than the peer and vault rows. All of it is under
`/admin/v1/federation`, behind the admin gate; every write (`POST`, `PUT`, `DELETE`) also needs a step-up
token (`Step-Up-Token`, the one `/admin/v1/step-up` issues), and a step-up token is also the fresh
check promotion and identity rotation ask for (a sign-in in the last five minutes counts too: the
time of the sign-in the session began with, which a refresh keeps). The routes added for the screens are in the OpenAPI
document at `/admin/v1/federation/openapi.json`.

- **Identity keys.** Each peer and each waiting pairing carries `identityKey` (hex): the key pinned
  for the peer, or the one its descriptor offers.
- **Vaults.** Each vault carries `ownerEmail` (an account's vault), `members`, `sizeBytes` and
  `waitingChanges`. A vault's name is ciphertext under a key only its members hold, so the server
  has none to give: a space has no email either, and the console shows its short id. `GET .../shareable` lists the
  vaults homed here that no peer holds yet (a vault whose policy went back to Local counts).
- **Peers.** Each peer carries `lagChanges` (versions this server holds that its last pull from the
  peer did not cover, counted to 100 per vault), `lagSeconds` (the age of the oldest of those),
  `lastChangeAt` and `lastChangeVault` (the newest item the peer wrote to a shared vault) and
  `theySendLogs` (this server holds event-log entries the peer sent; the peer's own Send switch is
  its own). A server's `name` is the host of its first address. `database` and `country` are
  this server's own, from its configuration; a descriptor carries neither, so a peer has none.
- **Now.** `POST .../check` visits every paired peer as the job would and says how each went;
  `POST .../consistency` compares the hash trees of every shared vault now, whatever the hourly
  schedule says, and visits an out-of-step peer soon after.
- **A peer's keys.** `GET .../peers/{id}/security` reads the peer's descriptor afresh and shows its
  suites against ours, the suite a session would use, its KEM key fingerprint and when this server
  first saw that key (a KEM key's creation time is not in the descriptor, so that is the nearest it
  can say of its age), its validity window and the last session. A descriptor that verifies under
  the pinned key is kept (in the `peer_security` table); when the peer can't be reached the kept one is shown.
  `GET .../peers/{id}/descriptor` serves it as a file.
- **This server.** `GET .../self` shows the descriptor, the identity fingerprint, the KEM key's age
  and the suites in order; `POST .../self/kem-rotation` replaces the KEM key now (the old one stays
  for the overlap), `POST .../self/identity-rotation` rotates the identity key through a signed
  record, and `PUT .../self/suites` signs the descriptor afresh with the suites turned on, in
  order, at least one of them one this build runs. The choice is written to
  `federation-suites.txt` beside the identity file, so a restart or a refresh keeps it.
- **A key that is not the pinned one.** `GET .../mismatches/{peer}` shows the key offered, the
  pinned one, when it was first and last offered, how many attempts met it and the address this
  server dialled (the key is only ever met by this server dialling the peer; a session a peer
  opens to this server is refused before it says which peer it is), and the vaults that can't sync
  meanwhile. `POST .../mismatches/{peer}/keep-blocking` puts the admin's decision on record; the
  pin stays and the refusal with it (table `peer_mismatches`).

## Peer health

A server keeps a short, in-memory record of whether each paired peer answers. It is not part of
the wire format: nothing is sent to the peer for it beyond an ordinary request.

- **Probe.** Every `KEMLOCK_FEDERATION_PROBE_SECONDS` (default 60; 0 turns the probes off), per
  peer, the server fetches the peer's signed descriptor (`GET /fed/v1/descriptor`, the public route)
  from the peer's addresses in order and checks it against the key pinned at pairing. An answer
  from another server, an expired descriptor or no answer is a failed probe. A probe has a timeout of
  10 seconds. After a failed probe the delay doubles for each further failure, to a ceiling of ten
  minutes, and every delay is spread by up to 20 percent either way, so servers that started
  together don't probe in step. A session that opens during a visit counts as an answer, and one that
  can't open as a failed probe, so the status stays right where the probes are off.
- **Status.** `unknown` until the first probe or visit; then `online` (the last probe answered in
  under 3 seconds), `degraded` (it answered slower, or fewer than three probes in a row failed) or
  `offline` (three or more in a row failed). A status nobody has refreshed for twice the backoff
  ceiling is `unknown` again. The record also holds when the peer last answered, how long that took,
  why the last probe failed and since when the probes have been failing. Nothing is kept across a
  restart: every peer is `unknown` until its first probe.
- **Placement.** `GET /kem/v1/placement` gives each server of a vault `status` (this server is
  always `online`), `lastSeen`, `latencyMs` and, while it is offline, `offlineSince`. The web
  vault's failover banner appears on its own when a vault's home is `offline`, and the storage page
  shows each status. A `degraded` home is not an outage: no banner. A peer that answers with an identity key other than the pinned one is `key-mismatch`: not an outage, no banner, and the changes waiting for it cannot be dropped.
- **Admin API.** Each peer of `/admin/v1/federation/peers` carries `health` (the status),
  `latencyMs`, `probeError`, `failingSince` and a `lastSeen` that is the later of its last session
  and its last answered probe. The admin federation screen shows it beside each peer.

## Waiting changes

Replication is pull: a peer asks for the versions its cursor doesn't cover, and this server only
nudges it when it has more. The **changes waiting** for a peer in a vault are therefore the versions
this server holds that the peer hasn't been given, counted from what the peer has echoed back (the
cursor of this server's last pull from it), to 100 per vault and over at most 20 pages. It is an
estimate that falls to nothing once the peer has caught up.

- **Reading.** `GET /kem/v1/placement` gives each vault `pending`: the changes waiting for one of its
  other servers, the one that is offline first, as `{id, summary, askedAt}`. `id` is the id of the
  server they wait for, `summary` says how many ("3 changes waiting for vps.example.net", with a plus
  when the count stopped at its limit) and `askedAt` is when the oldest was written. It is `null` when
  nothing waits. Every other waiting server is shown after the first is cancelled. The admin API's
  `waitingChanges` on a vault is the most that waits for any one server.
- **Cancelling.** `DELETE /kem/v1/placement/{vault}/pending/{change}` drops the queue to the server
  `change` names (the `id` above). `vault` is `me` (the caller's own vault), or a space id where the
  caller is a confirmed owner or admin (another member gets 403, a non-member 404). It answers 200
  `{dropped}`; 404 when nothing waits for that server or the vault isn't federated with it; 409
  while that server answers its probes, since changes queued for a server that is up are on their
  way, and only a server whose status is `offline` can have its queue dropped.
- **What it does.** The server keeps, for that peer and vault, a marker covering every version it
  holds at that moment (table `federation_withheld`: the peer, the vault and a version cursor). From
  then on its `Pull` and `Fetch` answers to that peer leave those versions out (the peer's cursor
  still moves past them, so it doesn't ask again), and they no longer count as waiting. A second
  cancel adds to the first. Changes written after the cancel are not covered and flow as usual.
- **What it never does.** It never deletes anything held here: the versions stay in this server's
  copy, in what the account's devices sync and in backups, and every other server of the vault is
  still given them. It does not ask the peer to forget anything it already has, and it does not touch
  the peer's own changes, which this server keeps pulling. It records an event, `federation.waiting_cancelled`
  (who, the vault, the server and how many), in the event log.
- **Taking it back.** `POST /kem/v1/placement/{vault}/pending/{change}/resume` (the same vault and
  server as the cancel, the same rights; 200 `{resumed: true}`, 404 when nothing was withheld) lifts
  the marker, at any time and whether or not the server is back, and records
  `federation.waiting_resumed`. The peer's cursor moved past the withheld versions while they were
  held back, so a pull alone doesn't bring them. The comparison of the two copies does: this server
  asks for one and a visit at the next opportunity, and the peer, at its next comparison (hourly, and
  at its first visit after it was away), sees the items it lacks and fetches them by id, which a
  resume no longer holds back. Until then the vault is reported out of step with that peer.
- **After a cancel.** The two copies of the vault differ by those versions, and the hourly hash-tree
  comparison reports the vault as out of step with that peer until a resume. Unpairing the peer
  forgets the markers kept for it.



## Not built yet

Nothing is open.
