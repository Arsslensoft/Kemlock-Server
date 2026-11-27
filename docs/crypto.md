# Kemlock crypto formats, version 1

This file fixes the bytes every Kemlock client and the server agree on. `kemlock-crypto` implements
it, and `test-vectors/` (CC0) pins each format with generated vectors. The Flutter app copies those
vectors and holds its Dart code to them; it never links this AGPL code. Change a format here only
with a new version label: released bytes never change.

The design behind it is "Kemlock Server: design and architecture", End-to-end encryption, and its
Decisions table.

## Conventions

- `‖` is concatenation. `u8`, `u16be`, `u32be`, `u64be` are unsigned big-endian integers.
- `lp(x)` is `u32be(len(x)) ‖ x`, used for every variable-length field inside a hashed or
  authenticated input, so fields can never run into each other.
- Labels are ASCII strings written in double quotes here, used as bytes, with no terminator.
- UUIDs are their 16 raw bytes (RFC 9562 byte order) inside binary inputs and the hyphenated
  lower-case form in JSON.
- An owner is `u8(type) ‖ uuid`, 17 bytes: type `0x01` for a user's own vault, `0x02` for a space.
  Ids that aren't UUIDs map to one as "Legacy ids" says.
- In JSON every binary value is base64url without padding (RFC 4648 §5). A decoder refuses padding,
  the standard alphabet and whitespace.
- HKDF is HKDF-SHA256 (RFC 5869) unless a format says otherwise. An absent salt is 32 zero bytes, as
  RFC 5869 says.
- AES-256-GCM uses a 12-byte random nonce and a 16-byte tag. A sealed value is
  `nonce(12) ‖ ciphertext ‖ tag(16)`.
- A decoder checks every length before it decrypts anything, and refuses unknown versions, unknown
  fields and trailing bytes.

## Suites

| Suite id | Used for | Algorithms |
| --- | --- | --- |
| `kx1` | Exchange keys: sealing a key to an account, a device, a space member | ML-KEM-1024 + X25519, combined as below |
| `sig1` | Signing keys: key bundles, manifests, member records | ML-DSA-65 + Ed25519, both must verify |
| `aead1` | Every symmetric seal | AES-256-GCM |
| `opaque1` | Password sign-in | OPAQUE-3DH, RFC 9807, configuration below |

### Crypto library

`kemlock-crypto` runs on aws-lc-rs natively and on RustCrypto in WebAssembly; both produce the bytes
this file fixes, and the vectors and cross-backend tests hold them to it. Two exceptions, both
explicit in the code and neither a silent fallback:

- **ML-KEM-1024 from the 64-byte seed.** The `kx1` private key holds the seed `d ‖ z`, and
  aws-lc-rs (checked up to 1.19.0, including its `unstable` module and the `aws-lc-sys` bindings)
  cannot rebuild a key from it: its `DecapsulationKey::new` takes the 3168-byte expanded key, and
  `generate` keeps the seed to itself. Expanding the seed ourselves with the library's SHA3/SHAKE
  would be reimplementing the KEM, so deriving the encapsulation key from a seed and decapsulating
  run on RustCrypto's `ml-kem` on every backend, and only those two. Encapsulation, which needs
  only the public key, runs on aws-lc. If aws-lc-rs gains seed-based keys, these two calls move to
  it and nothing in the format changes.
- **The FIPS build** (cargo feature `fips`, the `kemlock-server:fips` image). aws-lc-rs built on
  the AWS-LC FIPS module serves everything the module certifies: ML-KEM encapsulation, AES-256-GCM,
  HKDF, HMAC, SHA-2, Ed25519 and ECDSA P-256. No aws-lc-rs FIPS build has ML-DSA, so ML-DSA-65
  runs on RustCrypto's `ml-dsa`; neither library's certificate lists it. The ML-KEM seed
  operations above also stay on RustCrypto, so a `kx1` private key is expanded and used outside
  the module. OPAQUE's SHA-512 (opaque-ke is generic over digest 0.10) and Argon2id are outside it
  too. The feature will not compile together with `rustcrypto`.

Ed25519 verification is not left to each library: both backends follow the one rule of "Ed25519
verification rule" (under `sig1`), because the libraries differ on small-order and non-canonical
inputs.

## Account keys

- **Root key**: 64 random bytes, shaped like Bitwarden's user key so one account has one root
  whichever API it uses. On a Compatible account it is the Bitwarden user key.
- **Kemlock user key**: `HKDF(ikm = root, salt = absent, info = "kemlock/v1/user", L = 32)`.
- **Child keys** of the user key (or of a space key), each with its own label:
  `HKDF(ikm = user key, salt = absent, info = label, L = 32)`.

| Label | Key |
| --- | --- |
| `"kemlock/v1/item-wrap"` | Wraps item keys of the owner, and the link keys of their Sends; the meta keys of their Sends derive from it |
| `"kemlock/v1/private-keys"` | Seals the account's exchange and signing private keys |
| `"kemlock/v1/manifest"` | Reserved for the signed manifest's MAC-less parts |

### Master key

`Argon2id(password, salt, m, t, p, L = 32)`, version 0x13. The password is the UTF-8 of its NFC
form. New accounts use `m = 65536` KiB, `t = 3`, `p = 4` and a random 16-byte salt kept on the
server and returned before sign-in. The server answers unknown emails with settings and a salt
derived from the email under a server secret, so they look like real accounts.

### The password wrap of the root key (Kemlock-only accounts)

```
wrap key = HKDF(ikm = master key ‖ OPAQUE export key, salt = absent,
                info = "kemlock/v1/password-wrap", L = 32)
aad      = "kemlock/v1/root-wrap" ‖ account id (16) ‖ u32be(key version)
wrapped  = AES-256-GCM(wrap key, nonce, root key, aad)
```

The export key is OPAQUE's 64-byte export key. Neither the master key nor the export key alone
opens the wrap, so a stolen database allows no offline guessing without the OPAQUE server secret.

### Changing the master password and the sign-in address

The root key does not change when the master password does. The browser makes a new master key and
a new OPAQUE record, wraps the same root key again, and sends the three; the server swaps them in
together. Nothing else the root key protects is touched: the key version, the public bundle and its
signature, the sealed private keys, the Recovery Kit, the passkey PRF wraps, the trusted-device
copies and every item stay byte for byte, because they hang off the root key and not off the master
key. No item format changes.

- **The new master key** is `Argon2id(new password, new salt, m = 65536, t = 3, p = 4, L = 32)`
  with a new random 16-byte salt. The server accepts exactly these settings and a 16-byte salt, as
  at registration, so prelogin answers an account no differently from an unknown email.
- **The new wrap** is the password wrap above, `wrap key = HKDF(ikm = new master key ‖ new OPAQUE
  export key, …)`, over the same root key, with the **same** `aad` (`"kemlock/v1/root-wrap"` ‖
  account id ‖ `u32be(key version)`; the key version does not move) and a new random nonce. The key
  worker makes it from the handles of the new master key and export key and the open account's root
  key (`rewrapRoot`); the root key is never in JavaScript.
- **The new OPAQUE record** is a registration of the new master key. OPAQUE binds the record to its
  credential identifier, which is the account's email (lower-cased, `opaque1` above), so a change of
  **address** needs a new record too: it is registered under the new address while the browser still
  has the password. That is why changing the address asks for the master password, and why it
  cannot be done for an account that has none.

The routes need a session (`DPoP` and an access token); the one marked "no session" is opened from
the mail client. Every change that writes also needs the password again, as erasing the account does:
`loginState` and `finalization` are the last two messages of a fresh OPAQUE login
(`POST /kem/v1/auth/opaque/start` first, with the same device key). A login state works once, a
wrong password counts against the account like a wrong sign-in. With a second step on, a fresh
proof of it is asked beside the password, exactly as erasing the account asks it: `proof` is the code mailed by
`POST /kem/v1/account/two-factor/proof`, a current code of the authenticator app, the recovery code,
or a security key's or passkey's answer as `{"webauthn": …}`, and works once. The profile says
whether one is on (`twoStep`). A request with a second step on and no proof is refused with
`400 invalid-request` before the login state is spent; the proof is checked once the password is. A
stolen session and a guessed password are therefore not enough to take the account's password or
address over.

| Route | |
|---|---|
| `GET /kem/v1/account/profile` | `{userId, email, name, sso, hasPassword, compatible, pendingEmail, twoStep}`: `sso` is true when an identity provider is linked, `compatible` when the account is shared with Bitwarden apps, `pendingEmail` while a link can still be opened, `twoStep` when the account has a second step on. |
| `PATCH /kem/v1/account/profile` | `{name}`: trimmed, blank clears it, at most 100 characters and no control characters. Answers the profile. `403 sso-managed` for an identity provider's account. Event `account.name_changed`. |
| `POST /kem/v1/account/credentials/start` | `{request, email?}`: OPAQUE's `RegistrationResponse` for the account's own address, or for `email`, which must be well formed and not the account's own (`400`). Answers `{response, ticket}`, and answers the same for an address another account has (see "No account enumeration"). |
| `PUT /kem/v1/account/password` | `{loginState, finalization, upload, kdf, wrappedRootKey, ticket, proof?, signOutOthers?}`: replaces the OPAQUE record, the KDF settings and the wrap in one conditional write. `200 {tokens}`: new tokens for the device that asked when `signOutOthers` was true, else `null`. `409 account-changed` when the account was written meanwhile. Event `account.password_changed`. |
| `POST /kem/v1/account/email` | `{email, loginState, finalization, upload, kdf, wrappedRootKey, ticket, proof?}` with `upload` registered under `email` and `ticket` asked for it: keeps the change as pending and mails the new address. `202 {pendingEmail, expiresAt}`, for an address that has an account too. Three asks an hour per account. Event `account.email_change_requested`. |
| `DELETE /kem/v1/account/email` | Takes the pending change back. `204`, also when there was none. |
| `POST /kem/v1/account/email/confirm` | **No session.** `{token}`: opens the link. `200 {email}`. `409 account-changed` when the account was written meanwhile (the link still works). Event `account.email_changed`. |

`upload` is OPAQUE's `RegistrationUpload`, `kdf` is `{memoryKib, iterations, parallelism, salt}`, and
`wrappedRootKey` is the 92-byte wrap, all base64url as everywhere. The server checks the settings and
the lengths and never opens anything.

**The ticket.** `credentials/start` hands out, with the server's half of the registration, a ticket
sealed under `server.key` (purpose `"profile-registration"`, as the login state is, so the server keeps
nothing between the two messages). It holds the account, the DPoP key that asked, the address the
registration was asked for (none for a password), the SHA-256 of the credential identifier the OPRF
was evaluated for, and an expiry: as long as a login state lasts, five minutes. `PUT /password` and
`POST /email` must send it back as `ticket`, and it is checked before the password is spent: a ticket
that is missing, unreadable, run out, made for another account or another DPoP key, made for an
address when a password is changed or for a different address than the request's `email` (compared
the same way whether or not that address has an account), or made for an address the account no
longer has, is `400 invalid-request`. A registration made for one use can't be spent on another.

**`signOutOthers`** (default false) ends every other session of the account at once. The new
records and a **new security stamp** are written in the same conditional write, so every access token
and every refresh token the account holds stops working with it, the asking device's too; nothing
waits for a token to run out. The answer carries the asking device's new tokens (`tokens`, the same
as `POST /kem/v1/auth/token` answers), bound to its DPoP key and its device id, and its old refresh
tokens are deleted. The other devices, their trusted-device copies and their tokens are deleted as
`POST /kem/v1/devices/sign-out` does for one, after the write and best effort: they are dead by their
stamp whether or not that works, and the change is not reported failed if it does not. Without
`signOutOthers` the stamp stays, every device goes on and asks for the new password the next time it
unlocks with it; `tokens` is `null`. An access token whose device has been signed out is refused too,
whatever its stamp.

**Writes are conditional.** The password's records and the address change each update the account's
row only while it still has the `updated_at` and security stamp that were read, in one transaction
with the deletion of the pending change (and, for an address, the spending of this very link and the
move of the emergency grants), writing only the sign-in columns. A write that finds the row changed
writes nothing and answers `409 account-changed`: asking again is safe, and a link is not spent by a
change that did not happen.

**The address changes only when the link is opened.** Asking keeps one pending change per account (a
new ask replaces the old one, whose link stops working): the new address, the new record, settings
and wrap, and the SHA-256 of the link's token, which is 32 random bytes as base64url and is never
stored. The mail to the new address carries `<DOMAIN>/confirm-email?token=<token>`, good once and for
24 hours; the mail to the old address says a change was asked for, names the new address and carries
no link. The server must be able to send mail (`409 mail-off` otherwise), and a mail that cannot be
sent leaves nothing pending (`502 mail-failed`). Three asks an hour per account are accepted, counted
whether the address is free or not, on top of the limits every password check has; the fourth is
`429 rate-limited`, before the password is spent.

Opening the link looks at the account again, as it is now. An account that has been disabled or is
being deleted gets `400 email-change-invalid`, as an unknown token does. One that has since been linked
to an identity provider, shared with the Bitwarden apps or left with no password gets the refusal the
ask would have had (`403`), and its pending change is dropped, since it can never be applied; so does
an address another account has taken meanwhile (`409 email-taken`). Otherwise one conditional write
replaces the account's address, record, settings and wrap with the pending ones, gives it a **new
security stamp** (so every access and refresh token it holds stops working), spends the link, and
points the **emergency-access grants** at the new address: the grants in which the account is the
contact, and invitations still waiting at the old address, now name the new one (a grantor who already
has a grant to the new address keeps both as they were). Every device's tokens are then deleted, so
every device signs in again with the new address and password. A change of master password drops a
pending change of address, which was made from the old password and would put it back. Erasing the
account deletes it. Events carry no address.

**No account enumeration.** Asking for an address another account has looks, to whoever asks, like
asking for a free one. `credentials/start` evaluates the server's half of OPAQUE for random bytes
instead of that address and never for another account's identifier, and the ticket has the same size;
`POST /account/email` answers `202` with the same body, keeps a pending change that shows on the
profile as any other does, and tells the old address as ever. The address itself is mailed a notice
that it already has an account, that nothing was changed, and no link; the pending change that
stands in for the real one has a token nobody was given, so nothing opens it. The checks that can
fail (the ticket, the settings, the wrap, the rate limit, the password) come in the same order for
both. Only opening a link can say `email-taken`, when someone took the address between the ask and
the link.

**Notices.** Every mail is best effort and none carries a secret or a link but the one that confirms
the address: a new master password is mailed to the account's address (saying whether the other
devices were signed out), and a change of address that was made is mailed to the address it had,
naming the new one.

Who may change what:

- An account an identity provider owns (an SSO identity is linked) cannot change its name or its
  address: `403 sso-managed`. It may change its master password, if it has one.
- An account shared with the Bitwarden apps (`compatible`) holds its password hash and key in the
  Bitwarden account record, so its password and address are changed there: `403 compatible-account`.
- An account with no master password (single sign-on made it) has none to change, and a new address
  needs one: `403 no-password`. Adding a password to such an account is a separate change.

Other refusals: `400 invalid-request` for a malformed body, settings, wrap, upload, address, name or
ticket, or a login state that was used or has run out; `401 unauthorized` for a wrong password;
`400 email-change-invalid` for a token that is unknown, used or out of time, or whose account is
disabled or being deleted (never which); `409 email-taken` when someone took the address between the
ask and the link (the ask is then dropped); `409 account-changed` for a write that lost a race with
another write of the account; `429 rate-limited` for the fourth ask in an hour.

### The account's private keys

The kx1 and sig1 private keys are sealed under the user key's `"kemlock/v1/private-keys"` child:

```
plaintext = u8(1) ‖ kx1 private key (96) ‖ sig1 private key (64)          (161 bytes)
aad       = "kemlock/v1/private-keys" ‖ account id (16) ‖ u32be(key version)
sealed    = AES-256-GCM(private-keys child key, nonce, plaintext, aad)
```

The key version is the bundle's, so a key-pair replacement seals the new pair under a new version.

### The passkey PRF wrap of the root key

A passkey with the WebAuthn PRF extension wraps one more copy of the root key. The PRF is
evaluated with `first = SHA-256("kemlock/v1/prf-salt")`.

```
wrap key = HKDF(ikm = PRF output (32), salt = absent,
                info = "kemlock/v1/prf-wrap" ‖ lp(credential id), L = 32)
aad      = "kemlock/v1/root-wrap/prf" ‖ account id (16) ‖ u32be(key version) ‖ lp(credential id)
wrapped  = AES-256-GCM(wrap key, nonce, root key, aad)
```

The credential id is the raw WebAuthn credential id bytes.

`prf-wrap.json` pins the salt, wrap key, aad and wrapped key; `private-keys.json` does the same for
the sealed private keys above.

### The Recovery Kit

The Recovery Kit opens the vault without the master password: a random 32-byte **kit key** is split
into 3 pieces, any 2 of which rebuild it, and the root key is wrapped under the kit key. The split
and the wrap happen inside the key worker (`kemlock-wasm`); the page shows the pieces once and never
holds the root key.

The pieces are the Kemlock app's, byte for byte (`recovery_shares.dart`, `shamir.dart`):

```
piece = "BMCKIT1-" ‖ kit id ‖ "-" ‖ needed ‖ made ‖ index ‖ "-" ‖ share ‖ "-" ‖ check
```

- The kit id is 5 random bytes as 8 base32 characters; it ties the pieces of one kit together.
- `needed`, `made` and `index` are one digit each (`2`, `3`, `1` to `3`); a kit has at most 9 pieces.
- The share is the kit key's Shamir share, 32 bytes as 52 base32 characters. Base32 is RFC 4648's
  upper-case alphabet without padding; bits past the last whole byte are dropped when reading.
- The check is the first 4 base32 characters of `SHA-256` of the text before it (UTF-8).
- A piece is read in any case, with or without spaces. For print it is shown with the share in
  groups of four, and as a QR code of the plain text.

Shamir's secret sharing runs over GF(2^8) with the AES polynomial `x^8 + x^4 + x^3 + x + 1` and
generator 3. Each byte of the key is the constant term of its own random polynomial of degree
`needed - 1`; piece `i` holds the polynomials' values at `x = i`. Rebuilding interpolates at 0.

The root key's wrap is a passkey PRF wrap with its own labels:

```
wrap key = HKDF(ikm = kit key (32), salt = absent, info = "kemlock/v1/kit-wrap" ‖ lp(kit id), L = 32)
aad      = "kemlock/v1/root-wrap/kit" ‖ account id (16) ‖ u32be(key version) ‖ lp(kit id)
wrapped  = AES-256-GCM(wrap key, nonce, root key, aad)       nonce(12) ‖ ciphertext(64) ‖ tag(16)
```

The server keeps only the kit id, the key version, when the kit was made and the wrap. It never sees
a piece, the kit key or the root key. The wrap is also the verifier: a wrong kit key fails the AEAD
tag, so the worker knows whether the pieces it was given are right, and a kit made for an earlier key
version does not open (`GET /kem/v1/account/recovery-kit` says whether the kit is `current`).
That holds for the associated data only: the root key inside is the same until the root key is
rotated ("Rotating the root key"), which also makes a new kit.
Regenerating makes a new kit id and key and replaces the stored wrap, so every old piece stops
working. Pieces are not recoverable: lose 2 of 3 and the kit is gone; make a new one while signed in.

The routes (all need a session; the changes need a fresh proof, as turning a second step off does: the
code of `POST /kem/v1/account/two-factor/proof`, a current authenticator code, or the answer of a
security key or passkey as `{"webauthn": ...}`, to the options of
`POST /kem/v1/account/two-factor/proof/webauthn/options`; the challenge is single use and lasts two minutes):

| Route | |
|---|---|
| `GET /kem/v1/account/recovery-kit` | The kit's id, key version, time and wrap, or 404. |
| `POST /kem/v1/account/recovery-kit` | Creates the first kit; 409 when there is one. |
| `PUT /kem/v1/account/recovery-kit` | Regenerates: replaces the kit, with `proof`. |
| `DELETE /kem/v1/account/recovery-kit` | Removes it, with `proof`. |

Each change writes an `account.recovery_kit_created`, `_regenerated` or `_removed` event.

### The trusted-device copy of the root key

Only the device that made it ever opens it: the server stores it as an opaque blob, and no other
client reads it. So its inner format belongs to each platform, as long as:

- the blob starts with `u8(1)` and a platform byte (`0x01` Secure Enclave, `0x02` Android Keystore,
  `0x03` WebCrypto, `0x04` a browser extension's WebCrypto key), so a device can tell its own format from another version's;
- the wrapping key is non-extractable and never leaves the device's key store;
- where the platform's AEAD takes associated data, it is
  `"kemlock/v1/root-wrap/device" ‖ account id (16) ‖ device id (16) ‖ u32be(key version)`.

For WebCrypto (`0x03`) it is pinned as `u8(1) ‖ u8(3) ‖ AES-256-GCM(non-extractable AES-GCM key,
nonce, root key, that aad)`, with the AES-GCM output as `nonce(12) ‖ ciphertext ‖ tag(16)` and the
`aad` as given above. The web vault keeps that key in IndexedDB as a key object, in the crypto
worker, which is also the only place the root key is ever in JavaScript for this copy.

The Kemlock browser extension's copy (`0x04`, protection `browser`) has the same layout as
WebCrypto's, with `0x04` as the platform byte, so the
web vault never opens the extension's copy and the extension never opens the web vault's. Its
wrapping key is a non-extractable key kept in the extension's IndexedDB, which pages and content
scripts can't read.

### Keys of an account that has no password

A first single sign-on sign-in makes the account with `key_version` 0 and no key material. Its
device makes the keys as `account-keys.json` has them, with no password wrap and no OPAQUE record,
and sends them to `POST /kem/v1/account/keys/enrol`: the public bundle and its signature (for key
version 1, for this account), the sealed private keys, and this device's trusted-device copy of
the root key. The server checks the layouts, stores the keys only while `key_version` is still 0
(one conditional write, so of two racing enrolments one wins and the other gets 409), then the
copy; it answers 409 once the account has keys. Before enrolment `GET /kem/v1/account/keys`
answers 404. Once enrolled, such an account opens its vault with a trusted-device copy, a passkey's
PRF wrap, or another device's approval, and `GET /kem/v1/account/keys` answers with its keys and an
empty `wrappedRootKey`, since there is no password wrap. Adding a password later is a separate
change.

### Rotating the root key

The root key never changes by itself, so every copy ever made of it keeps opening the account's
keys, and every ciphertext they protect, for as long as the copy and its unlocking pieces exist: an
old Recovery Kit, a passkey's PRF wrap, a stolen trusted-device copy, a former emergency contact's
box, a space recovery box. Deleting such a copy on the server only stops the server handing it out;
anyone who kept the copy and later gets the ciphertext (a database leak, a backup) still opens the
current root. **Rotation** is the one operation that ends that: it makes a new random root key `R′`
at the next key version and moves everything `R` protected under it, so a copy of `R` opens only
what existed before the rotation.

The root key is the account's own, so a rotation is the person's own act, from a device that has
the root key open. It cannot be made for an account shared with the Bitwarden apps (`compatible`:
the root key is the Bitwarden user key, which those apps hold: `403 compatible-account`), nor for
one that has no keys yet (`404`).

**What changes.** With `N` the account's key version, a rotation installs `N′ = N + 1` (the
version after `N`, at most `2^32 - 1`; nothing else is accepted):

| What `R` protected | Under `R′` |
| --- | --- |
| The password wrap ("The password wrap of the root key") | A new wrap of `R′`, same master key and export key, `aad` with `u32be(N′)`. The OPAQUE record, the settings and the salt stay. Absent for an account with no password |
| The account's `kx1` and `sig1` private keys | **A new pair.** Both private keys were sealed under `R`, so whoever opens an old wrap opens them; a pair that stayed would go on signing and decrypting for them. The new public keys are the bundle of key version `N′`, signed by the new `sig1` key, and the pair is sealed under `R′`'s user key as "The account's private keys" says, with `u32be(N′)` |
| The old pair | Sealed once more, **under `R′`'s user key**, with the layout and label of the private keys and `u32be(N)` in the `aad` (`sealedPreviousPrivateKeys`). It is there for one reason: the signature of a `rekey` in a space must be made by the key the space has on record, which is the old one (see "Spaces", below). It is deleted on the client's say-so once that is done |
| Every item of the vault (`kem1`, owner `user:`) | **A fresh item key**, the item sealed under it again at revision `r + 1` (the revision is in the `aad`, so the ciphertext is new), and the item key wrapped under `R′`'s `item-wrap` child with `u32be(N′)`. Re-wrapping the old item key alone would not do: `R`'s `item-wrap` child opens every old wrap in every backup, and the item key it yields would still open today's ciphertext. A tombstone has nothing to change and keeps its revision |
| The Sends' `sealedKey` and `meta` ("Sends") | `sealedKey` wraps the same link key `K` under `R′`'s `item-wrap` child with `u32be(N′)`, and `meta` is sealed again under the meta key derived from it. The link key and the payload stay: `K` is in links already given out, and anyone with a link is meant to read it |
| The Recovery Kit | A new kit (new id, new key, new pieces), wrapped for `N′`. The old kit's row is replaced or deleted |
| The passkeys' PRF wraps | A new wrap of `R′` per passkey, for `N′`. It needs the passkey's PRF output, so the person must use each passkey once; one they cannot use now loses its wrap, and the passkey stays for signing in only |
| The trusted-device copies | Only the copy of the device that rotates is re-sealed (`deviceCopy`). Every other device's copy is deleted, with the device (below) |
| The emergency-access boxes | A new `"emergency-access"` box of `R′` to each contact's **current** bundle. A grant the client does not re-seal returns to `accepted` with no box, and the grantor confirms it again |
| The space recovery boxes ("Using the state") | A new `"account-recovery"` box of `R′` per enrolment, to the chain's current recovery key, with the same `keySeq`. One not re-sealed is deleted; the member enrols again |
| The duplicate tags ("Duplicate tags") | Deleted with the rewrite of the items: they are `HMAC` under a key of the user key |
| The signed manifest ("Signed manifest") | Not part of the install: the revisions and hashes change, and the old signature was made by the old `sig1` key. The rotating client signs a new one with the new key at a counter above the stored one, and `PUT`s it as soon as the install is done |

Not touched, because they do not come from the root key: the master password, its OPAQUE record and
KDF settings; the second step; passkeys as credentials; the space and collection keys (their
boxes are sealed *to* the old `kx1` key, see "Spaces" below); the contents of attachments and their
own keys. **An attachment's file key is in the item body**, so the body is new but the file's
ciphertext is the one the old body named: a person who must treat an old copy of `R` plus an old
backup as a threat to a file has to upload it again under a new key, which is an ordinary attachment
edit and no part of a rotation.

**The new keys, in the worker.** `R′` is 64 random bytes; its user key and children are derived as
for any root key. The new `kx1` and `sig1` pairs are fresh random keys (never derived from the old).
The bundle is
`"kemlock/v1/bundle" ‖ account id ‖ u32be(N′) ‖ kx1 public ‖ sig1 public`, signed by the new `sig1`
key under context `"bundle"`. All wraps above are the existing formats with `R′` and `u32be(N′)`;
nothing new is invented for them. A `kx1` or `sig1` public key equal to the old one is refused by
the server.

#### The re-encryption of an item

For each live item of the vault, with its `id`, `owner`, `kind`, `revision r`, `ciphertext`,
`itemKey` and `keyVersion v`:

```
old item key = unwrap(R's item-wrap child, itemKey, aad "kemlock/v1/item-key" ‖ id ‖ owner ‖ u32be(v))
json         = AES-256-GCM-open(old item key, ciphertext, aad "kemlock/v1/item" ‖ id ‖ u64be(r) ‖ lp(kind) ‖ owner)
new item key = 32 fresh random bytes
ciphertext′  = AES-256-GCM(new item key, nonce, json, aad "kemlock/v1/item" ‖ id ‖ u64be(r + 1) ‖ lp(kind) ‖ owner)
itemKey′     = AES-256-GCM(R′'s item-wrap child, nonce, new item key, aad "kemlock/v1/item-key" ‖ id ‖ owner ‖ u32be(N′))
```

An item that does not open under `R` (a body corrupted earlier) stops the rotation: the client
reports which one and rotates nothing. The JSON is carried over byte for byte.

#### Staging, and the install in one transaction

The items are the only part that can be large, so they travel apart from the install and the server
holds them **staged**, invisible to every reader and to sync:

```
PUT /kem/v1/account/rotation/items   {rotationId, toVersion, items: [{id, baseRevision, ciphertext, itemKey, writer?, writerKeyVersion?, writeSignature?}]}
```

- `rotationId` is 16 random bytes the client makes, base64url: it names one attempt. A request with
  another `rotationId` than the account's staged rows discards those rows first.
- 1 to 200 items per request, and no more than fit the server's 2 MiB JSON body limit: a client
  batches by encoded size and sends fewer items when they are large. A row is replaced when the
  same `id` is staged again, so a request that failed is simply sent again. `baseRevision` is the revision the client read; `ciphertext`
  and `itemKey` are as above, at revision `baseRevision + 1`. The server cannot check that; it
  checks the lengths (`ciphertext` 28 bytes up to the item limit, `itemKey` 60 bytes), that the item
  is live, the account's own, in format `kem1`, and at `baseRevision` now, and that `toVersion` is
  the account's version plus one.
- **Each item is signed.** The re-encrypted item is a write of the account like any other (revision
  `baseRevision + 1`, `keyVersion = N′`), so the client signs it ("Signed item writes"): the statement
  of that write, with the writer's key version `N′`, signed by the **new** `sig1` key `R′` brings,
  and sends `writer`, `writerKeyVersion` (`N′`) and `writeSignature` beside the item, all three or
  none. The server cannot check it when it is staged (it holds the new bundle only from the install),
  so it keeps it with the row and checks the signature, and that the writer is the account at
  version `N′`, at the install; see step 8.
- `DELETE /kem/v1/account/rotation` discards the staged rows (abandoning); rows older than two hours
  are ignored and deleted by the next request. Staged rows change nothing a device can see. A page
  that is closed mid-rotation loses `R′` with it, and its staged rows are useless: the next attempt
  starts over with a new `rotationId`.

This is the **resumable** choice: the vault is never half rotated (no item exists under `R′` until
the install), and a rotation that fails at any point leaves the account exactly as it was. Writing
the items under `R′` one batch at a time through the ordinary item routes was rejected: until the
last batch, the account would hold items its other devices cannot open, and an abandoned attempt
would leave them unreadable for good.

```
POST /kem/v1/account/rotation
{ "rotationId", "fromVersion": N, "toVersion": N′,
  "loginState", "finalization", "proof"?,           the password again, as for PUT /account/password
  "publicBundle", "bundleSignature",
  "sealedPrivateKeys", "sealedPreviousPrivateKeys",
  "wrappedRootKey"?,                                 the password wrap, 92 bytes
  "kit"?: {"kitId", "wrappedKey"}, "dropKit"?: bool,
  "deviceCopy"?: {"wrappedKey", "protection"},
  "passkeys": [{"id", "wrappedKey"}], "dropPasskeys": [id],
  "emergency": [{"id", "sealedKey"}], "dropEmergency": [id],
  "recovery": [{"space", "keySeq", "box"}], "dropRecovery": [space],
  "sends": [{"id", "sealedKey", "meta"}],
  "spacesHandled": bool }
```

`GET /kem/v1/account/rotation` answers what the server holds that the install must cover, so the
client builds the request from the server's own list: `{keyVersion, hasPassword, publicBundle,
kit: {kitId} | null, passkeys: [{id, credentialId}], deviceCopies: [{deviceId}], emergency: [{id,
state, granteeId, granteeEmail, granteeBundle}], asContact: [{id, state}], recovery: [{space, keySeq}],
sends: [{id, kind}], items: {count}, spaces: count,
previousKeys: {keyVersion, sealed} | null}`. `passkeys` lists only the passkeys that have a PRF wrap;
`emergency` only grants that hold a box; `asContact` the grants in which this account is the **contact**
and holds a box (below). `granteeBundle` is the contact's bundle as the server holds it now; a client
seals the new root key to it only after the person compared its fingerprint with the one on the
contact's own screen, and otherwise drops the grant, because the server could have swapped it.

**What the server checks**, all of it inside the one transaction that writes, so a request that
fails any check writes nothing and answers `409 rotation-incomplete` (what changed since the client
read it) or `400 invalid-request` (what is malformed), and one that loses a race answers
`409 account-changed`:

1. The account is not `compatible`, is not federated (it is not a copy made by a replica, and its
   personal vault has no replicas: `409 rotation-federated`, a limitation: another server holds
   copies of the wraps and of the items that a rotation here cannot replace), has keys, and
   `fromVersion` is its `key_version` and `toVersion` is the next one (`409 rotation-stale-version`
   otherwise).
2. With a password, the password is right and, when a second step is on, a fresh `proof` is given
   (both as `PUT /account/password` does). **With no password, a fresh answer of a passkey or
   security key is required** (`proof` as `{"webauthn": …}`), never a session alone, whether or not a
   second step is on. These are checked **after** every other check that needs no secret, and after
   the checks below on a plain read of what the account holds, so a refusal that can be known
   (`rotation-incomplete`) does not spend a login state or a one-time proof; the transaction checks
   again.
3. The bundle parses, is for this account at key version `toVersion`, its signature verifies under
   its own `sig1` key, and neither its `kx1` nor its `sig1` public key is the old bundle's. Both
   sealed private-key blobs are exactly 189 bytes (`private-keys` above).
4. `wrappedRootKey` is present, and 92 bytes, exactly when the account has a password wrap.
5. Every wrap is well formed by its own length rule: a kit's id is 8 base32 characters and its wrap
   92 bytes; each passkey wrap 92 bytes; each emergency box and recovery box the length of its
   format; a send's `sealedKey` 64 bytes beginning with `u32be(N′)`; a `meta` 28 bytes to 16 KiB; a
   device copy as for any copy.
6. **Every wrap of `R` the server holds is either replaced or named as dropped, and nothing else.**
   For passkeys, emergency grants and recovery enrolments, the ids in the list and in its `drop…`
   list are disjoint and together are exactly the set the server holds now; for the kit, `kit` or
   `dropKit` when one exists; for sends, the list is exactly the account's Sends. An id the server
   does not hold, or one it holds that the request does not name (a wrap another device added while
   the client worked), is `409 rotation-incomplete`: the client reads the plan again and redoes
   the missing part.
7. `deviceCopy` is the calling device's own; every other device's copy is deleted.
8. The staged rows of `rotationId` are exactly the account's live items, each at its `baseRevision`
   now. An item written, deleted or created since the client read it makes the answer
   `rotation-incomplete`, naming how many; the client stages those again (a round that stages only
   the changed items) and installs again. A live item of format `bw` is `409
   rotation-unsupported-items`.
   Each staged item's signature, when it has one, verifies over the statement of the write the install
   makes (the item's id, owner and kind, revision `baseRevision + 1`, its sealed value at `N′`),
   under the new `sig1` key of the bundle the request brings; one that doesn't is refused (`422
   invalid-signature`), and nothing is written. An owner that takes signed writes only ("The
   signed-only flag") has no unsigned staged item installed (`422 signature-required`): a vault that
   asked for signed writes only stays that way through a rotation, and a client that cannot sign
   (an old one) cannot rotate it. The signature is stored with the item like any signed write.
9. The account is in no space, or `spacesHandled` is true (`409 spaces-need-rekey`). Only accepted and
   confirmed memberships count: an invitation not yet accepted does not. And if an earlier
   rotation's previous keys are still kept for the spaces, the install is refused
   (`409 rotation-spaces-pending`): see "Spaces".
10. The vault has at most 50,000 live items: the install is one transaction, and a larger vault is
    refused (`400`) rather than half moved. The server writes the staged items 500 at a time.

**What the server writes**, in that transaction and not before: the account's row (bundle,
signature, sealed private keys, password wrap, `key_version = N′`, a new **security stamp**, new
`updated_at`), conditional on the `updated_at` and stamp it read; the previous private keys; the
items (as the ordinary write does: revision `baseRevision + 1`, `keyVersion = N′`, a new change per
item, the item's duplicate tags deleted); the sends; the kit; the passkey wraps (the dropped ones
removed); the emergency boxes (dropped grants back to `accepted`); the recovery boxes; the device
copies; the account's answered device approvals (`auth_requests` that hold a root key sealed to a new
device's one-time key); the staged rows removed. **The grants in which the account is the contact**
hold a box the grantor sealed to the account's old `kx1` key: each goes back to `accepted` with no
box, and its grantor confirms the account's new bundle again. The locks that make this exact: the
install takes the `server_meta` lock that every item write takes, and the account's row lock, before
it reads; every write of a wrap (a PRF wrap, a device copy, the kit, an emergency box, a recovery
box, a Send, a device approval) takes the account's row lock too, so a wrap written meanwhile is
seen, or waits. A writer that waited then reads the account's `key_version` again under that lock, and
a wrap that is for another version is refused (`409 key-version-stale`, with `currentKeyVersion`; an
account at version 0 accepts any), so a write made from keys read before the install can't leave a
wrap of `R` behind. The version comes from what the write carries: a PRF wrap's and a kit's
`keyVersion`, the `u32be` that begins a new Send's `sealedKey`, and the optional `keyVersion` of a
Send's edit (`PUT /kem/v1/sends/{id}`), of a device copy (`PUT /kem/v1/devices/key-copy`), of an
emergency confirmation (`POST .../emergency/grants/{id}/confirm`) and of a space recovery
enrolment. **What this does not cover:** a request from a client that doesn't send `keyVersion`
(one made before this field) is accepted without the check, so a Send edit's `meta`, a device copy,
an emergency box or a recovery box made from the old keys could land after an install that replaced
them (the next rotation covers it, as it covers any wrap, and a copy of an old version opens
nothing); and a device approval, which carries no key version, is never checked. Nothing else the
server holds refers to `R` afterwards: **no wrap of `R` stays in this server's database** except
those. That holds for this server only: a backup taken earlier still has the old
wraps and ciphertexts, a device that was offline keeps its own copy of what it opened (its trusted
copy on the server is deleted with the device), and another server's copies are why a federated
account is refused. After the commit, and best effort, the other devices are signed out and their rows and
tokens deleted as `PUT /account/password` with `signOutOthers` does, and the calling device gets new
tokens (`{keyVersion, tokens}`); the event `account.keys_rotated` is written (no key material). The
account's address is mailed a notice, and so is the grantor of each grant the install reset above
(the grants in which the account is the contact): the mail says their emergency contact replaced
their keys and that they must confirm the contact again in Emergency access, until which the
contact has no access. Every mail is best effort, sent after the commit, and carries no key
material.

Two slugs look alike and are different rules. `key-version-stale` answers **409** on
the wrap routes above (a PRF wrap, a kit, a Send, a device copy, an emergency box, a recovery box),
and **422** on a signed item write whose signature is for a key version the account no longer has;
both carry `currentKeyVersion` and mean "the account's keys changed after this device unlocked:
unlock again". `stale-key-version` (409) is another rule: a write of an item under a collection
key version that a `keys` record has replaced (the scenario of "A write under the old version leaves
it held"), and its `currentKeyVersion` is the collection's, not the account's.

Other devices' sessions end with the stamp: each signs in again and sees at
`GET /kem/v1/account/keys` a `keyVersion` it did not hold, so it opens with the password, a passkey,
the new kit or another device's approval and makes its trusted-device copy again. A copy of the old
version no longer opens (its `aad` has `u32be(N)`), and a device deletes the key and the local data
it kept for `N`. **What a device that did not rotate does, exactly**, when it learns another device
rotated (a `401` with `security-stamp-changed`, a push that finds its session ended, or a
`keyVersion` it did not hold):

1. It treats the session as ended and signs in again (password, passkey, the new kit or an approval).
2. It discards the root key it held, its trusted-device wrapping key and copy, and its tab and
   reload copies, every key derived from the old root (item-wrap, private keys, space keys it opened
   with them), and every value it kept sealed under the old user key: space anchors, pins, key-box
   stores, signed-owner memory. A value that does not open there is **lost, not damaged**: the device
   asks again (first contact of each space) instead of refusing.
3. It fetches the account's keys at the new version and verifies the new bundle against what it
   opens, shows the new fingerprint, and drops its sync cursor: every item is at a new revision.
4. It makes its own trusted-device copy again, for `N′`.
5. It re-pins: another member's pin of this account is for the old fingerprint and shows "replaced
   their keys" until it is compared again; this account's own pins of other people stay (they are
   theirs) but are sealed again by the device that rotated, or asked again on one that did not.
6. It removes its passkeys' unlock marks (their PRF wraps were removed unless the rotating device
   touched them), its emergency contacts that were not confirmed again, and treats grants that name
   the account as the contact as waiting for their grantor's new confirmation.
7. It stops using an old Recovery Kit: its pieces open nothing.

**Spaces.** Space, collection and group keys are not under `R`, but the old `kx1` key is gone: the
boxes sealed to it can no longer be opened by a device that has not already opened them, and the
account's `sig1` key is new. A client that is in a space therefore, **after** the install and while
it still holds the old keys (the previous private keys let another device continue):

1. in each space with a chain, appends a `rekey` ("Space chain": the bundle at `N′`, signed with the
   old `sig1` key and cosigned with the new one), then a `seal` of each key the member holds to its
   own new bundle (it is Awaiting those keys, and as a holder it may seal them), or waits for
   another holder's seal;
2. in a space with none, seals the keys it holds to its own new bundle through the key routes;
3. then deletes the previous keys (`DELETE /kem/v1/account/rotation/previous-keys`), which takes what
   the install takes: the password again, and the second step's proof, or with no password a
   passkey's answer.

The previous keys are kept **only for an account that is in a space**, and an install is refused
(`409 rotation-spaces-pending`) while an earlier rotation's are still kept: a `rekey` must be
signed by the key a space has on record, and a second rotation would replace the only copy of it.
The server accepts a `rekey` only if its bundle is byte for byte the account's registered, current
one, so the `rekey` must follow the install before the account rotates again.

Until then the member's confirmations are for the old key version, and "Member confirmation"
applies: every other member sees "replaced their keys" and may compare the new fingerprint. A client
that cannot do (1) and (2) must not rotate an account that is in a space; the server asks it to say
so with `spacesHandled` and refuses with `409 spaces-need-rekey` otherwise. The web vault does not
do it yet, and says so.

A write of an item to the account's own vault must name the account's current key version (`400`
otherwise), in a single write and in a batch: a device that missed the rotation, or a replica
serving an older state, can't store an item sealed under keys the account no longer has. A
deletion carries no sealed value and is not checked.

`GET /kem/v1/account/rotation` answers `previousKeys` while they exist, so a second device that
opens the vault with the new keys can finish the spaces: it opens `sealedPreviousPrivateKeys` with
`R′`'s user key (`aad` with `u32be(previous version)`).

**What a client must do** (the Kemlock app, the browser extension and any other):

- Offer rotation only to an unlocked account that is not `compatible`; say that it signs every
  other device out and needs each passkey's use and each emergency contact's current bundle; ask
  for the password (or, with none, the account's way in).
- Make `R′`, the new pair and the bundle, re-encrypt every item and Send in a worker and stage
  the items in batches with progress; never send `R′`, a key or a plaintext. Show the new
  fingerprint afterwards.
- Seal every wrap of `R′` before the install, and send no wrap of `R`.
- On `409 rotation-incomplete`, read the plan again, stage the items it names and any new wrap, and
  install again; give up after five rounds.
- After the install and before it commits to the new keys, seal again every value it keeps locally for
  the account under the old user key (the web vault's space anchors and pins, a key-box store, a
  signed-owner memory): they are sealed under a child of the user key, so none opens after a
  rotation. A client that did not rotate and finds them unreadable treats them as lost, not as
  damaged: it asks again (first contact), and does not trust or refuse on what it cannot read.
- After the install, sign and `PUT` a new manifest, show the new Recovery Kit once, make the
  device's trusted-device copy, delete the key and local data of version `N` it still holds, and
  do the spaces' part before it forgets the old keys.
- A device that was not the one rotating treats a `keyVersion` it did not hold, on its next
  sign-in, as "keys were rotated": it discards its copy of the root key, its sealed local data and
  its derived keys.

`rotation.json` in test-vectors pins: a root key `R` and `R′` with their user keys and `item-wrap`
children; the item re-encryption (old ciphertext and wrap, the JSON, the new item key, ciphertext
and wrap, with the `aad`s), and that the new envelope does not open under `R`'s keys, at revision
`r`, or with the old item key; the Send re-wrap (`sealedKey` and `meta` under `N′`, and that the
old ones do not open under `R′`); the password, kit and passkey wraps of `R′` at `N′`, and that the
same wraps of `R` at `N` do not open at `N′`; the new bundle and sealed private keys at `N′`, and
the previous private keys sealed under `R′` at `N`.

## `kx1`: the hybrid exchange key

- Public key: `ML-KEM-1024 encapsulation key (1568) ‖ X25519 public key (32)`, 1600 bytes.
- Private key: `ML-KEM-1024 seed d ‖ z (64) ‖ X25519 private key (32)`, 96 bytes. The ML-KEM key
  pair is expanded from the 64-byte seed as FIPS 203 `ML-KEM.KeyGen_internal(d, z)` does.
- Encapsulation to `pk = pk_m ‖ pk_x`:
  1. `(ct_m, ss_m) = ML-KEM-1024.Encaps(pk_m)`;
  2. an ephemeral X25519 key `e`; `ct_x = X25519(e, 9)`; `ss_x = X25519(e, pk_x)`;
     an all-zero `ss_x` is refused;
  3. `ss = SHA3-256("kemlock/v1/kx1" ‖ ss_m ‖ ss_x ‖ ct_x ‖ pk_x)`;
  4. the ciphertext is `ct_m (1568) ‖ ct_x (32)`, 1600 bytes.

  This is X-Wing's construction (draft-connolly-cfrg-xwing-kem) over ML-KEM-1024, with one
  deliberate difference: Kemlock's label comes **first**, as a domain-separation prefix, where
  X-Wing's later drafts put their label last. The order is part of the format; don't "fix" it.
  `ct_m` stays out of the hash because ML-KEM's implicit rejection already binds it.
- Decapsulation recomputes `ss` the same way, and also refuses an all-zero `ss_x`. It never reports
  which half failed.

### Sealed box

Seals a short secret (a key) to an exchange public key under a context label:

```
(ct, ss) = kx1.Encaps(pk)
key      = HKDF(ikm = ss, salt = absent, info = "kemlock/v1/seal" ‖ lp(context), L = 32)
box      = u8(1) ‖ ct (1600) ‖ AES-256-GCM(key, nonce, secret, aad = lp(context) ‖ lp(aad))
```

`aad` is the caller's extra binding (for example the recipient's account id); it is not stored in
the box. A box opened under another context label fails. Contexts in use:

| Context | Seals |
| --- | --- |
| `"device-approval"` | The root key to a new device's one-time key pair; `aad` = account id (16) ‖ approval request id (16), 32 bytes, so an answer can't be replayed onto another request, and the account id must be the sealing account's own |
| `"space-key"` | A space key to a member; `aad` = space id (16) ‖ u32be(space key version) ‖ recipient account id (16), 36 bytes, so a server can't serve one space's or one version's box as another's |
| `"collection-key"` | A collection key to a member; `aad` = space id (16) ‖ collection id (16) ‖ u32be(collection key version) ‖ recipient account id (16), 52 bytes. A collection's key versions are its own, not its space's |
| `"emergency-access"` | A root key to an emergency contact; `aad` = the contact's account id (16) |
| `"account-recovery"` | A member's root key (64 bytes) to a space's recovery key; `aad` = space id (16) ‖ account id (16) ‖ u64be(`seq` of the chain record that set the recovery key), 40 bytes, so a box can't be served for another space, another member or another recovery key |

### Device-approval phrase

A new device and the device approving it both show five words, so a person can see that the key
about to receive the root key is the one the new device made.

```
digest = SHA-256("kemlock approval v1" ‖ the new device's one-time kx1 public key (1600))
bits   = the first 65 bits of digest, most significant first
word i = list[(bits[13i .. 13i+13] as a big-endian 13-bit number) mod 7776],  i = 0 .. 4
phrase = the five words, lower case, joined by single spaces
```

- The list is EFF's large word list (<https://www.eff.org/dice>, CC BY 3.0 US): 7,776 lines, one
  word per line, LF endings, no dice numbers, `abacus` first. The file is
  `crates/kemlock-domain/src/unlock/eff_large_wordlist.txt`, SHA-256
  `6d557f0693958fb5e650b68b5bee585eb82cf4da32965505c789e924743bc522`.
- A 13-bit group from 7776 to 8191 wraps with `mod 7776`, so the first 416 words are twice as
  likely. That costs under half a bit of the phrase's 64.6 bits, and the phrase only has to make
  two keys' phrases differ, not stay secret.
- **Each client computes the phrase itself**, from the public key it made (the new device) or the
  key it is about to seal to (the approving device). The server's `phrase` field is a cross-check
  only and is never shown, or a server could substitute a key and send matching words to both
  screens.

- **The keys the new device ends up with are checked.** The phrase shows the box went to the key the
  new device made; nothing the new device holds shows that the root key inside is the account's, so a
  server could seal a root key of its own to that key, with sealed private keys that open under it.
  The new device therefore needs the account's bundle and sealed private keys, and opens its vault
  only if the public halves of the `kx1` and `sig1` private keys it opens are exactly the bundle's,
  for the account and key version it signed in with. It then shows the bundle's fingerprint
  ("Public-key bundle and fingerprint") and treats the vault as open only after the person has typed
  the last group of five digits as the approving device shows it (so "same" is not pressed blindly)
  and confirmed. A mismatch, or no answer, locks the vault and ends the session. A server that
  forged the bundle too is caught only by this comparison.
- **What the approving device shows.** Every client that can approve (the Kemlock app, the browser
  extension, the web vault) shows the fingerprint of its own account's bundle, worked out from its own
  unlocked keys and never taken from the server, on a screen of its own that is reachable at any
  time: at least on its devices screen, whether or not a request is pending, and not only inside the
  request. The new device sends the person there after approval, when the request has gone from the
  list, so a fingerprint shown only beside a pending request cannot be compared. An approving device
  that cannot work the fingerprint out says so, and does not approve.

`phrase.json` in test-vectors pins the digest, the five 13-bit groups, their indexes and the phrase
for several keys, one of them with a group that wraps the list.

## `sig1`: the hybrid signing key

- Public key: `ML-DSA-65 public key (1952) ‖ Ed25519 public key (32)`, 1984 bytes.
- Private key: `ML-DSA-65 seed ξ (32) ‖ Ed25519 seed (32)`, 64 bytes.
- The signed message is `m' = "kemlock/v1/sig1" ‖ lp(context) ‖ lp(message)`. The contexts are
  `"bundle"`, `"manifest"`, `"confirm"`, `"key-box"` ("Signed key boxes"), `"space-chain"` ("Space chain") and
  `"item-write"` ("Signed item writes").
- Signature: `ML-DSA-65.Sign(sk_m, m', ctx = empty) (3309) ‖ Ed25519.Sign(sk_e, m') (64)`,
  3373 bytes. ML-DSA signing may be hedged or deterministic; verifiers accept both.
- Verification passes only when both verify over the same `m'`.
- The Ed25519 half of a public key must pass the key checks below when the key is parsed, so a
  bundle or a record that carries a weak Ed25519 key is refused (invalid) before anything is
  verified under it.

### Ed25519 verification rule

Every implementation of `sig1` (the server on aws-lc-rs or RustCrypto, the web vault in
WebAssembly, the Kemlock app, the browser extension) must verify the Ed25519 half by this one rule,
so that a record the server accepts is a record every client accepts. It is RFC 8032's check without
the cofactor, plus the checks that make it strict. With `p = 2^255 - 19` and `L` the order of the
base point, `Ed25519.Verify(A, m', R ‖ S)` passes only when all of these hold:

1. **`A`** (the public key) is a canonical encoding: its 255-bit `y` (little endian, top bit
   cleared) is below `p`. A `y` of `p` or more is refused, and so is a sign bit set on a point
   whose `x` is 0. It is not one of the eight points of small order, whichever way the sign bit
   goes: `y` is none of `0`, `1`, `p - 1`, and the two of order 8,
   `26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05` and
   `c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a` (little endian). And it
   decodes to a point on the curve.
2. **`R`** (the first 32 bytes of the signature) meets the same three conditions as `A`.
3. **`S`** (the last 32 bytes, little endian) is below `L` = `2^252 +
   27742317777372353535851937790883648493`. A check of the top three bits alone is not enough.
4. `[S]B = R + [k]A` holds exactly, with no multiplication by the cofactor, where
   `k = SHA-512(R ‖ A ‖ m') mod L` is taken over the bytes of `R` and `A` as sent.

This is RustCrypto's `verify_strict` (`ed25519-dalek`) with an explicit canonical-key check added:
`verify_strict` reads the key through curve25519-dalek's `decompress`, which accepts a `y` of `p`
or more. aws-lc refuses an `S` of `L` or more and non-canonical keys but not a small-order `A` or
`R`. So `kemlock-crypto` runs the byte checks of 1 to 3 itself, on both backends, before the
library checks the equation, and both give one answer. A mixed-order key (a point plus a point of
small order, which is not itself of small order) is not refused: the exact equation of 4 decides,
and every implementation that follows 4 agrees.

Parsing a `sig1` public key (and so a bundle) applies the byte checks of condition 1 to the Ed25519
half and refuses the key when they fail. Whether the point is on the curve is found when something
is verified under it, where it fails like any other wrong key; a bundle is only stored by the server
once its own signature verifies (below). The same checks apply to any other Ed25519 public key that
comes from outside, such as a DPoP proof's key.

`sig1-edge.json` in test-vectors pins the verdicts for each edge case of "Taming the many EdDSAs"
(Chalkias et al., 2020).

## Public-key bundle and fingerprint

```
bundle      = "kemlock/v1/bundle" ‖ account id (16) ‖ u32be(key version)
              ‖ kx1 public key (1600) ‖ sig1 public key (1984)
fingerprint = SHA-512("kemlock/v1/fingerprint" ‖ bundle)
```

The bundle is signed with the account's own `sig1` key under context `"bundle"`. The server checks
that signature, under the key the bundle itself carries, when an account registers its keys and
when a device enrols them, and refuses a bundle whose signature does not verify (invalid), so no
client is ever given a bundle that does not prove its own key. People compare
the fingerprint as 12 groups of 5 digits: group `i` (0 to 11) is
`u40be(fingerprint[5i .. 5i+5]) mod 100000`, written with leading zeros, so the 60 digits use the
first 60 of the 64 hash bytes.

### Member confirmation

A space hands its keys only to a member that someone already in the space confirmed: the confirmer
compared the member's fingerprint with the one on the member's own screen, and signs that they did.

```
statement = "kemlock/v1/confirm" ‖ space id (16) ‖ member id (16) ‖ u32be(member key version)
            ‖ fingerprint (64) ‖ confirmer id (16)
signature = sig1 signature of the confirmer's own key, context "confirm", over the statement
```

The statement is 134 bytes and the signature 3373. The fingerprint is the member's bundle
fingerprint (above) that the confirmer compared, and the key version is the member's key version
of that bundle, so a confirmation stops covering a member whose account later moves to a new key
version. The confirmer signs with the `sig1` key in their own bundle.

The server rebuilds the statement from what it holds (the space, the member, the member's current
key version, the fingerprint the confirmer sent, and the confirmer as the signed-in account),
refuses a request whose statement differs by a byte or whose fingerprint isn't that of the
member's current bundle, and checks the signature against the `sig1` public key in the confirmer's
bundle. It keeps the statement and signature beside the member, in the `confirmation` field it
returns: `statement`, `signature` and `fingerprint` are base64url, next to `by`, `at` (seconds)
and `memberKeyVersion`. Any other member's client
verifies the pair again against the confirmer's bundle, so a server that invented a confirmation
can't pass it off as a person's.

## `kem1`: the item envelope

Each item has its own random 32-byte item key. The revision is part of what is sealed, so the
**client assigns it**: a new item is revision 1, and each write is the previous revision plus one.
The server stores what it is sent, checks `If-Match` against the stored revision and refuses any
revision that isn't the stored one plus one.

```
aad        = "kemlock/v1/item" ‖ item id (16) ‖ u64be(revision) ‖ lp(kind) ‖ owner (17)
ciphertext = AES-256-GCM(item key, nonce, item JSON (UTF-8), aad)

wrap aad   = "kemlock/v1/item-key" ‖ item id (16) ‖ owner (17) ‖ u32be(key version)
item_key   = AES-256-GCM(owner's "kemlock/v1/item-wrap" child key, nonce, item key, wrap aad)
```

- `kind` is the item's kind as ASCII, 1 to 64 bytes of `[a-z0-9_-]`, such as `login`, `note`,
  `file`, `otp` (the MFA code), `backup-codes`, `passkey`, `card`, `identity`, `contact`,
  `certificate`, `ssh-key`, `pgp-key`. The server checks only the alphabet and the length, so a
  kind it has never heard of is stored as it is; "Item bodies" below says what each kind holds.
- The item key wrap is not bound to the revision, so an edit may keep the item key.
- What the server can check: lengths, that a sealed value is at least 28 bytes, the kind's
  alphabet, the revision rule and the owner. It can't check the AAD: only a device holding the key
  can, which is the point.

On the wire an item is:

```json
{ "id": "…uuid…", "owner": "user:…uuid…", "kind": "login", "format": "kem1",
  "revision": 4, "keyVersion": 1, "ciphertext": "…b64url…", "itemKey": "…b64url…",
  "deleted": false }
```

A `kem1` item may also carry `writer`, `writerKeyVersion` and `writeSignature`, the writing
account's signature of the write ("Signed item writes"); an owner that has seen one refuses writes
without. A deleted item is a tombstone: `deleted: true` with `ciphertext` and `itemKey` absent. Its
revision still moves on, so a device sees the deletion as a newer write. `deleted` is always
present, `true` or `false`, in both directions; the server refuses an item without it. `owner` is
`user:<uuid>` for a person's own vault and `space:<uuid>` for a space, hyphenated lower case.

### Signed key boxes

A sealed box is anonymous: whoever knows a member's `kx1` public key can seal anything to it, and the
`aad` only stops a box being served as another one. So the server, which knows every member's public
key, could make a collection key of its own, seal it to a member and serve it, and a new item that
member wrote to that collection would be readable by the server. A space with a chain commits every
box in the signed chain (`open_key`, "Using the state"), which authenticates it. **A space with no
chain gets the same from the member who sealed each box signing it.**

```
statement = "kemlock/v1/key-box" ‖ lp(box context) ‖ lp(aad) ‖ lp(box)
            ‖ sealer id (16) ‖ u32be(sealer key version)
signature = sig1 signature of the sealer's own key, context "key-box", over the statement
```

- The box context is `"space-key"` or `"collection-key"` and `aad` is that box's own `aad` ("Sealed
  box"), so the statement names the space, the collection, the key version and the recipient. The
  box is the 1661 bytes of `u8(1) ‖ ct ‖ AES-256-GCM(…)`. The statement is 1756 bytes for a space key
  and 1777 for a collection key, and the signature 3373.
- The **sealer** is the account that made the box: the one signed in when it was sent. The key
  version is the version of the sealer's bundle whose `sig1` key signs.
- The signature stays beside the box, never inside it, so a box's bytes (and the seal hash a chain
  commits) don't change.

**What the server does.** Every route that takes a sealed space key or collection key for a space
with no chain also takes the signature, base64url, next to the box: `signature` in each `{user, sealed}`,
`{collection, user, sealed}` and `{collection, sealed}` entry of a request, `sealedSpaceKeySignature` beside
`sealedSpaceKey` (creating a space, confirming a member) and `sealedKeySignature` beside the first
collection's `sealedKey`. The server rebuilds the statement
from the route (the space, the collection, the key version it will store, the recipient and the box)
with the signed-in account as sealer and that account's registered key version, and refuses the
request (invalid, `400`) unless the signature verifies under the `sig1` key of the sealer's
registered bundle. It stores `sealedBy` (the sealer's id and key version) and the signature with
each key copy, a member's space key copy and each collection key copy, and serves them with it:

```json
"sealedBy": {"account": uuid, "keyVersion": int, "signature": base64url}   or null
```

on a member's own entry (next to `sealedSpaceKey`) and on each collection key copy it serves. It
doesn't judge the sealer's authority again: its own rules already say who may seal what. A copy the
server holds from before signatures, and any copy of a space with a chain, has `sealedBy` `null`.
Replacing a key (a `confirm` again, a key replacement, a grant) replaces the box and its signature
together. Key copies the chain commits (a `confirm`, `seal`, `keys` or `collection` record) carry no
signature.

**What a client does, before it opens a key of a space with no chain.** The key is the member's own
copy of the space key, or one of the collection copies the server serves. The client opens the box
only when one of these holds:

1. **A signed box.** `sealedBy` is present, the signature verifies over the statement the client
   rebuilds itself (the space, key version and recipient from what it is opening, never from the
   server's description of the box) under the `sig1` key of the sealer's bundle, and the sealer is
   trusted:
   - the sealer is the client's own account, and the bundle is the one the client holds (not the
     server's copy), at the key version the signature names; or
   - the sealer is a confirmed member whose bundle is verified as for a recipient ("Member
     confirmation": the bundle is theirs, signed by itself, at their current key version, and their
     confirmation traces, through members who are themselves verified, to the client's own account
     or to a fingerprint a person compared, a **pin**), the signature's key version is that
     bundle's, **and** the sealer held authority to seal that key:
     - the space key: an owner or admin, or a custom member with `manage-users` (a confirmer);
     - a collection key: an owner or admin, or a member with Manage on the collection (directly or
       through a group), or a custom member with `manage-users` or `manage-groups` who holds a grant
       on the collection (the confirmation and the group change seal the keys of the collections
       they cover).
2. **A box already accepted.** The client remembers, in its sealed local store, the SHA-256 of each
   box it accepted for (space, key, version). A box with that hash is accepted again without the
   sealer being checked, so a sealer who has since left, or whose account has moved to another key
   version, doesn't lock a member out of a key they already hold. A box with another hash for the
   same (space, key, version) is checked as 1, and is refused when it fails.
3. **A box from before signatures.** `sealedBy` is `null`, and the rule for those is below.

**Comparing first.** A signed box whose sealer the client can't trace (nobody it trusts confirmed
them, and no person compared their fingerprint here) is not opened, and the client says which member
a person should compare: the sealer if nobody confirmed them, or the root the walk of confirmations
ended at. The person compares that member's fingerprint with what the member's own app shows; once
it matches, the client trusts what that member confirmed and sealed (a **pin**, as in "Member
confirmation"), and opens the keys. It is the comparison first contact asks for with a chain, and
without it a space with no chain has nothing that ties a sealer to a person.

A box that fails all three is not opened, and the client shows the space's keys as "Can't be
checked". A space with a verified chain skips all of this: the chain authenticates its boxes, and
requiring a signature there too would only repeat the work. A client that has ever been served a chain
for a space never reads it as having none ("Using the state").

**Boxes made before this change.** There are boxes no one signed, and no later signature can prove
who made them. The rule keeps existing spaces usable without opening the door to new forgeries:

- A client **accepts and remembers** an unsigned box once per (space, key, version): the first time
  it meets one it opens it, stores its SHA-256 as in 2 and marks it "sealed before keys were
  signed". The mark is shown to the person on the space ("Some keys of this space were sealed before
  keys were signed; ask an owner or admin to re-seal them"), and goes when the box is replaced.
- An unsigned box that differs from the one remembered for that (space, key, version) is refused.
- A client also keeps, for each space, whether it ever accepted a **signed** box of it. From then on
  it refuses an unsigned box of any key it had not already accepted: every box made since signatures
  began carries one, so such a box is a signature taken away, or a key the server made. A box it
  accepted before still opens (rule 2). When a space serves both kinds, a client takes the unsigned
  boxes first, so one pass doesn't depend on the order the server lists them in.
- An unsigned box is replaced by a signed one when the key is replaced (the next key version is
  sealed and signed by whoever replaces it), when an owner or admin confirms the member again (which
  seals the current space key and the member's collection keys anew), or when an owner or admin
  **re-seals the space's keys**.

**Re-sealing.** `POST /kem/v1/spaces/{id}/reseal`, for a space with no chain whose keys aren't
waiting for a replacement, takes
`{"members": [{"user", "sealedSpaceKey", "sealedSpaceKeySignature", "collectionKeys": [{"collection",
"sealed", "signature"}]}]}`: a fresh box, signed as above by the signed-in owner or admin, of the
current space key for each confirmed member listed, and of the current key of any collection that
member already holds a copy of. The server checks them as it does on a confirmation (each box
1661 bytes and its signature the sealer's over this box, at the current key version, for that
member; each collection one the member holds a copy of, none twice, none waiting for replacement),
replaces those copies and their signatures in one transaction, changes no role, grant or key
version, and answers `200` with `{"resealed": n}`; `403` for anyone but an owner or admin, `409` for a
space with a chain. A client re-seals only to members it verified as for a confirmation, and only
the collection keys it holds (an owner or admin holds those of the collections it is granted), so a
collection whose key no owner or admin holds stays unsigned until its key is replaced.

What this leaves open, stated plainly: a device that has seen **no signed box of that space** yet
accepts an unsigned box on first sight, for the space key and every collection key, because nothing
yet tells it that signatures have begun. A server that serves such a device boxes of its own before
the device has accepted any signed one is not caught, until the space is re-sealed or its keys are
replaced and the device has seen the signed boxes. The mark makes such boxes visible, and re-sealing
(or a key replacement) removes the exposure; a server can't use it on a device that has already
accepted a signed box of the space.

**A sealer's key version.** The statement binds the key version of the sealer's bundle, so a client
verifies a signature against the sealer's bundle **at the version the signature names**, not only
their current one. A client that can get the sealer's earlier bundles (a history of bundles by key
version, each signed by the one before it, the newest being the one it traced) verifies a box the
sealer made before their account moved on. A client that holds only the current bundle can't: such a
box then passes only by rule 2 on a device that already accepted it, and is replaced at the next
replacement or confirmation, as with every key their account held. A box signed at a version the
client has no bundle for is refused.

### Items of a space

An item whose owner is `space:<id>` uses the same construction with these keys:

```
wrap key   = HKDF(ikm = the collection's key, salt = absent, info = "kemlock/v1/item-wrap", L = 32)
wrap aad   = "kemlock/v1/item-key" ‖ item id (16) ‖ owner (17, the space) ‖ u32be(key version)
item_key   = AES-256-GCM(wrap key, nonce, item key, wrap aad)
```

- The item key is wrapped under the `item-wrap` child of the key of the **collection** the item is in,
  not of the space key, so only a member granted that collection can open it. The member's own user
  key is not involved.
- The `key version` in the wrap aad, and the `keyVersion` the item carries on the wire, are the
  version of the **collection's** key (the space key's version doesn't enter). A client seals under
  the newest version it holds of that collection, and opens with the version `keyVersion` says.
  The ciphertext's own `aad` is the item aad above, with the owner `space:<id>`.
- A space item on the wire names its collection in `collectionId` (required when writing one, absent
  for an item of a vault), and the key that opens it is that collection's, at `keyVersion`.
- The rules that use `keyVersion` (I2, "What the server checks", and "Items" under "What a client
  checks") are about this collection key version.

## Item bodies

The item JSON sealed in `ciphertext` is a body whose members depend on the kind. The Kemlock app
writes most of them (`kemlock-core`, one JSON object for each entry), and the web vault writes the
same keys. The members below are the **additions** of Kemlock Server's web vault. They follow these
rules, so the Kemlock app and every older client keep working:

- Every member here is **optional**. A body that has none of them is exactly the body an earlier
  version wrote: an item the web vault doesn't edit is never rewritten, and one it edits gains a
  member only when the person used the feature.
- A client **ignores a member it doesn't know** and writes it back as it found it. `kemlock-core`
  keeps the keys it doesn't read (`extra`), and the server never sees a body at all.
- A member that is empty is **left out**, not written as `[]`, `""` or `null`.

### `links`

Items linked to this one, as a list of `{ "id": "<item uuid>" }` sorted by `id` (lower-case
hyphenated UUIDs, compared as text, each once, never the item's own id). An entry may carry other
keys, which a client keeps, and an entry a client can't read stays where it is, after the others.

A link is **two-way**: A links B when both bodies name each other. Linking writes both items and
unlinking removes both ends, so a client that finds one end only (a write that failed halfway)
shows the link and may mend it. A link may join an item of the person's own vault to an item of a
space; the person needs write access to both. A code that the importer made from a login's TOTP
carries `linkedLoginId` (the login's item id); a client reads it as a link on both items (the login
shows the code), removes it when the person unlinks them from either side, and never copies it
into `links`.

### `fields`: custom fields

Any kind but `passkey` and `file` may hold custom fields, as a list of
`{ "name", "value", "kind", "adminField"? }`:

| `kind` | value |
| --- | --- |
| `text` | any text |
| `hidden` | any text, shown masked |
| `boolean` | `"true"` or `"false"` (a checkbox) |
| `linked` | written by the Bitwarden importer; a client that can't edit it keeps it as it is |

`adminField` is the id of the admin's definition (`GET /kem/v1/custom-fields`) the field was made
from. Its `name` and `kind` are the admin's and are fixed; the person fills in the value. A field
with no `adminField` is the person's own. A field is never required, a field with no name is left
out, and a definition that is later changed or deleted does not change the fields already on items.
A client writes a field nobody edited back exactly as it found it (every key, in the same order), an
edited one with only its edited members changed, and every entry it can't edit (a `linked` field, one
with no name) where it was.

### Login websites: `uris`, `urls`, `websites`

A login's websites are written three ways in step, so an older client reads the one it knows:

- `uris`: a list of `{ "uri", "match"? }` where `match` is Bitwarden's rule number (absent is the
  default rule, which fills on the base domain): `0` base domain, `1` host, `2` starts with, `3`
  exact, `4` regular expression, `5` never. A regular expression is a pattern, not an address.
- `urls`: the addresses, in order, without the regular expressions (the web vault's own key, always
  written, `[]` for none).
- `websites`: the hosts the websites fill on, each once, without the regular expressions and the
  Never rule (the key the Kemlock app reads on a login and on a code).

A login written before `uris` has `urls` alone, and every address in it is on the default rule.

### MFA code and backup codes

- `name` (optional): what the item is called; without it the item is named by its issuer and
  account (`otp`) or its `serviceName` (`backup-codes`).
- `websites` (optional): the hosts a code is used on, as on a login. A code linked to an item that has
  websites shows that item's websites and doesn't write its own; unlinked, it writes the hosts
  typed. `backup-codes` have no `websites` in `kemlock-core`, so there it is a member that app keeps.

### `file`: a File item

A File item is an item of kind `file`:

```
{ "name", "notes"?, "favorite"?, "file": { "id", "name", "size", "type"?, "key", "addedAt",
  "sha256"?, "kemlockFile"? }, "links"?, "updatedAt" }
```

`file` is one attachment entry (below). The item holds no `fields` and no `attachments`. An app that
doesn't know the kind lists it as an item of an unknown kind and keeps its body.

### Attachments

A file is stored as a `KMA1` file (see "Files" under "Sends") under **its own random 256-bit key**,
which the body holds, so the server holds only ciphertext. The body names it the way the Kemlock
app names an attachment (`kemlock-core` `NoteAttachment`):

| member | meaning |
| --- | --- |
| `id` | 16 random bytes, base64url |
| `name` | the file's name |
| `size` | its size in bytes before encryption |
| `type` | its media type, when the picker knew it |
| `key` | the file's own AES-256 key, standard base64 |
| `addedAt` | epoch milliseconds |
| `sha256` | the SHA-256 of the bytes before encryption, 64 lower-case hex digits (written by the web vault; the duplicate finder reads it, see "Duplicate tags") |
| `kemlockFile` | the id of the file on the server, from `POST /kem/v1/items/{id}/files` |

A secure note (`note`) holds any number of them, in `attachments`, up to 100; no other kind has
attachments. A File item holds one, in `file`. A client writes an entry it didn't change back
exactly as it found it (a missing member stays missing, no value is filled in, no key moves), and an
entry in `attachments` that it can't read stays where it is.

The server takes a file only for an item that **exists**, and a body never names a file the server
lacks. So a client saves the item first, without the files just chosen; asks for each upload with
the exact length of the `KMA1` file; sends the bytes (`PUT /kem/v1/items/{id}/files/{fileId}`,
always to the server's own route, even where the server also offers a pre-signed address); and
saves the item again with `kemlockFile` and `sha256` on each entry. A try that fails after the item
was saved goes on from that item, and does not send a file that the body already names (matched by
the attachment `id`) again. It deletes from the server the files a person removed last, once no
body names them. Files count against the person's attachment
quota, and the server refuses a file over its size limit.

The server keeps a file under one item's id, so a client that makes a new item from an old one (a
copy of a note, a move to another owner, a merge of notes) sends each file again under the new item.
It reads the sealed bytes (`GET /kem/v1/items/{id}/files/{fileId}`) and sends them as they are: the
chunks of a `KMA1` file are not bound to the item, so they open with the same key, and nothing is
decrypted. The new entry keeps `id`, `name`, `size`, `type`, `key`, `addedAt` and `sha256`, and
names the file the server made for it in `kemlockFile`. As for any upload, the new item is saved
first without the files, and a body never names a file the server lacks. A copy makes the new
item's name the original's, unchanged, and leaves behind what belongs to the original alone: its
`id`, `links`, `linkedLoginId`, `passkeys` and `passwordHistory`, and its dates.

### Contact

A contact is a person, with an optional OpenPGP public key:

```
{ "name", "company"?, "email"?, "phone"?, "address"?, "public"?, "source", "note"? }
```

`company`, `email`, `phone` and `address` (free text, with line breaks) are additions. `public` is
the binary transferable public key in base64, as the Kemlock app writes it; a contact with no key
has no `public` and `source` is `manual`. An app that expects a key reads `public` as empty for such
a contact.

### Card, identity, SSH key, PGP key and certificate

These keep the members `kemlock-core` writes (`PaymentCard`, `Identity`, `VaultKey`) and gain
only `links` and `fields`, above. The web vault no longer asks for a card's brand. It writes `brand` from the
number (Visa, Mastercard, American Express, Discover, Diners Club, JCB, UnionPay, Maestro) only when
the number changed or the card had no brand; otherwise `brand` stays as stored, as it does when the
number names no brand.

## Space, collection and group names

The names of a space, of its collections and of its groups are encrypted under the space key, so
the server stores them as ciphertext. Each name is a `kem1` envelope under a child of the space
key, so no new construction is added:

```
name key   = HKDF(ikm = space key, salt = absent, info = "kemlock/v1/space-name", L = 32)
ciphertext = AES-256-GCM(name key, nonce, name (UTF-8), aad)       nonce(12) ‖ ciphertext ‖ tag(16)
aad        = "kemlock/v1/item" ‖ id (16) ‖ u64be(space key version) ‖ lp(kind) ‖ owner (17)
```

- `id` is the object's own id: the space's id for the space's own name, the collection's id for a
  collection's, the group's id for a group's.
- `kind` is `"space-name"`, `"collection-name"` or `"group-name"`.
- `owner` is the space: `0x02 ‖ space id`, `space:<uuid>` on the wire.
- The revision slot of the `kem1` aad holds the **space key version** the name is sealed under, as
  a `u64be`. A name opens only under the space, id, kind and key version it was sealed with. A
  rename under the same key version is a fresh nonce, not a new key.
- The name key is used as the envelope's item key directly: there is no item-key wrap. The
  plaintext is the name's UTF-8 text itself, not a JSON string.
- A sealed name is at most 4096 bytes, so a name is at most 4068 bytes of UTF-8. The server checks
  that length and the 28-byte minimum, and nothing else: it can't open a name.

`space-names.json` in test-vectors pins names sealed under a fixed space key.

## Wire forms of signed structures

The bundle, the manifest and every other signed structure travel as their exact bytes,
base64url-encoded, never re-encoded as JSON, so a signature is always checked over the bytes that
were signed. The signature is a sibling field, never inside the signed bytes. Field names are set
per route in the server's OpenAPI spec (`/kem/v1/openapi.json`); for registration they are
`publicBundle` and `bundleSignature`.

## Legacy ids

The server keys items and spaces by UUID, but the Kemlock app holds older ids it can't change,
because sync pairs copies of an entry across WebDAV, Vaultwarden and the server by them: 0.1.0
entries such as `acc-1`, 16-hex entry ids such as `3f2c9a71e4b0d856`, and space ids of 1 to 64
characters of `[A-Za-z0-9_-]`. A client maps any id that isn't a hyphenated lower-case UUID to a
deterministic UUIDv8 (RFC 9562 §5.8), so every client makes the same one:

```
space uuid = uuidv8(SHA-256("kemlock/v1/legacy-id" ‖ lp("space") ‖ lp(old space id)))
item uuid  = uuidv8(SHA-256("kemlock/v1/legacy-id" ‖ lp("item") ‖ owner (17) ‖ lp(old item id)))
```

`uuidv8(h)` takes `h[0..16]`, sets the version nibble (`b[6] = b[6] & 0x0f | 0x80`) and the
variant bits (`b[8] = b[8] & 0x3f | 0x80`). Old ids are their UTF-8 bytes, exactly as stored. The
item's owner is part of its input, because two people's 0.1.0 vaults both hold an `acc-1`; a space
owner uses its mapped space uuid. The original id stays inside the item's JSON, so a client still
pairs copies by it. A client never maps an id that already is a UUID.

## Signed manifest

```
manifest = "kemlock/v1/manifest" ‖ owner (17) ‖ u64be(counter) ‖ u32be(n)
           ‖ n × (item id (16) ‖ u64be(revision) ‖ SHA-256(ciphertext) (32) ‖ u8(deleted))
```

Entries are sorted by item id bytes. A tombstone's hash is 32 zero bytes. The writer signs it with
`sig1` under context `"manifest"`. The counter only goes up; a device keeps the highest it has seen. A server
refuses a write whose counter is more than 2^32 above the one it stores for that owner (`400`), so
no writer can set it near its limit and make every later write stale. A space's manifest may be
written by any confirmed member with edit on a collection ("Using the state"), so this bound is what
keeps one of them from freezing it.

### How a client uses it

- **Checking.** A client checks a manifest's signature before it relies on it: an account's own
  (`user:`) with the `sig1` key of its own keys, never a bundle the server served; a space's with the
  bundle of a signer the space vouches for ("Using the state", Manifest). It keeps, per owner, the
  manifest of the highest counter it has verified and the ids it saw deleted, with the tombstone's
  revision, for as long as the server keeps tombstones (180 days). It refuses a lower counter, another
  manifest at the same counter, or none where it has seen one, and shows the person that it did.
- **Comparing.** Against the manifest it holds, an item served at a lower revision than its entry is
  *rolled back*; a live entry whose item is not served at all, not even as a tombstone, is *missing*
  (a member of a space is sent every envelope of it, so this holds there too); an id seen deleted that
  is served live at or below its tombstone's revision, or live where the manifest lists it deleted, is
  *resurrected*; a tombstone the client did not write for an entry the manifest lists live is
  *deleted* (another device may have deleted it, or the server is hiding it, and nothing tells
  them apart), unless the tombstone's write signature verifies ("Signed item writes"): then it is
  a deletion by that writer and is accepted; a revision more than 2^32 above the entry's is *implausible*. Each is shown to the
  person as a warning. An item newer than its entry, or not listed, was written by a device that
  has not signed a manifest since (an app that writes none, for one), and is accepted.
- **Writing.** After its own writes, and only then, a client signs the manifest it last accepted
  with items it was served taken in, at a counter one above the highest it knows (above the server's
  `currentCounter` when it answers 409, unless that is 2^32 above its own), and `PUT`s it. It takes in
  only live items whose envelope opened under its keys (the revision is sealed into the envelope, so
  one the server made up cannot open) and tombstones it wrote itself, at a revision above the
  entry's and not 2^32 above it. It never takes in an item served at a lower revision, never drops
  an entry for an item the server did not serve, never makes a deleted entry live, and takes in
  nothing for an id it flagged or saw deleted, so signing never makes a rollback, a hidden item
  or a resurrection permanent. A tombstone that is neither served nor remembered as seen is dropped,
  so the manifest does not outgrow the server's size limit.

## Signed item writes

A federation change record is signed by the server that accepted the write ("Change records and
origin signatures" in `docs/federation.md`), so on its own it proves nothing about *who* wrote the
item. A replica in a vault's set could sign tombstones for every item, re-sign an old ciphertext it
holds as a new revision (the `kem1` aad binds the revision, but the replica sends the old envelope
again under its own old revision number, and a client sees "newer than the manifest"), or write
without limit. So every `kem1` write is also signed by the **writing account**, with a `sig1` key
only that account's devices hold. A server can pass such a signature on, but can neither make nor
alter one.

### The signature

```
statement = "kemlock/v1/item-write" ‖ owner (17) ‖ item id (16) ‖ lp(kind) ‖ u64be(revision)
            ‖ u64be(replaces) ‖ u8(deleted) ‖ envelope hash (32)
            ‖ writer account id (16) ‖ u32be(writer key version)
            ‖ u8(0)                          for an item of a vault
              or u8(1) ‖ collection id (16)  for an item of a space
signature = sig1 signature of the writer's own key, context "item-write", over the statement
```

- `owner` is the 17-byte owner of the item (a vault or a space), `kind` is the item's kind in
  ASCII, and `revision` is the revision written. `replaces` is the revision the write replaces:
  `revision - 1`, so `0` for a new item. A verifier takes `replaces` from the revision and refuses
  a statement whose `replaces` isn't that; it is in the signed bytes so a later format can lift the
  rule without moving the signature's meaning.
- `deleted` is `1` for a tombstone and `0` for a live revision.
- `envelope hash` is `SHA-256(u32be(key version) ‖ lp(ciphertext) ‖ lp(item key))` of the
  envelope as written ("`kem1`: the item envelope": `keyVersion` is the collection's for a space
  item), and 32 zero bytes for a tombstone, as in the manifest. It binds the wrapped item key and
  the key version as well as the ciphertext, so a replica can't pair a signed ciphertext with
  another key.
- `writer account id` and `writer key version` name the account and the bundle version whose
  `sig1` key made the signature.
- `collection` is the collection the item is written into, for an item of a space, and nothing for an
  item of a vault: the statement has the flag byte `0` there. A statement of a space's item without
  a collection, or of a vault's with one, is not a statement. The collection is the one `PUT`
  names (`collectionId`), so a replica can't move a signed item into another collection, and the
  writer's right to edit it can be checked by whoever holds the record.

The statement is `21 + 17 + 16 + (4 + len(kind)) + 8 + 8 + 1 + 32 + 16 + 4 + 1` bytes, and 16 more for
an item of a space; the signature
is 3373 bytes. `kemlock-crypto`'s `item_write` module builds it, and `test-vectors/item-write.json`
pins the bytes, the envelope hashes, the signatures and the statements a signature must not cover.

What the signature does not cover: the server's change id, HLC time and lineage (the origin server's
signature covers those), and `bw` items, which have no `kem1` envelope.

### Who may write

- **A vault** (`user:`): the writer is the owner's own account.
- **A space** (`space:`): the writer is a confirmed member allowed to write the item's collection.
  For a chained space that is the chain's verified state ("Using the state"): confirmed, with
  `edit` on the collection, and the writer's bundle is the one the chain records for it. For an
  unchained space it is the server's confirmed member list and the member's confirmed bundle
  ("Member confirmation"). A deletion needs the same edit access as any write.

### Where it travels

- **Client to server.** `PUT /kem/v1/items/{id}`, `POST /kem/v1/items:batch` and the writes of a
  key replacement take three new optional members on the item: `writer` (the writing account's id),
  `writerKeyVersion` and `writeSignature` (base64url). All three or none; `writer` must be the
  signed-in account. The items a key replacement writes again (the `writes` of the chain append
  route and of `POST /kem/v1/spaces/{id}/key-replacement`) and those a reseal writes through the
  batch route are writes like any other: signed by the account that makes them, with the item's
  collection bound, and checked the same way. A signed-only space refuses them unsigned on the chain
  append route and the batch route; the route that replaces keys without a chain still accepts an
  unsigned re-write from an owner or an admin ("Accepting records").
- **Stored** with the item's change, as one value `writer (16) ‖ u32be(key version) ‖ signature
  (3373)`, 3393 bytes, and **served back** on sync (`GET /kem/v1/sync`, siblings included) in the
  same three members, so any device can check it.
- **Federation.** The change record carries the same 3393 bytes in field 15 ("Change records and
  origin signatures" in `docs/federation.md`). The origin's signature covers the field, so a relay
  can't strip it.

### What each party checks

**The server, at write time**, for a `kem1` write that carries a signature:

1. `writer` is the signed-in account, and `writerKeyVersion` is that account's current key version;
2. the signature verifies, over the statement the server rebuilds from the write, under the `sig1`
   key of the account's registered bundle (the bundle it checked at registration);
3. the usual item rules (`If-Match`, `revision = stored + 1`, authority over the owner or the
   collection) already make `replaces` the stored revision;
4. the owner isn't **signed-only** (below) unless the write is signed.

A write that fails 1 or 2 is `422` `invalid-signature`; an unsigned `kem1` write to a signed-only
owner is `422` `signature-required`. Nothing is stored. A `bw` write is never signed and is not
subject to this.

**A federation peer, on a record** (`apply`), for a `kem1` record:

1. if it carries a signature, the writer must be allowed for the record's owner (the owner's own
   account for a vault, a member of the space or one taken out of it, per the peer's replicated
   member list), and for a space the record names the collection (field 16) and the writer must be
   allowed to edit it (a confirmed member with edit on it, or one taken out since: what they signed
   before is theirs); a collection or member the peer doesn't know yet is left out for now, not
   refused. The
   peer must hold the writer's bundle at the signature's key version (the replicated account or
   member copy), and the signature must verify over the statement rebuilt from the record. Else the
   record is refused, as a record from a stranger is;
2. if it carries none and the owner is signed-only, it is refused;
3. a record that names the head in its lineage at no higher revision than the head's is refused
   (see "Rollback" in `docs/federation.md`);
4. a signed record does not set the flag on this peer: only the owner's own request at that server does.

**A client, on sync**, for each `kem1` revision it is served, tombstones included. It checks the
signature under the writer's bundle, taken as follows: the account's own `sig1` key for its own
vault, never a bundle the server served; for a space, the bundle of a writer the space vouches for
("Using the state"), who must be allowed to write the item's collection. The verdict is one of:

- `signed`: the signature verifies and the writer is allowed.
- `unsigned`: none came.
- `invalid`: one came and fails, or its writer isn't allowed, or `replaces` isn't `revision - 1`.
- `unknown`: it can't be checked now: the vault is locked, the writer's bundle at that key version
  isn't held, or the space doesn't vouch for the writer (a member who has left, say).

A revision at or below the revision the client already holds is never a change. Otherwise the
client takes a revision in as the item's current one when it is `signed`; it **never takes in an
`invalid` one**; and for an `unsigned` or `unknown` one it follows its own record, never what the
server says. It keeps, per owner, the highest revision of each item it has seen with a valid
signature (the **floor**), sealed in its local store so a reload or a fresh full sync still has it.
It takes in no `unsigned` or `unknown` revision above an item's floor, tombstones included, and
once it has seen the owner signed it takes in none of an item it holds at all, and it shows the
refusal to the person, who still has the revision they held. An item it never saw signed, and an
item on a client that has never seen the owner signed, is taken in as it always was. So a server
can't turn signing off by leaving it out for what the client has seen, which is why the signed
manifest stays: it lists revisions the owner's devices signed, for the rest.

The manifest keeper uses the verdict for deletions ("How a client uses it"): a tombstone whose
signature verifies, by the account itself or by a member allowed to write the collection, is a
deletion by that writer, not a "deleted by another device or the server". It is not flagged, and the
next manifest may list the item as deleted.

### The signed-only flag

Bitwarden-API writes, an older Kemlock client and the import tools can't sign. So the server keeps,
per owner, a flag **signed-only**:

- it is set only when the owner asks: `PUT /kem/v1/owners/{owner}/signed-writes` (`204`), by the
  account for its own vault, or by an owner or admin of a space for that space. A signed write does
  not set it, because the Kemlock app doesn't sign yet and one device that does must not lock out
  the others. The same people clear it with `DELETE` on the same path, which asks for the password
  again (the OPAQUE messages of a fresh login, and a fresh proof beside them when a second step is
  on), as erasing the account does, because clearing it lets a stolen session write what the
  account's keys never signed. Both are logged. Erasing the owner clears it too;
- once set, an unsigned `kem1` write or record for that owner is refused by this server and by
  every federation peer that holds the flag. The home publishes it as a home record of kind
  `signed-writes` (`docs/federation.md`, "Writer signatures"), signed like every home record, so the
  replicas hold it too, and drop it when the owner clears it at the home. Ask at the home: a flag
  set at a replica holds there only, until the home's record next says otherwise.

**What stays unprotected.** `bw` items (a Bitwarden-format cipher has no `kem1` envelope), so
Bitwarden apps' writes are accepted whatever the flag says, and so can be rolled back, deleted and
re-signed by a malicious replica. A vault or space that no signing client has written is not
signed-only, so a replica can still delete or roll back its items. And signing does not stop a
replica from **withholding** records, or from replaying an old signed revision *to a client that
never saw a later one*; the manifest and "Sync cursor" are what notice those. A signer who has lost
control of the account's keys can still write. For a space, a federation peer checks that the
writer may edit the collection the record names, from the member list and grants it holds; a
member taken out since counts for what they signed before, since the grants then are not known.

### Key versions

A write names the key version of the bundle that signed it (`writerKeyVersion`), and is checked
under **that** version's bundle. An account that replaces its keys (a new bundle at the next key
version) therefore keeps every bundle it had, and what it signed before stays verifiable.

- **The server** keeps every bundle of an account by key version: written wherever the account's
  bundle is written, and whichever path replaces it keeps the one it replaces first, so a key
  replacement can't lose the version before it. It accepts a **new** write only under the
  account's **current** key version, so a replaced key can't sign again.
- **A rotation of the root key** writes every item again at the new key version, so each is signed by
  the new key at that version: the client signs the statement of each re-encrypted item when it
  moves it, and the install keeps the signature with the item ("Rotating the root key", staging).
  Without that, the items a rotation writes would be unsigned and refused by a vault that takes
  signed writes only, and by a client that holds an item at a floor.
- **Reading one.** `GET /kem/v1/accounts/{id}/bundles/{version}` answers
  `{keyVersion, publicBundle, bundleSignature}` (base64url) to the account itself and to a
  confirmed member of a space the account is a confirmed member of. An unknown account, a version it
  never had and a caller who may not read it are the same `404`.
- **Federation.** A `member-account` record carries the account's past bundles (payload key 14, in
  ascending key version, at most 64), each with the time the account replaced it (`superseded
  at`, Unix seconds). A receiver keeps the record only when each past bundle is the
  account's own, at the version it says, below the current one, and carries a valid signature of
  its own key, as the current bundle must. A peer then checks a record's writer signature against
  the bundle of the key version the signature names, and refuses it when it holds none.
  **A replaced key signs nothing made after it was replaced.** A peer refuses a record signed under
  a past version when the change was made (its clock, the origin's) no earlier than five minutes
  before the time the account replaced that version: a stolen old key can't write new changes
  once the account has moved on, whatever the signature says. The server does not need the rule
  at write time, which already takes only the current version. A client does not apply it: it
  has no trustworthy time for the replacement, and leans on the floor and on the server's check.
- **A client** checks at the writer's current version as before. At an older version it takes a
  bundle from the server's history only when all of these hold: it parses as that account's bundle
  at that version; it carries a valid signature of its own key; and its fingerprint is the one the
  client **pinned** while that bundle was the account's current one: its own keys vouched for the
  account's own bundle, and the verified space chain ("Using the state") for a member's. The pins
  are kept sealed in the browser's local store, one per version, never replaced.
  **A signer that is only the server's word** vouches nothing: a client with no verified chain for a
  space, and no way to trace a member's keys to a confirmation it can follow, has only the server's
  member list, and pins nothing from it, so a member's write under a key version they have since
  replaced has no verdict there. The web vault reads a space's verified chain, or traces the keys of
  a member of an unchained space to a confirmation it can follow, and pins what those vouch for.
  A version the client never saw vouched has no verdict (`unknown`), and so does one above the
  writer's current version, because a bundle the server serves for an old version is otherwise a
  bundle the server can make up. A client that first sees an account after it replaced its keys
  therefore cannot vouch for writes signed under the keys before.

### Limits that go with it

A federation server also bounds what one origin can write: a rate and a size per origin
("Per-origin quotas" in `docs/federation.md`).

## Space chain

Every change to who is in a space, their roles, the collections, groups and grants, the key
versions and the seals, the policies, the recovery key and the space's home epoch is a **record**
of the space's chain. The member who makes a record signs it with their own `sig1` key, and each
record holds the labelled hash of the record before it. The server stores the chain and serves it,
but it holds no member's signing key, so it can't make a record. Every member's client verifies the
whole chain from the creator's self-signed first record, and takes members, bundles, roles, grants,
key versions, seals and policies only from the state the chain gives, never from the server's
lists.

What the chain is for. A hostile server, even one that stores and serves the chain, can't:

- add a key, an Owner, an Admin or a member: only a signer the chain allows makes a record;
- widen anyone's access: every record is checked against the authority the chain already gives its
  signer, and no signer may widen their own;
- hand a member a key the chain didn't commit to: every seal's hash is in the chain;
- roll back keys, members or policies, or fork the chain, unnoticed: a device keeps the links of
  every record it accepted, and refuses a chain that ends earlier or differs.

### Record

A record is a JSON object with exactly these nine members:

| Member | JSON type | Value |
| --- | --- | --- |
| `v` | integer | `1`, the chain format version. Any other value is malformed. |
| `space` | string | The space's UUID. For a WebDAV space moved to the server, the legacy-id UUID ("Legacy ids"). |
| `seq` | integer | `0` for the first record, then the previous record's `seq` plus one. At most 65,535 ("Limits"). |
| `prev` | string | Base64url of 32 bytes: the link of the previous record, or 32 zero bytes when `seq` is `0` ("Hash link"). |
| `epoch` | integer | The space's home epoch, from `1` to `2^32 - 1`. `1` in the first record; see "Epochs". |
| `at` | integer | When the record was made, in Unix seconds, from `0` to `2^53 - 1`. For display only. |
| `by` | string | The signer's account id, a UUID. |
| `kind` | string | One of the kind names in "Kinds". |
| `body` | object | What the kind sets, with exactly the members its section lists. |

#### Encoding

A record is written in a strict subset of JSON, so it has exactly one spelling. A reader refuses
as **malformed** anything outside it:

- **Values.** Objects, arrays, strings, integers, `true` and `false`. `null` is never a value: an
  optional member is absent, and there is no other way to say "none".
- **Integers** are from `0` to `2^53 - 1` (`9007199254740991`), written as decimal digits with no
  leading zero. A `-`, a `.`, an `e` or `E`, or a larger value is malformed, so `-0`, `1.0`, `1e0`
  and `9007199254740992` are refused. A member may narrow the range further (key versions are
  `u32`).
- **Strings** hold only the characters `A-Z a-z 0-9 - _ :`, between `"` and `"`, with no escape.
  Every string this format has is a UUID, base64url, a name from a closed list or a `prefix:uuid`
  form, so no string ever needs one. A `\` anywhere in a string is malformed. That refuses every
  escape, a lone surrogate (`\ud800`) among them, and all non-ASCII text.
- **Objects.** Member names are ASCII letters. Each appears once, in byte order (which is RFC 8785
  order for ASCII names), with exactly the members the record or its kind lists. A name given twice,
  a missing member or an unknown one is malformed.
- **Arrays** in this format are sets. Each is written in strictly ascending byte order of the sort
  key its kind names, so an element given twice, or two elements out of order, are malformed. That
  is the only rule for duplicates: there is no "keep the last" and no "collapse".
- No whitespace, no byte-order mark, nothing after the closing `}`. Objects nest at most 6 deep.

The record's **bytes**, which are signed and hashed, are its RFC 8785 (JCS) serialisation in UTF-8.
For this subset that serialisation is exactly the text described above. So the top-level members
always come in this order:

```
{"at":…,"body":{…},"by":"…","epoch":…,"kind":"…","prev":"…","seq":…,"space":"…","v":1}
```

A reader accepts only canonical bytes. It may parse and serialise again and compare byte for byte,
or check the rules above as it reads; both must refuse the same inputs. A JSON library that keeps
the last of two equal member names, or reads `1.0` as `1`, still refuses them by that comparison.

UUIDs match `^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`, and the version and
variant bits aren't checked. Inside binary inputs a UUID is its 16 raw bytes, and byte order of the
hyphenated text is byte order of the raw bytes. Binary values are base64url without padding: a
decoder refuses `=`, `+`, `/`, a length ≡ 1 (mod 4), and text that doesn't encode again to itself.

#### Signature

```
m'        = "kemlock/v1/sig1" ‖ lp("space-chain") ‖ lp(record bytes)
signature = sig1 signature of m' with the signer's private key            (3373 bytes)
```

The context `"space-chain"` joins the `sig1` contexts beside `"bundle"`, `"manifest"` and
`"confirm"`, so a signature made under one of them never verifies as a record, nor a record's
signature under them. The prefix of `m'` is `6b656d6c6f636b2f76312f73696731` `0000000b`
`73706163652d636861696e`.

The key that verifies a record is the `sig1` key of the bundle **the chain records** for `by` in the
state just before the record ("Verification"), not the server's newest bundle for the account. The
first record is verified with the bundle it carries.

A `rekey` record is signed twice over the same `m'`: the `signature` by the signer's recorded key,
and the `cosignature` by the key of the bundle the record installs.

#### Wire form

A signed record travels as its exact bytes, as "Wire forms of signed structures" says:

```json
{"entry": "<base64url of the record bytes>", "signature": "<base64url of 3373 bytes>"}
{"cosignature": "<base64url of 3373 bytes>", "entry": "…", "signature": "…"}      a rekey record
```

The first form has exactly those two members, and the second exactly those three, used for `rekey`
and only for it. A client refuses an unknown member, a missing one, a `cosignature` on any other
kind, and a signature that isn't 3373 bytes. A chain is a JSON array of these objects in ascending
`seq`.

### Hash link

```
link(record) = SHA-256("kemlock/v1/space-chain/link" ‖ record bytes)       32 bytes
prev(0)      = 32 zero bytes          "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
prev(n)      = link(record n - 1)     for n ≥ 1
```

The link covers the record bytes only, not the signatures, so two valid signatures of one record
give the same link. The **head** of a chain is `(seq, link)` of its last record.

**The anchor.** For each space, a device keeps, sealed in its vault's encrypted store, the
**anchor**: the `seq` and `epoch` of the last record it accepted, and the link of every record it
accepted, from `seq` 0 to that one (32 bytes each, at most 2 MiB). The anchor never goes back,
except by a fence ("Epochs"). A device that lost its anchor can't rebuild it from the server: it
starts again from "First contact".

### Values

| Name | JSON form | Rule |
| --- | --- | --- |
| uuid, account id | string | As in "Encoding". |
| hash | string, base64url | Exactly 32 bytes. |
| bundle | string, base64url | The exact bytes of a public-key bundle, 3621 bytes ("Public-key bundle and fingerprint"). |
| signature | string, base64url | Exactly 3373 bytes. |
| statement | string, base64url | A member confirmation statement, exactly 134 bytes ("Member confirmation"). |
| kx1 public key | string, base64url | Exactly 1600 bytes. |
| key version | integer | From `1` to `2^32 - 1`. |
| count | integer | From `1` to `10000`. |
| role | string | `owner`, `admin`, `custom` or `member`. |
| custom permission | string | `create-collections`, `manage-groups` or `manage-users`. |
| collection permission | string | `view`, `view-hide-passwords`, `edit`, `edit-hide-passwords` or `manage`. |
| grantee | string | `user:<uuid>` or `group:<uuid>`. |
| key ref | string | `space` (the space key) or `collection:<uuid>` (that collection's key). |
| name target | string | `space`, `collection:<uuid>` or `group:<uuid>`. |

Each collection permission gives three rights:

| Permission | edit | hidePasswords | manage |
| --- | --- | --- | --- |
| `view` | no | no | no |
| `view-hide-passwords` | no | yes | no |
| `edit` | yes | no | no |
| `edit-hide-passwords` | yes | yes | no |
| `manage` | yes | no | yes |

In binary inputs a key ref is `u8(1)` for the space key, or `u8(2) ‖ collection id (16)`.

### State

Verification turns a chain into a **state**. The state before the first record is empty.

| Part | Holds |
| --- | --- |
| head, epoch | `(seq, link)` of the last record, and its epoch. |
| home | The server id and promotion hash of the last `fence`, or none. |
| members | By account id: role, custom permissions (a set), status (`invited`, `confirmed` or `removed`), who invited them, and once confirmed their bundle, its self-signature, and either their confirmation (statement, signature, confirmer, `seq`) or the `seq` of their last `rekey`. |
| space | The space key version and whether it is **marked**; the space name's hash and name version. |
| collections | By id: parent or none, name hash and name version, key version, marked or not. |
| groups | By id: name hash and name version, and the set of member ids. |
| grants | By (collection, grantee): a collection permission. |
| key checks | By (key ref, key version): the 32-byte check of that key ("Seal commitments"). |
| seals | By (key ref, key version, account id): the bundle key version the seal is to, and the `seq` of the record that committed it. |
| commitments | By (key ref, key version, `seq`): the count and digest that record committed. |
| retired ids | Ids of deleted collections and groups. They can't be used again. |
| policies | The policy set ("`policies`"), every setting off at first. |
| recovery key | 1600 bytes, or none. |

Terms, all taken in a given state:

- **In the space**: a member whose status is `invited` or `confirmed`.
- **Access** of member `m` to collection `c` combines every grant on `c` whose grantee is `user:m`,
  or `group:g` where group `g` holds `m`: `edit` and `manage` are true if any grant gives them,
  `hidePasswords` only if every grant hides passwords. With no such grant `m` has no access. Status
  isn't looked at, and nesting gives nothing: a grant on a parent says nothing about its children.
- Access **widens** from `a` to `b` when `b` gives a right `a` doesn't (`edit` or `manage`), drops
  `hidePasswords`, or `a` is none and `b` isn't.
- **Entitled** to the space key: every confirmed member. Entitled to the key of collection `c`: every
  confirmed member with access to `c`.
- `m` **holds** key `k` when the seals have an entry for (`k`, `k`'s current version, `m`), to any
  bundle version. `m` is **covered** for `k` when that entry is to `m`'s current bundle version.
- **Awaiting**(`k`): the members entitled to `k` who aren't covered for it.
- **Lost**(`k`) across a record, from state `S` to `S'`, for a key at the same version in both: the
  members who, in `S`, were entitled to `k` and held it, and who in `S'` aren't entitled to it. A key that is **marked** must be replaced
  before it is used again ("Removal and replacement").
- **Rank** of a role: `owner` > `admin` > `custom` > `member`. One role and permission set is
  **narrower** than another when its rank is lower, or both are `custom` and its permissions are a
  strict subset.

### Commitments

The chain never holds a sealed key or a sealed name: they are large, and the server already stores
them. It holds their hashes, and the server serves the bytes. A client uses a seal or a name only
when its hash is the one the chain committed.

#### Seal commitments

A record that publishes seals carries, for each key it seals, one commitment:

```
seal hash = SHA-256(box)                         box: the 1661-byte sealed box of the key
digest    = SHA-256("kemlock/v1/space-chain/seals" ‖ space id (16) ‖ key ref ‖ u32be(key version)
                    ‖ u32be(n) ‖ n × (account id (16) ‖ u32be(bundle key version) ‖ seal hash (32)))
check     = HKDF(ikm = key (32), salt = absent,
                 info = "kemlock/v1/space-chain/key-check" ‖ space id (16) ‖ key ref ‖ u32be(key version),
                 L = 32)
```

- The **recipients** of a commitment are never listed in it. Each kind's rules name them exactly, as
  a set the verifier derives from the state, and the `n` entries of the digest are those
  recipients in ascending order of account id bytes, each with the bundle key version the chain
  records for them and the hash of their box. `count` must equal `n`.
- The boxes are the existing ones: context `"space-key"` with `aad = space id (16) ‖ u32be(space key
  version) ‖ recipient account id (16)`, or context `"collection-key"` with `aad = space id (16) ‖
  collection id (16) ‖ u32be(collection key version) ‖ recipient account id (16)`, sealed to the `kx1`
  key of the recipient's chain-recorded bundle.
- The **check** is made once, by the member who makes a key version, and lets every recipient see
  that the key they opened is that version's key and not another a holder sealed them.

In JSON a commitment is an object, sorted by `key` in arrays:

```json
{"check": hash, "count": count, "digest": hash, "key": key ref, "version": key version}   makes a key version
{"count": count, "digest": hash, "key": key ref, "version": key version}                  shares an existing one
```

#### Name commitments

A name is the `kem1` envelope crypto.md already fixes for names: under
`HKDF(ikm = space key, salt = absent, info = "kemlock/v1/space-name", L = 32)`, with id = the space's,
collection's or group's id, revision = the space key version, kind `"space-name"`,
`"collection-name"` or `"group-name"`, and owner `space:<space id>`. The chain commits to
`SHA-256(sealed name)` as a `nameHash`, and records as the **name version** the space key version
current when the record is accepted. A name is sealed under exactly that version.

The `keys` record that replaces the space key commits to every name again, packed:

```
names = n × (u8(type) ‖ id (16) ‖ SHA-256(sealed name) (32))      type 1 space, 2 collection, 3 group
```

in ascending order of `type ‖ id`, with exactly one entry for the space and for every collection and
group in the state.

### Kinds

There are 21 kinds:

| Kind | Does |
| --- | --- |
| `create` | Makes the space: its maker as Owner, its first collection and their keys. |
| `invite` | Invites an account with a role, and grants it collections. |
| `confirm` | Confirms an invited member, or a confirmed member's newer bundle, after a fingerprint comparison. |
| `rekey` | A member replaces their own bundle, signed by the old key and the new. |
| `role` | Changes a member's role or custom permissions, making an Owner included. |
| `remove` | Removes a member, or a member leaves. |
| `grant`, `ungrant` | Sets or takes away a grant. |
| `collection`, `move`, `collection-delete` | Makes, moves or deletes a collection. |
| `group`, `group-members`, `group-delete` | Makes a group, changes its members, deletes it. |
| `rename` | Commits a new name for the space, a collection or a group. |
| `seal` | Shares keys a member holds with the members awaiting them. |
| `keys` | Replaces keys with new versions. |
| `policies` | Sets the space's policies. |
| `recovery-key`, `recovery-key-clear` | Sets or clears the account recovery key. |
| `fence` | Raises the epoch after the home moved. |

*Malformed* is a shape the format refuses whatever the state. *Invalid* is a record that makes no
sense in the state it meets. The authority rules of each kind are gathered in "Authority". Every
record must change the state: a record that would leave it as it was is invalid.

#### `create`

```json
"body": {"bundle": bundle, "bundleSignature": signature, "collection": {"id": uuid, "nameHash": hash},
         "member": account id, "nameHash": hash, "seals": [commitment, commitment]}
```

- Only at `seq` 0, and `seq` 0 is always a `create` (invalid). Its `epoch` is `1` (bad epoch).
- `member` equals `by` (invalid). `bundle` parses and its account id is `member` (bad bundle). The
  `bundleSignature` is the bundle's own `sig1` signature under `"bundle"`, by the key in it (bad
  bundle).
- `seals` holds exactly two commitments that make key versions: `collection:<collection.id>` and
  `space`, each at version `1`, each with the recipient set {`member`} (invalid).

State: the member is an `owner`, `confirmed`, invited by themselves, with this bundle and no
confirmation. The space key is at version `1`, the space name has this hash at name version `1`.
The collection exists at the top level with key version `1` and this name hash at name version `1`,
granted `manage` to `user:<member>`. Both key checks and both seals are recorded.

#### `invite`

```json
"body": {"custom": [custom permission…], "grants": [{"collection": uuid, "permission": collection permission}…],
         "member": account id, "role": role}
```

- `member` isn't in the space (invalid). An account that was removed may be invited again; it starts
  with nothing.
- `role` isn't `owner` (invalid): an Owner is made from a confirmed member with `role`.
- `custom` is empty unless `role` is `custom` (invalid). It may be empty for `custom`.
- `grants` is sorted by `collection`, and may be empty (malformed). Each collection exists (invalid).

State: a new member record, `invited`, with this role and these permissions, invited by `by`. Each
grant becomes the grant `user:<member>` on its collection at once. The member has access but isn't
entitled to anything until they are confirmed, so no key is sealed to them.

#### `confirm`

```json
"body": {"bundle": bundle, "bundleSignature": signature, "member": account id,
         "statement": statement, "statementSignature": signature}
```

- `member` is in the space and isn't `by` (invalid).
- `bundle` parses and its account id is `member` (bad bundle). Its `bundleSignature` verifies under
  `"bundle"` with its own key (bad bundle).
- If `member` is `confirmed`, the bundle's key version is greater than the recorded one (invalid).
- `statement` is the 134-byte confirmation over this bundle: its space id is `space`, its member id
  and key version are the bundle's, its fingerprint is `SHA-512("kemlock/v1/fingerprint" ‖ bundle)`,
  and its confirmer id is `by` (bad confirmation). The `statementSignature` verifies under
  `"confirm"` with the `sig1` key of `by`'s recorded bundle (bad confirmation).

State: the member is `confirmed` with this bundle and the confirmation `{by, statement,
statementSignature, seq}`. Their role and grants stay. The member is now entitled to the space key
and to every collection they have access to, and awaits those seals.

#### `rekey`

```json
"body": {"bundle": bundle, "bundleSignature": signature}
```

The record's `cosignature` is required.

- `bundle` parses, its account id is `by`, and its key version is greater than that of `by`'s
  recorded bundle (bad bundle, then invalid). Its `bundleSignature` verifies (bad bundle).
- The `signature` verifies with `by`'s recorded bundle, and the `cosignature` with the new bundle's
  `sig1` key (bad signature).

State: `by`'s bundle is the new one, and the `seq` of this record is kept in place of a
confirmation. Nobody compared the new fingerprint: the old key vouched for it. A client shows "<name>
replaced their keys" and offers to compare the new fingerprint. The member keeps holding their keys,
and awaits seals to the new bundle.

This is how an Owner, the only Owner included, keeps signing after replacing their key pair. The
app signs a `rekey` in every space before it lets go of the old private key.

#### `role`

```json
"body": {"custom": [custom permission…], "member": account id, "role": role}
```

- `member` is in the space (invalid).
- `custom` is empty unless `role` is `custom` (invalid).
- When `role` is `owner`, `member` is `confirmed` and `custom` is empty (invalid).
- The role or the permissions differ from the member's (invalid).

State: the member's role and custom permissions are these. Roles give no access to items: access
is by grant only.

#### `remove`

```json
"body": {"member": account id, "replace": [key ref…]}
```

- `member` is in the space (invalid).
- `replace` is exactly the key refs `k` with a non-empty Lost(`k`) across this record (invalid).

State: the member's status is `removed`, and the record keeps nothing else of them. Every grant
`user:<member>` is deleted, and the member leaves every group. Every key in `replace` is marked. So a
confirmed member's removal always marks the space key, and every collection key they held. See
"Removal and replacement".

#### `grant`

```json
"body": {"collection": uuid, "grantee": grantee, "permission": collection permission}
```

- `collection` exists. A `user:` grantee is in the space; a `group:` grantee exists (invalid).
- The grantee has no grant on the collection, or one with another permission (invalid).

State: the grantee's grant on the collection is `permission`. A member newly entitled awaits the
collection's seal.

#### `ungrant`

```json
"body": {"collection": uuid, "grantee": grantee, "replace": [key ref…]}
```

- The grantee has a grant on the collection (invalid).
- `replace` is exactly the key refs with a non-empty Lost across this record (invalid). It is
  `[]` or `["collection:<collection>"]`.

State: the grant is deleted, and the keys in `replace` are marked.

#### `collection`

```json
"body": {"collection": uuid, "grants": [{"grantee": grantee, "permission": collection permission}…],
         "nameHash": hash, "parent"?: uuid, "seals": [commitment]}
```

- `collection` neither exists nor is retired (invalid).
- `parent`, when present, exists, and the new collection's depth is at most 16: `1` plus the number of
  collections on the path from `parent` to the top, `parent` included (invalid). Absent `parent`
  means the top level.
- `grants` is sorted by `grantee`, from 1 to 1,000 (malformed), and lists `user:<by>` with any
  permission (invalid). Grantees follow the rules of `grant`.
- `seals` holds one commitment that makes version `1` of `collection:<collection>`; its recipients
  are the confirmed members with access to the new collection (invalid).

State: the collection, at key version `1`, with this parent, name hash (at the current space key
version) and grants, and its key check and seals.

#### `move`

```json
"body": {"collection": uuid, "parent"?: uuid}
```

- `collection` exists. `parent`, when present, exists, isn't `collection` and isn't below it. The
  parent changes (invalid).
- After the move, no collection is deeper than 16 (invalid).

State: the collection's parent is `parent`, or none.

#### `collection-delete`

```json
"body": {"collection": uuid}
```

- `collection` exists, and no collection has it as parent (invalid). The server also refuses it
  while the collection holds a live item.

State: the collection, its grants, its seals, key checks and commitments are gone, and its id is
retired. Nobody holds a key of it any more, so nothing is marked; a client refuses every item that
names it.

#### `group`

```json
"body": {"group": uuid, "nameHash": hash}
```

- `group` neither exists nor is retired (invalid).

State: the group, with no members, and this name hash at the current space key version.

#### `group-members`

```json
"body": {"add": [account id…], "group": uuid, "remove": [account id…], "replace": [key ref…]}
```

- `group` exists (invalid). `add` and `remove` are sorted, share no element, and hold 1 to 1,000
  ids between them (malformed).
- Each id in `add` is in the space and not in the group; each id in `remove` is in the group
  (invalid).
- `replace` is exactly the key refs with a non-empty Lost across this record (invalid).

State: the group's members change, and the keys in `replace` are marked.

#### `group-delete`

```json
"body": {"group": uuid, "replace": [key ref…]}
```

- `group` exists, and `replace` is exactly the key refs with a non-empty Lost (invalid).

State: the group and every grant to it are gone, its id is retired, and the keys in `replace` are
marked.

#### `rename`

```json
"body": {"nameHash": hash, "target": name target}
```

- `target` exists, and `nameHash` differs from its current one (invalid).

State: the target's name hash is `nameHash`, at the current space key version.

#### `seal`

```json
"body": {"seals": [commitment…]}
```

- 1 to 1,001 commitments of the form that shares a key version, sorted by `key` (malformed).
- Each `key` exists, its `version` is the key's current version, the key isn't marked, and Awaiting
  of it isn't empty. The recipients are Awaiting of that key, in the state before (invalid).

State: a seal for each recipient, to their current bundle key version, committed at this `seq`.

#### `keys`

```json
"body": {"names"?: "<base64url of the packed names>", "rotate": [commitment…]}
```

- `rotate` holds 1 to 257 commitments that make key versions, sorted by `key`, at most one of them
  `space` (malformed). Each `key` exists and each `version` is its current version plus one, at most
  `2^32 - 1` (invalid). The recipients of each are the members entitled to that key.
- `names` is present exactly when `rotate` has `space` (invalid). It is a whole number of 49-byte
  entries, sorted, with one for the space and for each collection and group of the state and no
  other (invalid).
- A key that isn't marked may be replaced too.

State: each key in `rotate` is at its new version, with its key check and its seals, and isn't
marked any more. When the space key is replaced, every name takes the hash `names` gives, at the
new name version.

#### `policies`

```json
"body": {"policies": {
  "accountRecovery": bool, "alwaysShowEmail": bool, "centralOwnership": bool,
  "disableExport": bool, "disableSend": bool, "duplicateMatching": bool,
  "masterPassword": {"enforceOnLogin": bool, "minComplexity": 0..4, "minLength": 0..128,
                     "requireLower": bool, "requireNumbers": bool, "requireSpecial": bool,
                     "requireUpper": bool},
  "noCardItems": bool, "noPinUnlock": bool, "requireSso": bool,
  "sessionTimeout": {"action": "none" | "lock" | "log-out", "minutes": 0..525600},
  "singleSpace": bool, "twoStep": bool}}
```

- Every member is present, with these types and ranges (malformed). There are no other policy
  names: a new one needs a new version of this section.
- `sessionTimeout.action` is `none` exactly when `minutes` is `0` (invalid).
- When `accountRecovery` is `true`, the state after has a recovery key (invalid).
- The set differs from the current one (invalid).

State: the policy set is this one. It maps to the server's `SpacePolicies` one to one: `0` and
`false` everywhere in `masterPassword` is `master_password: None`, a `minLength` or `minComplexity` of
`0` is `None`, `minutes: 0` is no timeout, and `log-out` is `logOut`. `accountRecovery` and
`duplicateMatching` are the plan's account recovery and duplicate-matching switches.

#### `recovery-key`, `recovery-key-clear`

```json
"body": {"key": kx1 public key}
"body": {}
```

- `recovery-key`: the ML-KEM-1024 half passes FIPS 203's encapsulation-key check, and a trial
  `kx1` encapsulation to the key succeeds, which refuses a low-order X25519 half (invalid). The key
  differs from the current one (invalid).
- `recovery-key-clear`: a recovery key is set, and `accountRecovery` is `false` (invalid).

State: the recovery key is `key`, or none.

#### `fence`

```json
"body": {"home": uuid, "promotion": hash}
```

- The record's `epoch` is the state's epoch plus one (bad epoch, see "Epochs").
- `home` is the id of the space's new home server, and `promotion` is `SHA-256` of the federation
  promotion record that moved the home to it, as its envelope's bytes.

State: the epoch rises by one, and the home is `home` with this promotion hash.

### Epochs

A record's `epoch` equals the state's epoch, or the state's epoch plus one. It is the epoch plus one
exactly when the kind is `fence`, and only an Owner signs a `fence`. Anything else is a **bad
epoch**: a lower epoch, a higher one by more than one, a `fence` that doesn't raise it, or another
kind that does. The first record's epoch is `1`. There is no other way to change the epoch.

The federation promotion record ("Home epochs, promotion and the fence" in `docs/federation.md`)
moves a vault's home and raises its epoch, but it is signed by a server. The chain doesn't trust a
server to move its epoch, so after a promotion the new home accepts no chain record until an Owner's
client has checked the promotion and signed the `fence` that names it. Records the old home took
after the promotion, under the old epoch, never become part of the new chain: a device that had
accepted them drops them when it meets the fence ("Verification", step 1).

A client that holds the promotion record for the fence's epoch, through the sync plan, checks that
its hash is `promotion` and its new home is `home`, and refuses the chain as **bad epoch** if not. A
client that doesn't hold it accepts the Owner's fence.

### Removal and replacement

Removing someone ends their access in the chain at once, and the chain says which keys they could
still use:

- A `remove` deletes the member's grants and group memberships. If they are invited again, they
  start with nothing.
- A `remove`, `ungrant`, `group-members` or `group-delete` names in `replace` every key that a member
  held and is no longer entitled to. The verifier computes that set itself and refuses a record that
  names another. Those keys are **marked**.
- A marked key is replaced by a `keys` record, which gives it a new version sealed only to the
  members entitled to it. Replacing the space key also commits every name again.
- **While the space key is marked**, a record may not confirm anyone, make a collection or a group,
  `rename` anything, `seal` any key, or give anyone access they didn't have to any collection.
- **While a collection's key is marked**, a record may not `seal` it or give anyone access they didn't
  have to that collection.

Such a record is invalid. What happens to items is in "Using the state".

### Authority

Every record but `create` is signed by a member who is `confirmed` in the state before it, with a
recorded bundle (unknown signer). Their role is the one they hold in that state, `S`, and `S'` is the
state the record gives.

Four relations, all taken in `S`, with `t` the target member and `s` the signer:

| Relation | Owner | Admin | Custom | Member |
| --- | --- | --- | --- | --- |
| **Manage**(`t`), `t ≠ s` | any member | any member who isn't an Owner | with `manage-users`: a `custom` or `member` whose permissions are all among `s`'s | nobody |
| **Assign**(role, permissions) | any role | any but `owner` | with `manage-users`: `member`, or `custom` with permissions all among `s`'s | nothing |
| **MayGrant**(`c`) | yes | yes | if `s`'s access to `c` has `manage` | if `s`'s access to `c` has `manage` |
| **GroupAdmin** | yes | yes | with `manage-groups` | no |

Four rules hold for every kind but `create`:

1. **Owners change Owners.** If the record touches an Owner, `s` is an Owner. A record touches an
   Owner `o` (an Owner in `S` or in `S'`) when it changes `o`'s role, permissions, status, bundle or
   group memberships, or `o`'s access to a collection that exists in both `S` and `S'`.
2. **Nobody widens themselves.** The record doesn't widen `s`'s own role or permissions, nor `s`'s
   access to any collection that exists in `S`. `create` is exempt; a new `collection` gives its maker
   access only to a collection that didn't exist.
3. **Access changes need MayGrant.** For each collection that exists in both `S` and `S'` on which any
   member's access differs, MayGrant(that collection) holds for `s`. The access of the member a
   `remove` removes is left out of this rule; Manage covers it.
4. **A confirmed Owner remains.** `S'` has at least one confirmed Owner. This is a kind rule, checked
   in step 5 of "Verification": a record that leaves none is invalid, whoever signed it.

On top of those, each kind:

| Kind | Who may make it |
| --- | --- |
| `create` | Only `seq` 0, by `body.member`, who becomes the Owner. |
| `invite` | Assign(`role`, `custom`). Rule 3 asks MayGrant for every collection in `grants`. |
| `confirm` | Manage(`member`). |
| `rekey` | Any confirmed member, for themselves only: the record has no target. |
| `role` | For `member = by`: only a narrower role or permission set. Otherwise Manage(`member`) and Assign(`role`, `custom`). Rule 1 makes `role: owner`, and any change to an Owner, an Owner's. |
| `remove` | For `member = by`: any confirmed member (leaving). Otherwise Manage(`member`). |
| `grant`, `ungrant` | MayGrant(`collection`). |
| `collection` | An Owner, an Admin, or a Custom member with `create-collections`. |
| `move`, `collection-delete` | MayGrant(`collection`). |
| `group` | GroupAdmin. |
| `group-members`, `group-delete` | GroupAdmin, with rule 3 asking MayGrant for every collection on which a member's access changes. |
| `rename` | `space`: an Owner or an Admin. `collection:<c>`: MayGrant(`c`). `group:<g>`: GroupAdmin. |
| `seal` | A member who holds every key it seals. |
| `keys` | `space`: an Owner or an Admin. `collection:<c>`: a member entitled to `c` who is an Owner or an Admin, or has `manage` on `c`, or any member entitled to `c` while `c` is marked. |
| `policies` | An Owner or an Admin. Changing `accountRecovery` is an Owner's only. |
| `recovery-key`, `recovery-key-clear` | An Owner. |
| `fence` | An Owner. |

Why the less obvious rows:

- A Custom member with `manage-groups` can make and name groups, but can't use a group to give access
  they couldn't give by `grant`, and can't add themselves to a group that would widen their own
  access (rules 2 and 3).
- An Admin can't lower, take away or widen an Owner's grant, even through a group (rule 1).
- Whoever makes a new key version learns the key, so a `keys` record for a collection is signed only
  by a member entitled to it. A plain member entitled to a marked collection may replace its key, so
  a collection no Owner or Admin can open never stays paused for good.
- A `seal` shares a key only with members the chain already entitles, so a holder can fulfil an
  entitlement but never make one.

### Verification

A client verifies the whole chain against its anchor, if it has one. A refusal names one of these
reasons: malformed, too large, wrong space, bad sequence, bad link, bad epoch, unknown signer, bad
signature, bad bundle, bad confirmation, invalid, not allowed, forked, rolled back. The checks run in
this order, which fixes the reason a record that breaks several rules gets. The server's error codes
follow the same order and names.

0. **Reading.** Each element of the array is a wire-form object whose `entry` is canonical record
   bytes, with a body of its kind's exact shape (malformed). Each record, and the chain, is within
   "Limits" (too large). If any element fails, the **whole chain** is refused before any record is
   applied.
1. **For each record**, in the order served, starting from the empty state `S`:
   1. *Anchor.* If the anchor has a link at this `seq` and it differs from this record's link, and no
      earlier record differed, this `seq` is the **divergence**. A divergence is allowed only at a
      `fence`; at any other kind the chain is refused as **forked**. After a divergence, the anchor
      isn't compared again.
   2. *Position.* `space` is the space being verified (wrong space). `seq` is `S`'s head `seq` plus
      one, or `0` when `S` has no head (bad sequence). `prev` is `S`'s head link, or 32 zero bytes
      (bad link). `epoch` follows "Epochs" (bad epoch). The kind is `create` exactly when `seq` is `0`
      (invalid).
   3. *Signer.* For `create`, the body's bundle parses and is `by`'s (bad bundle). Otherwise `by` is
      confirmed in `S` with a recorded bundle (unknown signer).
   4. *Signatures.* The record's `signature` with the signer's key, then a `rekey`'s `cosignature`
      with the new bundle's key (bad signature). Then a carried bundle's self-signature (bad bundle),
      then a `confirm`'s statement signature (bad confirmation). A key or signature of the wrong
      length is a bad signature.
   5. *Kind rules* of the kind's section, against `S`, which give `S'` (invalid, bad bundle or bad
      confirmation), then "Removal and replacement", rule 4 of "Authority" and the state limits of
      "Limits" (invalid).
   6. *Authority*: rules 1 to 3 of "Authority" and the kind's row (not allowed).
   7. `S := S'`, whose head is `(seq, link)` and whose epoch is the record's.
2. **After the last record.**
   - With a divergence at `seq d`: the anchor's epoch must be lower than the epoch of the `fence` at
     `d`, or the chain is refused as **forked**. The device's records from `d` to its anchor's `seq`
     are **dropped**: the app lists them for the space's Admins to redo or drop, and says so plainly
     when one of them was a `remove`.
   - Without one: if the anchor's `seq` is greater than the chain's head `seq` (an empty chain's is
     `-1`), the chain is refused as **rolled back**.

A chain refused at any step gives nothing: the client keeps its anchor, shows the space as "Can't be
checked", opens and seals no key, and syncs none of the space's items. The refusal names the record's
`seq` and the reason, for the logs. A chain that verifies gives its state, and its links become the
new anchor.

Because each record links to the one before, an equal link at a `seq` means the whole chain up to it
is the one the device accepted.

**Incremental verification.** A client may keep, sealed beside its anchor, the state at the anchor,
fetch only `?from=<anchor seq + 1>`, and apply the same steps from there. The result must be the one
a full verification gives. It verifies in full from `seq` 0 on first contact, when the kept state is
missing or unreadable, and after an update of these rules.

### First contact

Verification shows only that a chain is consistent: a server could make a whole space of its own,
with its own keys, and it would verify. What ties a chain to people is a fingerprint comparison, made
once per space and device, before the device trusts the chain.

**Who.** The device picks an **anchor person** `P`, and compares `P`'s fingerprint:

- An invitee's device: `P` is the inviter, the `by` of the `invite` that is in effect for this
  account. If the inviter is no longer a confirmed member, `P` is a confirmed Owner the person picks.
- A confirmed member's new device: `P` is the confirmer, the `by` of the record that last confirmed
  this account. A device whose own account's current key signed a `rekey` after that one (the state
  keeps the `seq` of the member's last `rekey`) needs no comparison: its own key vouches for the
  chain. Other records the account signed since don't count, because the state doesn't keep them.
- The creator's device made `create` itself and is its own anchor.

So a client's answer is one of three, never a bare "none": **no comparison** (the creator's device, or
an account whose own current key signed a `rekey`), **compare with `P`**, or **pick an Owner**. "Pick an
Owner" also covers an account the chain doesn't have, a removed member, and a confirmed member nobody
confirmed who isn't the creator; it is never read as "no comparison". Even for the first, the client
checks that the bundle the chain records for its own account is the one it holds itself: a chain that
records another one vouches for nothing, and the client treats it as the third answer.

**What is confirmed.** The fingerprint `SHA-512("kemlock/v1/fingerprint" ‖ bundle)` of `P`'s bundle
**as the verified chain records it at its head**, shown as the 12 groups of 5 digits or compared
from `P`'s QR code in constant time, against what `P`'s own app shows under Settings › Account
security. That bundle must have signed or cosigned a record at or after the `invite` (or
confirmation) that admitted this account. A match shows that `P`'s real key made that record. An
honest client signs a record only on a chain it verified and anchored, so the chain up to that record
is the one `P` accepted, and everything after it was checked against authority that chain gave.

**When.** On the accept screen, after the chain verifies and before any of these: the Accept button,
storing an anchor, opening or sealing any key, account recovery enrolment, and showing the space's
members, policies or notices as checked. For a new device of a member, before the space syncs. If the
person taps "Not now", or the digits differ, the invitation stays unanswered, the device stores
nothing, and the app says that a different fingerprint means someone else's key is in the way.

**After.** The device stores its anchor at the head it compared against, and from then on only the
fork, rollback and fence rules apply. When the chain later confirms this account, the device checks
that the `confirm` records its own bundle, byte for byte.

### Using the state

A space with no chain is not covered by any of this. Its client takes who is in it and which key
version is current from the server, and checks only what it can: that a member's bundle is theirs and
that someone it can trace to itself, or to a fingerprint its person compared, confirmed exactly those
keys, and that the member who sealed each key it opens signed it ("Signed key boxes"). A server can still hand an unchained space's members a key of its own at the next version, or
leave one out of a replacement, and nothing in the space shows it: **an unchained space trusts the
server for which key version is current, and a chained space doesn't.** That is why a client that has
ever been served a chain for a space never reads the space as unchained again, and why a space is
made as a chain wherever the client can build one.

- **Bundles.** A member's keys are the chain's bundle, never the server's. A member the server lists
  but the chain doesn't confirm, or whose server bundle differs by a byte from the chain's, gets no
  seal, and the client logs it.
- **Opening a key.** A client opens the space key and each collection key at **the chain's current
  version** only, never at the version the server names. It takes the seal the chain committed for
  (key, version, itself), and accepts the box only when:
  1. the commitment at that `seq` covers just this member and the digest recomputed from its own box
     is the committed one; or the server's seal hash list for that `seq` (`G5`) names exactly the
     recipients the chain gives, with their bundle versions, holds `SHA-256` of this box for this
     member, and gives the committed digest;
  2. the box opens with the `aad` above, under the key of the bundle version committed; and
  3. the key's check is the chain's for that version.

  Otherwise the client uses no key of that version, and shows the space's keys as "Can't be checked".
- **Sealing.** A client seals only to the members Awaiting gives, to the `kx1` key of their recorded
  bundle, and publishes the seals with a `seal`, `keys` or `collection` record. A confirmer's app
  sends a `seal` for the keys it holds right after a `confirm`; any other holder's app does the same
  when it finds a member awaiting a key it holds.
- **Names.** A client shows a name only when `SHA-256` of the sealed name the server serves is the
  chain's hash for it, and the `kem1` envelope opens at the chain's name version. Otherwise it shows
  "Name can't be checked". Names change only with the space key or a `rename`, so a removed member who
  kept an old space key reads no name committed after the replacement.
- **Items.** For a collection `c`:
  - a client writes items only under `c`'s current key version, and none while `c` or the space key
    is marked;
  - it accepts an item revision only when its `keyVersion` is `c`'s current version, and refuses one
    under an older or a newer version;
  - after it verifies a record that marks `c` or the space key, it accepts no revision in `c` newer
    than the ones it already accepted, until the `keys` record that replaces the marked key;
  - an item that names a deleted or unknown collection is refused.

  Refused revisions are held and shown, as unlisted items are. The member who replaces `c`'s key
  writes again only the items it accepted and the latest manifest lists, under the new version, and
  names every other live item as held ("What the server checks", I3). So a removed member's write
  under a key they kept is never re-wrapped into the new key.
- **Manifest.** The space manifest at `/kem/v1/manifests/space:<id>` is accepted only from a signer the
  verified chain shows as `confirmed` with `edit` on at least one collection, and its `"manifest"`
  signature is checked with that signer's chain-recorded bundle.
- **Policies and recovery** come from the chain's policy set. Account recovery enrolment seals the
  member's root key under the `"account-recovery"` context only to the chain's recovery key, only
  while `accountRecovery` is on, only after first contact, and only after the member agrees. The box's
  `aad` is `space id (16) ‖ account id (16) ‖ u64be(seq)`, where the account is the member's own
  and `seq` is that of the chain record (`recovery-key`) that set the recovery key the box is
  sealed to. A box is current only while the chain's recovery key is still the one that record
  set; after a later `recovery-key` or `recovery-key-clear` it is stale, and a client opening it
  must use the `seq` the server gives with it.
  - `PUT /kem/v1/spaces/{id}/members/me/recovery` takes `{"box": base64url, "keySeq": uint}`: the
    1693-byte box (`u8(1)` first). It is for a confirmed member and replaces any earlier box. It
    answers `204`; `409` `recovery-not-enabled` when the chain's `accountRecovery` is off, and `409`
    `stale-recovery-key` (with `current`, the chain's `keySeq`) unless `keySeq` is the `seq` of the
    record that set the chain's current recovery key.
  - `DELETE /kem/v1/spaces/{id}/members/me/recovery` withdraws it: `204`, also when there was none.
  - `GET /kem/v1/spaces/{id}/members/{user}/recovery` answers `{"box", "keySeq", "stale"}` to a
    confirmed Owner or Admin: an Owner may recover any confirmed member, an Admin any but an Owner
    (`403`). `404` when the member isn't confirmed or enrolled, or the caller isn't in the space;
    `403` to any other caller. `stale` is `true` when `keySeq` is no longer the chain's current
    recovery key record. Every confirmed member, Owners included, may enrol. A box is kept until
    withdrawn or replaced, and goes when the member leaves or is removed.

### What the server stores, serves and checks

**Storage**

- S1. The server keeps, for each space, an append-only list of signed records indexed by `seq` from
  `0`: the exact record bytes and signature bytes it accepted, and a `rekey`'s cosignature. It never
  re-encodes, rewrites, reorders or deletes a record while the space exists.
- S2. The server changes its own state of a space (members, roles, permissions, confirmations,
  collections, groups, grants, key versions, sealed keys, names, policies, the recovery key) only by
  accepting chain records, in the same transaction that appends them, so its state is always the
  derived state of its chain. Its "accepted" step of an invitation is its own and isn't in the chain;
  its revoke and remove are both `remove`, and its restore is a new `invite`.
- S3. With each record that commits seals or names, it keeps the boxes and sealed names the record
  committed, by `seq`.
- S4. A collection id and a group id belong to one space on a server. Clients choose them, so the
  server refuses a create, a record or a change that names an id another space holds (`409`
  `already-exists`, and `400` for a chain request), and never moves, replaces or deletes a row of another
  space. A client chooses a fresh random UUID for each.

**Serving**

- G1. `GET /kem/v1/spaces/{id}/chain` answers `200` with the whole chain, as an array of wire-form
  objects in ascending `seq` from `0` to the head, with exactly their members and unpadded
  base64url.
- G2. `?from=<seq>` answers the records with `seq ≥ from`: an empty array past the head, and `400` for
  a value that isn't an integer from `0`.
- G3. Only an invited or confirmed member gets the chain. Any other account, a removed member
  included, gets `404`, as for every other space route. This holds for a `POST` too: it answers `404`, not
  a `409` with the head, to anyone but a member of a space that exists or has a chain.
- G4. The home and the space's replicas may serve the chain; records are signed, so a replica needs
  no trust. Only the home accepts records.
- G5. `GET /kem/v1/spaces/{id}/chain/{seq}/seals` answers the seal hashes record `seq` committed:
  `[{"bundleVersion": int, "key": key ref, "member": uuid, "sealHash": hash, "version": int}]`, sorted
  by `key` then `member`. Each member fetches their own box through the existing key routes.

**Accepting records.** `POST /kem/v1/spaces/{id}/chain` takes
`{"records": [wire form…], "seals": [{"box", "key", "member", "seq", "version"}…],
"names": [{"name", "seq", "target"}…]}`: 1 to 16 records to append in order, the boxes their
commitments cover and the sealed names their hashes cover. It appends all or none, and answers `201`
with the new head `{"link", "seq"}`, `409` with the current head when `seq` or `prev` isn't the
next, and `422` with the reason of "Verification" otherwise. A `keys` record that replaces collection
keys is sent here, beside its re-written items: the request may also carry `"held": [uuid…]`, the
live items the record leaves held (I3), and `"writes": [{"collection", "expectedRevision",
"item"}…]`, the items it re-writes, each as the next revision under the collection's new key
version (an `item` is written as `PUT /kem/v1/items/{id}` takes it). They are stored in the same transaction as the records. A write is of a live item of a
collection whose key a `keys` record of the request replaces, by a member with edit on it; an item
is written once and is not also held; any other write is refused (`400`, or `422`
`held-not-rotated` for a collection the request does not replace).

**Each re-written item is a signed write** ("Signed item writes"): the member who replaces the key
signs it with their own `sig1` key, over the statement of a space's item, so the statement binds the
item's collection, the new envelope (key version, ciphertext and wrapped item key) and the revision,
and the item carries `writer`, `writerKeyVersion` and `writeSignature`. The server checks each one
as it checks any write (the writer is the signed-in account at its current key version, the signature
verifies under its registered bundle, `invalid-signature` otherwise), before anything is stored, and
this route refuses an unsigned `kem1` re-write for a space that takes signed writes only (`422`
`signature-required`). The web vault signs them in the worker, as it does the items its reseal
writes again (`POST /kem/v1/items:batch`), so a signed-only space is not stuck behind its own key
replacement and a client that holds an item at its floor takes the re-written revision in. Of the
two key replacement routes, only this one requires it: the route that replaces keys without a chain
(`POST /kem/v1/spaces/{id}/key-replacement`) still accepts an unsigned re-write from an owner or
an admin in a signed-only space, so that no client is left at `423 space-keys-pending` for want of
one that signs; a re-write there that carries a signature is checked like any other.

**Who may write items here, and how many.** A request re-writes each item once, at most 6,000 of
them. Before any signature is checked, the server reads the chain's state: the caller must be a
confirmed member with edit on the collection of every item (`404` for a stranger, `422`
`space-chain-refused` otherwise), so a request from someone who may not write costs no
signature check. The signatures are then checked on a blocking thread, not on a request worker.

**The size of the request.** The signatures make a key replacement about four times larger than
it was: each re-written item adds a signature of 4.5 KiB in base64url to its envelope, and the whole
replacement is one request. The route reads 8 MiB from any signed-in caller, as a stream, so
nothing past 8 MiB is held for anyone else. It reads up to **32 MiB** only when the chain's state
has a collection key marked ("Removal and replacement") that the caller may replace: a confirmed
member entitled to that key, with edit on the collection, as the worker's replacement decides it.
A stranger, a member who may only view, and an owner of a space with no key waiting get `413` as
soon as the body passes 8 MiB. The pending-answer route (`POST .../chain/pending/{pending}`) never
reads above 8 MiB: no queued change is a `keys` record.

**Large bodies.** A body above 8 MiB is a *large body*, and the server limits them:

- *Places.* It has two, and an account and a space have one each at a time. A request that finds
  none waits up to ten seconds, and the next place goes to the request that has waited longest:
  an account has one place or one turn in the queue, never two, so the queue is round-robin
  between accounts, and a request that comes back after its turn goes behind the others. After the
  ten seconds it is `429` with `Retry-After`, as it is at once for an account or a space that
  has a place or a turn already.
- *Every large body counts* against the account that sent it, whatever came of it (read, refused,
  too slow, or stored): the account waits 60 seconds, counted from the moment the request is over,
  before another. The one exception is a request that was stored (`201`) and replaced a marked
  collection key, which is what the places are for: it costs neither the wait nor budget.
- *A budget* of four large bodies an hour for each account, on top of the places (`429` with
  `Retry-After`).
- *A floor on the rate.* Every body, from its first byte, has 30 seconds and one more second for
  each 256 KiB it has by then: it must arrive at **256 KiB a second or faster** (2 Mbit/s) after a
  30 second start, and no chunk may take more than 15 seconds; otherwise it is `408`, and a place it
  held is free again at once. The chain's two POST routes have a timeout of five minutes of their
  own, which this floor stays well under; the other routes keep 30 seconds. 32 MiB is room for about
  5,000 items of ordinary size (about 6 KiB each with their signatures), which takes at most
  2 minutes 30 at the slowest rate allowed; a space with more live items in the replaced
  collections, or a connection slower than that, can't have its keys replaced from the web vault,
  which says so and sends nothing.

*What remains.* These limits bound what one account can ask of a server, not what many can. A person
who can make accounts (each its own space, each with a marked key it may replace) can still keep both
places busy and so delay the key replacements of others by up to the ten seconds a request waits,
each of them. A server with sign-ups off, where only its admin makes accounts, has no such person.

The server refuses a record unless all of these hold:

- A1. Its bytes are canonical and within "Limits", and its body has its kind's exact shape.
- A2. `space` is the route's space.
- A3. `seq` and `prev` follow the current head. The append is atomic against the head: of two racing
  appends one wins and the other gets `409`.
- A4. `epoch` is the chain's current epoch, or that plus one for a `fence`. The home accepts records
  only while it is the home of the space's current federation epoch. After a promotion it accepts only
  a `fence` whose epoch is the promotion's, whose `home` is itself and whose `promotion` is the hash
  of that promotion record, and then records of that epoch.
- A5. `by` is the authenticated account, for every record of the request.
- A6. `at` is within 10 minutes of the server's clock. Clients don't check it.
- A7. The record passes every rule of its kind, "Removal and replacement", "Limits" and
  "Authority", against the state at the current head, exactly as "Verification" applies them. One
  bad record makes a space "Can't be checked" for every member, for good, so the server must never
  accept a record a client would refuse.
- A8. The signature verifies under `"space-chain"` with `by`'s chain-recorded bundle, a `rekey`'s
  cosignature with its new bundle, carried bundles' self-signatures, and a `confirm`'s statement
  signature with the confirmer's chain-recorded bundle.
- A9. A `create` comes only with the request that makes the space, and its bundle is byte for byte the
  creator's registered bundle.
- A10. A `confirm`'s statement is byte for byte the one the server rebuilds, as "Member confirmation"
  says, and its bundle, like a `rekey`'s, is byte for byte the account's registered bundle at that key
  version.
- A11. For each seal commitment, the request carries exactly one box per recipient the chain derives,
  each 1661 bytes starting with `u8(1)`, and `count` and the digest recomputed from them match. For
  each name hash, it carries the sealed name, 28 to 4096 bytes, whose `SHA-256` matches.
- A12. A `confirm` is for a member who has accepted the invitation: the server's own "accepted" step
  (S2), which comes after the `invite` record in an earlier request and before the `confirm`, and a
  `confirm` that follows an `invite` of the same member in its own request is refused. A member the
  server holds only as invited (never accepted) is not a member for any policy, key or sync, even
  if the chain says `confirmed`. A later `confirm` of a member who is already confirmed (a new key
  version) needs no new acceptance. Refused as "not allowed" (`422`).
  A server that ran before this rule may hold members a chain confirmed who never accepted. It can't
  tell them from the rest: the row's accepted time was written when the confirm landed, so it records
  no consent. It repairs nothing; an Owner or Admin who finds such a member (a confirmed member they
  never invited, or one whose invitation was never accepted) removes them with a `remove` record.

**Items**

- I1. While the space key is marked, the server answers every item and manifest write in the space
  with `423`; while a collection's key is marked, every item write into it.
- I2. It refuses an item write whose `keyVersion` isn't its collection's current key version.
- I3. A key replacement may name live items as **held**, which it does for items it couldn't vouch
  for: they may be writes by a removed member under a key that member kept. The server keeps them,
  doesn't serve them as live, and counts them as covered in its completeness check. It holds only
  live items of a collection whose key a `keys` record of the same request replaces; an item of
  any other collection, a deleted item or an unknown one is `422` `held-not-rotated`, so a member
  who may replace one key can't take items of another collection out of service.
- I4. A held item leaves the held state in one way only.
  1. **Release on write.** It is released when the server accepts a new revision of that same item
     id whose `keyVersion` is its collection's current key version, and I2 refuses every other, so
     a write under the item's old version never releases it. A tombstone, a delete of that item,
     releases it the same way, though it has no version to compare. Only a member with edit on the
     item's collection may make either write: that is the rule for every item write, and the server
     refuses anyone else (`403`) and stores nothing, so the item stays held. The new revision
     replaces the held one and is served as live: it is a new change like any write, so every
     device receives it as one.
  2. **Nothing else releases it.** Not a chain record of any kind, not a timer, not a decision of
     the server. An item nobody with edit writes stays held: stored, not served as live, and counted
     as covered.
  3. **Who is sent it.** A held item is in no live page of `GET /kem/v1/sync`, and the cursor and
     the 304 answer ignore it as live. No route serves it as live. `GET /kem/v1/sync` still sends
     it to every confirmed member of the space, whatever access they have, with `"held": true` and
     the `keyVersion` it had, so an item the space manifest lists doesn't go missing from a member's
     copy and their client doesn't stop at a missing item. It is not served to anyone who isn't a
     confirmed member. A member who joins later receives the held items, as "Sync cursor" says.

### Changes from outside Kemlock clients

The server's Bitwarden-compatible routes and its SSO group sync change members and groups without
anyone's signing key, which S2 forbids on a space with a chain. The server setting
`space_chain_external_changes` (environment `KEMLOCK_SPACE_CHAIN_EXTERNAL_CHANGES`) says what
happens to such a change, for a space that has a chain. A space with no chain, such as one made
through the Bitwarden routes, is changed as before, and a `create` never makes a chain for a space
that exists (A9), so those stay without one.

| Value | Behaviour |
| --- | --- |
| `queue` (default) | The route or the sync answers as it would for a change that worked, and the change is kept as a pending change for an Owner's or Admin's app to read and sign. Nothing changes until a record is appended. |
| `refuse` | The change is refused (`409`, "the space's changes are signed records"). The space is read-only to Bitwarden apps. |
| `unchained` | As `refuse`, and Bitwarden-compatible apps don't list the chained space at all. |

Only a member's client makes a record.

#### Pending outside changes

A queued change is one of: add a member (`invite`), remove or revoke one (`remove`), change a role
(`role`), set a grant (`grant`), take a grant away (`ungrant`). Only a confirmed Owner or Admin
sees or answers them; anyone else gets `404` or `403`.

```
GET    /kem/v1/spaces/{id}/chain/pending         the pending changes, oldest first
POST   /kem/v1/spaces/{id}/chain/pending/{n}     answer one: the body is an append request
DELETE /kem/v1/spaces/{id}/chain/pending/{n}     drop one: 204, recorded in the space's event log
```

```json
{"id": uuid, "source": "bitwarden" | "sso", "queuedAt": unix seconds,
 "requestedBy": {"account": uuid | null, "email": string | null, "via": "Bitwarden-compatible API" | "SSO group rule"},
 "change": {"kind": "add-member" | "remove-member" | "role" | "grant-set" | "grant-remove",
            "account": uuid, "email": string | null,
            "role": "owner" | "admin" | "custom" | "member",                 add-member, role
            "custom": ["manage-users", "manage-groups", "create-collections"],   add-member, role
            "grants": [{"collection": uuid, "permission": collection permission}],   add-member
            "collection": uuid, "permission": collection permission}}        grant-set, grant-remove
```

The answer is an append request ("Accepting records"). The server checks it as any append (A1 to
A11) and also that it records exactly the queued change: one record, of the kind in brackets above,
for the same account, with the same role and custom permissions, grants or permission (an
`invite`'s `grants` are the change's `grants`).
A record that is not that change is `422` `pending-change-mismatch`. When it is appended the
change is applied with the record and the entry is marked done in the same transaction.

### Limits

Sizes of records, lists and chains are checked in step 0 of "Verification": beyond them is **too
large**, and the whole chain is refused. Wherever a kind's section says a list's length is malformed,
an empty list is malformed and a list past the limit is too large. Counts in the state are checked in
step 5: a record that takes the state beyond them is **invalid**.

| What | At most |
| --- | --- |
| A record's bytes | 196,608 (192 KiB) |
| A chain | 65,536 records, and 64 MiB of record bytes |
| A request to the append route | 16 records |
| `invite.grants`, `collection.grants` | 1,000 |
| `group-members.add` and `.remove` together | 1,000 |
| `seal.seals` | 1,001 |
| `keys.rotate` | 257: the space key and 256 collection keys |
| Members in the space (invited or confirmed) | 10,000 |
| Collections | 1,000, nested at most 16 deep |
| Groups | 1,000 |
| Grants on one collection | 1,000 |
| A sealed name | 4,096 bytes, as the server's domain has it |

The record limit fits the largest record, a `keys` that replaces the space key and 256 collection
keys with 2,001 names packed, about 170,000 bytes, and keeps a record with its two signatures, as raw
bytes, inside a federation home record's 256 KiB payload.

### Test cases

`test-vectors/space-chain.json` holds a valid chain with every kind, and one chain per refusal below,
each with the `seq` and reason a verifier must give; cases 19 to 22 are tests of the server and have
no chain there. In words:

1. **Self-widening through a group.** A Custom member with only `manage-groups` adds themselves to a
   group that is granted Finance: not allowed. Adding themselves to a group with no grants is
   accepted; a later `grant` of Finance to that group, signed by them, is not allowed.
2. **Group access needs MayGrant.** The same member adds Ana to that group: not allowed. Once they hold
   `manage` on Finance, the same record is accepted, and Ana awaits Finance's key.
3. **Owners change Owners.** In a space with two confirmed Owners, an Admin's `ungrant` of an Owner's
   grant, `group-members` removing an Owner, `grant` to a group that holds an Owner, and `role`
   demoting an Owner are each not allowed. The same records signed by the other Owner are accepted.
   In a space with one confirmed Owner, demoting or removing them is invalid, whoever signs it.
4. **Removal ends access.** Lee, confirmed, holds Finance's key through a group. Their `remove` with
   `"replace": []` is invalid; with `["collection:<finance>", "space"]` it is accepted. Afterwards Lee
   has no grant and is in no group, and inviting Lee again gives them no grant.
5. **A marked key isn't shared.** After Lee's removal, a `seal` of the space key, a `confirm`, and a
   `grant` of Finance to a new member are each invalid. A `keys` record that replaces the space key
   and Finance's key with every name is accepted, and clears both marks; one that replaces the space
   key without `names`, or with a collection missing, is invalid.
6. **Keys come from the chain.** The chain has the space key at version 3. The server serves a box at
   version 2 that opens: the client doesn't use it. It serves a version-3 box whose hash isn't
   committed, or a hash list with an extra recipient: refused. A box that opens to a key whose check
   isn't the chain's: refused.
7. **Old key versions after removal.** After Finance's key moves to version 2, an item revision in
   Finance under version 1 is held, not applied. A revision that arrives between the `remove` and the
   `keys` record is held too.
8. **Epochs.** A `role` with the epoch plus one: bad epoch. A `fence` with the epoch plus two, or with
   the same epoch: bad epoch. A record with a lower epoch: bad epoch. A `fence` with the epoch plus
   one signed by an Admin: not allowed.
9. **Fence and dropped records.** A device anchored at `seq` 12, epoch 1, served a chain whose `seq`
   10 is a `fence` to epoch 2 and whose `seq` 0 to 9 match its anchor: accepted, and 10 to 12 of its
   own are dropped. If its link at 9 differs: forked. A device anchored at epoch 2 served the old
   home's epoch-1 records past the fence: forked.
10. **The only Owner replaces their keys.** A `rekey` with a valid cosignature is accepted; the next
    record signed with the new key is accepted, and one signed with the old key is a bad signature. A
    `rekey` without a cosignature is malformed; with a cosignature by another key, a bad signature; to
    a bundle of the same key version, invalid.
11. **One spelling.** Each is malformed: `null` for `parent`, `"custom": null`, `1.0`, `-1`,
    `9007199254740992`, `"A"`, `"\ud800"`, `custom` out of order, an id twice in `add`, a member
    name twice, a space after a colon, an unknown member, a cosignature on a `grant`. A record whose
    `prev` is the unlabelled `SHA-256` of the record before is a bad link.
12. **Limits.** A record of 196,609 bytes and a chain of 65,537 records are too large. The 1,001st
    collection and the 10,001st member are invalid.
13. **First contact.** A server serves an invitee a chain it made, with its own Owner key. The
    inviter's fingerprint on the accept screen differs from the inviter's own screen: the app stores
    nothing, offers no Accept, and seals nothing to the recovery key the fake chain names. With the
    real chain the digits match, and the anchor is stored.
14. **Rollback and fork.** The device accepted `seq` 12; the server's chain ends at 9: rolled back. The
    server's `seq` 12 differs from the anchor's: forked.
15. **Policies.** An Admin's `policies` that turns `accountRecovery` on: not allowed. An Owner's that
    turns it on with no recovery key: invalid. An Admin's that turns `requireSso` on: accepted.
    `sessionTimeout` with `minutes: 0` and `action: "lock"`: invalid.
16. **Who replaces a key.** An Admin without access to Finance replaces Finance's key: not allowed. A
    member with `view` on Finance replaces it while it is marked: accepted; while it isn't: not
    allowed.
17. **Custom managing Custom.** A Custom member with `manage-users` changes the role of a Custom
    member who has `create-collections`, which the signer lacks: not allowed.
18. **Reason order.** A record signed by a key the chain doesn't record for `by`, which also breaks
    the authority table, is a bad signature. A record with a bad link and a bad signature is a bad
    link.
19. **A held item released by a write.** Finance's key moves to version 2 and the `keys` record
    names an item in Finance, written under version 1, held. A write of that item under version 2
    by a member with edit is accepted and releases it: the new revision is in the sync of every
    member as a change, and the item is no longer marked held.
20. **A write under the old version leaves it held.** A write of the held item under version 1 is
    refused (`409` `stale-key-version`, naming version 2) and stores nothing. The item is still
    held: every confirmed member, with or without edit, is sent it marked held with version 1.
21. **A held item deleted by a tombstone.** A delete of the held item, which names no key version,
    by a member with edit is accepted and releases it: every member receives the tombstone as a
    change.
22. **A member without edit cannot release it.** A member with view access, or none, writing the
    held item under version 2, or deleting it, is refused (`403`) and stores nothing. The item stays
    held, and is still sent to that member marked held.

These pin the layout and the link only. They aren't a valid chain: the record before `seq` 7 isn't
given. They use `uuid(n) = 00000000-0000-4000-8000-<n as 12 hex digits>`.

A `fence` at `seq` 7 whose `prev` is 32 bytes of `0x11`, with `promotion` the `SHA-256` of the ASCII
text `example promotion record`, 313 bytes:

```
{"at":1700000700,"body":{"home":"00000000-0000-4000-8000-0000000000f2","promotion":"QTHxrde9FN788OzrLL4TpaPmaC2O0E5WgPn8_Ws-K0Q"},"by":"00000000-0000-4000-8000-000000000002","epoch":2,"kind":"fence","prev":"ERERERERERERERERERERERERERERERERERERERERERE","seq":7,"space":"00000000-0000-4000-8000-000000000001","v":1}
link = baf5fdb659e027e88cfe5f2a68f05e1fb2537ad9c99ea2b37869ff5924536947
     = uvX9tlngJ-iM_l8qaPBeH7JTetnJnqKzeGn_WSRTaUc (base64url)
```

The unlabelled `SHA-256` of the same bytes is `04cce6ca…7016608a`; a verifier that gets that value
hashes without the label.

A `role` linked to it, 319 bytes:

```
{"at":1700000800,"body":{"custom":["create-collections","manage-users"],"member":"00000000-0000-4000-8000-000000000003","role":"custom"},"by":"00000000-0000-4000-8000-000000000002","epoch":2,"kind":"role","prev":"uvX9tlngJ-iM_l8qaPBeH7JTetnJnqKzeGn_WSRTaUc","seq":8,"space":"00000000-0000-4000-8000-000000000001","v":1}
link = 8aa6fb9d20088eeb1cbb86b48f0ded3b0aa2120cc7ebdbbc5f288e7b637336af
     = iqb7nSAIjuscu4a0jw3tOwqiEgzH69u8XyiOe2NzNq8 (base64url)
```

The links are `SHA-256` of `"kemlock/v1/space-chain/link"` followed by these exact bytes, and a unit
test in `kemlock-crypto` checks both. `space-chain.json` pins the same layout with real `sig1`
signatures, seal digests and key checks.

## Sends

A Send shares a note or a file through a link. Its key is in the link's fragment, which a browser
never sends, so the server holds ciphertext only and can't open it. A person with the link opens the
Send; the owner's devices open their own copy through the account.

```
link key K  = 32 random bytes
send id     = a UUID version 4 the client chooses and sends when it makes the Send
access id   = base64url(send id (16))                              22 characters
link        = https://<host>/#/send/<access id>/<base64url(K)>     the key is 43 characters
```

`K` is 32 bytes, not the 16 of Bitwarden's Send keys, so the whole chain stays at 256 bits. A
Bitwarden app's Sends keep Bitwarden's own format and the server stores them opaque; nothing here
applies to them, and a client never mixes the two. The fragment is the only place `K` goes: not the
server, not a log, not a referrer.

The client picks the id, as it assigns an item's revision, because the seals below bind it and the
client seals before the server could name one. The server refuses an id that isn't a version 4 UUID
and answers 409 for one it already holds.

### Keys

```
payload key = HKDF(ikm = K, salt = absent, info = "kemlock/v1/send-payload", L = 32)
proof salt  = HKDF(ikm = K, salt = absent, info = "kemlock/v1/send-proof" ‖ send id (16), L = 16)
meta key    = HKDF(ikm = owner's "kemlock/v1/item-wrap" child key, salt = absent,
                   info = "kemlock/v1/send-meta" ‖ send id (16) ‖ u32be(key version), L = 32)
```

The payload key and the proof salt come from `K`, so whoever has the link has them. The meta key
comes from the owner's item-wrap key and never from `K`: a link holder, a recipient or anyone the
link was forwarded to, must never read the owner's notes. The key version is the one `sealedKey`
names, so the owner derives the meta key without opening `K` first.

### Sealed parts

The kind is `text` or `file`, as ASCII. Every seal is `nonce(12) ‖ ciphertext ‖ tag(16)`.

```
aad       = label ‖ send id (16) ‖ lp(kind)
payload   = AES-256-GCM(payload key, nonce, payload JSON, aad, label "kemlock/v1/send-payload")
meta      = AES-256-GCM(meta key, nonce, meta JSON, aad, label "kemlock/v1/send-meta")

sealedKey = u32be(key version) ‖ AES-256-GCM(owner's "kemlock/v1/item-wrap" child key, nonce, K,
            aad = "kemlock/v1/send-key" ‖ send id (16) ‖ u32be(key version))          64 bytes
```

- `payload` is what a recipient opens. Its JSON is one UTF-8 object with exactly these fields: for a
  note `{"name": string, "text": string}`, for a file `{"name": string, "mime": string, "size":
  integer}`, where `size` is the file's plaintext length. A reader refuses any other field.
- `meta` is the owner's list entry, `{"name": string, "notes": string}`, which a recipient can't
  open: `K` doesn't give its key. The owner reads the key version from `sealedKey`, derives the
  meta key from the item-wrap key and opens `meta`, so a list needs no link in hand.
- The key version is the one the account's item-wrap key had when the Send was made, so a Send made
  before a key-pair replacement still names the version that wraps its key. The wrap names no owner:
  the id is a random UUID, and only the owner's own item-wrap key opens it.
- Binding the id and kind stops the server from passing one Send's payload off as another's, or a
  note's as a file's. An edit to a note re-seals `payload` under the same `K` and `meta` under the same
  meta key, with fresh nonces. The payload is not bound to a revision, so a server can serve a note's older text; that is
  accepted, because the server already decides whether to serve a Send at all.

### Files

A file Send's bytes are one `KMA1` file, the format the Kemlock app writes attachments in, under the
payload key:

```
"KMA1" ‖ nonce prefix (8 random bytes) ‖ chunk 0 ‖ chunk 1 ‖ … ‖ last chunk
chunk = AES-256-GCM(key, nonce = prefix ‖ u32be(counter), aad = 0x00, or 0x01 for the last chunk,
                    up to 65536 bytes of plaintext) ‖ tag(16)
```

The counter starts at 0. Every chunk but the last holds exactly 65,536 bytes of plaintext (65,552
sealed); the last holds the rest, possibly nothing, so a file ends in exactly one last chunk.
Reordered or cut chunks fail. The file is `12 + plain + 16 × max(1, ⌈plain / 65536⌉)` bytes long, and
the client announces that length as `file.size` when it makes the Send, so the server can refuse an
upload of another length or one that doesn't start with `KMA1`. The payload JSON names the file and
gives its plaintext size; the file carries no name.

### Password

A Send may have a password. The client turns it into a proof with a slow hash bound to the Send:

```
proof = Argon2id(NFC password as UTF-8, proof salt, m = 19456 KiB, t = 2, p = 1, L = 32)
```

The parameters are fixed here, so a recipient needs nothing from the server to derive the proof, and
19 MiB runs on a phone. The proof is the `password` field, base64url of 32 bytes, when a Send is
made or its password changed and on every access. The server never sees the password. It keeps a
random 32-byte salt and `HMAC-SHA-256(salt, "kemlock/v1/send-password" ‖ proof)`, compares in
constant time and counts wrong tries per Send (10 a minute, then doubling delays). The proof salt
comes from `K`, so a copy of the database alone can't test guesses: it needs the link as well, and
then each guess costs an Argon2id.

### Sending an item

A Send can share an item of the vault. It is a note Send (`kind` `text`) whose `text` is a JSON
envelope the browser builds from the chosen item, so the sealing, the server, its routes and a
Bitwarden client are unchanged; a client that doesn't know the envelope shows the JSON as text.

```
{"kemlockSend":1,"kind":"card","name":"Visa","fields":{"number":"4111 1111 1111 1111","expiry":"05/2029"}}
```

- `kemlockSend` is the envelope version, `1`. A reader that finds another value treats the text as
  plain text.
- `kind` is the item's kind: `login`, `note`, `card`, `identity`, `otp`, `backup-codes`, `ssh-key`,
  `pgp-key`, `certificate` or `contact`. `name` is the item's name.
- `fields` maps a field key to a non-empty string. Each kind sends only the keys it names, in this
  order, and nothing else: no id, history, favorite, pin or timestamp.

| kind | keys |
| --- | --- |
| `login` | `username`, `password`, `urls` (one per line), `notes` |
| `note` | `text` |
| `card` | `cardholder`, `number`, `brand`, `expiry` (`MM/YYYY`), `code`, `pin`, `note` |
| `identity` | `title`, `givenName`, `middleName`, `familyName`, `company`, `email`, `phone`, `username`, `birthDate`, `address` (lines, one per line), `city`, `region`, `postalCode`, `country`, `note` |
| `otp` | `type`, `issuer`, `label`, `secret`, `algorithm`, `digits`, `period`, `counter`, `note` |
| `backup-codes` | `serviceName`, `codes` (the unused ones, one per line), `note` |
| `ssh-key` | `algorithm`, `public`, `private`, `note` |
| `pgp-key` | `public`, `private`, `note` |
| `certificate` | `algorithm`, `certificate`, `private`, `note` |
| `contact` | `public`, `note` |

The access page shows the item read-only: labelled fields, the secrets (`password`, `number`,
`code`, `pin`, `secret`, `codes`, `private`) masked until shown, and a copy button on each. A key
the kind doesn't define is dropped. Numbers are written as decimal text. The owner's list entry
(`meta`) names the Send as the person typed it; the envelope is only in `payload`.

### What the server checks

Lengths and shapes, never the seals: `id` is a version 4 UUID; `kind` is `text` or `file`; `meta`
and `payload` are at least 28 bytes (a nonce and a tag around nothing) and at most 16 KiB and
256 KiB; `sealedKey` is exactly 64 bytes; `password` is exactly 32 bytes; a file Send's `file.size`
is a length `KMA1` chunks make, and its upload has the header and that length. It can't check an
AAD, a key or a JSON field: only someone holding `K` can.

`send.json` in test-vectors pins the keys, AADs, seals, wrap and proof of a note and of a file, and
the changed ids, kinds, keys and key versions that must not open them.

## `opaque1`: OPAQUE configuration

RFC 9807 OPAQUE-3DH with exactly the configuration of its appendix C test vector 1 apart from the
context:

| Parameter | Value |
| --- | --- |
| OPRF | ristretto255-SHA512 |
| Key exchange group | ristretto255 |
| KDF | HKDF-SHA512 |
| MAC | HMAC-SHA512 |
| Hash | SHA-512 |
| KSF | Identity |
| Context | `"kemlock/v1/opaque"` |
| Client identity | none (the client public key) |
| Server identity | none (the server public key) |
| Credential identifier | the account's email, trimmed and lower-cased, as UTF-8 |
| Password input | the 32-byte Argon2id master key, not the typed password |

The KSF is Identity because the password input is already the Argon2id master key: every guess
costs one Argon2id whether it is made against OPAQUE or against the wrap, and the client runs the
same Argon2id for both. `opaque-ke` 4 implements it on the server; the app's Dart client is held to
RFC 9807's vectors and to the vectors in `test-vectors/opaque.json`.

The server's OPAQUE setup (OPRF seed and server key pair) is sealed with `server.key`.

## Password-protected exports

Kemlock writes a vault out as Bitwarden's password-protected JSON export (`kemlock-import`'s
`bitwarden_export`; the web vault runs it in the browser as WebAssembly), so the file opens in
Bitwarden and Vaultwarden and reads back into Kemlock. It is a Bitwarden format, not a Kemlock
one, and the server never sees it; it is written down here because a Kemlock client must write
and read it byte for byte. Two variants exist: `bitwarden-json`, which is exactly Bitwarden's file, and
`kemlock-json`, which is the same file with one more member, `kemlock`, inside the encrypted data.

### The file

Two-space indented JSON, members in this order:

```json
{
  "encrypted": true,
  "passwordProtected": true,
  "salt": "<16 random bytes, standard base64 with padding>",
  "kdfType": 1,
  "kdfIterations": 3,
  "kdfMemory": 64,
  "kdfParallelism": 4,
  "encKeyValidation_DO_NOT_EDIT": "2.<iv>|<ciphertext>|<mac>",
  "data": "2.<iv>|<ciphertext>|<mac>"
}
```

- `kdfType` is 0 for PBKDF2-HMAC-SHA256 and 1 for Argon2id. A PBKDF2 file has no `kdfMemory` and no
  `kdfParallelism`. `kdfMemory` is in MiB.
- **Defaults of a new export**: Argon2id, 3 passes (`kdfIterations`), 64 MiB, 4 lanes: the
  parameters of a Kemlock master key (above). A writer and a reader both hold the cost to
  Bitwarden's import bounds: PBKDF2 5,000 to 2,000,000 rounds; Argon2id 2 to 10 passes, 16 MiB to
  1 GiB, 1 to 16 lanes. A file outside them is refused before any work, so what is written can
  always be read back.
- An `EncString` of type 2 is `2.` ‖ base64(iv) ‖ `|` ‖ base64(ciphertext) ‖ `|` ‖ base64(mac), standard
  base64 with padding: AES-256-CBC with PKCS#7 padding under the encryption key and a fresh random
  16-byte IV, and `mac = HMAC-SHA256(mac key, iv ‖ ciphertext)`. A reader checks the MAC before it
  decrypts; a wrong password is a MAC that doesn't match.

### Keys

```
salt text  = the "salt" member, its base64 text as written
master key = PBKDF2-HMAC-SHA256(password, salt text as UTF-8, kdfIterations, L = 32)
           | Argon2id(password, SHA-256(salt text as UTF-8), m = kdfMemory × 1024 KiB,
                      t = kdfIterations, p = kdfParallelism, L = 32), version 0x13
enc key    = HKDF-Expand-SHA256(prk = master key, info = "enc", L = 32)      (no extract step)
mac key    = HKDF-Expand-SHA256(prk = master key, info = "mac", L = 32)
```

The password is its UTF-8 bytes exactly as typed, with no normalisation, as Bitwarden has it
(unlike the NFC of an account's master key); an empty or blank password is refused. Argon2id's
salt is the SHA-256 of the salt text, 32 bytes, and not the 16 random bytes.

### What is encrypted

- `encKeyValidation_DO_NOT_EDIT` is a random version 4 GUID (36 characters, hyphenated lower case)
  encrypted as an `EncString`, so a reader can test a password without opening the data.
- `data` is the plain export, as UTF-8 text, encrypted as an `EncString` under the same keys with
  its own IV.

### The plain export

One JSON object, two-space indented, members in this order:

```json
{ "encrypted": false, "folders": [ { "id": "…", "name": "…" } ], "items": [ … ],
  "kemlock": { "version": 1, "items": [ { "id": "…", "kind": "login", "data": { … } } ] } }
```

- `folders` and `items` are Bitwarden's individual-vault JSON, each item's members in the order
  Bitwarden's exporters print them, so a Bitwarden client reads it unchanged. A Kemlock item maps to
  Bitwarden `type` 1 (login), 2 (secure note), 3 (card), 4 (identity) or 5 (SSH key); an item
  kind Bitwarden has no type for becomes a secure note, and a one-time-password item linked to a
  login that has no code of its own becomes that login's `totp` (the first one only), as Bitwarden
  has no item that is only a code. A folder is one entry per path, named by the path, with the id
  `uuid4form(SHA-256("kemlock/v1/export-folder" ‖ path)[0..16])`, where `uuid4form` sets the version
  nibble to 4 and the variant bits as RFC 9562 does, so the same vault always names its folders the
  same.
- `kemlock` is present in the `kemlock-json` variant only, and Bitwarden ignores it. `version` is 1;
  `items` lists every item of the export, of every kind and in the vault's order, each as
  `{ "id", "kind", "data" }` with `data` the item's plaintext JSON object exactly as Kemlock stores
  it. Kemlock's own reader (`kemlock-import`) imports from `folders` and `items`, the Bitwarden
  part, and doesn't read this member; it is there for a reader that wants every field.

## Duplicate tags

```
dedup key = HKDF(ikm = user key or space key, salt = absent,
                 info = "kemlock dedup v1" ‖ owner (17) ‖ u32be(key version), L = 32)
tag       = HMAC-SHA256(dedup key, canonical input)
```

The canonical input is a JSON array whose first element is the tag's name (`cred`, `account`,
`secret`, `passkey`, `card`, `note`, `key`, `codes`, `identity`, `contact`, `document`, `file`),
followed by the normalised values as strings, serialised as RFC 8785 (JCS) without whitespace. Tags
are the full 32 bytes.

`contact`, `document` and `file` are later additions. A client that doesn't know a tag name makes
none of that name, and the items that already have tags keep them unchanged.

### Normalisation

Every client turns a raw item into the same canonical values, or the same item gets two tags.
"Lower case" below always means each code point's **simple** lowercase mapping (UnicodeData field
13), with no SpecialCasing and no final-sigma rule: `İ` (U+0130) becomes `i`, `Σ` always becomes
`σ`, `ẞ` becomes `ß`, and `ß` stays `ß` (so `Straße` and `STRASSE` don't match). NFC is Unicode
normalisation form C. "Trimmed" means stripped of characters with the Unicode `White_Space`
property (U+FEFF is not one). Each tag's input is `[name, value…]` in this order:

| Tag | Values |
| --- | --- |
| `cred` | site, username, password |
| `account` | site, username |
| `secret` | the secret |
| `passkey` | relying party, credential id |
| `card` | number, expiry |
| `note` | text |
| `key` | fingerprint |
| `codes` | each code |
| `identity` | full name, email |
| `contact` | email, phone |
| `document` | number |
| `file` | content hash |

- **site**: one per website: the registrable domain by the Public Suffix List (ICANN and private
  sections), lower case, Punycode; the whole host instead for an IP address or a host under the
  app's shared hosts (`sharedHosts`). A website whose rule is `regex` or `never` makes no tag.
  The list is the snapshot `test-vectors/public_suffix_list.dat` (version `2026-11-21_04-33-45_UTC`,
  commit `87a2c1b8de5886a133ff4da21b2aa6fec88d8739`), SHA-256
  `017501d3fa7911c60ac7e0f68df4122b07216c585c15dc30e0f0c74b8d13a2b9`, and both sides use that one.
  A rule is the first white-space-separated word of a line that is not a `//` comment; the
  algorithm is the list's own (longest matching rule, `!` exceptions first, `*` when nothing
  matches), run on Punycode labels, and a host that is itself a public suffix is its own site.
  A website's host is read from its text (a URL with or without a scheme, or a bare host) by
  dropping the scheme, user information, port, path, query, fragment and one trailing dot; it is
  made NFC, then lower case, then each non-ASCII label Punycode (RFC 3492), and a host with
  anything but `a-z`, `0-9`, `-`, `_` and `.` left in it is no site. An IPv4 address, or an IPv6
  address written as RFC 5952 text without brackets, is its own site; so is an `androidapp://` or
  `iosapp://` package name, and a host equal to or under a shared host.
- **username**: trimmed of Unicode white space, NFC, lower case. **password**: exactly as typed.
- **secret**: the decoded secret bytes (any case, spaces and padding accepted on input),
  re-encoded as RFC 4648 base32, upper case, no padding.
- **relying party**: lower case. **credential id**: base64url without padding (a padded value or one
  in the standard alphabet is decoded and written again; one that is not base64 stays as it is).
- **number**: the card number's ASCII digits only. **expiry**: `YYYY-MM` (a month 1 to 12, a year of
  two digits, meaning 20yy, or four), or `""` when unknown.
- **text** (note): NFC; CRLF and lone CR become LF; spaces and tabs at the end of each line
  removed; blank lines at the end removed.
- **fingerprint**: an SSH key's OpenSSH `SHA256:…` fingerprint, or a PGP key's v4 or v6
  fingerprint as upper-case hex. A certificate's fingerprint is the same: its SHA-256 (or SHA-1)
  thumbprint of the DER, as upper-case hex with the colons, spaces and a leading `0x` left out, so
  `AB:CD:…` and `abcd…` are one value. A certificate makes a `key` tag. A value that is neither
  an `SHA256:…` fingerprint nor 40 or 64 hex digits has no tag.
- **each code** (backup codes): trimmed, empty ones and duplicates dropped, sorted by code point,
  one value each.
- **full name** and **email** (identity): trimmed, NFC, lower case.
- **email** (contact): trimmed, NFC, lower case, as a username is. **phone**: its ASCII digits
  only, so `+1 (555) 0142` and `15550142` are one value. A contact whose email and phone are both
  empty has no tag; with one of them, the other is the empty string. The email is the contact's
  own `email`; the address a public key was looked up by (`sourceEmail`) is not read. A contact
  that holds a PGP public key also makes a `key` tag with that key's fingerprint, as a PGP key
  item does.
- **number** (`document`, one per identity document): NFC, lower case, and only its letters and
  digits (Unicode alphabetic and numeric characters), so `X 1234-567` and `x1234567` are one
  value. A number of fewer than four letters and digits has no tag.
- **content hash** (`file`): the SHA-256 of the file's plaintext, as 64 hex digits in lower case
  (any case on input). A File item's `file` entry may hold it as `sha256`, beside its `name`,
  `size` and `key`; a file without one has no tag.

A login has one `cred` and one `account` tag per site, each site once; a login with no site has
none. An identity has one `identity` tag and one `document` tag per document number, each number
once. A client that groups identities does so by `document`: two identities that share one are
copies. An identity with no document is a copy of every identity with no document that shares its
`identity` tag, and of the one identity with documents that shares it; with several identities with
documents it is a copy of none of them (it could be of any), and two identities that both have
documents are never copies by `identity` alone, since one person's passport and licence share a name
and an email. A card, note, key, certificate, code, contact, file or identity with nothing to hash (no
digits, no text, an unreadable fingerprint or secret, no codes, an empty name and email, an empty
email and phone, no hash) has no tag.

`dedup-normalise.json` in test-vectors pins raw values in and canonical inputs out, including
`İstanbul`, `ΣΑΣ`, `Straße` against `STRASSE`, a decomposed `é`, a base32 secret with spaces,
lower case and padding, a note with CRLF and trailing blanks, duplicate backup codes, a
certificate's SHA-256 and SHA-1 thumbprints with colons, in lower case and after `0x`, a contact's
phone with punctuation next to an email-only and a phone-only contact, a document number with
spaces and dashes (and one too short to count), and a file's hash in upper case.

## Sync cursor

The cursor `GET /kem/v1/sync` returns is opaque to clients, and the server reads two versions. A
device syncs its own vault and every space it is a confirmed member of, and the cursor remembers,
per owner, the last sequence number seen from each origin server. An owner the cursor does not
list starts from nothing and is sent its whole history once, which is how a device that joins a
space receives the items the space already had. Sequence numbers belong to the origin server, not
to an owner, so one vector over all of a device's owners (version 1) could not tell the owners
apart, and a device holding a high sequence from its own vault never saw a joined space's earlier
items.

```
v1 = u8(1) ‖ u16be(n) ‖ n × (server id (16) ‖ u64be(seq))
v2 = u8(2) ‖ u16be(n) ‖ n × (owner (17) ‖ u16be(k) ‖ k × (server id (16) ‖ u64be(seq)))
```

Owners are ascending in the `u8(type) ‖ uuid` form above (type `0x01` or `0x02`, any other is
refused, except `0x03` below), origins ascending, no sequence of 0, no owner with `k` of 0
(an owner with nothing seen is left out), at most 1,024 owners and 256 origins each, and no trailing
bytes. A cursor the server can't read is a full-sync-required answer. The server writes version 2 on every page it
returns. A version 1 cursor is read as every owner at that vector, which is what it meant, and the
page that answers it carries a version 2 cursor. An answer of "nothing changed" (304) has no page
and echoes the cursor it was sent as the `ETag`, so a version 1 cursor stays version 1 until the
next page. Held items (I4) have entries of their own in the same list, written `u8(0x03) ‖ collection
id (16)` in the owner's place and sorted after every owner. A held item is in no owner's vector; the
entry of its collection says what the device has been sent of that collection's held items, so the
cursor and the 304 answer follow them too. The cursor lists such an entry exactly for the collections
that hold items in the spaces the account syncs when the page is issued, whatever access the
account has on them, so a member who joins a space later finds its entries absent and is sent its
held items from the start, as with the rest of that space, and a space the account leaves drops its
entries. Entries count toward the 1,024. A version 1 cursor
has none. The cursor lists exactly the owners the account syncs when a page is issued, so a space
the account is removed from drops out of it and is sent again from the start if the account joins
it again. A space the device joined while it held a version 1 cursor stays missing its earlier
items, because that cursor can't say which owners it was issued for; a device that finds items
missing starts over with no cursor. Federation's cursors between servers stay version 1, one per
vault.

## Server-side secrets

`server.key` is 32 random bytes in `data/server.key` (mode 0600), an environment variable or a
mounted secret. Secrets the server must read are sealed as
`u8(1) ‖ AES-256-GCM(HKDF(server.key, info = "kemlock/v1/server-seal" ‖ lp(purpose)), nonce, value,
aad = lp(purpose))`, with purposes such as `"opaque-setup"`, `"totp"`, `"token-signing-key"`,
`"smtp-password"`.

Secrets that belong to one account (its TOTP seed, the sealed lists and settings of its email,
YubiKey, Duo and security-key methods, and its recovery code) are sealed under the purpose
`purpose ‖ ":" ‖ account id` (the id in its hyphenated lower-case form, for example
`"totp:2f9c0d1e-…"`), so a sealed value copied into another account's row by someone who can write
the database but doesn't hold `server.key` doesn't open there. Values stored before that was done
are sealed under the bare purpose; they open as before and are sealed again, bound, when they are
used for a sign-in (the TOTP seed) or written again (the other methods and the recovery code). The
short-lived states handed to a client (login states, challenges, setup and prompt states) keep a
bare purpose: each carries its own expiry and the account it is for.

## Test vectors

`test-vectors/` holds one JSON file per format, generated by `cargo run -p kemlock-crypto --bin
kemlock-vectors` from fixed seeds, and checked by CI to regenerate byte for byte. Each file carries
its format version and a description, and `SHA256SUMS` lists them. The folder is CC0-1.0 so any
client may copy it.

Its files are `account-keys.json`, `password-wrap.json`, `argon2id.json`, `kx1.json`, `sealed-box.json`, `sig1.json`, `sig1-edge.json` (the Ed25519 verification rule's edge cases and their verdicts), `bundle.json`, `kem1.json`, `manifest.json`, `dedup.json`, `dedup-normalise.json`, `server-seal.json`, `opaque.json`, `legacy-ids.json`, `phrase.json`, `private-keys.json`, `prf-wrap.json`, `confirm.json` (member confirmation statements, their signatures and the statements a signature must not cover), `key-box.json` (signed key box statements for a space key and a collection key, their signatures and the statements a signature must not cover), `item-write.json` (signed item writes: envelope hashes, statements, signatures and the statements a signature must not cover), `send.json`, `space-names.json` (names of a space, a collection and a group sealed under a fixed space key) and `space-chain.json` (the space chain: a valid chain with every kind, the record encoding, the labelled link, and one chain per refusal with the `seq` and reason a verifier must give); the `federation-*.json` files of the federation wire formats, listed in `federation-SHA256SUMS`; and `public_suffix_list.dat`, the Public Suffix List snapshot the dedup site rule uses (MPL-2.0, not CC0).
