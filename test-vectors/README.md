# Kemlock test vectors

Known-answer vectors for every byte format in [`docs/crypto.md`](../docs/crypto.md). They are
public domain ([CC0-1.0](LICENSE)), with one exception named under Licences below: the Flutter
app, the web vault and any other client may copy them and hold their own code to them. Clients never link the AGPL code in `kemlock-crypto`; they
link nothing but these files.

Each file is JSON with four fields:

```json
{ "format": "kx1", "version": 1, "description": "…", "cases": [ … ] }
```

Every binary value is lower-case hex. A case names its inputs (keys, seeds, nonces where a format
draws them) and the bytes the format must produce from them, so a client can both open the vector
and rebuild it. Where a format has a random part (a nonce, an ML-KEM encapsulation) the vector
carries the bytes, and the check is to open them and to re-seal with the nonce they contain.

| File | Pins |
| --- | --- |
| `account-keys.json` | Root key, Kemlock user key (`kemlock/v1/user`), labelled child keys |
| `password-wrap.json` | Wrap key from master key and OPAQUE export key, AAD, wrapped root key |
| `argon2id.json` | Master key for small and default parameters, UTF-8 (NFC) passwords |
| `kx1.json` | Hybrid exchange key: private and public key, ciphertext, shared secret, implicit-rejection outputs |
| `sealed-box.json` | Sealed box to a `kx1` key under a context label, one case per context with the aad the clients use (device-approval, space-key, collection-key, emergency-access, account-recovery) and the parts it is built from; the contexts that must not open it |
| `sig1.json` | Hybrid ML-DSA-65 + Ed25519 signatures, public keys from seeds |
| `sig1-edge.json` | The Ed25519 verification rule: small-order, non-canonical and mixed-order keys, non-canonical S and R, with the verdict of each |
| `bundle.json` | Public-key bundle, its 60-digit fingerprint (12 groups of 5), its signature |
| `kem1.json` | Item AAD, item ciphertext, item-key wrap, with the key chain from the root key |
| `manifest.json` | Signed manifest encoding (entries sorted, tombstones), signature |
| `dedup.json` | Dedup key, RFC 8785 canonical inputs (with escaping cases) and tags |
| `server-seal.json` | Server-side seals under `server.key` by purpose |
| `opaque.json` | A full OPAQUE registration and login with every message, the random inputs, the export key and the session key |
| `legacy-ids.json` | Space and item UUIDs mapped from legacy ids, and `is_uuid` cases |
| `dedup-normalise.json` | Raw item values in, canonical tag inputs and tags out: the normalisation of duplicate tags |
| `phrase.json` | The five-word device-approval phrase for several kx1 public keys, with the 13-bit groups and word indexes |
| `private-keys.json` | The account's sealed kx1 and sig1 private keys under the user key's `private-keys` child |
| `prf-wrap.json` | The passkey PRF wrap of the root key: salt, wrap key, aad, wrapped key |
| `confirm.json` | Member confirmation: the 134-byte statement, the member's bundle and fingerprint behind it, the confirmer's sig1 signature, and the statements it must not cover |
| `item-write.json` | Signed item writes: the envelope hash of a live write (`SHA-256(u32be(key version) ‖ lp(ciphertext) ‖ lp(item key))`, zero for a tombstone), the statement, the writer's sig1 signature, the 3,393-byte stored form, and the statements it must not cover |
| `send.json` | Sends: the link, the payload and meta keys and the proof salt from the link key, the sealed payload, meta and link key with their AADs, the Argon2id password proof (also from a decomposed password), and a KMA1 file under the payload key |
| `space-chain.json` | The space chain: the labelled hash link of the spec's two examples, records that must be refused as malformed, the record signing input and signature, seal commitments with real boxes (digest, key check, aad), and the chains of the spec's test cases, each with the verdict a verifier must give |

| `space-names.json` | Names of a space, a collection and a group sealed as `kem1` envelopes under the space key's `kemlock/v1/space-name` child: the name key, the aad, the ciphertext, a rename under one key version and a second key version |
| `rotation.json` | Rotating the root key: an item opened under the old item-wrap key and sealed again under a fresh item key at revision + 1 (old and new envelopes, wraps and aads), a Send moved to the new item-wrap key, the password and PRF wraps of the new root key at the new key version, and the new key pair, its bundle and the old pair sealed under the new user key |

`SHA256SUMS` lists the files in `sha256sum -c` format.

## Licences

Everything in this folder is CC0-1.0 except `public_suffix_list.dat`. That file is an unmodified
snapshot of the Public Suffix List and is licensed MPL-2.0, not CC0; keep its header and licence
with it when you copy it. [`LICENSE`](LICENSE) says the same. The repository's top-level `NOTICE`
lists all third-party material.

## What a client checks

- **kx1, sealed-box, bundle**: derive the public key from the private key (ML-KEM-1024 from the
  64-byte seed `d ‖ z`, FIPS 203 `KeyGen_internal`; X25519), decapsulate the ciphertext and get the
  shared secret, open the box under its context, and refuse it under every context in
  `wrong_contexts`. `changed_ciphertexts` must decapsulate to the listed secrets: ML-KEM rejects
  implicitly, so a changed ciphertext gives another secret and not an error.
- **sealed-box** aads: rebuild `aad` from `aad_parts` as the contexts table in `docs/crypto.md`
  says (device-approval: account id ‖ request id, 32 bytes; space-key: space id ‖ `u32be` key
  version ‖ recipient id, 36; collection-key: space id ‖ collection id ‖ `u32be` key version ‖
  recipient id, 52; emergency-access: the contact's id, 16; account-recovery: space id ‖ account id ‖
  `u64be` seq of the record that set the recovery key, 40, sealing a 64-byte root key), and refuse the box under an aad with
  any byte changed.
- **sig1**: derive the public key from the seeds, verify the signature, and fail on another
  context, a changed message and a changed signature byte in either half. ML-DSA signatures in
  these files are deterministic; hedged ones verify the same.
- **sig1-edge**: for each case, check that the key passes or fails the parse-time key check
  (`key_ok`) and that verification of `public_key`, `message` and `signature` gives `valid`, with
  the rule of `docs/crypto.md` ("Ed25519 verification rule"). A library that only checks the
  signature equation will accept the small-order cases; it must not.
- **opaque**: replay the exchange with the listed random inputs and compare every message. The
  blind scalars are 32-byte little-endian scalars; the server also draws a 64-byte dummy masking
  key before the masking nonce (RFC 9807 vectors don't list it). The configuration is that of
  RFC 9807 appendix C, vector 1, except for the context `kemlock/v1/opaque`.
- **dedup**: values are given already normalised. **dedup-normalise**: run each case's raw values
  through your normaliser and compare the canonical inputs and tags. It needs
  `public_suffix_list.dat` (the Public Suffix List, MPL-2.0, not CC0; its SHA-256 is in
  `docs/crypto.md`). Lower case is the simple mapping, never the language's full or locale-aware one.
- **phrase**: hash the key, read five 13-bit groups, take each modulo 7776 into EFF's large list
  (SHA-256 in `docs/crypto.md`) and compare.
- **confirm**: rebuild the statement from the space, member, key version, the fingerprint of
  `member_bundle` and the confirmer, compare it with `statement`, and verify `signature` under
  the confirmer's public key with context `confirm`. It must fail under every `wrong_contexts`
  entry and over every `changed_statements` entry (one field changed each), and with any byte of
  the statement or signature flipped.
- **item-write**: rebuild `envelope_hash` from `key_version`, `ciphertext` and `item_key` (32 zero bytes
  for a tombstone), then the statement from `owner`, `item_id`, `kind`, `revision`, `revision - 1`,
  `deleted`, the hash, `writer` and `writer_key_version`, compare it with `statement`, and verify
  `signature` under `writer_public_key` with context `item-write`. It must fail under every
  `wrong_contexts` entry and over every `changed_statements` entry. `stored` is `writer ‖
  u32be(writer_key_version) ‖ signature`.
- **send**: derive the payload key and the salt from `link_key` and the meta key from `wrap_key` (never
  from `link_key`) by their labels, rebuild each aad from `send_id`
  and `kind`, open `payload`, `meta` and `sealed_key` (the first four bytes of `sealed_key` are the key
  version), and refuse them under another id, kind, key or key version. Derive `proof` from the NFC
  password and the salt, and open `file` (a `KMA1` file) under `payload_key`. `link` is
  `/#/send/<access_id>/<link_key in base64url>`.
- **space-names**: derive `name_key` from `space_key` by the label `kemlock/v1/space-name`, rebuild
  the aad from `id`, `key_version`, `kind` and `owner` (`0x02 ‖ space_id`), open `ciphertext` to
  `text` (UTF-8, not JSON), and refuse it under another space, id, kind, key version, or under the
  space key itself.
- **private-keys**, **prf-wrap**: derive the key, rebuild the aad, open the blob, and refuse it under
  another account, key version, credential or key.

## Regenerating

The files are generated, never edited. From the repository root:

```sh
cargo run -p kemlock-crypto --features vectors --bin kemlock-vectors -- --out test-vectors
```

The generator uses the RustCrypto backend with a ChaCha20 stream seeded per file from
`SHA-256("kemlock-vectors/<file>")`, so the output is identical on every run. CI regenerates it and
fails on any difference, and `kemlock-crypto`'s tests check every committed vector against both
backends (aws-lc-rs and RustCrypto). A format change that alters any byte here needs a new format
label in `docs/crypto.md`, not a regenerated file.

## Using them

Copy the folder (or just the `.json` files and `SHA256SUMS`) into the client's test fixtures and
check the sums when you update. Keep the `LICENSE` with them.

`openapi.json` is the `/kem/v1` OpenAPI 3.1 document the server serves at `GET /kem/v1/openapi.json`,
for clients' contract tests to check against without building the server. It is not generated by
`kemlock-vectors`: `kemlock-api-kem`'s test `the_committed_openapi_file_is_the_served_document` fails
when it goes stale, and `KEMLOCK_WRITE_OPENAPI=1` rewrites it (then update its line in `SHA256SUMS`).
