//! The web vault's crypto: `kemlock-crypto` on its RustCrypto backend, compiled to WebAssembly and
//! exposed through wasm-bindgen as one class, [`Vault`].
//!
//! The design keeps every key in a WebAssembly worker that React never reads from. So no key ever
//! crosses into JavaScript except the wrapped forms the server stores: master keys, OPAQUE export
//! keys and half-finished OPAQUE exchanges are handles (numbers) into a table here; an unlocked
//! account's keys live in this module's memory, and `lock` wipes them. What does cross is what the
//! server stores or sees (base64url strings: OPAQUE messages, the public bundle, its signature,
//! the sealed private keys, the wrapped root key, an item's ciphertext and wrapped item key), a
//! decrypted item's JSON for the page to show, and fingerprints and TOTP enrolment for the page
//! to display.
//!
//! - [`session`]: the state and the operations, in plain Rust.
//! - [`wasm`]: the JavaScript skin (`Vault`).
//! - [`sends`](mod@sends): Sends (`docs/crypto.md`), where the one key that leaves WebAssembly lives,
//!   the link key, because it belongs in a URL's fragment;
//! - `approval`: a new device's one-time key and the root key an approval seals to it;
//! - `prf`: the passkey PRF wrap of the root key;
//! - `kit`: the Recovery Kit, a 2-of-3 split of a key that wraps the root key;
//! - `manifests`: signing and checking the signed manifest;
//! - `sharing`: sealing the root key, the member confirmation and a released emergency key;
//! - `spaces`: a space's keys and their encrypted names;
//! - `chain`: a space's signed chain, verified, and the keys opened only through it;
//! - `chain_build`: the records of a space's chain made here, signed, and checked before they leave;
//! - `b64`, `ids`, `totp`, `error`: small pieces of both.
//!
//! The formats are `docs/crypto.md`'s, and `kemlock_crypto::private_keys` adds the layout of the
//! sealed private keys. Tests that run `kx1` live in `src/tests.rs` and run in WebAssembly
//! (`wasm-pack test --node crates/kemlock-wasm`), where the RustCrypto backend is the only one.

mod approval;
mod b64;
mod chain;
mod chain_build;
mod error;
mod ids;
mod kit;
mod manifests;
mod prf;
mod rotation;
mod sends;
mod session;
mod sharing;
mod spaces;
mod totp;
mod wasm;

pub use wasm::Vault;

#[cfg(all(test, target_arch = "wasm32"))]
mod tests;
