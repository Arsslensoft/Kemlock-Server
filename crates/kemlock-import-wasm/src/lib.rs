//! The web vault's import worker: `kemlock-import` compiled to WebAssembly and exposed through
//! wasm-bindgen as three functions, so a file is read and an export written inside the browser and
//! never reaches the server.
//!
//! - `detect(bytes)`: which format the bytes are and whether they need a password, as the JSON
//!   `{"format": "...", "encrypted": true}`;
//! - `parse(bytes, format?, password?, keyFile?)`: the `ImportBatch` as the crate's own JSON
//!   (snake_case fields, kebab-case enum values, file bytes as standard base64);
//! - `exportEncrypted(kind, itemsJson, password)`: the bytes of a password-protected export of
//!   `kind` (`bitwarden-json` or `kemlock-json`), written by `kemlock_import::bitwarden_export`.
//!
//! Every failure is an `Error` whose message is one of `ImportErrorCode`'s names in
//! web/src/import/contract.ts (`too-large`, `bad-password` and the rest) and nothing more. A
//! password never leaves the call: its copy here is wiped when the call ends.
//!
//! This is its own module beside `kemlock-wasm` so the import code (rPGP, KeePass, the parsers) is
//! only downloaded when someone imports, and the crypto worker that holds keys stays small. The
//! logic is plain Rust in [`ops`] and tested natively; `wasm.rs` is the JavaScript skin.

mod ops;
mod wasm;

#[cfg(all(test, target_arch = "wasm32"))]
mod tests;
