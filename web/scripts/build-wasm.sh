#!/usr/bin/env bash
# Builds the two WebAssembly modules for the browser, then shrinks and speeds each with wasm-opt:
#
#   crates/kemlock-wasm         -> web/src/crypto/pkg  (the crypto worker: every key)
#   crates/kemlock-import-wasm  -> web/src/import/pkg  (the import worker: files and exports)
#
# Both output folders are git-ignored.
#
#   web/scripts/build-wasm.sh          build both modules
#   web/scripts/build-wasm.sh test     run both crates' WebAssembly tests under node
#
# Needs wasm-pack (which fetches the wasm-bindgen CLI that matches Cargo.lock) and wasm-opt from
# binaryen, and the wasm32-unknown-unknown target (`rustup target add wasm32-unknown-unknown`).
# getrandom's `wasm_js` backend is enabled by each crate's own Cargo.toml, so no RUSTFLAGS are needed.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$root"

if [ "${1:-}" = "test" ]; then
  wasm-pack test --node crates/kemlock-wasm
  exec wasm-pack test --node crates/kemlock-import-wasm
fi

if ! command -v wasm-opt >/dev/null 2>&1; then
  echo "wasm-opt not found: install binaryen (https://github.com/WebAssembly/binaryen)" >&2
  exit 1
fi

# Profiles can only be set in the root manifest, so the release profile is set here: full LTO and
# one codegen unit for the smallest, fastest module (Argon2id is the hot spot), speed over size.
export CARGO_PROFILE_RELEASE_OPT_LEVEL="${CARGO_PROFILE_RELEASE_OPT_LEVEL:-3}"
export CARGO_PROFILE_RELEASE_LTO="${CARGO_PROFILE_RELEASE_LTO:-fat}"
export CARGO_PROFILE_RELEASE_CODEGEN_UNITS="${CARGO_PROFILE_RELEASE_CODEGEN_UNITS:-1}"
export CARGO_PROFILE_RELEASE_PANIC="${CARGO_PROFILE_RELEASE_PANIC:-abort}"

# build <crate> <output folder> <wasm file name>
build() {
  local crate="$1" out="$2" name="$3"
  rm -rf "$out"
  # wasm-pack resolves --out-dir against the crate, so it gets an absolute path.
  wasm-pack build "crates/$crate" --target web --release --out-dir "$out"
  local wasm="$out/$name"
  wasm-opt "-${WASM_OPT_LEVEL:-O3}" --all-features -o "$wasm.opt" "$wasm"
  mv "$wasm.opt" "$wasm"
  ls -l "$wasm"
}

build kemlock-wasm "$root/web/src/crypto/pkg" kemlock_wasm_bg.wasm
build kemlock-import-wasm "$root/web/src/import/pkg" kemlock_import_wasm_bg.wasm
