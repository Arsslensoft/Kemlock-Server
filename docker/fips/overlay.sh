#!/bin/sh
# The FIPS build's dependency overlay: pins aws-lc-rs to one 1.17.x release without its default
# backend, turns on kemlock-crypto's `fips` feature for every crate that uses it, and moves
# Cargo.lock to match, inside the build container only.
#
#   sh docker/fips/overlay.sh 1.17.4 /out
#
# The repository's Cargo.toml and Cargo.lock are not touched: the main build stays on aws-lc-rs
# 1.19, and this overlay is applied to a copy in docker/Dockerfile.fips. The lock difference is
# written to <out>/fips-overlay.diff and goes into the image and the release, so what the FIPS
# build resolved can be audited against the main lockfile.
#
# Two edits to the workspace Cargo.toml, because a cargo feature can't say "this build only" for a
# dependency's default features or a pin:
#   - aws-lc-rs: `=<pin>` and `default-features = false`, so the non-FIPS `aws-lc-sys` backend is
#     not built beside the FIPS one. It does not enable aws-lc-rs's `fips` feature itself;
#   - kemlock-crypto: `features = ["fips"]`, which turns on aws-lc-rs/fips and RustCrypto's ml-dsa
#     for ML-DSA-65 (which no aws-lc-rs FIPS build has). The build is then refused at compile time
#     if aws-lc-rs isn't on the FIPS module, or if `rustcrypto` is on beside `fips`.
set -eu

pin="${1:?usage: overlay.sh <aws-lc-rs version, e.g. 1.17.4> <output dir>}"
out="${2:?usage: overlay.sh <aws-lc-rs version> <output dir>}"

case "$pin" in
  1.17.*) ;;
  *) echo "overlay.sh: the FIPS image is pinned to aws-lc-rs 1.17.x, not $pin" >&2; exit 1 ;;
esac

grep -q '^aws-lc-rs = ' Cargo.toml || {
  echo "overlay.sh: no 'aws-lc-rs = ' line in the workspace Cargo.toml" >&2
  exit 1
}
grep -q '^kemlock-crypto = { path = "crates/kemlock-crypto", default-features = false }$' Cargo.toml || {
  echo "overlay.sh: the workspace Cargo.toml's kemlock-crypto line is not the one this overlay edits" >&2
  exit 1
}

mkdir -p "$out"
cp Cargo.lock "$out/Cargo.lock.main"

# `unstable` stays on because the workspace asks for it.
sed -i "s|^aws-lc-rs = .*|aws-lc-rs = { version = \"=${pin}\", default-features = false, features = [\"alloc\", \"ring-io\", \"ring-sig-verify\", \"unstable\"] }|" Cargo.toml
sed -i 's|^kemlock-crypto = { path = "crates/kemlock-crypto", default-features = false }$|kemlock-crypto = { path = "crates/kemlock-crypto", default-features = false, features = ["fips"] }|' Cargo.toml

cargo update -p aws-lc-rs --precise "$pin"

diff -u "$out/Cargo.lock.main" Cargo.lock > "$out/fips-overlay.diff" || true
rm "$out/Cargo.lock.main"

# Fails when the FIPS module is not in the tree, so a mistake here cannot ship as a normal build.
cargo tree --locked -i aws-lc-fips-sys > "$out/fips-tree.txt"
if cargo tree --locked -i aws-lc-sys > /dev/null 2>&1; then
  echo "overlay.sh: the non-FIPS aws-lc-sys is still in the tree" >&2
  cat "$out/fips-tree.txt" >&2
  exit 1
fi
# kemlock-crypto must be built with `fips`, or aws-lc-rs would have no backend (or, worse, the
# formats would not route ML-DSA to RustCrypto).
cargo tree --locked -e features -i kemlock-crypto > "$out/fips-features.txt"
grep -q 'feature "fips"' "$out/fips-features.txt" || {
  echo "overlay.sh: kemlock-crypto is not built with its fips feature" >&2
  cat "$out/fips-features.txt" >&2
  exit 1
}
echo "overlay.sh: aws-lc-rs ${pin} with aws-lc-fips-sys; lock difference in $out/fips-overlay.diff"
