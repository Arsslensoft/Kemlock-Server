#!/usr/bin/env bash
# Runs cargo in a Rust container, for machines without a Rust toolchain.
#
#   tools/cargo.sh build
#   tools/cargo.sh test --workspace
#   tools/cargo.sh 'cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings'
#
# The registry and the target directory live in Docker volumes
# (kemlock-cargo-registry, kemlock-server-target), never in the checkout, so
# a synced folder doesn't copy gigabytes of build output. The container is
# capped at CARGO_CPUS (6) and CARGO_MEMORY (8g) so the machine stays usable,
# and only one build runs at a time: a second call waits for the first.
set -euo pipefail

here="$(cd "$(dirname "$0")/.." && pwd)"
image="${RUST_IMAGE:-rust:1}"
cpus="${CARGO_CPUS:-6}"
memory="${CARGO_MEMORY:-8g}"
lock="${TMPDIR:-/tmp}/kemlock-server-cargo.lock"

if [ $# -eq 0 ]; then
  echo "usage: tools/cargo.sh <cargo args> | '<shell command>'" >&2
  exit 2
fi

# One argument with a space or a shell operator is a command line; otherwise
# the arguments go to cargo.
if [ $# -eq 1 ] && [[ "$1" == *" "* || "$1" == *"&&"* ]]; then
  cmd="$1"
else
  cmd="cargo $*"
fi

# Git Bash on Windows rewrites /paths; keep the container's paths as written.
export MSYS_NO_PATHCONV=1

exec 9>"$lock"
flock 9 2>/dev/null || true

docker run --rm \
  --cpus "$cpus" --memory "$memory" \
  -v "$here":/work \
  -v kemlock-cargo-registry:/usr/local/cargo/registry \
  -v kemlock-server-target:/target \
  -e CARGO_TARGET_DIR=/target \
  -e CARGO_TERM_COLOR=always \
  -w /work \
  "$image" bash -c "rustup show active-toolchain >/dev/null 2>&1 || true; $cmd"
