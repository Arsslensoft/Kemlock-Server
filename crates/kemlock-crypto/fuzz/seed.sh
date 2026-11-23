#!/usr/bin/env bash
# Seeds each target's corpus, then run e.g.:
#   cargo +nightly fuzz run opaque_server -- -max_total_time=60
# A pull request runs every target briefly and a nightly run goes longer, both from these seeds
# (.github/workflows/fuzz.yml).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
vectors="$here/../../../test-vectors/opaque.json"
# First byte: the message (see the targets), then the bytes of the test vectors' messages.
field() { grep -m1 -o "\"$1\": *\"[0-9a-f]*\"" "$vectors" | cut -d'"' -f4; }
seed() { # target, first byte (octal), field
  mkdir -p "$here/corpus/$1"
  { printf "\$2"; field "$3" | xxd -r -p; } >"$here/corpus/$1/$3"
}
seed opaque_server 000 server_setup
seed opaque_server 001 request
seed opaque_server 002 record
seed opaque_server 003 ke1
seed opaque_client 000 response
seed opaque_client 001 ke2
