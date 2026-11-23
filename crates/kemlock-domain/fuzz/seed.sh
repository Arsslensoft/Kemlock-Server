#!/usr/bin/env bash
# Seeds each target's corpus, then run e.g.:
#   cargo +nightly fuzz run sync_cursor -- -max_total_time=60
# A pull request runs every target briefly and a nightly run goes longer, both from these seeds
# (.github/workflows/fuzz.yml).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
seed() { mkdir -p "$here/corpus/$1"; cat >"$here/corpus/$1/$2"; }

# Version 1 (one vector) and version 2 (owners), empty and with one owner and one origin.
printf '\001\000\000' | seed sync_cursor v1-empty
printf '\002\000\000' | seed sync_cursor v2-empty
# One owner (a user, all zero id) with one origin (id 1) at sequence 5.
{
  printf '\002\000\001'
  printf '\000'; head -c 16 /dev/zero
  printf '\000\001'
  head -c 15 /dev/zero; printf '\001'
  head -c 7 /dev/zero; printf '\005'
} | seed sync_cursor v2-one-owner
