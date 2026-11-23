#!/usr/bin/env bash
# Seeds each target's corpus, then run e.g.:
#   cargo +nightly fuzz run restore -- -max_total_time=60
# A pull request runs every target briefly and a nightly run goes longer, both from these seeds
# (.github/workflows/fuzz.yml).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
seed() { mkdir -p "$here/corpus/$1"; cat >"$here/corpus/$1/$2"; }

printf '\000age-encryption.org/v1\n-> X25519 AAAA\nBBBB\n--- CCCC\n' | seed restore header
printf '\001(\265/\375 \000\001\000\000' | seed restore zstd-frame
printf '\002' | seed restore tar-empty
printf '{"format":1,"createdAt":"2026-11-23T03:00:00Z","kemlockVersion":"0.1.0","database":"sqlite","migrations":["m1"],"tables":[{"name":"users","rows":2,"columns":["id"]}],"files":[{"path":"data/server.key","size":3,"sha256":"00"}],"attachments":"external"}' | seed manifest manifest
printf 'age1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqy3pjsq4' | seed keys recipient
printf '# created: 2026-11-23\n# public key: age1x\nAGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ' | seed keys identity
