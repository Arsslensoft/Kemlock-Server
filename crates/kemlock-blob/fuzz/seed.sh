#!/usr/bin/env bash
# Seeds each target's corpus, then run e.g.:
#   cargo +nightly fuzz run kma1 -- -max_total_time=60
# A pull request runs every target briefly and a nightly run goes longer, both from these seeds
# (.github/workflows/fuzz.yml).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
fixtures="$here/../tests/fixtures"
mkdir -p "$here/corpus/kma1"
cp "$fixtures/two-chunks.kma1" "$here/corpus/kma1/two-chunks.kma1"
# The small files of kma1.json, base64: empty, short and the other shapes the app wrote.
n=0
for b64 in $(grep -o '"kma1": *"[A-Za-z0-9+/=]*"' "$fixtures/kma1.json" | cut -d'"' -f4); do
  n=$((n + 1))
  printf '%s' "$b64" | base64 -d >"$here/corpus/kma1/fixture$n"
done
