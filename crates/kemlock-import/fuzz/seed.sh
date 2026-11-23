#!/usr/bin/env bash
# Seeds each target's corpus from the hand-made fixtures, then run e.g.:
#   cargo +nightly fuzz run chrome -- -max_total_time=60
# A pull request runs every target briefly; a nightly run goes longer from the same seeds.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
fixtures="$here/../tests/fixtures"
seed() { # target, fixture folder
  mkdir -p "$here/corpus/$1"
  find "$fixtures/$2" -type f ! -name '*.mjs' -exec cp {} "$here/corpus/$1/" \;
}
for t in chrome safari firefox lastpass nordpass roboform keeper enpass protonpass kdbx; do seed "$t" "$t"; done
seed bitwarden bitwarden; seed bitwarden_csv bitwarden; seed onepassword onepassword
seed onepassword_csv onepassword; seed dashlane dashlane; seed detect .; seed csv .
seed zip dashlane; seed zip onepassword
mkdir -p "$here/corpus/encstring"
grep -rho '2\.[A-Za-z0-9+/=]*|[A-Za-z0-9+/=]*|[A-Za-z0-9+/=]*' "$fixtures/bitwarden" | sort -u | \
  awk '{ print > ("'"$here"'/corpus/encstring/seed" NR) }'
