#!/usr/bin/env bash
# Runs cargo-audit on the Cargo.lock in the current directory and opens one GitHub issue for each
# advisory that has none yet (open or closed), so a new advisory is reported once.
#
#   tools/audit-issues.sh <ref label>      e.g. main, or v1.2.3
#
# Needs cargo-audit, jq and gh, and GH_TOKEN with `issues: write`. Exits 1 when an advisory is
# found, so the workflow run fails as well.
set -euo pipefail

label="${1:?usage: audit-issues.sh <ref label>}"
repo="${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is not set}"

report="$(mktemp)"
cargo audit --json >"$report" || true

# Vulnerabilities and warnings (unmaintained, unsound) that carry an advisory; a bare yanked
# warning has none and is left to cargo-deny.
rows="$(jq -r '
  [ (.vulnerabilities.list // [])[], ((.warnings // {}) | to_entries[].value[]) ]
  | .[] | select(.advisory != null)
  | [ .advisory.id, .package.name, .package.version, .advisory.title, (.advisory.url // "") ]
  | @tsv' "$report")"

if [ -z "$rows" ]; then
  echo "cargo-audit: no advisories for $label"
  exit 0
fi

gh label create security --repo "$repo" --color B60205 \
  --description "A security advisory or report" 2>/dev/null || true

status=0
while IFS=$'\t' read -r id crate version title url; do
  echo "::error title=$id::$crate $version: $title ($label)"
  status=1
  # One issue per advisory and crate, whichever ref found it.
  marker="$id in $crate"
  existing="$(gh issue list --repo "$repo" --state all --label security \
    --search "\"$marker\" in:title" --json number --jq 'length')"
  if [ "$existing" != "0" ]; then
    continue
  fi
  gh issue create --repo "$repo" --label security \
    --title "$marker: $title" \
    --body "cargo-audit found [$id]($url) in \`$crate\` $version in the dependencies of \`$label\`.

Update or replace the crate, or, if the advisory does not apply, record why in \`deny.toml\` and
\`.cargo/audit.toml\` before closing this issue. This issue was opened by the nightly audit workflow."
done <<<"$rows"
exit "$status"
