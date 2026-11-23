#!/usr/bin/env bash
# Writes THIRD-PARTY-NOTICES.txt at the repository root: the licence texts of the Rust crates and
# the npm packages that end up in the binaries. Release archives and images ship it beside LICENSE
# and NOTICE (the MIT, BSD, Apache-2.0, ISC and OFL licences require their text to accompany
# binary copies); the server serves it at /THIRD-PARTY-NOTICES.txt.
#
#   cargo install --locked --version 0.9.3 cargo-about     # once; CARGO_ABOUT_VERSION below
#   (cd web && npm ci --omit=dev --ignore-scripts)          # the web licence texts are read from node_modules
#   tools/third-party-notices.sh
#
# It fails when a crate's licence is not in about.toml's accepted list (the same list as
# deny.toml), when a crate has no licence text, or when a runtime npm package has none, so a new
# dependency with an unhandled licence is caught here. Set SKIP_WEB=1 where web/ has no lockfile.
set -euo pipefail

CARGO_ABOUT_VERSION="0.9.3"

here="$(cd "$(dirname "$0")/.." && pwd)"
cd "$here"
out="${1:-THIRD-PARTY-NOTICES.txt}"
die() { echo "third-party-notices: $*" >&2; exit 1; }

command -v cargo >/dev/null || die "cargo is needed"
command -v node >/dev/null || die "node is needed"
cargo about --version >/dev/null 2>&1 \
  || die "cargo-about is needed: cargo install --locked --version $CARGO_ABOUT_VERSION cargo-about"
found="$(cargo about --version | awk '{print $2}')"
[ "$found" = "$CARGO_ABOUT_VERSION" ] \
  || echo "third-party-notices: warning: cargo-about $found, pinned $CARGO_ABOUT_VERSION" >&2

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# 1. The Rust crates: each licence text once, with the crates that use it.
cargo about generate --workspace --all-features --locked --fail about.hbs > "$work/rust.txt"

# 2. Apache-2.0 crates may carry a NOTICE file that has to travel too; cargo-about only gathers
#    licence files. Take the NOTICE files of the crates cargo-about listed.
cargo about generate --workspace --all-features --locked --fail --format json > "$work/about.json"
cargo metadata --format-version 1 --locked > "$work/metadata.json"
node - "$work/about.json" "$work/metadata.json" > "$work/rust-notice-files.txt" <<'JS'
import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';

const [aboutPath, metadataPath] = process.argv.slice(2);
const about = JSON.parse(readFileSync(aboutPath, 'utf8'));
const metadata = JSON.parse(readFileSync(metadataPath, 'utf8'));
const dirs = new Map(metadata.packages.map((p) => [`${p.name} ${p.version}`, dirname(p.manifest_path)]));

const used = new Set();
for (const licence of about.licenses) {
  for (const user of licence.used_by) used.add(`${user.crate?.name} ${user.crate?.version}`);
}
const sections = [];
for (const key of [...used].sort()) {
  const dir = dirs.get(key);
  if (!dir) continue;
  for (const file of readdirSync(dir).filter((f) => /^notice(?:[-._].*)?$/i.test(f)).sort()) {
    const text = readFileSync(join(dir, file), 'utf8').replace(/\r\n?/g, '\n').trim();
    sections.push(`${'-'.repeat(90)}\n${key}: ${file}\n${'-'.repeat(90)}\n\n${text}\n`);
  }
}
if (sections.length > 0) {
  console.log('NOTICE files of the Rust crates\n===============================\n');
  console.log(sections.join('\n'));
}
JS

# 3. The web vault's npm packages (web/scripts/third-party-notices.mjs exits 1 on a missing text).
if [ -f web/package-lock.json ] && [ "${SKIP_WEB:-0}" != 1 ]; then
  (cd web && node scripts/third-party-notices.mjs) > "$work/web.txt" \
    || die "the web licence texts are incomplete (did you run npm ci in web/?)"
else
  echo "third-party-notices: no web/package-lock.json or SKIP_WEB=1: leaving the web section empty" >&2
  echo "The web vault is not part of this build." > "$work/web.txt"
fi

{
  cat <<'HEADER'
KEMLOCK SERVER: THIRD-PARTY NOTICES
===================================

Kemlock Server is licensed AGPL-3.0-only (LICENSE). The binaries and the web vault in this
distribution include the third-party software below, each under its own licence. NOTICE lists the
third-party files that are part of the repository itself.

Part 1: Rust crates
Part 2: web vault npm packages (including the Geist fonts, SIL Open Font License 1.1)

HEADER
  echo
  echo "##########################################################################################"
  echo "# PART 1: RUST CRATES"
  echo "##########################################################################################"
  echo
  cat "$work/rust.txt"
  echo
  cat "$work/rust-notice-files.txt"
  echo
  echo "##########################################################################################"
  echo "# PART 2: WEB VAULT NPM PACKAGES"
  echo "##########################################################################################"
  echo
  cat "$work/web.txt"
} > "$out"
echo "wrote $out"
