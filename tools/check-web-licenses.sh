#!/usr/bin/env bash
# Fails when a production dependency of the web vault has a licence outside the allow-list.
#
#   (cd web && npm ci --omit=dev --ignore-scripts)
#   tools/check-web-licenses.sh
#
# The list is deny.toml's [licenses] allow-list, so a licence the Rust tree may not use is not
# allowed in the npm tree either, plus the two the web vault needs and deny.toml does not:
#   OFL-1.1     the Geist fonts (@fontsource-variable/*), which ship inside the bundle as data
#   Unlicense   isbot, a public-domain dedication
# Dev dependencies are not shipped, so they are not checked here. dependency-review-action
# (.github/workflows/dependency-review.yml) checks what a pull request adds, in both trees.
# Keep this list, deny.toml and the allow-licenses of dependency-review.yml in step.
set -euo pipefail

cd "$(dirname "$0")/../web"
[ -d node_modules ] || { echo "run 'npm ci --omit=dev --ignore-scripts' in web/ first" >&2; exit 2; }

allowed=(
  "AGPL-3.0-only"
  "Apache-2.0"
  "MIT"
  "MIT-0"
  "BSD-2-Clause"
  "BSD-3-Clause"
  "ISC"
  "Zlib"
  "Unicode-3.0"
  "CC0-1.0"
  "OpenSSL"
  "MPL-2.0"
  "CDLA-Permissive-2.0"
  "0BSD"
  "OFL-1.1"
  "Python-2.0"
  "Unlicense"
)
only_allow="$(IFS=';'; echo "${allowed[*]}")"

# The package itself (private, AGPL-3.0-only) is excluded; everything it ships is checked.
exec npx --yes license-checker-rseidelsohn@5.0.1 \
  --start . \
  --production \
  --excludePrivatePackages \
  --onlyAllow "$only_allow" \
  --summary
