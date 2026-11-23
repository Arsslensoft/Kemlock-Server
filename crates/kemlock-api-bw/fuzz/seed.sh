#!/usr/bin/env bash
# Seeds each target's corpus, then run e.g.:
#   cargo +nightly fuzz run cipher_request -- -max_total_time=60
# A pull request runs every target briefly and a nightly run goes longer, both from these seeds
# (.github/workflows/fuzz.yml).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
fixtures="$here/../tests/fixtures"
seed() { mkdir -p "$here/corpus/$1"; cat >"$here/corpus/$1/$2"; }

# EncStrings of the accounts Vaultwarden made, whole: the name, notes and key of a cipher.
mkdir -p "$here/corpus/enc_string"
grep -rho '2\.[A-Za-z0-9+/=]*|[A-Za-z0-9+/=]*|[A-Za-z0-9+/=]*' "$fixtures" | sort -u | head -n 200 |
  awk '{ print > ("'"$here"'/corpus/enc_string/seed" NR) }'

seed cipher_request login <<'JSON'
{"encryptedFor":"00000000-0000-0000-0000-000000000000","type":1,"name":"2.AAAA|BBBB|CCCC","notes":null,"favorite":false,"reprompt":0,"folderId":"","key":"2.AAAA|BBBB|CCCC","login":{"username":"2.AAAA|BBBB|CCCC","password":"2.AAAA|BBBB|CCCC","uris":[{"uri":"2.AAAA|BBBB|CCCC","match":"1"}],"passwordRevisionDate":"2026-11-07T10:00:00Z"},"fields":[{"name":"2.AAAA|BBBB|CCCC","value":"2.AAAA|BBBB|CCCC","type":"1"}],"passwordHistory":[{"password":"2.AAAA|BBBB|CCCC","lastUsedDate":"2026-11-07T10:00:00Z"}],"lastKnownRevisionDate":"2026-11-07T10:00:00Z"}
JSON
seed cipher_request note <<'JSON'
{"encryptedFor":"u","type":2,"name":"2.AAAA|BBBB|CCCC","secureNote":{"type":0},"attachments2":{"a":{"fileName":"2.AAAA|BBBB|CCCC","key":"2.AAAA|BBBB|CCCC"}}}
JSON
seed cipher_request ssh <<'JSON'
{"encryptedFor":"u","type":5,"name":"n","sshKey":{"privateKey":"p","publicKey":"q","keyFingerprint":"f"}}
JSON
seed stored_cipher login <<'JSON'
{"id":"00000000-0000-0000-0000-000000000000","type":1,"creationDate":"2026-11-07T10:00:00.000000Z","revisionDate":"2026-11-07T10:00:00.000000Z","deletedDate":null,"reprompt":0,"key":null,"name":"2.AAAA|BBBB|CCCC","notes":null,"fields":null,"passwordHistory":null,"data":{"Username":"x","Uris":[{"Uri":"y","Match":"0"}]},"folderId":null,"favorite":false,"archivedDate":null,"attachments":[{"id":"a","fileName":"f","size":3,"key":null}]}
JSON
mkdir -p "$here/corpus/client_version"
n=0
for v in 2024.12.0 2026.6.0 2024.11.9 2025.1.0-beta.1 1.2; do
  n=$((n + 1))
  printf "%s" "$v" >"$here/corpus/client_version/seed$n"
done
