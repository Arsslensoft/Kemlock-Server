#!/usr/bin/env bash
# Seeds each target's corpus, then run e.g.:
#   cargo +nightly fuzz run sync_batch -- -max_total_time=60
# A pull request runs every target briefly and a nightly run goes longer, both from these seeds
# (.github/workflows/fuzz.yml).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
seed() { mkdir -p "$here/corpus/$1"; cat >"$here/corpus/$1/$2"; }

item='{"id":"018f0000-0000-7000-8000-000000000001","owner":"user:018f0000-0000-7000-8000-000000000002","kind":"login","format":"kem1","revision":1,"keyVersion":1,"ciphertext":"AAAA","itemKey":"BBBB","deleted":false}'
tomb='{"id":"018f0000-0000-7000-8000-000000000001","owner":"user:018f0000-0000-7000-8000-000000000002","kind":"login","format":"kem1","revision":2,"keyVersion":1,"deleted":true,"deletedAt":"2026-11-07T10:00:00Z"}'
printf '%s' "$item" | seed item_dto item
printf '%s' "$tomb" | seed item_dto tombstone
printf '{"writes":[{"expectedRevision":null,"item":%s},{"expectedRevision":1,"item":%s}]}' "$item" "$tomb" | seed sync_batch batch
printf '{"since":"AgAA","limit":500}' | seed sync_batch query-v2
printf '{"since":"AQAA"}' | seed sync_batch query-v1

# A proof or token to refuse, and a claims object to lay over a valid one (odd first byte).
printf '\000eyJhbGciOiJFZERTQSJ9.e30.AAAA' | seed dpop raw
printf '\001{}\n{"jti":"proof-2","htm":"GET"}' | seed dpop overlay
printf '\001{"typ":"dpop+jwt"}\n{"iat":1800000100}' | seed dpop overlay-iat
printf '\000eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCJ9.e30.AAAA' | seed jws raw
printf '\001{"exp":1800000000}' | seed jws overlay-expired
printf '\001{"adm":true,"cnf":{"jkt":"x"}}' | seed jws overlay-admin
