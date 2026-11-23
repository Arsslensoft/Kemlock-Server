#!/usr/bin/env bash
# Seeds each target's corpus, then run e.g.:
#   cargo +nightly fuzz run cipher_json -- -max_total_time=60
# A pull request runs every target briefly and a nightly run goes longer, both from these seeds
# (.github/workflows/fuzz.yml).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
seed() { mkdir -p "$here/corpus/$1"; cat >"$here/corpus/$1/$2"; }

printf '1\nname\nnotes\n[{"Name":"n","Value":"v","Type":"1"}]\n[{"Password":"p","LastUsedDate":"2026-11-07T10:00:00Z"}]\nkey\n{"Username":"u","Password":"p","Uris":[{"Uri":"https://example.org","Match":"1"}],"PasswordRevisionDate":"2026-11-07T10:00:00Z"}' | seed cipher_json login
printf '2\nname\n\n\n\n\n{"Type":0}' | seed cipher_json note
printf '5\nname\n\n\n\n\n{"PrivateKey":"a","PublicKey":"b","KeyFingerprint":"c"}' | seed cipher_json ssh
printf '{"domain":"https://vault.example.org","signups_allowed":false,"smtp_password":"x","admin_token":"y","org_creation_users":""}' | seed settings config
printf '[{"id":1,"name":"Key","migrated":false,"credential":{"cred_id":"AAAA","cred":"BBBB"}}]\n[{"keyHandle":"AAAA","name":"Old","reg":"BBBB","counter":0,"migrated":false}]' | seed two_step keys
printf '{"email":"a@example.org","token":"1"}' | seed two_step email
printf '{"Keys":["ccccccccccccc"],"Nfc":true}' | seed two_step yubikey
printf '{"host":"h","ik":"i","sk":"s"}' | seed two_step duo
printf '2024-05-01 10:00:00.123456' | seed times db
printf '2026-11-07T10:00:00+02:00' | seed times rfc3339
