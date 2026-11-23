#!/usr/bin/env bash
# The scripted SSO gate: "an SSO user opens the vault with no password", against a real Keycloak.
#
#   tools/sso-gate/run.sh
#
# Starts Keycloak with the `kemlock` realm (docker-compose.yml), waits until it answers, runs the
# `sso_keycloak` test of kemlock-server against it, and stops Keycloak again. The test builds the
# real server in process, plays the browser (Keycloak's login page), signs a phone in through SSO,
# makes and wraps a root key on the device, signs in again, and opens an item sealed before.
#
# Environment:
#   CARGO         how to run cargo (default `cargo`). On a machine without a Rust toolchain use
#                 CARGO=tools/cargo.sh with KEMLOCK_SSO_GATE_ISSUER pointing at an address the
#                 container reaches, such as http://host.docker.internal:8180/realms/kemlock.
#   KEMLOCK_SSO_GATE_ISSUER   the realm's issuer URL (default http://localhost:8180/realms/kemlock)
#   KEEP_KEYCLOAK=1           leave Keycloak running afterwards
#   WAIT_SECONDS              how long to wait for Keycloak (default 180)
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
compose=(docker compose -f "$here/docker-compose.yml")
cargo_cmd="${CARGO:-cargo}"
issuer="${KEMLOCK_SSO_GATE_ISSUER:-http://localhost:8180/realms/kemlock}"
wait_seconds="${WAIT_SECONDS:-180}"
# Where this script reaches Keycloak, whatever address the test uses.
probe="http://localhost:8180/realms/kemlock/.well-known/openid-configuration"

cleanup() {
  status=$?
  if [ "${KEEP_KEYCLOAK:-0}" != "1" ]; then
    "${compose[@]}" down -v >/dev/null 2>&1 || true
  fi
  exit "$status"
}
trap cleanup EXIT

"${compose[@]}" up -d

echo "waiting for Keycloak at $probe (up to ${wait_seconds}s)"
deadline=$(( $(date +%s) + wait_seconds ))
until curl -fsS "$probe" >/dev/null 2>&1; do
  if [ "$(date +%s)" -ge "$deadline" ]; then
    echo "Keycloak didn't come up in ${wait_seconds}s; its log:" >&2
    "${compose[@]}" logs --tail 60 keycloak >&2 || true
    exit 1
  fi
  sleep 3
done
echo "Keycloak is up"

cd "$repo"
export KEMLOCK_SSO_GATE_ISSUER="$issuer"
# shellcheck disable=SC2086
$cargo_cmd test -p kemlock-server --test sso_keycloak -- --nocapture
echo "the SSO gate passed against Keycloak ($issuer)"
