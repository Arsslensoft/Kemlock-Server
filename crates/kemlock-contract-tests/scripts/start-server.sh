#!/usr/bin/env bash
# Starts a built kemlock-server for the apps' own tests, with Bitwarden compatibility and signups on,
# and waits until it answers /alive.
#
#   start-server.sh <binary> <domain> <port> <data-folder> [default-limits]
#
# <domain> is the address the apps use (DOMAIN): the Kemlock app's security-key tests and the
# attachment addresses need it to be the address the tests are given. With a fifth argument of
# `default-limits` the login rate limits stay at the server's own defaults; otherwise they are
# raised, since the suites sign in far more often than a person does.
set -euo pipefail

binary=$1
domain=$2
port=$3
data=$4
limits=${5:-raised}

mkdir -p "$data"
env_limits=()
if [ "$limits" != "default-limits" ]; then
  env_limits=(
    LOGIN_RATELIMIT_SECONDS=1 LOGIN_RATELIMIT_MAX_BURST=100000
    UNAUTHENTICATED_RATELIMIT_SECONDS=1 UNAUTHENTICATED_RATELIMIT_MAX_BURST=100000
  )
fi

env DOMAIN="$domain" ROCKET_ADDRESS=127.0.0.1 ROCKET_PORT="$port" DATA_FOLDER="$data" \
  SIGNUPS_ALLOWED=true SIGNUPS_VERIFY=false KEMLOCK_BITWARDEN_COMPAT=true LOG_LEVEL=info \
  "${env_limits[@]}" \
  nohup "$binary" >"$data/server.log" 2>&1 &
echo $! >"$data/server.pid"

for _ in $(seq 1 90); do
  if curl -fsS "http://127.0.0.1:$port/alive" >/dev/null 2>&1; then
    echo "kemlock-server answers on 127.0.0.1:$port for $domain"
    exit 0
  fi
  sleep 1
done
echo "kemlock-server did not answer /alive in 90 seconds; its log:" >&2
cat "$data/server.log" >&2
exit 1
