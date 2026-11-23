#!/usr/bin/env bash
# Opens a WebSocket on both routes through one proxy example and checks the message that comes
# back from a stand-in upstream.
#
#   deploy/proxy/test/run.sh caddy|traefik|nginx|haproxy
set -euo pipefail

proxy="${1:?usage: run.sh caddy|traefik|nginx|haproxy}"
here="$(cd "$(dirname "$0")" && pwd)"
dir="$(dirname "$here")"
net="kemlock-proxytest-$proxy"
node_image="node:24-bookworm-slim"
export MSYS_NO_PATHCONV=1

cleanup() {
  docker rm -f "$net-stub" "$net-proxy" >/dev/null 2>&1 || true
  docker network rm "$net" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup
docker network create "$net" >/dev/null

# The stand-in upstream has the name the examples use for Kemlock.
docker run -d --name "$net-stub" --network "$net" --network-alias kemlock \
  -v "$here/stub.mjs":/stub.mjs:ro "$node_image" node /stub.mjs >/dev/null

case "$proxy" in
  caddy)
    docker run -d --name "$net-proxy" --network "$net" --network-alias proxy \
      -e KEMLOCK_HOST=http://:80 -v "$dir/caddy/Caddyfile":/etc/caddy/Caddyfile:ro caddy:2 >/dev/null ;;
  traefik)
    docker run -d --name "$net-proxy" --network "$net" --network-alias proxy \
      -v "$dir/traefik/dynamic.yml":/etc/traefik/dynamic.yml:ro traefik:v3.5 \
      --providers.file.filename=/etc/traefik/dynamic.yml --entrypoints.web.address=:80 >/dev/null ;;
  nginx)
    docker run -d --name "$net-proxy" --network "$net" --network-alias proxy \
      -v "$dir/nginx/kemlock.conf":/etc/nginx/conf.d/default.conf:ro nginx:1 >/dev/null ;;
  haproxy)
    docker run -d --name "$net-proxy" --network "$net" --network-alias proxy \
      -v "$dir/haproxy/haproxy.cfg":/usr/local/etc/haproxy/haproxy.cfg:ro haproxy:3.2 >/dev/null ;;
  *) echo "unknown proxy: $proxy" >&2; exit 2 ;;
esac

# Wait for the proxy to answer /alive through to the stub.
ready=0
for _ in $(seq 1 30); do
  if docker run --rm --network "$net" "$node_image" node -e \
    "fetch('http://proxy/alive').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"; then
    ready=1
    break
  fi
  sleep 1
done
if [ "$ready" != 1 ]; then
  echo "$proxy: the proxy never answered /alive" >&2
  docker logs "$net-proxy" >&2 || true
  exit 1
fi

for route in /kem/v1/live /notifications/hub; do
  docker run --rm --network "$net" -v "$here/client.mjs":/client.mjs:ro "$node_image" \
    node /client.mjs "ws://proxy$route"
done
echo "$proxy: both WebSocket routes pass"
