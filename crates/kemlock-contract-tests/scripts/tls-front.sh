#!/usr/bin/env bash
# Puts https in front of a server on 127.0.0.1, for the Kemlock app, which refuses http
# (`vwServerUrl`, mobile/lib/features/sync/vaultwarden/vw_api.dart:83-90). A self-signed certificate
# for `localhost` is made, and socat ends TLS and passes the bytes on. The certificate's SHA-256
# fingerprint is written to <dir>/fingerprint.txt, which the app's tests take as VAULTWARDEN_PIN
# (mobile/test/vaultwarden_server/server_kit.dart:7).
#
#   tls-front.sh <dir> <tls-port> <upstream-port>
set -euo pipefail

dir=$1
tls_port=$2
upstream_port=$3

mkdir -p "$dir"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  -keyout "$dir/key.pem" -out "$dir/cert.pem" 2>/dev/null
openssl x509 -in "$dir/cert.pem" -noout -fingerprint -sha256 | cut -d= -f2 >"$dir/fingerprint.txt"

nohup socat "OPENSSL-LISTEN:$tls_port,bind=127.0.0.1,reuseaddr,fork,cert=$dir/cert.pem,key=$dir/key.pem,verify=0" \
  "TCP:127.0.0.1:$upstream_port" >"$dir/socat.log" 2>&1 &
echo $! >"$dir/socat.pid"

for _ in $(seq 1 30); do
  if curl -fsS --cacert "$dir/cert.pem" "https://localhost:$tls_port/alive" >/dev/null 2>&1; then
    echo "https://localhost:$tls_port answers, certificate $(cat "$dir/fingerprint.txt")"
    exit 0
  fi
  sleep 1
done
echo "https://localhost:$tls_port did not answer; socat log:" >&2
cat "$dir/socat.log" >&2
exit 1
