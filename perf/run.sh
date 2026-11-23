#!/usr/bin/env bash
# Runs the performance suite against a freshly started server and writes JSON results.
#
#   perf/run.sh --profile ci                 # the short suite every pull request runs
#   perf/run.sh --profile full --rig vps --database-url postgres://kemlock:kemlock@127.0.0.1/kemlock
#
# Needs release builds of kemlock-server, kemlock-cli and kemlock-loadgen (--bin, default
# target/release), k6 and oha on PATH, and curl, node and jq. See perf/README.md.
set -euo pipefail

profile=ci
rig=""
bin="target/release"
results="perf/results"
database_url=""
port=8080

while [ $# -gt 0 ]; do
  case "$1" in
    --profile) profile="$2"; shift 2 ;;
    --rig) rig="$2"; shift 2 ;;
    --bin) bin="$2"; shift 2 ;;
    --results) results="$2"; shift 2 ;;
    --database-url) database_url="$2"; shift 2 ;;
    --port) port="$2"; shift 2 ;;
    *) echo "unknown flag: $1" >&2; exit 2 ;;
  esac
done
[ -n "$rig" ] || rig=vps

here="$(cd "$(dirname "$0")" && pwd)"
bin="$(cd "$bin" && pwd)"
mkdir -p "$results"
results="$(cd "$results" && pwd)"
rm -f "$results"/*.json "$results"/*.txt

# The profile: the standard load's size is always the design's; only the durations change.
if [ "$profile" = full ]; then
  duration=10m; idle_wait=60; starts=10; delta_duration=2m; fanout_rounds=12; oha_duration=30s
else
  duration=60s; idle_wait=10; starts=3; delta_duration=30s; fanout_rounds=4; oha_duration=10s
fi
scale=1; [ "$rig" = vps ] && scale=10
sockets=1000; [ "$rig" = vps ] && sockets=5000
[ "$profile" = full ] || sockets=200
base="http://127.0.0.1:$port"
sidecar="http://127.0.0.1:9099"
ip_header="X-Forwarded-For"

work="$(mktemp -d)"
server_pid=""
sidecar_pid=""
sampler_pid=""
cleanup() {
  for pid in "$sampler_pid" "$sidecar_pid" "$server_pid"; do
    [ -z "$pid" ] || kill "$pid" 2>/dev/null || true
  done
  wait 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

to_secs() { case "$1" in *m) echo $(( ${1%m} * 60 )) ;; *s) echo "${1%s}" ;; *) echo "$1" ;; esac; }
now_ms() { echo $(( $(date +%s%N) / 1000000 )); }
rss_kib() { awk '/^VmRSS:/ {print $2}' "/proc/$1/status"; }

start_server() {
  # `env`, so the optional DATABASE_URL assignment is read as one.
  env DATA_FOLDER="$work/data" DOMAIN="$base" ROCKET_ADDRESS=127.0.0.1 ROCKET_PORT="$port" \
    SIGNUPS_ALLOWED=true LOG_LEVEL=warn IP_HEADER="$ip_header" \
    KEMLOCK_TRUSTED_PROXIES="127.0.0.1,::1" ${database_url:+DATABASE_URL="$database_url"} \
    "$bin/kemlock-server" > "$work/server.log" 2>&1 &
  server_pid=$!
}
wait_alive() {
  for _ in $(seq 1 600); do
    curl -fsS -o /dev/null "$base/alive" 2>/dev/null && return 0
    kill -0 "$server_pid" 2>/dev/null || { cat "$work/server.log" >&2; echo "the server exited" >&2; return 1; }
    sleep 0.05
  done
  echo "the server never answered /alive" >&2; return 1
}
stop_server() { kill "$server_pid" 2>/dev/null || true; wait "$server_pid" 2>/dev/null || true; server_pid=""; }

# 1. Cold start: process start to the first 200 from /alive, with no migrations pending, median.
mkdir -p "$work/data"
start_server; wait_alive; stop_server        # the first start runs the migrations
times=()
for _ in $(seq 1 "$starts"); do
  t0="$(now_ms)"; start_server; wait_alive; t1="$(now_ms)"; stop_server
  times+=("$((t1 - t0))")
done
cold_ms="$(printf '%s\n' "${times[@]}" | sort -n | awk '{a[NR]=$1} END {print a[int((NR+1)/2)]}')"

# 2. Idle memory: VmRSS a minute after start (10 s in the short suite), no clients.
start_server; wait_alive
sleep "$idle_wait"
idle_kib="$(rss_kib "$server_pid")"

# 3. Seed the standard load: 100 accounts of 500 items of 2 KiB.
"$bin/kemlock-loadgen" --base-url "$base" --ip-header "$ip_header" seed \
  --accounts 100 --items 500 --out "$results/accounts.json"
"$bin/kemlock-loadgen" --base-url "$base" --ip-header "$ip_header" seed \
  --accounts 2 --items 5000 --prefix big --out "$results/big.json"

"$bin/kemlock-loadgen" --base-url "$base" --ip-header "$ip_header" serve \
  --accounts "$results/accounts.json" --proxy-listen 127.0.0.1:9100 --proxy-account 0 \
  > "$work/sidecar.log" 2>&1 &
sidecar_pid=$!
for _ in $(seq 1 200); do
  curl -fsS -o /dev/null "$sidecar/health" 2>/dev/null && break
  kill -0 "$sidecar_pid" 2>/dev/null || { cat "$work/sidecar.log" >&2; exit 1; }
  sleep 0.5
done

# 4. The unchanged sync through oha: 304 without a database read. Done first, while the seeded
# cursor is still current.
cursor="$(node -e "console.log(JSON.parse(require('fs').readFileSync('$results/accounts.json','utf8')).accounts[0].cursor)")"
oha -z "$oha_duration" -c 16 --no-tui --output-format json \
  "http://127.0.0.1:9100/kem/v1/sync?since=$cursor" > "$results/oha-sync0.json"

# 5. The standard load: k6 for syncs, puts and sockets, the Rust driver for sign-ins, and a
# sampler for peak memory.
( while kill -0 "$server_pid" 2>/dev/null; do rss_kib "$server_pid"; sleep 1; done ) > "$work/rss.txt" &
sampler_pid=$!
signin_secs=$(( $(to_secs "$duration") + 5 ))
"$bin/kemlock-loadgen" --base-url "$base" --ip-header "$ip_header" signin \
  --accounts "$results/accounts.json" --rate $((2 * scale)) --duration-secs "$signin_secs" \
  --out "$results/signin.json" > /dev/null &
signin_pid=$!
k6 run --quiet -e ACCOUNTS="$results/accounts.json" -e RIG="$rig" -e SCALE="$scale" \
  -e ENFORCE="${ENFORCE:-0}" -e RESULTS_DIR="$results" -e BASE_URL="$base" -e SIDECAR_URL="$sidecar" \
  -e DURATION="$duration" "$here/k6/standard.js" > /dev/null
wait "$signin_pid"
kill "$sampler_pid" 2>/dev/null || true; sampler_pid=""
peak_kib="$(sort -n "$work/rss.txt" | tail -1)"

# 6. The other scenarios.
common=(-e RIG="$rig" -e ENFORCE="${ENFORCE:-0}" -e RESULTS_DIR="$results" -e BASE_URL="$base" -e SIDECAR_URL="$sidecar")
k6 run --quiet -e ACCOUNTS="$results/accounts.json" "${common[@]}" -e DURATION="$delta_duration" "$here/k6/delta100.js" > /dev/null
# The full sync's accounts hold 5,000 items, so they get a proof service of their own.
"$bin/kemlock-loadgen" --base-url "$base" --ip-header "$ip_header" serve   --accounts "$results/big.json" --listen 127.0.0.1:9098 > "$work/sidecar-big.log" 2>&1 &
big_pid=$!
for _ in $(seq 1 200); do curl -fsS -o /dev/null "http://127.0.0.1:9098/health" 2>/dev/null && break; sleep 0.5; done
k6 run --quiet -e ACCOUNTS="$results/big.json" "${common[@]}" -e SIDECAR_URL="http://127.0.0.1:9098"   -e DURATION="$delta_duration" "$here/k6/full-sync.js" > /dev/null
kill "$big_pid" 2>/dev/null || true
k6 run --quiet -e ACCOUNTS="$results/accounts.json" "${common[@]}" -e SOCKETS="$sockets" -e ROUNDS="$fanout_rounds" "$here/k6/fanout.js" > /dev/null

# 7. Binary and image-adjacent numbers, then fold everything into one summary.
cat > "$results/system.json" <<JSON
{
  "rig": "$rig",
  "profile": "$profile",
  "idle_rss_mib": $(awk "BEGIN {printf \"%.1f\", $idle_kib / 1024}"),
  "load_peak_rss_mib": $(awk "BEGIN {printf \"%.1f\", $peak_kib / 1024}"),
  "binary_mib": $(awk "BEGIN {printf \"%.2f\", $(stat -c %s "$bin/kemlock-server") / 1048576}"),
  "cold_start_ms": $cold_ms
}
JSON
node "$here/compare.mjs" --summarize "$results" > "$results/summary.json"
echo "perf: results in $results (summary.json)"
