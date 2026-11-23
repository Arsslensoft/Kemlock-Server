# Performance harness

The design's targets (Performance targets) and how each is measured. k6 drives the scenarios,
oha the single-endpoint throughput, and `kemlock-loadgen` (crates/kemlock-loadgen) does what
neither can: OPAQUE sign-ins, and the DPoP proofs every authenticated request carries.

## The pieces

| Piece | Job |
|---|---|
| `kemlock-loadgen seed` | Makes the standard load: 100 accounts of 500 items, each item 2,048 bytes of ciphertext, and writes the accounts file (ids, items, sync cursors) |
| `kemlock-loadgen serve` | Holds a signed-in device per account. k6 asks it for the `Authorization` and `DPoP` headers of each request (`POST /proof`). With `--proxy-listen` it is also a signing reverse proxy, so oha can send authenticated requests |
| `kemlock-loadgen signin` | The design's "small Rust driver": OPAQUE sign-ins at a fixed rate, reporting the server's time for both messages. The client's OPAQUE work runs between the two requests, outside both clocks, and the real client's Argon2id never runs |
| `k6/standard.js` | The standard load: 14 delta syncs a second, 4 puts a second, 200 WebSockets (x10 on the VPS) |
| `k6/delta100.js` | Delta sync with 100 changed items, zstd requested |
| `k6/full-sync.js` | Full sync of 5,000 items, page by page |
| `k6/fanout.js` | WebSocket fan-out: 5,000 sockets, last nudge after a put |
| `run.sh` | Starts a server, runs everything, writes `results/*.json` and `summary.json` |
| `compare.mjs` | Folds the results into `summary.json`; compares with main's last run (fails at more than 10% worse p95, or a missed size or memory target) |

## The standard load

100 accounts of 500 items of 2 KiB, 200 WebSockets open, 20 requests a second: 70% delta syncs
(14/s, k6), 20% puts (4/s, k6), 10% sign-ins (2/s, `kemlock-loadgen signin`). The VPS runs ten
times that (`--rig vps`, `SCALE=10`). Load generators call the server directly, not through a
proxy.

```bash
cargo build --release -p kemlock-server -p kemlock-cli -p kemlock-loadgen
perf/run.sh --profile ci                  # 60 s of load, every pull request
perf/run.sh --profile full --rig vps      # 10 minutes, nightly and before a release
```

Or by hand:

```bash
DOMAIN=http://127.0.0.1:8080 SIGNUPS_ALLOWED=true LOG_LEVEL=warn \
  IP_HEADER=X-Forwarded-For KEMLOCK_TRUSTED_PROXIES=127.0.0.1,::1 \
  DATA_FOLDER=/tmp/kemlock target/release/kemlock-server &

LG="target/release/kemlock-loadgen --ip-header X-Forwarded-For"
$LG seed --accounts 100 --items 500 --out accounts.json
$LG serve --accounts accounts.json &                    # the proof service, on 127.0.0.1:9099
$LG signin --accounts accounts.json --rate 2 --duration-secs 600 --out signin.json &
k6 run -e ACCOUNTS=$PWD/accounts.json -e RIG=vps -e DURATION=10m perf/k6/standard.js
```

The server's sign-in and registration limits count per client address (10 a minute and 10 an
hour). One machine would be refused at once, so the harness makes up a client address for each
device and sends it in `X-Forwarded-For`, and the server is told to trust it from loopback
(`IP_HEADER`, `KEMLOCK_TRUSTED_PROXIES`). That is the same setting a proxy deployment uses.

## oha: the unchanged sync and attachments

oha can't make DPoP proofs, and a repeated proof is refused (the server remembers each `jti` for
five minutes), so it goes through the signing proxy:

```bash
$LG serve --accounts accounts.json --proxy-listen 127.0.0.1:9100 --proxy-account 0 &
cursor=$(jq -r '.accounts[0].cursor' accounts.json)

# Unchanged sync: must answer 304 without a database read. Target p50 1 ms, p95 5 ms on the VPS.
oha -z 30s -c 16 --no-tui "http://127.0.0.1:9100/kem/v1/sync?since=$cursor"
oha -z 30s -c 16 --no-tui --output-format json "http://127.0.0.1:9100/kem/v1/sync?since=$cursor" > oha-sync0.json
```

The proxy adds one loopback hop, a fraction of a millisecond, and each run is compared with
main's last run on the same machine, which cancels it. Read absolute numbers with that in mind.

Attachments: 256 MiB each way into and out of the local folder, at least
100 MB/s on the VPS, with the server's RSS sampled during the run and at most 1 MiB buffered per
transfer. The attachment routes are not in `/kem/v1` yet (the `kemlock-blob` adapter adds them),
so the paths below are placeholders; use the ones its OpenAPI document lists.

```bash
head -c 268435456 /dev/urandom > 256MiB.bin
pid=$(pgrep -x kemlock-server)

# Upload, 4 transfers at a time.
oha -n 8 -c 4 --no-tui -m PUT -T application/octet-stream -D 256MiB.bin \
  "http://127.0.0.1:9100/kem/v1/attachments/<id>" &
while kill -0 $! 2>/dev/null; do awk '/^VmRSS:/ {print $2}' /proc/$pid/status; sleep 0.5; done | sort -n | tail -1

# Download.
oha -n 8 -c 4 --no-tui "http://127.0.0.1:9100/kem/v1/attachments/<id>"
```

The proxy buffers a body in its own memory (up to 512 MiB), not in the server's, so the RSS it
samples is the server's.

## What each target in the design is measured by

| Target | Measured by |
|---|---|
| Idle memory (RSS) | `run.sh`: `VmRSS` from `/proc/<pid>/status`, 60 s after start, no clients (10 s in the short suite) |
| Memory under the standard load | `run.sh`: peak `VmRSS` sampled each second over the k6 run |
| Binary and image size | `run.sh` (binary); release.yml checks the image on disk and the pull size per architecture |
| Cold start | `run.sh`: process start to the first 200 from `/alive`, no migrations pending, median of 10 starts (3 in the short suite) |
| Sign-in, OPAQUE | `kemlock-loadgen signin` |
| Sign-in, Compatible | Not here yet: it needs the Bitwarden API (`kemlock-api-bw`) and a replay of the Bitwarden CLI's requests, with the hash's own cost timed alone and subtracted |
| Delta sync, 0 changes | oha through the proxy |
| Delta sync, 100 changes | `k6/delta100.js` |
| Full sync, 5,000 items | `k6/full-sync.js`. The API pages at 500 today; the walk of ten pages is timed. When the streaming full sync lands, one request will do, and `first byte` is then the response's `http_req_waiting` |
| Item put | `k6/standard.js`: `PUT` with `If-Match`, one 2 KiB item |
| WebSocket fan-out | `k6/fanout.js`. All sockets are on one account (a space has no route yet). The putter sends at a wall-clock boundary and each socket measures the time from it to its nudge, which includes the put's own latency, so it is an upper bound |
| Attachment throughput | oha, above |
| Web vault load | Not here: bundle-size check and Lighthouse CI belong to the `web/` build |

## The CI rule

`.github/workflows/perf.yml`. Every pull request runs the short suite on `ubuntu-24.04` (amd64,
the VPS column), SQLite, and `compare.mjs` checks it against main's last run:

- a p95 more than 10% worse (sign-in, unchanged sync, the sync and put mix, delta 100, full
  sync, fan-out, cold start) fails the build;
- a missed size or memory target (idle RSS, peak RSS under load, binary size) is shown and listed,
  not enforced: the pull request runs on a shared runner (`compare.mjs --advisory-targets`), and
  the `rigs` job enforces them on the VPS;
- an unchanged sync that does not answer 304, or a failed sign-in, fails the build.

The absolute latency targets are enforced where they mean something: `ENFORCE=1` turns the k6
thresholds into the design's table (set by the `rigs` job on the VPS, nightly and
before each release, once `PERF_RIGS=true` and the runner exists). Shared CI runners are noisy, so
a pull request is held to "no worse than main", not to the VPS's numbers. There is no Raspberry Pi
target.

## Known limits of this first version

- Sign-ins use a new device each time. A long run adds devices to each account; if the server
  later caps devices per account, the driver needs to reuse one.
- The Compatible sign-in and the web vault targets are not measured yet (see the table).
- `compare.mjs` reads oha's JSON as `latencyPercentiles` in seconds and `statusCodeDistribution`;
  check them against the oha version in `perf.yml`.
