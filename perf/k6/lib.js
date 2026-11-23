// Shared by the k6 scenarios.
//
// k6 can't make DPoP proofs, so every request to the server is preceded by one call to
// `kemlock-loadgen serve` (POST /proof), which holds a signed-in device per seeded account. The
// call to the proof service is tagged name=proof and left out of every threshold: only the
// request to the server carries the scenario's name, so only it is timed.
//
// Environment:
//   BASE_URL      the server, default http://127.0.0.1:8080 (the rigs call it directly, not
//                 through a proxy)
//   SIDECAR_URL   kemlock-loadgen serve, default http://127.0.0.1:9099
//   ACCOUNTS      the accounts file `kemlock-loadgen seed` wrote (absolute path)
//   RIG           vps: which column of the design's targets table to use
//   ENFORCE       1 to fail the run on a missed target (nightly and release runs on the rigs);
//                 otherwise thresholds are loose and only make k6 compute the percentiles
//   SCALE         10 for the VPS ("ten times the standard load"); 1 for the bare standard load
import http from 'k6/http';
import { SharedArray } from 'k6/data';

export const BASE = (__ENV.BASE_URL || 'http://127.0.0.1:8080').replace(/\/$/, '');
export const SIDECAR = (__ENV.SIDECAR_URL || 'http://127.0.0.1:9099').replace(/\/$/, '');
export const RIG = __ENV.RIG || 'vps';
export const ENFORCE = __ENV.ENFORCE === '1';
export const SCALE = Number(__ENV.SCALE || (RIG === 'vps' ? 10 : 1));
export const OUT = __ENV.RESULTS_DIR || '.';

const FILE = __ENV.ACCOUNTS;
if (!FILE) {
  throw new Error('set ACCOUNTS to the accounts file that `kemlock-loadgen seed` wrote');
}

// One element per account, so an iteration parses one account, not the whole file.
export const accounts = new SharedArray('accounts', () => JSON.parse(open(FILE)).accounts);
export const sample = new SharedArray('sample', () => [JSON.parse(open(FILE)).sample])[0];
export const ACCOUNT_COUNT = accounts.length;
export const ITEMS_PER_ACCOUNT = accounts[0].itemIds.length;

// The design's targets table, by rig: [p50, p95] in milliseconds.
const TARGETS = {
  vps: { sync0: [1, 5], delta100: [10, 30], fullsync: [200, 400], put: [6, 20], nudge: [null, 100] },
};

/** Thresholds for one named request: the design's targets when ENFORCE, else loose ones. */
export function limit(name, key) {
  const [p50, p95] = TARGETS[RIG][key];
  const metric = `http_req_duration{name:${name}}`;
  if (!ENFORCE) return { [metric]: ['p(95)<600000'] };
  return { [metric]: [...(p50 ? [`p(50)<${p50}`] : []), `p(95)<${p95}`] };
}

let nonce = null;

function headerOf(res, wanted) {
  for (const key in res.headers) {
    if (key.toLowerCase() === wanted) return res.headers[key];
  }
  return null;
}

/** Learns the server's DPoP nonce, which every response carries. */
function prime() {
  const res = http.get(`${BASE}/kem/v1/config`, { tags: { name: 'config' } });
  nonce = headerOf(res, 'dpop-nonce');
}

/** The Authorization and DPoP header values for one request, from the proof service. */
export function proofFor(account, method, path) {
  if (nonce === null) prime();
  const reply = http.post(
    `${SIDECAR}/proof`,
    JSON.stringify({ account, method, path, nonce }),
    { headers: { 'Content-Type': 'application/json' }, tags: { name: 'proof' } },
  );
  if (reply.status !== 200) {
    throw new Error(`the proof service answered ${reply.status}: ${reply.body}`);
  }
  return reply.json();
}

/**
 * One authenticated request as account `account`. `path` has no query; `query` is "?a=b" or "".
 * When the server asks for a new nonce, once more.
 */
export function signed(account, method, path, query, body, headers, name) {
  for (let attempt = 0; attempt < 2; attempt++) {
    const proof = proofFor(account, method, path);
    const res = http.request(method, `${BASE}${path}${query || ''}`, body, {
      headers: Object.assign({ Authorization: proof.authorization, DPoP: proof.dpop }, headers || {}),
      tags: { name },
    });
    const fresh = headerOf(res, 'dpop-nonce');
    if (fresh) nonce = fresh;
    if (res.status === 401 && attempt === 0 && String(res.body).includes('use-dpop-nonce')) continue;
    return res;
  }
  return null;
}

/** The cursor a sync answered with: the ETag (set when no more pages follow) or the body. */
export function cursorOf(res) {
  const etag = headerOf(res, 'etag');
  if (etag) return etag.replace(/^W\//, '').replace(/"/g, '');
  return null;
}

/** An item in the wire shape (docs/crypto.md), reusing the seeder's valid sealed values. */
export function itemBody(userId, itemId, revision) {
  return JSON.stringify({
    id: itemId,
    owner: `user:${userId}`,
    kind: 'login',
    format: 'kem1',
    revision,
    keyVersion: 1,
    ciphertext: sample.ciphertext,
    itemKey: sample.itemKey,
    deleted: false,
  });
}

/** The WebSocket URL for the server's /kem/v1/live. */
export function liveUrl() {
  return `${BASE.replace(/^http/, 'ws')}/kem/v1/live`;
}

/** A handleSummary body: the named requests' percentiles in one JSON file. */
export function summary(file, data, names, extra) {
  const out = { rig: RIG, enforce: ENFORCE, metrics: {} };
  for (const name of names) {
    const m = data.metrics[`http_req_duration{name:${name}}`];
    if (!m) continue;
    out.metrics[name] = {
      count: data.metrics[`http_reqs{name:${name}}`] ? data.metrics[`http_reqs{name:${name}}`].values.count : undefined,
      p50_ms: m.values.med,
      p95_ms: m.values['p(95)'],
      p99_ms: m.values['p(99)'],
      max_ms: m.values.max,
    };
  }
  if (extra) Object.assign(out.metrics, extra(data));
  const text = JSON.stringify(out, null, 2);
  return { [`${OUT}/${file}`]: text, stdout: `${text}\n` };
}

export const trendStats = ['avg', 'min', 'med', 'p(90)', 'p(95)', 'p(99)', 'max'];
