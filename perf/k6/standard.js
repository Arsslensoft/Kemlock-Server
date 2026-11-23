// The design's standard load (Performance targets): 100 accounts of 500 items of 2 KiB, 200
// WebSockets open, and 20 requests a second: 70% delta syncs, 20% puts, 10% sign-ins.
//
// k6 drives the syncs (14 a second), the puts (4 a second) and the sockets. The sign-ins (2 a
// second) are OPAQUE and need a real client, so `kemlock-loadgen signin` runs beside k6 (perf/run.sh
// starts both). The VPS runs ten times that: SCALE=10.
//
//   kemlock-loadgen seed --accounts 100 --items 500 --out accounts.json
//   kemlock-loadgen serve --accounts accounts.json &
//   k6 run -e ACCOUNTS=$PWD/accounts.json -e RIG=pi -e DURATION=10m perf/k6/standard.js
import exec from 'k6/execution';
import ws from 'k6/ws';
import { check } from 'k6';
import {
  ACCOUNT_COUNT, ITEMS_PER_ACCOUNT, SCALE, accounts, cursorOf, itemBody, limit, liveUrl,
  proofFor, signed, summary, trendStats,
} from './lib.js';

const DURATION = __ENV.DURATION || '10m';
const DURATION_MS = (() => {
  const m = /^(\d+)(s|m|h)$/.exec(DURATION);
  if (!m) throw new Error('DURATION must look like 90s, 10m or 1h');
  return Number(m[1]) * { s: 1000, m: 60000, h: 3600000 }[m[2]];
})();
const SOCKETS = 200 * SCALE;

export const options = {
  summaryTrendStats: trendStats,
  scenarios: {
    // 70% of 20 requests a second.
    sync: {
      executor: 'constant-arrival-rate',
      exec: 'syncDelta',
      rate: 14 * SCALE,
      timeUnit: '1s',
      duration: DURATION,
      preAllocatedVUs: 50,
      maxVUs: 400,
    },
    // 20%.
    put: {
      executor: 'constant-arrival-rate',
      exec: 'putItem',
      rate: 4 * SCALE,
      timeUnit: '1s',
      duration: DURATION,
      preAllocatedVUs: 20,
      maxVUs: 200,
    },
    // 200 sockets held open for the whole run (2,000 on the VPS).
    live: {
      executor: 'per-vu-iterations',
      exec: 'live',
      vus: SOCKETS,
      iterations: 1,
      maxDuration: `${Math.ceil(DURATION_MS / 1000) + 120}s`,
    },
  },
  thresholds: Object.assign(
    {},
    limit('sync', 'sync0'),
    limit('put', 'put'),
    { 'http_req_failed{name:sync}': ['rate<0.01'], 'http_req_failed{name:put}': ['rate<0.01'] },
  ),
};

// Each VU keeps the latest cursor it has seen for each account, so a delta is what changed since
// that VU last looked: small, as a real client's is.
const cursors = {};

export function syncDelta() {
  const a = exec.scenario.iterationInTest % ACCOUNT_COUNT;
  const account = accounts[a];
  const since = cursors[a] || account.cursor;
  const res = signed(a, 'GET', '/kem/v1/sync', `?since=${since}`, null, null, 'sync');
  check(res, { 'sync is 200 or 304': (r) => r && (r.status === 200 || r.status === 304) });
  if (res && res.status === 200) {
    const next = cursorOf(res);
    if (next) cursors[a] = next;
  }
}

// Replaces item (a, j): each iteration number maps to one item and the revision it is at, so no
// two writes in a run touch the same item at the same revision, and no write conflicts.
export function putItem() {
  const n = exec.scenario.iterationInTest;
  const a = n % ACCOUNT_COUNT;
  const j = Math.floor(n / ACCOUNT_COUNT) % ITEMS_PER_ACCOUNT;
  const previous = 1 + Math.floor(n / (ACCOUNT_COUNT * ITEMS_PER_ACCOUNT));
  const account = accounts[a];
  const id = account.itemIds[j];
  const res = signed(
    a, 'PUT', `/kem/v1/items/${id}`, '',
    itemBody(account.userId, id, previous + 1),
    { 'Content-Type': 'application/json', 'If-Match': String(previous) },
    'put',
  );
  check(res, { 'put is 200': (r) => r && r.status === 200 });
}

export function live() {
  const a = (exec.vu.idInTest - 1) % ACCOUNT_COUNT;
  const proof = proofFor(a, 'GET', '/kem/v1/live');
  const res = ws.connect(
    liveUrl(),
    { headers: { Authorization: proof.authorization, DPoP: proof.dpop } },
    (socket) => {
      socket.on('message', () => {});
      socket.setTimeout(() => socket.close(), DURATION_MS);
    },
  );
  check(res, { 'upgraded to a WebSocket': (r) => r && r.status === 101 });
}

export function handleSummary(data) {
  return summary('k6-standard.json', data, ['sync', 'put']);
}
