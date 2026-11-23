// WebSocket fan-out: N sockets on one account (the Pi's 1,000, the VPS's 5,000) and one put every
// PERIOD ms. The putter sends at a wall-clock boundary (a multiple of PERIOD), and each socket
// records how long after that boundary its "sync now" arrived. That is the time from the put's
// start to the nudge, so it includes the put's own latency: an upper bound on the design's "time
// from the put's response to the last 'sync now'" (put p95 is 25 ms on the Pi). All k6 VUs share
// one machine and one clock.
//
//   k6 run -e ACCOUNTS=$PWD/accounts.json -e RIG=pi -e SOCKETS=1000 perf/k6/fanout.js
import exec from 'k6/execution';
import ws from 'k6/ws';
import { check, sleep } from 'k6';
import { Trend } from 'k6/metrics';
import {
  ENFORCE, ITEMS_PER_ACCOUNT, RIG, accounts, itemBody, liveUrl, proofFor, signed, summary,
  trendStats,
} from './lib.js';

const SOCKETS = Number(__ENV.SOCKETS || (RIG === 'vps' ? 5000 : 1000));
const PERIOD = Number(__ENV.PERIOD_MS || 5000);
const ROUNDS = Number(__ENV.ROUNDS || 12);
const ACCOUNT = 0;
// Sockets connect over the first RAMP seconds; the putter starts after they are all up.
const RAMP = Number(__ENV.RAMP_S || 60);
const HOLD_MS = (ROUNDS + 2) * PERIOD;

const nudge = new Trend('nudge_ms', true);

export const options = {
  summaryTrendStats: trendStats,
  scenarios: {
    sockets: {
      executor: 'per-vu-iterations',
      exec: 'listen',
      vus: SOCKETS,
      iterations: 1,
      maxDuration: `${Math.ceil((RAMP * 1000 + HOLD_MS) / 1000) + 120}s`,
    },
    putter: {
      executor: 'per-vu-iterations',
      exec: 'put',
      vus: 1,
      iterations: 1,
      startTime: `${RAMP + 15}s`,
      maxDuration: `${Math.ceil((ROUNDS + 2) * PERIOD / 1000) + 60}s`,
    },
  },
  thresholds: ENFORCE ? { nudge_ms: ['p(95)<100'] } : { nudge_ms: ['p(95)<600000'] },
};

export function listen() {
  sleep(Math.random() * RAMP);
  const proof = proofFor(ACCOUNT, 'GET', '/kem/v1/live');
  const res = ws.connect(
    liveUrl(),
    { headers: { Authorization: proof.authorization, DPoP: proof.dpop } },
    (socket) => {
      socket.on('message', () => {
        // Nothing counts before the putter starts.
        if (exec.instance.currentTestRunDuration < (RAMP + 15) * 1000) return;
        const now = Date.now();
        // The boundary this nudge belongs to: the last multiple of PERIOD before it.
        nudge.add(now - Math.floor(now / PERIOD) * PERIOD);
      });
      socket.setTimeout(() => socket.close(), (RAMP + 15) * 1000 + HOLD_MS);
    },
  );
  check(res, { 'upgraded to a WebSocket': (r) => r && r.status === 101 });
}

export function put() {
  const account = accounts[ACCOUNT];
  for (let round = 0; round < ROUNDS; round++) {
    // Wait for the next boundary, then send.
    const wait = PERIOD - (Date.now() % PERIOD);
    sleep(wait / 1000);
    const id = account.itemIds[round % ITEMS_PER_ACCOUNT];
    const res = signed(
      ACCOUNT, 'PUT', `/kem/v1/items/${id}`, '', itemBody(account.userId, id, 2 + Math.floor(round / ITEMS_PER_ACCOUNT)),
      { 'Content-Type': 'application/json', 'If-Match': String(1 + Math.floor(round / ITEMS_PER_ACCOUNT)) },
      'fanout-put',
    );
    check(res, { 'put is 200': (r) => r && r.status === 200 });
  }
  // Let the last nudges arrive before the sockets close.
  sleep(PERIOD / 1000);
}

export function handleSummary(data) {
  return summary('k6-fanout.json', data, ['fanout-put'], (d) => ({
    nudge: {
      p50_ms: d.metrics.nudge_ms.values.med,
      p95_ms: d.metrics.nudge_ms.values['p(95)'],
      max_ms: d.metrics.nudge_ms.values.max,
      sockets: SOCKETS,
    },
  }));
}
