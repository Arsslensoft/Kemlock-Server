// Full sync of 5,000 items (about 10 MiB of JSON before compression), as the pages the API serves
// today: 500 items a page until `more` is false. `full_sync_ms` is the whole walk; the first
// byte of the first page is `http_req_waiting` of the first request.
//
// Seed an account with 5,000 items first:
//   kemlock-loadgen seed --accounts 4 --items 5000 --prefix big --out big.json
//   k6 run -e ACCOUNTS=$PWD/big.json -e RIG=pi perf/k6/full-sync.js
import exec from 'k6/execution';
import { check } from 'k6';
import { Trend } from 'k6/metrics';
import { ENFORCE, RIG, ACCOUNT_COUNT, signed, summary, trendStats } from './lib.js';

const fullSync = new Trend('full_sync_ms', true);
const firstByte = new Trend('full_sync_first_byte_ms', true);

// [p50, p95] full walk, and the first-byte p95, by rig.
const WALK = RIG === 'vps' ? [200, 400] : [500, 1000];
const FIRST_BYTE = RIG === 'vps' ? 30 : 50;

export const options = {
  summaryTrendStats: trendStats,
  scenarios: {
    full: {
      executor: 'constant-vus',
      vus: Math.min(Number(__ENV.VUS || 2), ACCOUNT_COUNT),
      duration: __ENV.DURATION || '2m',
    },
  },
  thresholds: ENFORCE
    ? {
        full_sync_ms: [`p(50)<${WALK[0]}`, `p(95)<${WALK[1]}`],
        full_sync_first_byte_ms: [`p(95)<${FIRST_BYTE}`],
      }
    : { full_sync_ms: ['p(95)<600000'], full_sync_first_byte_ms: ['p(95)<600000'] },
};

export default function () {
  const a = exec.vu.idInTest - 1;
  const started = Date.now();
  let since = null;
  let pages = 0;
  for (;;) {
    const query = since ? `?limit=500&since=${since}` : '?limit=500';
    const res = signed(a, 'GET', '/kem/v1/sync', query, null, { 'Accept-Encoding': 'zstd, br, gzip' }, 'fullsync');
    if (!check(res, { 'the page is 200': (r) => r && r.status === 200 })) return;
    if (pages === 0) firstByte.add(res.timings.waiting);
    pages += 1;
    const page = res.json();
    if (!page.more) break;
    since = page.cursor;
  }
  fullSync.add(Date.now() - started);
}

export function handleSummary(data) {
  return summary('k6-fullsync.json', data, ['fullsync'], (d) => ({
    full_sync: {
      p50_ms: d.metrics.full_sync_ms.values.med,
      p95_ms: d.metrics.full_sync_ms.values['p(95)'],
      first_byte_p95_ms: d.metrics.full_sync_first_byte_ms.values['p(95)'],
    },
  }));
}
