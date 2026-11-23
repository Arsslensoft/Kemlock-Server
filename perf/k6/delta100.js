// Delta sync with 100 changes: each iteration writes 100 existing items in one batch, then syncs
// since the cursor from before it, so the delta is exactly those 100 items. zstd is asked for, as a
// real client does; the cursor is read from the ETag so the body needs no decoding.
//
//   k6 run -e ACCOUNTS=$PWD/accounts.json -e RIG=vps perf/k6/delta100.js
import exec from 'k6/execution';
import { check } from 'k6';
import {
  ACCOUNT_COUNT, ITEMS_PER_ACCOUNT, accounts, cursorOf, itemBody, limit, signed, summary,
  trendStats,
} from './lib.js';

const CHANGES = 100;

export const options = {
  summaryTrendStats: trendStats,
  scenarios: {
    delta100: {
      executor: 'constant-vus',
      vus: Math.min(Number(__ENV.VUS || 8), ACCOUNT_COUNT),
      duration: __ENV.DURATION || '2m',
    },
  },
  thresholds: Object.assign({}, limit('delta100', 'delta100'), {
    'http_req_failed{name:delta100}': ['rate<0.01'],
  }),
};

// One account per VU, so the batches never collide on a revision.
const cursors = {};
const rounds = {};

export default function () {
  const a = exec.vu.idInTest - 1;
  const account = accounts[a];
  const round = rounds[a] || 0;
  rounds[a] = round + 1;
  const since = cursors[a] || account.cursor;

  const writes = [];
  for (let k = 0; k < CHANGES; k++) {
    const slot = round * CHANGES + k;
    const id = account.itemIds[slot % ITEMS_PER_ACCOUNT];
    const previous = 1 + Math.floor(slot / ITEMS_PER_ACCOUNT);
    writes.push({
      expectedRevision: previous,
      item: JSON.parse(itemBody(account.userId, id, previous + 1)),
    });
  }
  const batch = signed(
    a, 'POST', '/kem/v1/items:batch', '', JSON.stringify({ writes }),
    { 'Content-Type': 'application/json' }, 'batch',
  );
  check(batch, { 'the batch is 200': (r) => r && r.status === 200 });

  const res = signed(
    a, 'GET', '/kem/v1/sync', `?since=${since}`, null, { 'Accept-Encoding': 'zstd, br, gzip' },
    'delta100',
  );
  check(res, { 'the delta is 200': (r) => r && r.status === 200 });
  const next = res && cursorOf(res);
  if (next) cursors[a] = next;
}

export function handleSummary(data) {
  return summary('k6-delta100.json', data, ['delta100', 'batch']);
}
