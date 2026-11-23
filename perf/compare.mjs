// Folds a run's result files into one summary, and compares a summary with main's last one.
//
//   node perf/compare.mjs --summarize perf/results > perf/results/summary.json
//   node perf/compare.mjs perf/results/summary.json baseline/summary.json [--threshold 0.10] [--advisory-targets]
//
// The CI rule (design, Performance targets): a p95 more than 10% worse than main's last run on the
// same runner type, or a missed size or memory target, fails the build. Memory and size targets
// are absolute; latencies are relative here (the absolute latency targets are enforced by the
// k6 thresholds when ENFORCE=1, on the VPS).
//
// --advisory-targets is for the pull request run on a shared runner, which is not the VPS the
// size and memory targets are set for: a missed target is shown in the table and listed in the
// summary, and does not fail the run. The `rigs` job runs without it.
import { existsSync, readFileSync, appendFileSync } from 'node:fs';
import { join } from 'node:path';

const read = (dir, name) => {
  const file = join(dir, name);
  return existsSync(file) ? JSON.parse(readFileSync(file, 'utf8')) : null;
};

function summarize(dir) {
  const system = read(dir, 'system.json') ?? {};
  const out = { rig: system.rig, profile: system.profile, metrics: {} };
  const m = out.metrics;
  for (const key of ['idle_rss_mib', 'load_peak_rss_mib', 'binary_mib', 'cold_start_ms']) {
    if (system[key] !== undefined) m[key] = system[key];
  }
  const signin = read(dir, 'signin.json');
  if (signin) {
    m.signin_p50_ms = signin.signIn.p50Ms;
    m.signin_p95_ms = signin.signIn.p95Ms;
    m.signin_errors = signin.signIn.errors;
  }
  const take = (file, name, prefix) => {
    const k = read(dir, file)?.metrics?.[name];
    if (!k) return;
    m[`${prefix}_p50_ms`] = k.p50_ms;
    m[`${prefix}_p95_ms`] = k.p95_ms;
  };
  take('k6-standard.json', 'sync', 'sync_mix');
  take('k6-standard.json', 'put', 'put');
  take('k6-delta100.json', 'delta100', 'delta100');
  const full = read(dir, 'k6-fullsync.json')?.metrics?.full_sync;
  if (full) {
    m.fullsync_p50_ms = full.p50_ms;
    m.fullsync_p95_ms = full.p95_ms;
    m.fullsync_first_byte_p95_ms = full.first_byte_p95_ms;
  }
  const nudge = read(dir, 'k6-fanout.json')?.metrics?.nudge;
  if (nudge) m.nudge_p95_ms = nudge.p95_ms;
  // oha reports seconds. The unchanged sync must answer 304 every time.
  const oha = read(dir, 'oha-sync0.json');
  if (oha) {
    const pct = oha.latencyPercentiles ?? {};
    if (pct.p50 !== undefined) m.sync0_p50_ms = pct.p50 * 1000;
    if (pct.p95 !== undefined) m.sync0_p95_ms = pct.p95 * 1000;
    const codes = oha.statusCodeDistribution ?? {};
    const total = Object.values(codes).reduce((a, b) => a + b, 0);
    m.sync0_not_304 = total - (codes['304'] ?? 0);
  }
  return out;
}

// Absolute size and memory targets, by rig (the design's table). Always enforced.
const ABSOLUTE = {
  vps: { idle_rss_mib: 28, load_peak_rss_mib: 160, binary_mib: 25 },
};
// Relative: these may not be more than the threshold worse than the baseline.
const RELATIVE = [
  'signin_p95_ms', 'sync0_p95_ms', 'sync_mix_p95_ms', 'put_p95_ms', 'delta100_p95_ms',
  'fullsync_p95_ms', 'fullsync_first_byte_p95_ms', 'nudge_p95_ms', 'cold_start_ms',
];

function compare(currentFile, baselineFile, threshold, advisoryTargets = false) {
  const current = JSON.parse(readFileSync(currentFile, 'utf8'));
  const baseline = baselineFile && existsSync(baselineFile) ? JSON.parse(readFileSync(baselineFile, 'utf8')) : null;
  const failures = [];
  const advisories = [];
  const rows = [];

  const limits = ABSOLUTE[current.rig] ?? ABSOLUTE.vps;
  for (const [key, max] of Object.entries(limits)) {
    const value = current.metrics[key];
    if (value === undefined) continue;
    const ok = value <= max;
    rows.push([key, value, `<= ${max}`, ok ? 'ok' : advisoryTargets ? 'MISSED (advisory)' : 'MISSED']);
    if (!ok) (advisoryTargets ? advisories : failures).push(`${key} is ${value}, the target is ${max}`);
  }
  if ((current.metrics.sync0_not_304 ?? 0) > 0) {
    failures.push(`${current.metrics.sync0_not_304} unchanged syncs did not answer 304`);
  }
  if ((current.metrics.signin_errors ?? 0) > 0) {
    failures.push(`${current.metrics.signin_errors} sign-ins failed`);
  }

  for (const key of RELATIVE) {
    const now = current.metrics[key];
    const before = baseline?.metrics?.[key];
    if (now === undefined) continue;
    if (before === undefined) {
      rows.push([key, now.toFixed?.(2) ?? now, 'no baseline', '-']);
      continue;
    }
    const change = (now - before) / before;
    const ok = change <= threshold;
    rows.push([key, now.toFixed(2), `${before.toFixed(2)} (${(change * 100).toFixed(1)}%)`, ok ? 'ok' : 'WORSE']);
    if (!ok) failures.push(`${key} is ${(change * 100).toFixed(1)}% worse than main (${before.toFixed(2)} -> ${now.toFixed(2)})`);
  }

  const table = [
    `| metric | now | target or main | |`,
    `|---|---|---|---|`,
    ...rows.map((r) => `| ${r.join(' | ')} |`),
  ].join('\n');
  const verdict = failures.length === 0 ? 'Nothing enforced here failed.' : failures.map((f) => `- ${f}`).join('\n');
  const advisory = advisories.length === 0 ? '' : `\nTargets missed, shown and not enforced on this runner:\n${advisories.map((f) => `- ${f}`).join('\n')}\n`;
  const report = `### Performance (${current.rig}, ${current.profile})\n\n${table}\n\n${verdict}\n${advisory}${baseline ? '' : '\nNo baseline from main yet: relative checks were skipped.\n'}`;
  console.log(report);
  if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, `${report}\n`);
  return failures.length === 0 ? 0 : 1;
}

const args = process.argv.slice(2);
if (args[0] === '--summarize') {
  console.log(JSON.stringify(summarize(args[1]), null, 2));
} else {
  const t = args.indexOf('--threshold');
  const threshold = t >= 0 ? Number(args[t + 1]) : 0.1;
  const files = args.filter((a, i) => !a.startsWith('--') && args[i - 1] !== '--threshold');
  if (files.length < 1) {
    console.error('usage: compare.mjs <summary.json> [baseline summary.json] [--threshold 0.10]');
    process.exit(2);
  }
  process.exit(compare(files[0], files[1], threshold, args.includes('--advisory-targets')));
}
