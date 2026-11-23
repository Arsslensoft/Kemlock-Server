// Fails the build when the sign-in screen costs more than 250 KiB of JS and CSS, brotli
// (design: Performance targets). It counts the scripts and styles index.html names, the chunks
// they import statically, and the sign-in route's own chunk.
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { brotliCompressSync } from 'node:zlib';

const dist = fileURLToPath(new URL('../dist', import.meta.url));
const BUDGET = 250 * 1024;

const html = readFileSync(join(dist, 'index.html'), 'utf8');
const entries = [...html.matchAll(/(?:src|href)="\/(assets\/[^"]+\.(?:js|css))"/g)].map(
  (m) => m[1] as string,
);
const assets = readdirSync(join(dist, 'assets'));

const seen = new Set<string>();
function visit(file: string): void {
  if (seen.has(file)) return;
  seen.add(file);
  if (!file.endsWith('.js')) return;
  const code = readFileSync(join(dist, file), 'utf8');
  // Static imports only (`from"./x.js"`, `import"./x.js"`); dynamic imports are other routes.
  for (const m of code.matchAll(/(?:from|import)\s*"\.\/([^"]+\.(?:js|css))"/g)) {
    const name = m[1] as string;
    if (assets.includes(name)) visit(`assets/${name}`);
  }
}
entries.forEach(visit);

const signIn = assets.find((a) => /^SignInScreen-.*\.js$/.test(a));
if (signIn) visit(`assets/${signIn}`);

let total = 0;
for (const file of [...seen].sort()) {
  const size = brotliCompressSync(readFileSync(join(dist, file))).length;
  total += size;
  console.log(`${(size / 1024).toFixed(1).padStart(7)} KiB  ${file}`);
}
console.log(`${(total / 1024).toFixed(1).padStart(7)} KiB  total, budget ${BUDGET / 1024} KiB`);
if (total > BUDGET) {
  console.error('The sign-in screen is over its 250 KiB brotli budget.');
  process.exit(1);
}
