// Writes every text asset of dist/ in brotli, zstd and gzip beside the original, and a manifest
// of SHA-256 hashes for the "build hash" the apps check (design: Performance targets,
// "Precompressed web vault"). The server embeds dist/ whole and serves the smallest encoding the
// client accepts.
import { createHash } from 'node:crypto';
import { readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { constants, brotliCompressSync, gzipSync, zstdCompressSync } from 'node:zlib';

const dist = fileURLToPath(new URL('../dist', import.meta.url));
const compressible = /\.(?:html|js|css|json|svg|txt|wasm)$/;

function walk(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    return statSync(path).isDirectory() ? walk(path) : [path];
  });
}

const originals = walk(dist).filter(
  (f) => !/\.(?:br|zst|gz)$/.test(f) && !f.endsWith('web-build.json'),
);
const files: Record<string, string> = {};
for (const path of originals) {
  const data = readFileSync(path);
  const name = relative(dist, path).split(sep).join('/');
  files[name] = createHash('sha256').update(data).digest('hex');
  if (!compressible.test(path) || data.length < 256) continue;
  writeFileSync(
    `${path}.br`,
    brotliCompressSync(data, { params: { [constants.BROTLI_PARAM_QUALITY]: 11 } }),
  );
  writeFileSync(
    `${path}.zst`,
    zstdCompressSync(data, { params: { [constants.ZSTD_c_compressionLevel]: 19 } }),
  );
  writeFileSync(`${path}.gz`, gzipSync(data, { level: 9 }));
}

const buildHash = createHash('sha256')
  .update(
    Object.entries(files)
      .sort(([a], [b]) => (a < b ? -1 : 1))
      .map(([name, hash]) => `${name}\n${hash}\n`)
      .join(''),
  )
  .digest('hex');
writeFileSync(
  join(dist, 'web-build.json'),
  `${JSON.stringify({ sha256: buildHash, files }, null, 2)}\n`,
);
console.log(`precompressed ${originals.length} files; build hash ${buildHash}`);
