// Writes the licence texts of the npm packages that end up in the web vault bundle: every package
// in package-lock.json that is not a dev dependency, with its name, version, licence id and the
// licence files found in node_modules (LICENSE*, LICENCE*, COPYING*, OFL*, and NOTICE* for
// Apache-2.0 packages). Dependency-free, so it runs before or after `npm ci`.
//
//   npm ci && npm run notices > web-notices.txt     (tools/third-party-notices.sh does this)
//
// Exits 1 when a runtime package has no licence file, or is missing from node_modules: a release
// must not ship a package whose licence text it cannot include.
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
const lock = JSON.parse(readFileSync(join(root, 'package-lock.json'), 'utf8'));

const licenceFile = /^(?:licen[cs]e|copying|ofl)(?:[-._].*)?$/i;
const noticeFile = /^notice(?:[-._].*)?$/i;

// Runtime packages that ship no licence file but put no code in the bundle, each with the reason.
// Pinned by version: a new version has to be checked again.
const noCodeBundled = {
  'client-only@0.0.1':
    'A marker package of the React team. It ships no licence file, and the file the bundle takes\n' +
    '(index.js) is empty, so none of its code is in the web vault.',
};

function filesIn(dir, pattern) {
  return readdirSync(dir, { withFileTypes: true })
    .filter((entry) => entry.isFile() && pattern.test(entry.name))
    .map((entry) => entry.name)
    .sort();
}

const packages = [];
for (const [path, info] of Object.entries(lock.packages ?? {})) {
  // "" is the web package itself; links are workspace folders; dev packages are not bundled.
  if (path === '' || info.link || info.dev) continue;
  const name = info.name ?? path.slice(path.lastIndexOf('node_modules/') + 'node_modules/'.length);
  packages.push({ name, path, version: info.version, licence: info.license, optional: info.optional === true });
}
packages.sort((a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version));

const missing = [];
const sections = [];
for (const pkg of packages) {
  const dir = join(root, pkg.path);
  if (!existsSync(dir)) {
    // An optional package for another platform is not installed here and not in this bundle.
    if (!pkg.optional) missing.push(`${pkg.name}@${pkg.version}: ${pkg.path} is not installed (run npm ci first)`);
    continue;
  }
  let licence = pkg.licence;
  if (!licence) {
    try {
      licence = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8')).license;
    } catch {
      // reported below as unknown
    }
  }
  const licences = filesIn(dir, licenceFile);
  if (licences.length === 0 && noCodeBundled[`${pkg.name}@${pkg.version}`]) {
    const why = noCodeBundled[`${pkg.name}@${pkg.version}`];
    const rule = '-'.repeat(90);
    sections.push(`${rule}\n${pkg.name} ${pkg.version}\nLicence: ${licence ?? 'unknown'}\n${rule}\n\n${why}\n`);
    continue;
  }
  if (licences.length === 0) {
    missing.push(`${pkg.name}@${pkg.version} (${licence ?? 'unknown licence'}): no LICENSE, LICENCE, COPYING or OFL file`);
    continue;
  }
  const texts = [...licences, ...filesIn(dir, noticeFile)].map((file) => {
    const text = readFileSync(join(dir, file), 'utf8').replace(/\r\n?/g, '\n').trim();
    return `[${file}]\n\n${text}`;
  });
  const rule = '-'.repeat(90);
  sections.push(`${rule}\n${pkg.name} ${pkg.version}\nLicence: ${licence ?? 'unknown'}\n${rule}\n\n${texts.join('\n\n')}\n`);
}

if (missing.length > 0) {
  console.error('third-party-notices: runtime packages without a licence text:');
  for (const line of missing) console.error(`  ${line}`);
  process.exit(1);
}

process.stdout.write(
  [
    'KEMLOCK SERVER: THIRD-PARTY NOTICES, WEB VAULT DEPENDENCIES',
    '==========================================================',
    '',
    `The web vault is built from the ${sections.length} npm packages below (runtime dependencies in`,
    'web/package-lock.json, with their own dependencies). Kemlock Server\'s own licence is in LICENSE.',
    '',
    '',
    sections.join('\n'),
  ].join('\n'),
);
