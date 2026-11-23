// Which part of a host a site owns, by the Public Suffix List's algorithm (publicsuffix.org,
// MPL 2.0): accounts.example.com and mail.example.com are both example.com's, while alice.herokuapp.com
// and bob.herokuapp.com are two sites.
//
// The full list is 9,000 lines and would triple the vault's route chunk, and test-vectors/ does not
// pin a snapshot yet (docs/crypto.md says it will). This module embeds the rules that matter most
// in practice: the multi-label ICANN suffixes of the largest registries and the private suffixes of
// the big hosting platforms. A host whose suffix is not listed is treated as having a one-label
// suffix, which is right for every `.com`, `.org`, `.net`, `.io`, `.dev` and country code that has
// no second-level registry. `setPublicSuffixRules` swaps in a full snapshot (one rule per line, the
// list's own format) when the build pins one; the duplicate finder and the website hints read only
// `registrableDomain`, so nothing else changes.

const BUNDLED = `
// ICANN: second-level registries
co.uk
org.uk
me.uk
ltd.uk
plc.uk
net.uk
gov.uk
ac.uk
sch.uk
com.au
net.au
org.au
edu.au
gov.au
co.nz
org.nz
net.nz
govt.nz
co.jp
or.jp
ne.jp
ac.jp
go.jp
com.br
net.br
org.br
gov.br
com.cn
net.cn
org.cn
gov.cn
com.hk
com.tw
com.sg
com.my
com.mx
com.ar
com.tr
com.ua
com.pl
com.es
com.pt
co.za
org.za
co.in
net.in
org.in
ac.in
co.il
co.kr
or.kr
co.id
co.th
com.vn
com.ph
com.co
com.pe
com.ve
com.ec
com.eg
com.sa
com.ng
co.ke
// ICANN: wildcard and exception
*.ck
!www.ck
*.kawasaki.jp
!city.kawasaki.jp
// Private: places anyone can open a site under
github.io
githubusercontent.com
gitlab.io
herokuapp.com
vercel.app
netlify.app
pages.dev
workers.dev
web.app
firebaseapp.com
appspot.com
blogspot.com
wordpress.com
azurewebsites.net
cloudfront.net
s3.amazonaws.com
amazonaws.com
fly.dev
onrender.com
glitch.me
repl.co
myshopify.com
squarespace.com
wixsite.com
weebly.com
000webhostapp.com
ngrok.io
ngrok-free.app
duckdns.org
no-ip.org
dyndns.org
`;

interface Rules {
  plain: Set<string>;
  wildcards: Set<string>;
  exceptions: Set<string>;
}

function parseRules(text: string): Rules {
  const rules: Rules = { plain: new Set(), wildcards: new Set(), exceptions: new Set() };
  for (const raw of text.split('\n')) {
    const line = raw.trim();
    if (line === '' || line.startsWith('//')) continue;
    // A rule ends at the first whitespace, as the format says.
    let rule = (line.split(/\s/)[0] ?? '').toLowerCase();
    if (rule.startsWith('!')) {
      rules.exceptions.add(rule.slice(1));
    } else if (rule.startsWith('*.')) {
      rule = rule.slice(2);
      rules.wildcards.add(rule);
    } else {
      rules.plain.add(rule);
    }
  }
  return rules;
}

let current = parseRules(BUNDLED);

/** Replaces the bundled rules with a full snapshot of the list (its own text format). */
export function setPublicSuffixRules(text: string): void {
  current = parseRules(text);
}

const IPV4 = /^\d{1,3}(?:\.\d{1,3}){3}$/;

export function isIpAddress(host: string): boolean {
  return IPV4.test(host) || host.includes(':');
}

/** How many labels of `labels` (most specific first) are the public suffix. */
function suffixLabels(labels: string[]): number {
  for (let i = 0; i < labels.length; i += 1) {
    if (current.exceptions.has(labels.slice(i).join('.'))) return labels.length - i - 1;
  }
  let best = 1;
  for (let i = 0; i < labels.length; i += 1) {
    const rest = labels.slice(i);
    const count = rest.length;
    if (current.plain.has(rest.join('.'))) best = Math.max(best, count);
    if (rest.length > 1 && current.wildcards.has(rest.slice(1).join('.'))) best = Math.max(best, count);
  }
  return best;
}

/** `Mail.Example.CO.UK` -> `example.co.uk`. An IP address or a lone label is returned whole. */
export function registrableDomain(host: string): string {
  const lower = host.trim().toLowerCase().replace(/\.$/, '');
  if (lower === '' || isIpAddress(lower)) return lower;
  let ascii = lower;
  try {
    // The WHATWG URL parser applies IDNA and gives Punycode.
    ascii = new URL(`http://${lower}`).hostname;
  } catch {
    ascii = lower;
  }
  const labels = ascii.split('.');
  if (labels.length <= 1) return ascii;
  const count = suffixLabels(labels);
  if (labels.length <= count) return ascii;
  return labels.slice(labels.length - count - 1).join('.');
}

/** The host of a saved website: a scheme, path, port and user info are optional and dropped. */
export function hostOfWebsite(uri: string): string {
  let host = uri.trim().toLowerCase().replace(/^[a-z][a-z0-9+.-]*:\/\//, '');
  host = host.split(/[/?#]/)[0] ?? '';
  host = host.split('@').pop() ?? '';
  if (host.startsWith('[')) {
    const end = host.indexOf(']');
    return end > 0 ? host.slice(1, end) : host;
  }
  if (!IPV4.test(host.split(':')[0] ?? '') && host.split(':').length > 2) return host;
  return host.split(':')[0] ?? '';
}
