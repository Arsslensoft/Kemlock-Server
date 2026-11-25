# Kemlock web vault and admin console

One React 19 and TypeScript (strict) app, built into the server binary. The screens are the ones
on the design canvas, and its flow map is the route list in `src/app/router.tsx`.

| Concern | Choice |
| --- | --- |
| Build | Vite, one chunk per route, hashed file names, `assetsInlineLimit: 0`, SRI on every tag |
| Routing and data | TanStack Router (code routes, typed search params) and TanStack Query |
| Components | React Aria Components, styled by the canvas tokens in `src/styles/tokens.css` (Geist, dark and light) |
| Forms | React Hook Form with Zod schemas (`src/lib/schemas.ts`) |
| Text | ICU messages (FormatJS, `react-intl`) in `src/i18n/en.json`, keyed by message id |
| API | `src/api/client.ts`, hand-written for the routes the server has; types in `src/api/types.ts` |
| Crypto | `src/crypto/` (WebAssembly in a Web Worker); the app only sees `src/crypto-port.ts` |
| Tests | Vitest (`src/**/*.test.ts(x)`), Playwright and axe (`e2e/`) |

## Run it

Node 22.12 or newer.

```sh
npm install
npm run dev          # http://localhost:5173, proxies /kem to a server on localhost:8000
npm run typecheck
npm test             # Vitest, with a fake of the crypto worker
npm run build        # tsc, vite build, precompress, and the 250 KiB sign-in budget check
```

`npm run dev` needs a server: `DOMAIN=http://localhost:5173 ROCKET_PORT=8000 cargo run -p kemlock-server`.
The server prints the setup code in its log on first run.

### The API client

`npm run gen:api` reads `/kem/v1/openapi.json` from a running server (`KEMLOCK_URL`, default
`http://localhost:8000`), writes `src/api/schema.gen.d.ts` (not committed) and then type-checks
`src/api/wire.check.ts`, which ties the wire types in `src/api/types.ts` to it. A route the server
changes fails there, at build time.

Every authenticated call carries `Authorization: DPoP <token>` and a proof from the crypto worker.
The server's DPoP nonce is remembered and retried once; an expired access token is refreshed once.

### End to end

The Playwright journeys run against a real server that embeds the built web vault, so the CSP,
the isolation headers and the real crypto worker are all in play:

```sh
npm run build
cargo build -p kemlock-server --features web     # embeds web/dist
npx playwright install chromium
npm run e2e                                      # KEMLOCK_BIN, E2E_PORT, or BASE_URL + E2E_SETUP_CODE
```

With `BASE_URL=http://localhost:8080` the journeys use a server that is already running instead of
starting one; it must have been started with `DOMAIN` set to that same address, and
`E2E_SETUP_CODE` is the code it printed if the setup journey is to run.

The passkey journey (`e2e/a-passkey.spec.ts`) runs with the others after the numbered ones; it uses
Chromium's virtual authenticator with the PRF extension, so no key is needed: it makes a passkey
that opens the vault, confirms an admin change with it, and signs in with it.

The single sign-on journey (`e2e-sso/`) has its own config and server, because with a provider on
the sign-in screen takes a different path for every email. It signs in through Keycloak:

```sh
docker compose -f ../deploy/e2e/compose.yml up -d         # Keycloak 26.4, realm "kemlock" imported
set -a; . ../deploy/e2e/server.env; set +a                # SSO_ENABLED, SSO_AUTHORITY, SSO_CLIENT_*
npm run e2e:sso                                           # starts a server on 18081 with those
docker compose -f ../deploy/e2e/compose.yml down -v
```

It runs the setup journey first (SSO signs in as the admin it makes, found by email), then:

- a new Keycloak user signs in from the web vault: the browser makes the account's keys, keeps its own
  copy of the root key and opens the vault with no password; a second sign-in in the same browser opens
  it again from that copy, with no approval;
- the admin signs in from a new browser through Keycloak and Kemlock's second step, and another open
  browser approves it;
- a third user, at protocol level, plays the device itself (`e2e/dpop.ts` signs the DPoP proofs) and
  checks that the tokens `sso/finish` gives work.

Run it against a fresh server only.

`e2e/global-setup.ts` starts the binary on a fresh data folder and reads the setup code from its
log. The specs run in order: `0-delivery` (headers, SRI, caching), `1-setup` (the first-run
journey, which makes the admin and its authenticator secret) and `2-vault` (sign in, the vault
list, a new item, the Trash, lock and unlock). Each screen is checked with axe.

## Delivery

`cargo build -p kemlock-server --features web` embeds `web/dist` (rust-embed). Without the feature
the Rust workspace builds with no `web/dist`. A release build holds every file in the binary; a
debug build reads `web/dist` from disk, which is the development override.

- Headers on every response: the CSP from the design (`script-src 'self' 'wasm-unsafe-eval'`,
  `require-trusted-types-for 'script'`, `trusted-types kemlock`), COOP, COEP and CORP.
- `npm run build` writes brotli, zstd and gzip copies beside each text asset, and `web-build.json`
  with the SHA-256 of every file and of the bundle. The server picks the smallest encoding the
  client accepts. Files under `assets/` are `Cache-Control: public, max-age=31536000, immutable`;
  `index.html` is `no-cache` with an ETag.
- No inline script or style. The one thing React can't do under Trusted Types is `new Worker(url)`:
  use `scriptUrl()` from `src/lib/trusted-types.ts`, which owns the single `kemlock` policy.
- SRI covers the entry script and styles. A route chunk loaded later is checked by its hashed name
  and the build hash, not by SRI.

## What is not here yet

Built and wired to the server: sign-in (password, SSO, a passkey, an approval from another device,
also from the unlock screen, or with 2 of the 3 pieces of a Recovery Kit) and setup (with a security key or passkey), the vault with the item
forms for every kind (logins, notes, one-time codes, backup codes, cards, identities, SSH keys, PGP
keys, certificates and contacts), the Trash, Sends, spaces, import and export, duplicates, health,
devices and approvals, account security (an authenticator app, passkeys, security keys, YubiKey,
Duo, an emailed code, the recovery code, the Recovery Kit, emergency contacts) and the admin console (users and
invitations, event log, settings, SSO, migration, federation).

The Send list marks an item Send with its item's kind and icon: each text Send's payload is opened in the page
with its link key and only the kind is kept.

Not built, or not working yet:

- Scanning a Recovery Kit piece uses the browser's `BarcodeDetector` (Chromium, Safari) and, where
  there is none (Firefox), decodes the camera frames with `jsqr`, loaded only when the scanner opens.
  The kit is made and opened in the key worker, so the page never holds the root key
  (docs/crypto.md, "The Recovery Kit").
- An SSH key is made in the browser (Ed25519) or pasted as a PKCS#8 key; a PGP key or contact is
  pasted as armor; a certificate needs its key. Their detail pages read the stored halves (a
  certificate's subject and validity come from its PEM).
- First-run "Server basics": who can join, the email server, Kemlock's push relay and the backups
  (schedule, count, recipient) are saved by the server when setup finishes (as the admin
  Settings, where push and backups also have their own cards), and checked first; a value the
  server's environment sets stays as it is. The address and the files folder are configuration,
  not settings: `DOMAIN` is checked against sign-in proofs and `DATA_FOLDER` holds the store, so
  neither can change while the server runs. Setup only records the address, and Settings shows it
  beside the one in use and warns when they differ. The last setup screen lists both to copy into
  the server's environment. Bitwarden's push relay (`PUSH_*`) is set in Settings, not in setup.
- Where each vault lives (`src/api/placement.ts`): `GET /kem/v1/placement` is served from the
  federation state. A single server answers 404 and the failover banner and storage page show
  nothing. A server is named by the host of its address, and every peer's status is `unknown`,
  because the server does not probe its peers yet, so the banner does not appear on its own.
  Waiting changes are not kept per vault, so there is nothing to cancel.

### Federation: what a server cannot say

The federation screens call the real routes (`src/api/federation.ts` has the wire types and the
step into the screens' shapes). Every route the screens need is served; what a server cannot know,
it does not say, and the screens say nothing of it either:

- a vault has no name (it is ciphertext only its members read): the screens show the owner's
  email for an account's vault, and the short id for a space;
- a peer's name is the host of its first address, and its database and country are not in its
  descriptor: only this server's own are shown;
- a peer's security page has no TLS, session or event block: the server does not see the peer's
  transport, only its descriptor, KEM key, suites and the last handshake;
- a key mismatch names the address this server dialled (`fromAddress`), not an IP and port.

Writes need a `Step-Up-Token` (`check`, `consistency`, KEM and identity rotation, suites, keep
blocking); promotion and the identity rotation take a fresh check or a step-up token.
