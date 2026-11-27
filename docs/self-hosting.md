# Self-hosting Kemlock Server

Kemlock Server is one static binary and one multi-arch image. Only the container and its `/data`
volume are required. This page installs it on each platform, covers reverse proxies and checks
what you downloaded.

The image is `ghcr.io/arsslensoft/kemlock-server` (also on docker.io and quay.io when those
mirrors are enabled). It runs as user 65532 on port 8080 with a read-only root filesystem, and
writes only to `/data`.

| Tag | Moves | Use it for |
|---|---|---|
| `1.4.2` | never | pinning |
| `1.4` | patches | careful updates |
| `1` | new minor releases | auto-updaters such as Watchtower |
| `latest` | the newest stable release, across majors | trying it out |
| `edge` | every push to `main` | trying the next release |
| `testing` | follows `main` (same image as `edge`) | testing |
| `1.4.2-fips`, `1-fips`, ... | as above | the FIPS image (amd64 and arm64), once published |

## First start

There is no admin token. On its first run the server prints a one-time setup code in its log; its
setup page asks for that code before it creates the first admin account. Look for it in the
container log (`docker compose logs kemlock`, `journalctl -u kemlock`, the app's log in Unraid or
TrueNAS).

Set `DOMAIN` to the address clients use, for example `https://vault.example.com`. Sign-in proofs
are checked against it. Settings use Vaultwarden's names (`DOMAIN`, `DATABASE_URL`,
`SIGNUPS_ALLOWED`, `DATA_FOLDER`, `LOG_LEVEL`, `ROCKET_ADDRESS`, `ROCKET_PORT`, `IP_HEADER`), plus
`KEMLOCK_TRUSTED_PROXIES` (addresses or blocks such as `10.0.0.0/8`), `KEMLOCK_LOG_FORMAT`, `KEMLOCK_BROWSER_EXTENSION_IDS` (see below) and
`KEMLOCK_SERVER_KEY`. A Vaultwarden setting
Kemlock has no use for, such as `ADMIN_TOKEN`, is logged once as ignored.

The web vault and `/kem/v1/config` offer every user the source of the version running, and anyone
running a modified server must set `KEMLOCK_SOURCE_URL` (or `source_url` in `kemlock.toml`) to where
their own source is, per AGPL-3.0 section 13. Bitwarden apps are the exception: the Bitwarden
API's `/api/config` keeps Vaultwarden's answer (its `server.url` names Vaultwarden's repository),
so those apps don't show the offer; the web vault, which every account can open, does.

An image built locally needs the licence notices first: run `tools/third-party-notices.sh` (it
needs `cargo-about` and the web vault's `npm ci --omit=dev`) before `docker build`, which stops
with that hint otherwise. `--target binaries` does not need it.

Two-step login keeps every method Vaultwarden has: an authenticator app, security keys (WebAuthn and
the older U2F), emailed codes, YubiKey OTPs and Duo. A moved account keeps its setups. Emailed codes
are offered when `SMTP_HOST` is set (`_ENABLE_EMAIL_2FA`, `EMAIL_TOKEN_SIZE`, `EMAIL_EXPIRATION_TIME`
and `EMAIL_ATTEMPTS_LIMIT` as in Vaultwarden). YubiKeys need `YUBICO_CLIENT_ID` and
`YUBICO_SECRET_KEY` (`YUBICO_SERVER` for another validation server), and an account that never saved
Duo keys of its own uses `DUO_HOST`, `DUO_IKEY` and `DUO_SKEY`. These are read from the environment
and then from `config.json` in the data folder, so a Vaultwarden data folder that was configured in
its admin page carries them over.

### Browser extension sign-in (`KEMLOCK_BROWSER_EXTENSION_IDS`)

Single sign-on for the Kemlock browser extension ends at the extension's own address, which only
that extension can read: Chrome and Edge give it `https://<extension id>.chromiumapp.org/`, Firefox
`https://<hash>.extensions.allizom.org/`. The server hands a sign-in code to that address only for
an extension you name, because any other installed extension could otherwise read the code. Set
`KEMLOCK_BROWSER_EXTENSION_IDS` (or `browser_extension_ids` in `kemlock.toml`) to the
comma-separated ids of the extensions your people use, for example
`KEMLOCK_BROWSER_EXTENSION_IDS=abcdefghijklmnopabcdefghijklmnop,0123456789abcdef0123456789abcdef01234567`:
a Chrome or Edge extension's id, and for Firefox the hash its redirect address starts with. It is empty by default, so no extension
may until you set it. Letters and digits only; the server refuses to start on anything else.

An address is accepted only when it is exactly `https://<id>.chromiumapp.org/` or
`https://<hash>.extensions.allizom.org/` with the path `/` or `/sso`, the id is on the list, and
the sign-in began as a `kemlock-browser` device, which `finish` then requires too. The setting is
read at start and is not in the admin console. Sign-in with a passkey or a security key from the
extension runs on the server's own page, `/kem/v1/webauthn`, which needs no setting.

## Mail, push and live sync

None of this is required. Without `SMTP_HOST` the server only logs that a mail would have gone out
(the subject, never the body or the address), and without a push key an app with an open
connection still updates at once, and the others when they next sync.

### Mail (`SMTP_*`)

Vaultwarden's names, read from the environment. Mail covers emailed two-step codes, the notice
that a device signed in for the first time, device approval requests, emergency access, space
invitations (with a link to sign in and accept), the invitations of Bitwarden apps (with a link to sign in and accept, below) and the admin console's alerts and invitations to
the server. Notice mails say enough to recognise your own activity and never carry a key, an item
name or a link that opens anything without signing in.

| Setting | Default | Meaning |
|---|---|---|
| `SMTP_HOST` | unset | the SMTP server; mail is on only when it is set |
| `SMTP_FROM` | required with the host | the sender address |
| `SMTP_FROM_NAME` | `Kemlock` | the sender's name |
| `SMTP_SECURITY` | `starttls` | `starttls` (port 587), `force_tls` (port 465) or `off` (port 25, for a relay on your own network) |
| `SMTP_PORT` | by `SMTP_SECURITY` | the port, if not the usual one |
| `SMTP_USERNAME`, `SMTP_PASSWORD` | unset | the login; set both or neither |
| `SMTP_TIMEOUT` | `15` | seconds to wait for the server |
| `SMTP_ACCEPT_INVALID_CERTS` | `false` | accept a certificate that does not check out (a lab, never production) |
| `SMTP_ACCEPT_INVALID_HOSTNAMES` | `false` | accept a certificate for another name |
| `REQUIRE_DEVICE_EMAIL` | `false` | the Bitwarden API refuses a sign-in from a new device when the mail about it can't be sent, as in Vaultwarden |

A bad value stops the start and names the setting. The admin console shows whether mail is set up.
The Kemlock API mails from a task of its own, so a slow SMTP server does not hold up a sign-in.

### Verifying the email of a new account (`SIGNUPS_VERIFY`)

Off by default. When it is on and the server can send mail (`SMTP_HOST` is set), an account made on
a sign-up is held back until the link mailed to its address is opened: it can't sign in or be used,
the Kemlock API answers `email-not-confirmed` (403), and single sign-on does not link to it by
email. The link opens a page with a Confirm button (a mail scanner that fetches the link spends nothing; the button posts the token); it works once and runs out in 24 hours; `POST /kem/v1/accounts/confirm-email/resend`
(the sign-in screen's "send it again") mails a new one, at most one in five minutes. An account made
from an invitation (its token was mailed to the address) or as the first admin is not held, and
accounts that existed before the setting was turned on are confirmed. The hold only counts while the setting is on and mail works: turning it off (or losing `SMTP_HOST`) releases every held account. The Kemlock API's
`register/finish` answer then carries `"emailConfirmationRequired": true`; with the setting off it
is the answer it always was. The Bitwarden API follows the same setting for its own registration.

Without a mail server the setting can't work, so the console refuses to turn it on until a mail server (an SMTP host and a sender address, with a
user name only together with its password) is saved, and a server started with `SIGNUPS_VERIFY=true` and no `SMTP_HOST` logs a warning and
holds no one back. Without it anyone can register any address first: with sign-ups limited to
`@corp.com`, someone could take `ceo@corp.com` before its owner does. Turn it on whenever sign-ups
are open to people you don't know, or limited to a domain.

### Single sign-on and linking by email (`SSO_*`)

`SSO_SIGNUPS_MATCH_EMAIL` (default `false` for a new install; Vaultwarden's default is `true`) lets a
person's first sign-in with the provider link to the account that already has the email the provider
vouches for. A new install also asks for a proven domain (`KEMLOCK_SSO_REQUIRE_VERIFIED_DOMAIN`, default
`true`; the console's "Only accept people whose email domain is verified here"). A server whose settings
are stored already keeps the values it has. That is the risk to weigh: whoever controls an address at the provider (an open sign-up, an alias, a mail domain the
provider doesn't check) gets the Kemlock account of that address. Kemlock narrows it:

- the provider's `email_verified` must be true (`SSO_ALLOW_UNKNOWN_EMAIL_VERIFICATION` accepts a
  token with no such claim only where the domain is proven by DNS in the console);
- an account whose email was never confirmed (see `SIGNUPS_VERIFY`) is never linked;
- an account that has a second step is not linked at all: its own second step is asked at every
  sign-in the provider makes by email, whatever the provider's `amr` says, and nothing is stored
  that an abandoned challenge could leave behind. The `amr` skip ("Via SSO") applies only to
  identities of accounts SSO made and links made while the account had no second step. Links of
  accounts with a second step that were stored before this rule are unconfirmed from the update on,
  so their second step is asked at each sign-in too. An administrator's account counts as an admin
  only with a second step turned on, so linking to one by email asks for it before any token is
  issued;
- a back-channel logout ends only the devices that identity (or that provider session, `sid`)
  signed in (a device that passed the account's second step after SSO included), never the
  account's other devices. Devices SSO signed in before the update have no record and are not ended
  by a logout. Signing a device in some other way takes its record away.

To restore the old defaults of a server whose settings you want to behave like before this change
(link by email on, no proven domain needed), set `SSO_SIGNUPS_MATCH_EMAIL=true` and
`KEMLOCK_SSO_REQUIRE_VERIFIED_DOMAIN=false` for a new install, or tick the same two settings in the
console (a stored setting is never changed by an update).

Safer settings: set `SSO_SIGNUPS_MATCH_EMAIL=false` and let SSO make its own accounts (an existing
account then stays out of SSO and the sign-in answers `sso-linking-off`); or keep it on, require a
proven domain (the console's "Only accept people whose email domain is verified here") and turn `SIGNUPS_VERIFY` on.

### Invitations from Bitwarden apps (`KEMLOCK_BW_INVITES_AUTO_ACCEPT`)

An invitation to an organization, or to be an emergency contact, made from a Bitwarden app to an
account that already exists leaves that account **invited** until the person accepts. Vaultwarden
without mail takes such an account as accepted at once; this server does not, because it lets anyone
who can invite put another account into an organization (and bind it by that organization's
policies) without being asked.

How the person accepts:

- **With mail**, they get a link of the shape Vaultwarden mails
  (`/#/accept-organization/?organizationId=...&token=...`, `/#/accept-emergency/?id=...&token=...`).
  Opening it shows who invited them and asks for their master password; nothing is sent until they
  press the button. The page reads the account's key settings from the server's prelogin, makes the
  master password hash in the browser's crypto worker (PBKDF2 or Argon2id, as the account has it) and
  sends the token with that hash, never the password, and needs no sign-in, which an account made in a
  Bitwarden app could not do in the web vault. The token alone accepts nothing: the hash is checked as a
  sign-in is (the same count of wrong passwords per account, the same slowdown), and a successful
  accept starts no session, so the page ends with a link to sign in. A person signed in to a Bitwarden
  app can accept with that session instead. A key for account recovery is kept only with the password.
  An administrator (or, for an emergency contact, the grantor) then confirms. The link works for five
  days. An account that can sign in to the web vault also gets the usual space invitation, and can
  accept on its space page.
- **Without mail**, the administrator who invited (and the grantor, for an emergency contact) can
  read the same link from the Bitwarden API, `GET /api/organizations/{org}/users/{member}/invite-link`
  or `GET /api/emergency-access/{id}/invite-link`, and hand it over. The link accepts nothing by
  itself, for an organization or an emergency contact: the person proves who they are with the master password.

Set `KEMLOCK_BW_INVITES_AUTO_ACCEPT=true` (or the "Accept Bitwarden invitations for the invitee"
switch in the console, under sign-ups) to get Vaultwarden's behaviour back. It applies **only while
no mail is set up**, and only to an account that has a password. The risk: whoever can invite an
address can then make that account a member of their organization (an administrator still has to
confirm it before it sees anything), and bind it by that organization's policies once it is
confirmed. Turn it on only for a server whose members all trust each other, such as one person's
family.

### Push to phones

The server wakes the Kemlock apps itself, with a push that says only "sync now": no email, account
id, item or name. Nothing passes through Kemlock or anyone else. The admin console's Push card shows
where each stands.

**iPhone (Apple push), `KEMLOCK_APNS_*`.** Make a key for the Apple Push Notification service in
your own Apple developer account (Certificates, Identifiers & Profiles, Keys, with "Apple Push
Notifications service (APNs)" ticked), download the `.p8` file once, and note the key's id and your
team id. The server signs a short-lived token with it and posts to Apple's HTTP/2 API. Set all of
`KEMLOCK_APNS_KEY_FILE`, `KEMLOCK_APNS_KEY_ID` and `KEMLOCK_APNS_TEAM_ID`, or none. A bad value
stops the start and names the setting; the key never appears in logs. A server with no Apple key
sends no push to iPhones unless you turn on the relay below.

| Setting | Default | Meaning |
|---|---|---|
| `KEMLOCK_APNS_KEY_FILE` | unset | path to the `.p8` file |
| `KEMLOCK_APNS_KEY_ID` | unset | the key's id (10 letters and digits) |
| `KEMLOCK_APNS_TEAM_ID` | unset | your Apple developer team id |
| `KEMLOCK_APNS_TOPIC` | `com.kemlock.app` | the app's bundle id |
| `KEMLOCK_APNS_SANDBOX` | `false` | `true` pushes through Apple's sandbox, for development builds of the app |

Apple answers `BadDeviceToken` to a token from the wrong environment, so a wrong
`KEMLOCK_APNS_SANDBOX` fails every push and logs one warning per send. The tokens are kept; fix the
setting. Only a token Apple calls unregistered (410) is forgotten.

**Android (UnifiedPush).** Kemlock uses no Firebase. A phone with a UnifiedPush distributor (ntfy,
Gotify, NextPush and others) registers the endpoint URL the distributor gave it, and the server
posts an empty body to it (Web Push without a payload, RFC 8030). The endpoint must be `https` on
port 443 (the default) or 8443, so a client can't aim the server at other services. The server
resolves the name itself and refuses any address that is not public (loopback, private, link-local
and the like), follows no redirect, ignores `HTTPS_PROXY` and `ALL_PROXY`, and gives up on a push
after a few seconds, so an endpoint can't be used to reach your own network. Slow endpoints are
pushed to in a task of their own and never delay other pushes. Without a distributor, the app keeps
its live connection while it is open and syncs when opened.

| Setting | Default | Meaning |
|---|---|---|
| `KEMLOCK_UNIFIEDPUSH_ALLOW_PRIVATE` | `false` | `true` also pushes to endpoints on a private network (10/8, 172.16/12, 192.168/16, fc00::/7), for a ntfy or Gotify on your LAN. Loopback, link-local, unspecified and multicast addresses are never reached |

A name that resolves to an address the server won't reach is not forgotten: the push fails (and is
logged), and the next one looks the name up again. An endpoint written as an address that is not
allowed is forgotten. An account may register at most 20 UnifiedPush endpoints; the 21st is refused
with a 400.

**Kemlock's hosted relay, optional, `KEMLOCK_PUSH_RELAY*`.** A fallback for iPhones on a server
that has no Apple key (`docs/push-relay.md` is its contract). It is off unless you turn it on, and a
server with an Apple key never uses it. It receives only a device's push token, this server's
installation id and the nudge. Turn it on or off in the admin console's Push card (or
`POST /admin/v1/push-relay/enable` and `/disable`, behind the same password or code check as other
changes), or set `KEMLOCK_PUSH_RELAY=true` so the server registers at its next start. Turning it off
erases the installation at the relay and here, and works even when the relay can't be reached.

| Setting | Default | Meaning |
|---|---|---|
| `KEMLOCK_PUSH_RELAY` | `false` | `true` registers this server with the relay at start when it hasn't yet |
| `KEMLOCK_PUSH_RELAY_URL` | `https://push.kemlock.app` | another relay, such as your own; it must be `https`, because the installation key goes with every send |

### Push and backups are settings too

Every `PUSH_*`, `KEMLOCK_PUSH_RELAY*` and `KEMLOCK_BACKUP_*` variable above (schedule, count, folder,
recipient) is also a setting in the admin console (Settings, Push and Backups), and the first-run
setup saves the push switch and the backups. The installation id and key are kept sealed under
`server.key`. A saved value takes effect without a restart: the server rebuilds the relay and the
backup schedule looks again every 30 seconds. A variable that is set wins and the console shows it
read-only. A backup folder saved in the console must be inside the data folder; the variable may
name any folder or a bucket. `DOMAIN` and `DATA_FOLDER` are not settings: sign-in proofs are
checked against `DOMAIN` and the store lives in `DATA_FOLDER`, so they change only in the
environment, with a restart. Setup records the address it was given, and the console shows it
beside `DOMAIN` with a warning when they differ.

### Bitwarden's push relay (`PUSH_*`)

Bitwarden's phone apps don't use Kemlock's relay. As with Vaultwarden you register an installation
at <https://bitwarden.com/host> and set the three values below; Bitwarden is then a processor of
those pushes, on its own terms. The server registers each phone's push token at the relay
(`PUT /api/devices/identifier/{id}/token`) and sends it an update when its vault changes. The
messages on `/notifications/hub` (the open sockets of the apps and the web vault) need none of this.

| Setting | Default | Meaning |
|---|---|---|
| `PUSH_ENABLED` | `false` | turns Bitwarden's relay on |
| `PUSH_INSTALLATION_ID`, `PUSH_INSTALLATION_KEY` | required when enabled | the installation from bitwarden.com/host |
| `PUSH_RELAY_URI` | `https://push.bitwarden.com` | `https://push.bitwarden.eu` for the EU cloud |
| `PUSH_IDENTITY_URI` | `https://identity.bitwarden.com` | `https://identity.bitwarden.eu` for the EU cloud |

A missing id or key, or an address that is not `https`, stops the start.

### Several replicas

Live sync between replicas needs no setting: the server picks what the database offers. On SQLite
(one process) a change goes straight to the open sockets. On PostgreSQL every replica listens on a
`NOTIFY` channel, and the replica that took the write nudges its own sockets through it. On MySQL
each replica appends the owner to a small table and polls it every second. A nudge carries only the
owner, never what changed, and a replica that loses its connection nudges every socket once when it
is back. Only the replica that took a write pushes to phones, so a phone is woken once. Bitwarden
apps are told in detail by the replica that took the write and with a general sync by the others.

Password checks per account. However many addresses the guesses come from, one account has at most
one password check in flight on a replica, and the next starts a second after the last ended; the
others wait their turn in order (up to 16 waiting, past which a request skips the line and is held
back 3 seconds). A wrong password from one address counts against that address and slows the
account (a few seconds, once 10 wrong in 15 minutes or 100 an hour have come from anywhere). The
right password is only ever later, and no number of guesses from other addresses refuses it.

Rate limits and replay checks. Each replica keeps these in its own memory: the per-address limits
(sign-in starts, DPoP proofs, registration, device-approval requests), the per-address-and-account
limit on wrong passwords, and the replay sets of DPoP proofs and spent login states. With several
replicas behind one load balancer every per-address limit therefore multiplies by the number of
replicas (a client that spreads its tries over all of them gets that many), and a proof or login
state replayed against a different replica than the one that first saw it is not recognised there.
That is acceptable because none of them is the only thing standing in the way: a login state and a
second-step challenge are sealed with the shared server key and bound to the DPoP key of the device
that asked for them, an access token is bound to its device's key too, so a captured proof or state
is no use without that key, and the part that decides whether a guess may be made is shared. The
count of second-step attempts (authenticator codes, security keys, recovery codes, and the proofs
for changing a method) is kept in the database, per account: an attempt is reserved there before
the code is checked, so the limit (5 in 15 minutes by default, then doubling waits) holds across
replicas and restarts and parallel guesses can't all pass it. Open second-step challenges per
account, the admin console's step-up, mailed setup codes, and the slowdown after many wrong
passwords for one account are per replica. To keep a per-address limit as set, send each client
address to one replica (a load balancer's source-address affinity) or divide the limit by the
number of replicas in the console.

## Docker and Compose

```bash
curl -fsSLO https://raw.githubusercontent.com/arsslensoft/kemlock-server/main/compose.yaml
mkdir -p kemlock-data && sudo chown 65532:65532 kemlock-data   # the container's user writes here
$EDITOR compose.yaml                                            # set DOMAIN
docker compose up -d
docker compose logs kemlock                                     # the setup code
```

Vaultwarden's image listens on port 80 as root; this one runs as non-root on 8080, so change the
container side of an old port mapping. To move from Vaultwarden, see "Moving from Vaultwarden"
below.

The port is bound to `127.0.0.1` for a reverse proxy on the same host. A named volume
(`volumes: [kemlock-data:/data]`) needs no `chown`.

## Moving from Vaultwarden

The move copies a Vaultwarden server's accounts, vaults, files and settings as they are stored, so
nobody re-keys or signs in again, and it never changes Vaultwarden's own data. Stop Vaultwarden
(or use `--twice` below), then use either the console or the command line.

**From the admin console** (Move from Vaultwarden). The console reads only a SQLite file inside the
`import` folder of the server's data folder, `/data/import/` in the image. Copy Vaultwarden's data
folder (`db.sqlite3`, `attachments/`, `sends/`, `rsa_key.pem`, `config.json`) into it, for example
`/data/import/db.sqlite3`, and name the file (or the folder that holds `db.sqlite3`) relative to
the import folder, as plain names joined by `/` (no absolute path, drive, network share, `..` or `:`; they are refused before anything is opened). The optional second field names a folder inside it that holds the files when
they are not beside the database. Symbolic links are followed and a path that ends up outside the
import folder is refused; so is a database URL, and a missing source gets the same answer as a
refused one. An admin can't put files into the import folder, so only whoever runs the server
decides what the console may read. A MySQL or PostgreSQL Vaultwarden has to be moved with the
command line, or exported to SQLite first.

The console makes **one** move: once it has finished, it refuses to start another. People use their
accounts here from then on, and a second pass over the same snapshot would be one click from
undoing what they changed. **Empty the `import` folder when the move is done** (it holds your
Vaultwarden data, password hashes and keys included); a later pass is the command line's.

**From the command line**, on the server (`kemlock-cli import-vaultwarden --from <folder|url>
[--files <folder>] [--twice] [--apply] [--adopt-existing]`): `--from` is a data folder or a
`mysql://` or `postgres://` URL, and without `--apply` it only prints the plan. A URL with a password
in it goes in an environment variable, `--from-env VW_DATABASE_URL`: an argument is visible to every
user of the machine in the process list, so `--from` refuses a URL that carries a password.

Both write only what an import made. An account or space whose id already exists on this server is
the import's only when the import created it (the server keeps a record of each id a move created,
`vw_import_ids`) or nothing has that id yet. Everything else that names such an account or space (its
devices, two-step setups, memberships, items, attachments, collections, groups, Sends, events and
files) is skipped too, so a Vaultwarden database can't rewrite, sign in as, or take ownership in
accounts or spaces that aren't its own. Running a move again over its own earlier copy works as
before, but never over what this server has changed since: an account whose record, vault or
password was changed here after the import wrote it, a space that was renamed or whose members
changed, and an item revised here after the source's date are left as they are, with everything
that hangs off them. `--adopt-existing` overrides that too. Imported `config.json` settings become the
console's own settings (Settings screen; an environment variable still wins), but only these: `signups_allowed`,
`signups_verify`, `signups_domains_whitelist`, `invitations_allowed` and the `smtp_host`, `smtp_port`,
`smtp_security`, `smtp_username`, `smtp_from` and `smtp_from_name` of the SMTP settings, and only when the console
accepts the value. The source is not trusted to set anything else: Kemlock's own security, backup, push and
federation settings, and every secret, are not carried. The dry-run plan lists each value that would be written
and the move's entries in the admin event log (`admin.migration.setting`) name each one that was.

What was left alone is listed in the move's result and in the admin event log
(`admin.migration.done`, `admin.migration.failed` for the console and `admin.migration.cli` for
the command line, with where it read from, counts by kind and the ids it refused). If this server
already holds the same accounts from a move made before these records existed, the first run lists
them all; run the command line once with `--adopt-existing` to overwrite them on purpose (it prints
a warning, records the ids, and from then on the console may rerun the move). The console never
offers that.

## Podman (Quadlet)

```bash
mkdir -p ~/.config/containers/systemd
cp deploy/podman/kemlock.container deploy/podman/kemlock-data.volume ~/.config/containers/systemd/
$EDITOR ~/.config/containers/systemd/kemlock.container          # set DOMAIN
systemctl --user daemon-reload && systemctl --user start kemlock
loginctl enable-linger "$USER"
journalctl --user -u kemlock                                      # the setup code
```

## Kubernetes (Helm)

One replica on SQLite with a PersistentVolumeClaim, or several on PostgreSQL and S3.

```bash
helm install kemlock deploy/helm/kemlock-server \
  --set domain=https://vault.example.com \
  --set ingress.enabled=true --set ingress.className=nginx \
  --set 'ingress.hosts[0].host=vault.example.com' --set 'ingress.hosts[0].paths[0].path=/' \
  --set 'ingress.hosts[0].paths[0].pathType=Prefix'
kubectl logs deploy/kemlock-kemlock-server | grep -i "setup code"
```

Probes: `/alive` for liveness, `/health` for readiness (it also checks the database, migrations and
file storage and answers 503 naming what failed). The chart refuses `replicaCount > 1` unless the
database is PostgreSQL, attachments are in S3 (`blob.type=s3`, settings in `extraEnv`), every
replica shares one server key (`serverKey.existingSecret`) and persistence is off, because a
SQLite file and a local folder can't be shared. The PVC is kept when the release is deleted.

## Unraid

Add `deploy/unraid/kemlock-server.xml` as a template (Docker, Add Container, Template
repositories), or install it from Community Apps once listed. Set Domain, apply, and read the
container's log for the setup code. The template runs the container as `99:100` so it can write
the appdata folder.

## TrueNAS

`deploy/truenas/kemlock-server/` is the app in the apps catalog's layout. Until it is in the
catalog, add it to a catalog of your own or use Custom App with the image,
`ghcr.io/arsslensoft/kemlock-server:1`, port 8080, a dataset mounted at `/data` that user 568
can write, and `DOMAIN` set.

## Proxmox VE

On the Proxmox host, as root:

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/arsslensoft/kemlock-server/main/deploy/proxmox/kemlock-lxc.sh)" \
  -- --domain https://vault.example.com
```

It makes an unprivileged Debian 12 container, installs the release binary and runs it as the
systemd unit in `deploy/systemd/`. Before it installs anything it checks the archive's `SHA256SUMS`
and its cosign signature against this repository's `release.yml` at the release tag; a signature
that is missing or does not verify stops the install. cosign is in no Debian package, so the script
downloads a pinned cosign release from Sigstore and checks it against that release's checksum file
(`/usr/local/lib/kemlock` in the container). Update later with `kemlock-lxc.sh --update <ctid>`,
which checks the same way. The community-scripts version (`deploy/proxmox/`, see its README) does
the same check, with the same pinned cosign, on install and on update.

## Home Assistant

Add `https://github.com/arsslensoft/kemlock-server` under Settings, Add-ons, Add-on Store, Repositories (the
add-on repository is `deploy/home-assistant/`). Install Kemlock Server, set the `domain` option and
start it. Stop the add-on while taking a backup (the add-on sets `backup: cold`).

The add-on starts as root only to read its options and take ownership of its data, then runs the
server as an unprivileged user (uid 10001) that owns `/data/kemlock`. On every start it gives any
file in that folder that someone else owns (a restored backup, or data an earlier version wrote as
root) to that user. Everything the server writes must be inside `/data/kemlock`: if you set
`database_url` to a SQLite file, put the file in that folder.

## Synology Container Manager

1. Container Manager, Project, Create. Name it `kemlock`, and choose a path such as
   `/volume1/docker/kemlock`.
2. Paste `compose.yaml`. Change the volume to `/volume1/docker/kemlock/data:/data`, and add
   `user: "1026:100"` (your DSM user's id and the `users` group) under the service so it can write
   that folder. Set `DOMAIN`. Change `127.0.0.1:8080:8080` to `8080:8080` if the reverse proxy
   (Control Panel, Login Portal, Reverse Proxy) is not in a container on the same host.
3. Build and start. Open Container Manager, Container, `kemlock`, Log for the setup code.
4. In Control Panel, Login Portal, Reverse Proxy, add a rule from `https://vault.example.com` to
   `localhost:8080`. Add the custom headers `Upgrade: $http_upgrade` and
   `Connection: $connection_upgrade` (the Create, Custom Header, WebSocket shortcut does both) so
   `/kem/v1/live` and `/notifications/hub` work.

## QNAP Container Station

1. Container Station, Applications, Create. Name it `kemlock` and paste `compose.yaml`.
2. Change the volume to a shared folder such as `/share/Container/kemlock:/data` and set
   `user: "1000:100"` (an admin user and group that can write it). Set `DOMAIN`.
3. Create. Read the container's log for the setup code.
4. Put QNAP's reverse proxy (Control Panel, Applications, Reverse Proxy) or a proxy container in
   front of port 8080, with WebSocket upgrades on.

## systemd, Debian and Ubuntu

Release downloads (below) carry a static binary for Linux. `deploy/systemd/kemlock.service` runs
it with systemd's sandboxing, as user `kemlock`, settings from `/etc/kemlock/kemlock.env` and data
in `/var/lib/kemlock`. A signed apt repository and RPMs built on the Open Build Service are on the
packages list but not published yet.

## Release binaries

Each release attaches `kemlock-<version>-<target>.tar.gz` (a `.zip` on Windows) for these targets,
with a `SHA256SUMS` file, one cosign bundle per file, SLSA provenance and the SBOMs.

| Level | Targets |
|---|---|
| First class | `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`, `armv7-unknown-linux-musleabihf`, `arm-unknown-linux-musleabihf` (ARMv6) |
| Best effort | `i686`, `powerpc64le`, `riscv64gc` on Linux musl; `x86_64-unknown-freebsd`; `aarch64-apple-darwin`, `x86_64-apple-darwin`; `x86_64-pc-windows-msvc` |

There is no `s390x` build: Rust ships no prebuilt standard library for `s390x-unknown-linux-musl`
(a Tier 3 target), and building one needs a nightly toolchain.

## Reverse proxies

`deploy/proxy/` has examples for Caddy, Traefik, nginx and HAProxy, each tested in CI by opening a
WebSocket through it. Kemlock serves the API, the web vault and both WebSocket routes,
`/notifications/hub` and `/kem/v1/live`, on one port.

| Proxy | What it needs |
|---|---|
| Caddy | `reverse_proxy kemlock:8080`; WebSocket upgrades pass by default |
| Traefik | A router and a service on port 8080; WebSocket upgrades pass by default |
| nginx | `proxy_http_version 1.1` and the `Upgrade` and `Connection` headers on the two WebSocket routes; `client_max_body_size` at the file limit |
| HAProxy | A long `timeout tunnel`, such as `1h`, so idle WebSockets stay open |

- Real client IPs. The header named by `IP_HEADER` is trusted only from the addresses in
  `KEMLOCK_TRUSTED_PROXIES`, so rate limits and connection caps see the real client. Set both:
  without them every client looks like the proxy and shares one budget, so a few slow requests
  from one person can lock everyone out. `KEMLOCK_TRUSTED_PROXIES` takes addresses and blocks of
  them (`10.0.0.1, 10.244.0.0/16, fd00::/8`; `/0` is refused), and Kemlock refuses to start when
  `IP_HEADER` is set with no trusted proxy. `compose.yaml` trusts `X-Forwarded-For` from
  `172.16.0.0/12`, the Docker bridge networks the host's proxy arrives from; the Helm chart does
  the same from the private ranges when the ingress is on (set `ipHeader` and `trustedProxies` to
  narrow it to your controller). Kemlock reads every line of the header and takes
  the right-most address that is not a trusted proxy; have the outermost proxy drop any
  `X-Forwarded-For` the client sent (the HAProxy example does).
- Private only. Bind the port to a Tailscale or WireGuard address, or run Tailscale as a sidecar
  with `tailscale serve`, and nothing is open to the internet. A Cloudflare Tunnel needs no open
  port either, but Cloudflare then sees decrypted requests: vault data stays end-to-end encrypted
  and OPAQUE never sends the password, but a Compatible account's password hash passes through.
- No TLS of its own. Kemlock listens on plain HTTP only and gets no certificate itself, so put one
  of the proxies above, or a tunnel, in front of any address that isn't on a network you trust.
  A `DOMAIN` that starts with `http://` and isn't `localhost` or a loopback address makes the
  server log a warning at start-up.
- Slow clients and floods. A connection that hasn't delivered the head of its first request
  within 10 seconds is dropped, even if it sent nothing at all, and so is one whose write makes no
  progress for 60 seconds (a client that never reads its response). The head of a later request on
  a kept-alive connection may take 125 seconds, which is also how long such a connection may sit
  idle: set above what a proxy keeps an idle upstream connection for, so the proxy closes it
  first (Caddy's `reverse_proxy` keeps one for 2 minutes, nginx's `keepalive_timeout` in an
  `upstream` block defaults to 60 seconds; if you raise those past 125 seconds, a request can be
  sent down a connection that is closing and fail with a 502). One client address may hold
  `KEMLOCK_MAX_CONNECTIONS_PER_IP` connections at once (default 64, `max_connections_per_ip` in
  `kemlock.toml`, 0 for no limit; an IPv6 address counts by its /56), and further connections from
  it are closed. The addresses in `KEMLOCK_TRUSTED_PROXIES` are exempt, because behind a proxy
  every connection comes from the proxy. `KEMLOCK_MAX_CONNECTIONS` caps all connections together
  (default 4096, and never more than three quarters of the open-file limit the server runs under,
  read at start from `/proc/self/limits`; 0 for no limit): further clients wait in the operating
  system's queue until one ends, so a client that holds many connections can fill it, which is why
  the per-address limit is there too. Both count WebSockets for as long as their socket is open.
  Raise the open-file limit if you raise them (`LimitNOFILE` in systemd, `--ulimit nofile` in
  Docker). An HTTP/2 connection is pinged every 30 seconds and dropped when the peer doesn't
  answer within 20, is held to 100 streams and 32 KiB of request headers, and is ended gracefully
  once it has had no request in flight for 125 seconds.
- IPv6. Kemlock listens dual-stack on `[::]` by default. Rate limits count an IPv6 client by its
  /56 (the failed-password limit per account counts by /64), so a host that rotates through the
  /64s of its site shares one count.

## The web vault on a shared computer

The web vault keeps the person signed in, with the vault open, across a reload of the tab, and only
that. What it keeps lives in the tab's session storage: the tokens and the root key, both sealed
in a Web Worker under a key that belongs to that tab alone (non-extractable, in IndexedDB), and
honoured only for a reload within 10 seconds of the page leaving. A tab that was closed and restored,
or duplicated, has to sign in again. Every page of the vault stamps its tab's key every few seconds
and deletes the keys of tabs that have been silent for longer than a reload takes, on each load and on
each stamp, so what a closed tab left behind stops opening within about 14 seconds of anyone using
the vault again on that computer.

What this does not cover: a person with the browser's developer tools open on the vault's own
origin, and a tab closed a moment ago. They can keep stamping a closed tab's key from any page of the
origin and open the tab's storage with the vault's script blocked; the key then opens what it sealed.
The seal protects against someone who only has the browser profile's files, or the browser's session
restore, not against a script running on the origin. On a computer that other people use, give each
person their own browser profile or account, sign out when you leave, and lock the vault. A vault
locks by itself after 15 minutes idle and 5 hidden, sooner when a space's session timeout policy says
so, and a sign-out ends the session on the server too (the device and its trusted-device copy stay).

Tabs closed under an earlier version of the web vault are a remaining risk. That version kept the
tokens in the clear in the tab's session storage and sealed the open vault's root key under the
browser's shared trusted-device key. The first time a browser that was in use before signs in or
restores a tab on this version, the vault asks the server to end the device's other sessions and
keep the current one, so the tokens in old closed tabs stop working. The trusted-device key is not
reset, since other accounts that sign in on the same browser may depend on it. A root key sealed
under it in an old closed tab can still be opened by someone who runs script on the vault's origin,
but with no live token it can fetch nothing, and the web vault keeps no vault data in the browser to
decrypt instead: there is no service worker, no Cache API and no stored query cache, and IndexedDB
holds keys only.

## Operations

- Health: `/alive` is 200 while the process serves requests; `/health` also checks the database,
  migrations and file storage. The image's `HEALTHCHECK` runs `kemlock-server healthcheck`, because
  the image has no shell or curl.
- Logs: text, or `KEMLOCK_LOG_FORMAT=json`.
- Direct uploads to a bucket are off. `KEMLOCK_ATTACHMENT_PRESIGN` and
  `KEMLOCK_ATTACHMENT_PRESIGN_TTL` are still accepted but ignored (one warning at start when it is
  `true`), and every file goes through the server, which holds the size announced and the quota: a
  pre-signed `PUT` can't be bound to that length. A POST policy with `content-length-range` could
  bring direct uploads back (future work). Objects an earlier version left under `staging/` are
  deleted by the orphan purge once they are older than the orphan grace period.
- File permissions. On Unix a data folder the server creates is `0700`, and the SQLite database
  (with its `-wal` and `-shm` files and the copy made before a migration) and `server.key` are
  `0600`. A data folder that already exists keeps its mode, and the server warns at start-up when
  other users can read it: `chmod 700` it. SQLite runs with `secure_delete`, so deleted rows are
  overwritten with zeros rather than left in free pages.
- Reports of problems: the server answers `/.well-known/security.txt` (RFC 9116). Set who should
  hear about a problem with your server in the console (Settings, Security) or with
  `KEMLOCK_SECURITY_CONTACT` (an email address, or a `mailto:`, `tel:` or `https:` address)
  and, if you have a PGP key, `KEMLOCK_SECURITY_ENCRYPTION` (an `https:` or `openpgp4fpr:`
  address). The file always also lists where flaws in Kemlock Server itself are reported, and its
  `Expires` is always 180 days ahead.
- One-time Bitwarden token key replacement. Backup archives made before the Bitwarden token key was
  left out of them hold the live `rsa_key.pem`. At the first start after that change the server
  deletes `rsa_key.pem` and `rsa_key.pub.pem` once (recorded in the `bw_token_key_rotated` setting)
  and the Bitwarden API makes a new pair, so a copy of an old archive signs nothing here. The log
  says so. What it ends: "remember this device", invitation and verification tokens made before
  (people's second step is asked once more, and pending organization invitation links must be sent
  again). Bitwarden refresh tokens are database rows, so apps refresh silently. A key a Vaultwarden
  move brings later is kept, unless the server has Bitwarden accounts of its own (then the move
  leaves its key alone); an adopted source key signs tokens for every later account too, so move
  only from a Vaultwarden whose data nobody else ever held.
- Upgrades: migrations run forward at start-up. On SQLite the server first copies the database to
  `/data/backups/pre-<version>.sqlite3` and keeps the last three such copies (each is a plaintext
  copy of the whole database, so older ones are deleted). Within a major version migrations only add, so the
  previous release still runs on the new schema.
- Several replicas need PostgreSQL or MySQL, S3-compatible storage and one shared server key.

## Retention and the trash

The server deletes what has outlived its retention period once a day, on one replica at a time
(the Retention table of the privacy settings in the admin console sets the periods).

The trash needs one rule stated plainly, because two kinds of client use the server:

- **Bitwarden-API items** (Bitwarden apps, Vaultwarden imports): the server stores each cipher as
  the JSON the Bitwarden API serves, trash date included, so it deletes the ones in the trash
  longer than the trash setting, with their attachments, and leaves a tombstone.
- **Kemlock items**: the trash flag and date are inside the item's ciphertext, which the server
  cannot open. It sees a live item, so it **never purges a Kemlock item's trash**. The Kemlock apps
  empty their own trash on their own schedule; the server only ever sees that as an ordinary
  delete.

So the trash setting governs Bitwarden-API items only, and the admin console, the compliance
export and this page say so. An operator who must delete Kemlock items on a schedule has to rely on
the apps, or on the person erasing their account.

Erasing an account deletes everything of it at once: its items and the tombstones of its deleted
items (they are not left for the 180-day tombstone purge), files, Sends, devices, tokens and
sign-in log. Backups age out under the backup setting.

A person who deletes their own account may be given a grace period (the retention setting
"Deleted accounts", 0 to 30 days; 0 erases at once). While it runs the account is refused at
sign-in on both APIs, with an answer that says the account is being deleted (the Kemlock API's
`account-being-deleted` problem, 403; the Bitwarden API's "This user is being deleted"), and only
to someone who proved the password, so a stranger learns nothing. Signing in does not undo the
deletion. Only an admin can: `POST /admin/v1/users/{id}/cancel-erasure` takes the account off the
schedule (its sessions stay ended, so its owner signs in again). When the period ends the daily
retention job erases the account. An erasure also deletes the account's Sends and their files.

## Backups and restore

Back up `/data`, and keep `server.key` apart from the backups: a restore needs it to unseal the
server's secrets, and it is never inside a backup archive. The backup and restore guide
(`kemlock-cli backup`, `kemlock-cli restore --check`, the age recipient, S3 targets and the
restore drill) is `docs/backups.md`. The image carries only the server; the CLI is in
the `tools` build target (`docker build --target tools`), run with `--entrypoint /usr/local/bin/kemlock-cli`
and `/data` mounted, and in the release archives. Until `kemlock-cli backup` ships, stop the container and
copy the data folder (cold), or use the database's own dump for PostgreSQL and MySQL.

A backup archive is age-encrypted to a public recipient, so the encryption says nobody else can read
it, not who wrote it: anyone who can write to the backup destination can plant an archive. Each
archive therefore carries `manifest.mac`, right after `manifest.json`: the hex HMAC-SHA-256 of the
manifest's bytes, under a key derived from `server.key` (HMAC-SHA-256 of the label
`kemlock/v1/backup-manifest-mac` under the server key). The manifest lists every file's SHA-256, so
the code authenticates the whole archive. A restore (and the drill, `restore --check`) checks the
code with the `server.key` it is given, with `--server-key` or the data folder's own, and refuses
an archive whose code is missing or wrong, or that it has no key to check. For an archive you
made yourself before archives carried a code, check it with the drill and restore it with
`--allow-unauthenticated`; the restore then says in its notes that it did not authenticate the
archive. A server with no `server.key` at hand writes archives with no code and logs a warning.

A restore also limits what an archive can do. It refuses an archive that names `server.key` or a
database file, and installs only the sealed secrets (`*.sealed`) and `config.json` from the data
folder, and a `config/<name>.toml` (put beside an existing configuration file as
`.from-backup`, never over it); it says what it skipped. Every file it writes is readable by its
owner only. A backup leaves out the Bitwarden token key (`rsa_key.pem`), which is a plain file, and a
restore removes the data folder's copy: the server writes a new one at its next start. Bitwarden
apps refresh their tokens silently (refresh tokens are database rows); "remember this device",
invitation and verification tokens end. It
unpacks at most 16 GiB for one file, 50 times the archive's own size in total
(between 1 GiB and 4 TiB) and 2 million files.

The manifest, and with it the authentication code, is the last entry of an archive, so a restore
unpacks the whole archive into a scratch folder in the data folder before it can check the code.
The limits above are what bounds that: an archive somebody planted can use up to 50 times its own
size (at least 1 GiB) of disk until the check fails and the scratch folder is removed. Keep the
free space of the data folder's disk above that when the backup destination isn't one only you
write to.

## Verify what you downloaded

Every image is signed with cosign's keyless flow by digest: a short-lived Fulcio certificate tied
to this repository's release workflow, logged in Rekor. The identity to expect is the workflow
`release.yml` at a version tag, run by GitHub Actions:

```bash
cosign verify ghcr.io/arsslensoft/kemlock-server:1.4.2 \
  --certificate-identity-regexp '^https://github\.com/Arsslensoft/Kemlock-Server/\.github/workflows/release\.yml@refs/tags/v1\.4\.2$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Use the exact version in the identity as above, or `v[0-9].*` to accept any release. The
`edge` and `testing` tags are signed by the same workflow at `@refs/heads/main`. For the FIPS image use the
`-fips` tag with the same identity.

A release is a version tag on a commit of the default branch (`main`). `release.yml` fails a tag on
any other commit before it builds anything, but that is only a guard against a slip: a tag on an old
commit runs that commit's own copy of the workflow. What stops a tag from a write token is the
repository ruleset that `tools/repo-settings.sh` creates, which lets only administrators create,
move or delete a version tag. That ruleset exists only once the repository owner has run the script
(`tools/repo-settings.sh --dry-run` shows what it sends); until then any write token can still push
a version tag. Do not tag a release from a branch.

Binaries, with the bundle that sits beside each file:

```bash
cosign verify-blob kemlock-1.4.2-x86_64-unknown-linux-musl.tar.gz \
  --bundle kemlock-1.4.2-x86_64-unknown-linux-musl.tar.gz.sigstore.json \
  --certificate-identity-regexp '^https://github\.com/Arsslensoft/Kemlock-Server/\.github/workflows/release\.yml@refs/tags/v1\.4\.2$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum -c --ignore-missing SHA256SUMS
```

The SBOMs (CycloneDX, for the Rust tree and the web vault's npm tree) are attached to the release
and to the image as attestations:

```bash
cosign verify-attestation --type cyclonedx ghcr.io/arsslensoft/kemlock-server:1.4.2 \
  --certificate-identity-regexp '^https://github\.com/Arsslensoft/Kemlock-Server/\.github/workflows/release\.yml@refs/tags/v1\.4\.2$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

SLSA Build L3 provenance for the image and for the files in `SHA256SUMS`, with
[slsa-verifier](https://github.com/slsa-framework/slsa-verifier):

```bash
digest=$(docker buildx imagetools inspect ghcr.io/arsslensoft/kemlock-server:1.4.2 --format '{{json .Manifest}}' | jq -r .digest)
slsa-verifier verify-image "ghcr.io/arsslensoft/kemlock-server@$digest" \
  --source-uri github.com/arsslensoft/kemlock-server --source-tag v1.4.2
slsa-verifier verify-artifact kemlock-1.4.2-x86_64-unknown-linux-musl.tar.gz \
  --provenance-path multiple.intoto.jsonl \
  --source-uri github.com/arsslensoft/kemlock-server --source-tag v1.4.2
```

### Rebuild a release

`tools/verify.sh` rebuilds a tag with the release's own `docker/Dockerfile` (base images named by
digest, Zig and cargo-zigbuild pinned, `cargo build --locked`, `--remap-path-prefix`,
`SOURCE_DATE_EPOCH` set to the tag's commit time, no cache) and compares the binaries with the
published archive:

```bash
tools/verify.sh v1.4.2                 # prints: match
tools/verify.sh v1.4.2 --arch arm64
tools/verify.sh v1.4.2 --image         # compare with the binaries inside the published image
```

It prints `match`, or the files that differ and their hashes.
