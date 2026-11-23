# The Kemlock push relay: HTTP contract

Kemlock's mobile apps need a push to sync while they are closed. Their push keys (Apple's and
Firebase's) belong to Kemlock, so a self-hosted server can't send a push itself. Kemlock runs a
small hosted relay that holds those keys. The relay is a separate service; this page is the
contract between it and `kemlock-server` (`crates/kemlock-notify/src/push`).

## What the relay learns

A push carries nothing but "sync now". The relay receives:

- a device's push token and which service it is for (`fcm` or `apns`);
- the server's installation id, and the installation key as a credential;
- the request's own metadata: the server's IP address and the time.

It never receives an email, an account id, a device name, a space or an item. It can't tell which
tokens belong to one person, and the server can't read what the push services do with a token.
Kemlock is the operator's processor of the device tokens only, under the DPA and privacy notice
Kemlock publishes for the relay. An operator who wants no relay leaves it off: the apps then sync
when opened and over `/kem/v1/live`.

The relay keeps, per installation: its id, a hash of its key, the time it was made and the time of
its last send. It keeps no token after the send that carried it, and it logs no token.

## Opting in and out

Nothing is typed. In the admin console an operator turns the relay on, and the server calls
`POST /v1/installations`, stores the id, and stores the key sealed under `server.key`. Turning it off
calls `DELETE /v1/installations/{id}` and forgets both. The server forgets them even when the
relay can't be reached, so an operator is never stuck opted in. `KEMLOCK_PUSH_RELAY_URL` points the
server at another relay; the default is `https://push.kemlock.app`. The URL must be https (plain
http is accepted only for a loopback address), because the key travels with every send, and the
server never follows a redirect.

Restoring a database without `server.key` loses the key: the server then logs that the installation
key can't be opened, sends no push, and the operator turns the relay off and on again.

## Authentication

Registration is unauthenticated and rate limited per address. Every other call carries HTTP Basic
authentication with the installation id as the user and the installation key as the password:

```
Authorization: Basic base64("<installationId>:<installationKey>")
```

A wrong id or key is `401`. The id is `inst-` plus a UUID; the key is 32 random bytes, base64url.

## Endpoints

### `POST /v1/installations`

Request body: `{}`.

`201 Created`:

```json
{ "installationId": "inst-0b7c...", "installationKey": "Zm9v..." }
```

The key is shown once. `429` with `Retry-After` when an address registers too often.

### `POST /v1/push`

Wakes devices. Basic authentication.

```json
{
  "type": "sync",
  "tokens": [
    { "kind": "fcm", "token": "..." },
    { "kind": "apns", "token": "..." }
  ]
}
```

- `type` is `sync`, the only value.
- `kind` is `fcm` or `apns`. A token is 1 to 512 characters with no whitespace.
- At most 500 tokens per call; the server sends larger sets in several calls.

`202 Accepted`:

```json
{ "accepted": 1, "rejected": ["<token the push service no longer knows>"] }
```

`accepted` counts the tokens handed to the push services. `rejected` lists tokens the services
report as unregistered or invalid; the server deletes them, so a reinstalled app isn't pushed
forever. An `accepted` token isn't a delivery guarantee: the push is best effort, and an app that
misses one syncs the next time it opens.

The relay sends each device a data-only push, `{"type":"sync"}`, with the lowest priority that still
wakes the app (APNs `content-available`, FCM normal priority), and the app then syncs through the
server's API as usual. The push has no alert and no content.

Errors: `400` for a malformed body, `401` for a bad credential, `413` for more than 500 tokens,
`429` with `Retry-After` (per installation: 600 sends a minute, which a burst of writes never nears
because the server gathers writes made within a second into one send), `5xx` for the relay's own
trouble. On any failure the server logs it and drops that push; nothing queues.

### `DELETE /v1/installations/{id}`

Erases the installation. Basic authentication, and the id in the path must match the credential.
`204 No Content`; `404` for an installation that is gone already, which the server treats as done.

## What the server does

- `POST /kem/v1/devices/push-token` (a signed-in device, DPoP-bound like every `/kem/v1` call)
  stores `{ "kind": "fcm" | "apns", "token": "..." }` for that device; `DELETE` on the same path
  forgets it. Signing a device out deletes its token with it.
- When a write commits, the replica that took it gathers owners nudged within one second, finds the
  accounts whose devices should hear of it (a person for their own vault, a space's confirmed
  members for the space), and sends one `POST /v1/push` with those accounts' tokens. Other replicas
  don't push: they learn of the write through the fan-out and nudge their own sockets only.
- Tokens the relay rejects are deleted.
- A server that hasn't registered sends nothing.

## Bitwarden's apps

Bitwarden's phone apps don't use this relay. They wake through Bitwarden's own relay when the
operator sets `PUSH_ENABLED`, `PUSH_INSTALLATION_ID` and `PUSH_INSTALLATION_KEY`, as with Vaultwarden;
Bitwarden is then the processor, on its own terms (`crates/kemlock-notify/src/bitwarden/relay.rs`).
