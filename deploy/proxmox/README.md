# Kemlock Server on Proxmox VE

A [community-scripts](https://community-scripts.org) style installer: it creates an LXC container
and installs Kemlock Server in it, on Debian 13 or Alpine, amd64 or arm64.

```
deploy/proxmox/
  ct/kemlock-server.sh               runs on the Proxmox host: makes the container, and updates it
  install/kemlock-server-install.sh  runs inside the container: installs the server
  json/kemlock-server.json           the website's metadata for the script
  kemlock-lxc.sh                     the older standalone helper (Debian 12, flags), kept as it was
```

## Run it

As root in the Proxmox VE host's shell:

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/Arsslensoft/Kemlock-Server/main/deploy/proxmox/ct/kemlock-server.sh)"
```

It asks for Default or Advanced settings and for Debian or Alpine, then builds the container. The
defaults are small, since the server is one binary:

| OS | CPU | RAM | Disk |
|---|---|---|---|
| Debian 13 | 1 | 1024 MB | 4 GB |
| Alpine 3.24 | 1 | 512 MB | 2 GB |

The container is unprivileged. Every `var_*` setting of community-scripts works, for example
`var_cpu=2 var_ram=2048 bash -c "$(curl ...)"`, and so does `var_os=alpine` to skip the OS menu.

The script sets `COMMUNITY_SCRIPTS_URL` to this directory when it is unset, so the engine fetches
`install/kemlock-server-install.sh` from this repository and not from community-scripts/ProxmoxVE.
The engine itself (`build.func` and the rest) comes from community-scripts/core.

## What it installs

- The release binary, not a build from source. The install script picks the archive for the
  machine (`uname -m`): `kemlock-<version>-x86_64-unknown-linux-musl.tar.gz` or
  `kemlock-<version>-aarch64-unknown-linux-musl.tar.gz`, downloads it with `SHA256SUMS` from the
  latest GitHub release, and stops if the SHA-256 does not match. Both are the assets
  `.github/workflows/release.yml` publishes.
- `kemlock-server` and `kemlock-cli` in `/opt/kemlock-server/bin`, run by the system user
  `kemlock`. The data (SQLite file, `server.key`) is in `/opt/kemlock-server/data`.
- `/opt/kemlock-server/.env`, with Vaultwarden's setting names: `DOMAIN`, `DATA_FOLDER`,
  `ROCKET_ADDRESS` (`127.0.0.1`), `ROCKET_PORT` (`8080`), `IP_HEADER` and
  `KEMLOCK_TRUSTED_PROXIES`. The other settings are in `docs/self-hosting.md`.
- A hardened systemd unit (`kemlock-server.service`) on Debian, an OpenRC service on Alpine.
- Caddy from the distribution's packages, as the HTTPS front on port **8443**.

The cosign signature of the archive is not checked by the script. To check it by hand, use the
`cosign verify-blob` line in `docs/self-hosting.md` on the archive and its `.sigstore.json`.

## HTTPS

Kemlock Server speaks plain HTTP, and its first-run setup works only over HTTPS or from localhost.
It has no native TLS (`ROCKET_TLS` is ignored), so Caddy listens on `https://<container-ip>:8443`
with `tls internal` (a certificate from Caddy's own local CA, as Vaultwarden's script uses a
snakeoil one) and proxies to `127.0.0.1:8080`. WebSocket upgrades pass through. The server listens
on loopback only. The browser warns once about the certificate; to trust it, import Caddy's root
certificate, `/var/lib/caddy/.local/share/caddy/pki/authorities/local/root.crt`, on your devices.

The install script sets `DOMAIN=https://<container-ip>:8443`. Sign-in proofs are checked against
`DOMAIN`, so it has to be the address clients use.

### For production

Use a name and a certificate that clients trust:

1. Put a reverse proxy with a real certificate in front (Caddy, Traefik, nginx, Nginx Proxy
   Manager; the configs are in `deploy/proxy/`) and point it at `<container-ip>:8080`. For that,
   set `ROCKET_ADDRESS=0.0.0.0` in `.env`, and set `KEMLOCK_TRUSTED_PROXIES` to the proxy's address,
   or every client looks like the proxy.
2. Set `DOMAIN=https://vault.example.com` in `/opt/kemlock-server/.env`.
3. `systemctl restart kemlock-server` (Alpine: `rc-service kemlock-server restart`).

Or edit `/etc/caddy/Caddyfile` to your host name, and Caddy gets a Let's Encrypt certificate itself
if the container is reachable on ports 80 and 443. Then set `DOMAIN` to match and restart both
services. If the container's address changes (DHCP), do the same for the IP in `DOMAIN` and in the
Caddyfile, or reserve an address for it.

## The setup code

There is no admin token. On its first start the server logs a one-time setup code, and its setup
page asks for it before it creates the first admin account. In the container:

```bash
journalctl -u kemlock-server | grep -i 'setup code'            # Debian
grep -i 'setup code' /var/log/kemlock-server.log                # Alpine
```

The code is valid until the server restarts; a restart before setup makes a new one.

## Update

Type `update` in the container's console. The update script checks the latest release against
`~/.kemlock-server`, stops the service, deploys the new binary with community-scripts'
`fetch_and_deploy_gh_release` into `/opt/kemlock-server/bin`, starts the service, and upgrades
Caddy. The data is not touched, and the server copies its SQLite file before a migration. Note that
the helper downloads over HTTPS from GitHub but does not check `SHA256SUMS`; the first install does.

## Submitting it upstream

community-scripts takes new scripts in [DevScripts](https://github.com/community-scripts/DevScripts)
first (ProxmoxVE closes pull requests that add scripts), and then moves them to ProxmoxVE after
testing. Its website metadata is now kept on the website, so `json/kemlock-server.json` is the
text to give them, not a file their CI reads. To submit:

1. Delete the `COMMUNITY_SCRIPTS_URL` line and its comment at the top of `ct/kemlock-server.sh`.
   Everything else is as community-scripts writes it.
2. Keep the files under `ct/`, `install/` and `json/` as they are, and open the pull request
   against DevScripts with its template.
3. The engine derives the install script's name from `APP`, lower-cased with spaces removed, which
   is why `APP` is `Kemlock-Server` and the files are `kemlock-server*`. If the reviewers want the
   name `Kemlock Server`, they rename both files to `kemlockserver*`.

Test with the command at the top until then. The engine takes `dev_mode`, for example
`dev_mode=trace,keep bash -c "$(curl ...)"` keeps a container whose install failed.
