#!/usr/bin/env bash

# Copyright (c) 2021-2026 community-scripts ORG
# Author: Arsslensoft
# License: MIT | https://github.com/community-scripts/ProxmoxVE/raw/main/LICENSE
# Source: https://github.com/Arsslensoft/Kemlock-Server

source /dev/stdin <<<"$FUNCTIONS_FILE_PATH"
color
verb_ip6
catch_errors
setting_up_container
network_check
update_os

REPO="Arsslensoft/Kemlock-Server"
APP_DIR="/opt/kemlock-server"

# The address clients will use. First-run setup works only over HTTPS (or from localhost), so
# DOMAIN is https://<this address>:8443, which Caddy serves below.
container_ip() {
  local ip
  ip="$(ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n1)"
  [[ -n "$ip" ]] || ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
  [[ -n "$ip" ]] || {
    msg_error "Could not find the container's IP address"
    exit 1
  }
  echo "$ip"
}

# Writes /usr/local/bin/kemlock-fetch-release, which the install below and the update script
# (ct/kemlock-server.sh) both use, so a release is verified the same way each time: it downloads the
# latest release archive for this machine and SHA256SUMS, checks the SHA-256, unpacks into the
# directory it is given and prints the version. It exits non-zero, touching nothing else, if
# anything fails. The release assets are kemlock-<version>-<target>.tar.gz and SHA256SUMS
# (.github/workflows/release.yml), each with a cosign bundle (<file>.sigstore.json). When cosign
# happens to be installed it also checks the archive's signature against the release workflow's
# identity and fails if that does not verify; cosign is in no Debian 13 package, so otherwise only
# the SHA-256 is checked. docs/self-hosting.md has the command for checking the signature by hand.
write_fetch_helper() {
  cat <<'EOT' >/usr/local/bin/kemlock-fetch-release
#!/bin/sh
# Usage: kemlock-fetch-release STAGE_DIR   (prints the version; Kemlock Server's release verifier)
set -eu
REPO="Arsslensoft/Kemlock-Server"
stage="${1:?usage: kemlock-fetch-release STAGE_DIR}"
case "$(uname -m)" in
x86_64 | amd64) target="x86_64-unknown-linux-musl" ;;
aarch64 | arm64) target="aarch64-unknown-linux-musl" ;;
*)
  echo "no Kemlock Server release binary for $(uname -m)" >&2
  exit 1
  ;;
esac
# /releases/latest redirects to /releases/tag/<tag>; that needs no API call, so no rate limit.
tag="$(curl -fsSIL -o /dev/null -w '%{url_effective}' "https://github.com/${REPO}/releases/latest")"
tag="${tag##*/}"
case "$tag" in
v[0-9]*.[0-9]*.[0-9]* | [0-9]*.[0-9]*.[0-9]*) ;;
*)
  echo "no release of ${REPO} found" >&2
  exit 1
  ;;
esac
version="${tag#v}"
asset="kemlock-${version}-${target}.tar.gz"
base="https://github.com/${REPO}/releases/download/${tag}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
curl -fsSL -o "${tmp}/${asset}" "${base}/${asset}"
curl -fsSL -o "${tmp}/SHA256SUMS" "${base}/SHA256SUMS"
expected="$(awk -v a="$asset" '$2 == a || $2 == "*" a {print $1; exit}' "${tmp}/SHA256SUMS")"
actual="$(sha256sum "${tmp}/${asset}" | awk '{print $1}')"
if [ -z "$expected" ] || [ "$expected" != "$actual" ]; then
  echo "SHA-256 of ${asset} does not match SHA256SUMS" >&2
  exit 1
fi
# The signature, when cosign is here to check it: the archive must be signed by this repository's
# release workflow at this tag (a short-lived Fulcio certificate, logged in Rekor).
if command -v cosign >/dev/null 2>&1; then
  curl -fsSL -o "${tmp}/${asset}.sigstore.json" "${base}/${asset}.sigstore.json"
  repo_re="$(printf '%s' "$REPO" | sed 's/\./\\./g')"
  tag_re="$(printf '%s' "$tag" | sed 's/\./\\./g')"
  if ! cosign verify-blob "${tmp}/${asset}" \
    --bundle "${tmp}/${asset}.sigstore.json" \
    --certificate-identity-regexp "^https://github\\.com/${repo_re}/\\.github/workflows/release\\.yml@refs/tags/${tag_re}\$" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com >/dev/null 2>&1; then
    echo "the cosign signature of ${asset} does not verify" >&2
    exit 1
  fi
fi
mkdir -p "${tmp}/unpacked"
tar -xzf "${tmp}/${asset}" -C "${tmp}/unpacked"
cp -R "${tmp}"/unpacked/kemlock-*/. "$stage"/
echo "$version"
EOT
  chmod 0755 /usr/local/bin/kemlock-fetch-release
}

install_release() {
  local stage version f
  write_fetch_helper
  msg_info "Downloading Kemlock Server"
  stage="$(mktemp -d)"
  if ! version="$(/usr/local/bin/kemlock-fetch-release "$stage")"; then
    rm -rf "$stage"
    msg_error "Could not download and verify Kemlock Server"
    exit 1
  fi
  msg_ok "Downloaded Kemlock Server ${version} (SHA-256 checked)"

  msg_info "Installing Kemlock Server"
  install -d -m 0755 "${APP_DIR}/bin"
  install -m 0755 "${stage}/kemlock-server" "${APP_DIR}/bin/kemlock-server"
  install -m 0755 "${stage}/kemlock-cli" "${APP_DIR}/bin/kemlock-cli"
  install -d -m 0755 /usr/share/doc/kemlock-server
  for f in LICENSE NOTICE THIRD-PARTY-NOTICES.txt; do
    [[ ! -f "${stage}/$f" ]] || install -m 0644 "${stage}/$f" /usr/share/doc/kemlock-server/
  done
  rm -rf "$stage"
  # check_for_gh_release in the update script compares against this file.
  echo "$version" >"$HOME/.kemlock-server"
  msg_ok "Installed Kemlock Server ${version}"
}

# Settings use Vaultwarden's names (crates/kemlock-server/src/config.rs). The server listens on
# loopback only; Caddy is the HTTPS front, and the one address trusted to name the client.
configure_server() {
  local ip="$1"
  msg_info "Configuring Kemlock Server"
  mkdir -p "${APP_DIR}/data"
  cat <<EOT >"${APP_DIR}/.env"
DOMAIN=https://${ip}:8443
DATA_FOLDER=${APP_DIR}/data
ROCKET_ADDRESS=127.0.0.1
ROCKET_PORT=8080
IP_HEADER=X-Forwarded-For
KEMLOCK_TRUSTED_PROXIES=127.0.0.1
EOT
  chown -R root:root "${APP_DIR}/bin"
  chown kemlock:kemlock "${APP_DIR}/data"
  chmod 0700 "${APP_DIR}/data"
  chown root:kemlock "${APP_DIR}/.env"
  chmod 0640 "${APP_DIR}/.env"
  msg_ok "Configured Kemlock Server"
}

# The server speaks plain HTTP (ROCKET_TLS is not supported), so Caddy terminates TLS on :8443
# with its own local CA (`tls internal`), the way Vaultwarden's script uses a snakeoil certificate.
# Reverse proxying passes WebSocket upgrades (/notifications/hub, /kem/v1/live) with no extra setup.
configure_caddy() {
  local ip="$1"
  msg_info "Configuring Caddy"
  mkdir -p /etc/caddy
  cat <<EOT >/etc/caddy/Caddyfile
{
	auto_https disable_redirects
}

https://${ip}:8443, https://localhost:8443 {
	tls internal
	reverse_proxy 127.0.0.1:8080
}
EOT
  msg_ok "Configured Caddy"
}

# The server logs the one-time setup code (`setup code ABCD-EFGH-JKMN`, Crockford's base32) on its
# first start, a moment after it starts listening. Wait for it and show it, and say how to read it
# again: every restart makes a new code until the first admin exists.
print_setup_code() {
  local log_cmd="$1" code="" _
  for _ in $(seq 1 30); do
    code=$(sh -c "$log_cmd" 2>/dev/null | grep -oE 'setup code [0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}' | tail -n 1 | awk '{print $3}' || true)
    [ -n "$code" ] && break
    sleep 1
  done
  if [ -n "$code" ]; then
    echo -e "${INFO}${YW}The one-time setup code (the setup page asks for it):${CL} ${BGN}${code}${CL}"
  else
    echo -e "${INFO}${YW}Kemlock Server didn't print a setup code within 30 seconds; read it from its log:${CL}"
  fi
  echo -e "${TAB}${YW}A restart makes a new code until the first admin exists. Read the current one with:${CL}"
  echo -e "${TAB}${BGN}${log_cmd} | grep -i 'setup code' | tail -n 1${CL}"
}

setup_deb_based() {
  msg_info "Installing Dependencies"
  $STD apt install -y \
    curl \
    tar \
    ca-certificates \
    caddy
  msg_ok "Installed Dependencies"

  msg_info "Creating User"
  $STD addgroup --system kemlock
  $STD adduser --system --home "$APP_DIR" --shell /usr/sbin/nologin --no-create-home --gecos 'kemlock' --ingroup kemlock --disabled-login --disabled-password kemlock
  msg_ok "Created User"

  local ip
  ip="$(container_ip)"
  install_release
  configure_server "$ip"
  configure_caddy "$ip"

  msg_info "Creating Service"
  cat <<EOT >/etc/systemd/system/kemlock-server.service
[Unit]
Description=Kemlock Server
Documentation=https://github.com/Arsslensoft/Kemlock-Server/blob/main/docs/self-hosting.md
Wants=network-online.target
After=network-online.target

[Service]
User=kemlock
Group=kemlock
EnvironmentFile=-${APP_DIR}/.env
ExecStart=${APP_DIR}/bin/kemlock-server
Restart=on-failure
RestartSec=5
TimeoutStopSec=30
LimitNOFILE=65535
LimitNPROC=4096
PrivateTmp=true
PrivateDevices=true
ProtectHome=true
ProtectSystem=strict
DevicePolicy=closed
ProtectControlGroups=yes
ProtectKernelModules=yes
ProtectKernelTunables=yes
ProtectKernelLogs=yes
ProtectClock=true
ProtectHostname=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
MemoryDenyWriteExecute=yes
LockPersonality=yes
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources
UMask=0077
WorkingDirectory=${APP_DIR}
ReadWritePaths=${APP_DIR}/data

[Install]
WantedBy=multi-user.target
EOT
  systemctl enable -q --now kemlock-server
  systemctl enable -q caddy
  systemctl restart caddy
  msg_ok "Created Service"

  print_setup_code "journalctl -u kemlock-server -o cat --no-pager"
}

setup_alpine() {
  msg_info "Installing Dependencies"
  $STD apk add --no-cache \
    curl \
    tar \
    ca-certificates \
    caddy
  msg_ok "Installed Dependencies"

  msg_info "Creating User"
  $STD addgroup -S kemlock
  $STD adduser -S -D -H -h "$APP_DIR" -s /sbin/nologin -G kemlock -g kemlock kemlock
  msg_ok "Created User"

  local ip
  ip="$(container_ip)"
  install_release
  configure_server "$ip"
  configure_caddy "$ip"

  msg_info "Creating Service"
  cat <<'EOT' >/etc/init.d/kemlock-server
#!/sbin/openrc-run

name="Kemlock Server"
description="Kemlock Server, a Bitwarden-compatible password manager"
command="/opt/kemlock-server/bin/kemlock-server"
command_user="kemlock:kemlock"
command_background=true
pidfile="/run/${RC_SVCNAME}.pid"
directory="/opt/kemlock-server"
output_log="/var/log/kemlock-server.log"
error_log="/var/log/kemlock-server.log"

depend() {
  need net
  before caddy
}

start_pre() {
  checkpath -f -m 0640 -o kemlock:kemlock /var/log/kemlock-server.log
  # The settings are in /opt/kemlock-server/.env, the same file the Debian unit reads, and read
  # as systemd's EnvironmentFile reads it: KEY=value lines, # comments, one pair of quotes around
  # a value taken off. Never sourced, so a space, a $ or a backtick in a password is just text.
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in '' | '#'* | ';'*) continue ;; esac
    key=${line%%=*}
    value=${line#*=}
    [ "$key" != "$line" ] || continue
    key=$(printf '%s' "$key" | tr -d '[:space:]')
    case "$key" in '' | [0-9]* | *[!A-Za-z0-9_]*) continue ;; esac
    case "$value" in
      \"*\") value=${value#\"}; value=${value%\"} ;;
      \'*\') value=${value#\'}; value=${value%\'} ;;
    esac
    export "$key=$value"
  done </opt/kemlock-server/.env
}
EOT
  chmod +x /etc/init.d/kemlock-server
  $STD rc-update add kemlock-server default
  $STD rc-service kemlock-server start
  $STD rc-update add caddy default
  $STD rc-service caddy restart
  msg_ok "Created Service"

  print_setup_code "cat /var/log/kemlock-server.log"
}

run_os_setup

motd_ssh
customize
cleanup_lxc
