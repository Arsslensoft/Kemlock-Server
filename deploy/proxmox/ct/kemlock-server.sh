#!/usr/bin/env bash
# Until this script lives in community-scripts/ProxmoxVE, take the install script from this
# repository. Dropped when submitting upstream (see deploy/proxmox/README.md).
export COMMUNITY_SCRIPTS_URL="${COMMUNITY_SCRIPTS_URL:-https://raw.githubusercontent.com/Arsslensoft/Kemlock-Server/main/deploy/proxmox}"
_cs_boot="${COMMUNITY_SCRIPTS_CORE_DIR:-$(dirname "${BASH_SOURCE[0]}")/../../core}/core/build.func"
source "$_cs_boot" 2>/dev/null || source <(curl -fsSL "${COMMUNITY_SCRIPTS_CORE_URL:-https://raw.githubusercontent.com/community-scripts/core/main}/core/build.func")
# Copyright (c) 2021-2026 community-scripts ORG
# Author: Arsslensoft
# License: MIT | https://github.com/community-scripts/ProxmoxVE/raw/main/LICENSE
# Source: https://github.com/Arsslensoft/Kemlock-Server

# The hyphen is deliberate: the engine derives the install script (install/kemlock-server-install.sh),
# the website slug and the `update` command's script name from APP, lower-cased with spaces removed.
APP="Kemlock-Server"
var_tags="${var_tags:-password-manager}"
var_arm64="${var_arm64:-yes}"
var_unprivileged="${var_unprivileged:-1}"
if [[ -z "${var_os:-}" ]] && command -v pveversion >/dev/null 2>&1; then
  var_os=$(msg_menu "Choose the container OS" \
    "debian" "Debian 13" \
    "alpine" "Alpine (smaller footprint)")
fi

if [[ "${var_os:-}" == "alpine" ]]; then
  var_cpu="${var_cpu:-1}"
  var_ram="${var_ram:-512}"
  var_disk="${var_disk:-2}"
  var_version="${var_version:-3.24}"
else
  var_cpu="${var_cpu:-1}"
  var_ram="${var_ram:-1024}"
  var_disk="${var_disk:-4}"
  var_version="${var_version:-13}"
fi

header_info "$APP"
variables
color
catch_errors

# Downloads the latest release and checks its SHA-256 against that release's SHA256SUMS, with the
# helper the install script wrote (kemlock-fetch-release). Nothing is stopped or replaced until it
# passes; if it fails, the running version stays.
kemlock_stage_release() {
  KEMLOCK_STAGE="$(mktemp -d)"
  msg_info "Downloading and verifying the release"
  if ! KEMLOCK_VERSION="$(/usr/local/bin/kemlock-fetch-release "$KEMLOCK_STAGE")"; then
    rm -rf "$KEMLOCK_STAGE"
    msg_error "The release could not be downloaded or did not match SHA256SUMS; the running version is unchanged"
    exit 1
  fi
  msg_ok "Verified ${APP} ${KEMLOCK_VERSION} (SHA-256 checked)"
}

# With the service stopped: puts the verified binaries in place.
kemlock_swap_binaries() {
  install -m 0755 "$KEMLOCK_STAGE/kemlock-server" /opt/kemlock-server/bin/kemlock-server
  install -m 0755 "$KEMLOCK_STAGE/kemlock-cli" /opt/kemlock-server/bin/kemlock-cli
  rm -rf "$KEMLOCK_STAGE"
  # check_for_gh_release compares against this file.
  echo "$KEMLOCK_VERSION" >"$HOME/.kemlock-server"
}

update_deb_based() {
  if [[ ! -f /etc/systemd/system/kemlock-server.service ]]; then
    msg_error "No ${APP} Installation Found!"
    exit
  fi

  if check_for_gh_release "kemlock-server" "Arsslensoft/Kemlock-Server"; then
    kemlock_stage_release

    msg_info "Stopping Service"
    systemctl stop kemlock-server
    msg_ok "Stopped Service"

    msg_info "Updating ${APP} to ${KEMLOCK_VERSION}"
    kemlock_swap_binaries
    msg_ok "Updated ${APP} to ${KEMLOCK_VERSION}"

    msg_info "Starting Service"
    systemctl start kemlock-server
    msg_ok "Started Service"

    # Only a Caddy that is on: one the admin turned off, for a proxy in front of the container,
    # stays off.
    if systemctl is-enabled --quiet caddy 2>/dev/null; then
      msg_info "Updating Caddy"
      $STD apt update
      $STD apt install -y --only-upgrade caddy
      msg_ok "Updated Caddy"
    fi
    msg_ok "Updated successfully!"
  else
    msg_ok "${APP} is already up-to-date"
  fi
  exit
}

update_alpine() {
  if [[ ! -f /etc/init.d/kemlock-server ]]; then
    msg_error "No ${APP} Installation Found!"
    exit
  fi

  if check_for_gh_release "kemlock-server" "Arsslensoft/Kemlock-Server"; then
    kemlock_stage_release

    msg_info "Stopping Service"
    rc-service kemlock-server stop -q
    msg_ok "Stopped Service"

    msg_info "Updating ${APP} to ${KEMLOCK_VERSION}"
    kemlock_swap_binaries
    msg_ok "Updated ${APP} to ${KEMLOCK_VERSION}"

    msg_info "Starting Service"
    rc-service kemlock-server start -q
    msg_ok "Started Service"

    # Only a Caddy that is on: one the admin took out of the default runlevel, for a proxy in
    # front of the container, stays off.
    if rc-update show default 2>/dev/null | grep -qw caddy; then
      msg_info "Updating Caddy"
      $STD apk -U upgrade caddy
      rc-service caddy restart -q
      msg_ok "Updated Caddy"
    fi
    msg_ok "Updated successfully!"
  else
    msg_ok "${APP} is already up-to-date"
  fi
  exit
}

function update_script() {
  header_info
  check_container_storage
  check_container_resources
  run_os_update
}

start
build_container
description

msg_ok "Completed successfully!\n"
echo -e "${CREATING}${GN}${APP} setup has been successfully initialized!${CL}"
echo -e "${INFO}${YW}Access it using the following URL:${CL}"
echo -e "${TAB}${GATEWAY}${BGN}https://${IP}:8443${CL}"
echo -e "${INFO}${YW}The certificate is self-signed, so the browser warns once.${CL}"
# The setup code, read from the container's log: the first start logs it a moment after it listens.
if [[ "${var_os:-}" == "alpine" ]]; then
  log_cmd="cat /var/log/kemlock-server.log"
else
  log_cmd="journalctl -u kemlock-server -o cat --no-pager"
fi
setup_code=""
for _ in $(seq 1 30); do
  setup_code=$(pct exec "$CTID" -- sh -c "$log_cmd" 2>/dev/null |
    grep -oE 'setup code [0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}' | tail -n 1 | awk '{print $3}')
  [[ -n "$setup_code" ]] && break
  sleep 1
done
if [[ -n "$setup_code" ]]; then
  echo -e "${INFO}${YW}The one-time setup code (the setup page asks for it):${CL} ${BGN}${setup_code}${CL}"
else
  echo -e "${INFO}${YW}No setup code in the log yet; read it in the container with:${CL}"
fi
echo -e "${TAB}${YW}A restart makes a new code until the first admin exists. Read the current one in the container with:${CL}"
echo -e "${TAB}${BGN}${log_cmd} | grep -i 'setup code' | tail -n 1${CL}"
