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

# The release archive for this machine: kemlock-<version>-<target>.tar.gz (see release.yml).
kemlock_asset() {
  case "$(uname -m)" in
  x86_64 | amd64) echo "kemlock-*-x86_64-unknown-linux-musl.tar.gz" ;;
  aarch64 | arm64) echo "kemlock-*-aarch64-unknown-linux-musl.tar.gz" ;;
  *)
    msg_error "No ${APP} release binary for $(uname -m)"
    exit 1
    ;;
  esac
}

update_deb_based() {
  if [[ ! -f /etc/systemd/system/kemlock-server.service ]]; then
    msg_error "No ${APP} Installation Found!"
    exit
  fi

  if check_for_gh_release "kemlock-server" "Arsslensoft/Kemlock-Server"; then
    msg_info "Stopping Service"
    systemctl stop kemlock-server
    msg_ok "Stopped Service"

    if ! fetch_and_deploy_gh_release "kemlock-server" "Arsslensoft/Kemlock-Server" "prebuild" "latest" "/opt/kemlock-server/bin" "$(kemlock_asset)"; then
      systemctl start kemlock-server
      msg_error "Update failed, the previous version is still installed"
      exit 1
    fi
    chown -R root:root /opt/kemlock-server/bin
    chmod 0755 /opt/kemlock-server/bin/kemlock-server

    msg_info "Starting Service"
    systemctl start kemlock-server
    msg_ok "Started Service"

    msg_info "Updating Caddy"
    $STD apt update
    $STD apt install -y --only-upgrade caddy
    msg_ok "Updated Caddy"
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
    msg_info "Stopping Service"
    rc-service kemlock-server stop -q
    msg_ok "Stopped Service"

    if ! fetch_and_deploy_gh_release "kemlock-server" "Arsslensoft/Kemlock-Server" "prebuild" "latest" "/opt/kemlock-server/bin" "$(kemlock_asset)"; then
      rc-service kemlock-server start -q
      msg_error "Update failed, the previous version is still installed"
      exit 1
    fi
    chown -R root:root /opt/kemlock-server/bin
    chmod 0755 /opt/kemlock-server/bin/kemlock-server

    msg_info "Starting Service"
    rc-service kemlock-server start -q
    msg_ok "Started Service"

    msg_info "Updating Caddy"
    $STD apk -U upgrade caddy
    rc-service caddy restart -q
    msg_ok "Updated Caddy"
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
echo -e "${INFO}${YW}The certificate is self-signed, so the browser warns once. First start prints a one-time setup code:${CL}"
if [[ "${var_os:-}" == "alpine" ]]; then
  echo -e "${TAB}${BGN}grep -i 'setup code' /var/log/kemlock-server.log${CL}"
else
  echo -e "${TAB}${BGN}journalctl -u kemlock-server | grep -i 'setup code'${CL}"
fi
