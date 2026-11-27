#!/usr/bin/env bash
# Proxmox VE helper: makes an unprivileged Debian 12 LXC container and installs Kemlock Server in it
# from the release binary (static, so nothing else is needed), as a systemd service.
#
# Run it as root on the Proxmox VE host:
#
#   bash -c "$(curl -fsSL https://raw.githubusercontent.com/arsslensoft/kemlock-server/main/deploy/proxmox/kemlock-lxc.sh)"
#   bash kemlock-lxc.sh --domain https://vault.example.com --ram 256 --disk 4
#   bash kemlock-lxc.sh --update 105          # move container 105 to the latest release
#
# It downloads the release archive, its SHA256SUMS and its cosign bundle, and refuses to install on
# a SHA-256 mismatch or a signature that does not verify against this repository's release workflow.
set -Eeuo pipefail

REPO="arsslensoft/kemlock-server"

# Defaults, each overridable by a flag.
CTID=""
HOSTNAME_="kemlock"
DOMAIN=""
CORES=1
RAM=256
SWAP=256
DISK=4
BRIDGE="vmbr0"
IPCONFIG="ip=dhcp"
STORAGE=""
TEMPLATE_STORAGE="local"
VERSION=""
UPDATE=""

die() { echo "kemlock-lxc: $*" >&2; exit 1; }
msg() { echo "==> $*"; }

usage() {
  sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'
  cat <<'USAGE'

Flags: --ctid N  --hostname NAME  --domain URL  --cores N  --ram MiB  --swap MiB  --disk GiB
       --bridge vmbr0  --ip dhcp|CIDR  --gateway ADDR  --storage NAME  --template-storage NAME
       --version TAG  --update CTID
USAGE
}

GATEWAY=""
while [ $# -gt 0 ]; do
  case "$1" in
    --ctid) CTID="$2"; shift 2 ;;
    --hostname) HOSTNAME_="$2"; shift 2 ;;
    --domain) DOMAIN="$2"; shift 2 ;;
    --cores) CORES="$2"; shift 2 ;;
    --ram) RAM="$2"; shift 2 ;;
    --swap) SWAP="$2"; shift 2 ;;
    --disk) DISK="$2"; shift 2 ;;
    --bridge) BRIDGE="$2"; shift 2 ;;
    --ip) if [ "$2" = dhcp ]; then IPCONFIG="ip=dhcp"; else IPCONFIG="ip=$2"; fi; shift 2 ;;
    --gateway) GATEWAY="$2"; shift 2 ;;
    --storage) STORAGE="$2"; shift 2 ;;
    --template-storage) TEMPLATE_STORAGE="$2"; shift 2 ;;
    --version) VERSION="$2"; shift 2 ;;
    --update) UPDATE="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; die "unknown flag: $1" ;;
  esac
done

[ "$(id -u)" -eq 0 ] || die "run as root on the Proxmox VE host"
command -v pct >/dev/null || die "pct not found: this is for a Proxmox VE host"
command -v curl >/dev/null || die "curl is needed on the host"

# The newest release's tag, unless --version names one.
resolve_version() {
  if [ -n "$VERSION" ]; then return; fi
  VERSION="$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
    | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n1)"
  [ -n "$VERSION" ] || die "couldn't find the latest release of $REPO"
}

# Runs inside the container: downloads, verifies and installs the binaries for its architecture.
install_script() {
  cat <<'INSTALL'
set -Eeuo pipefail
repo="$1"; tag="$2"
case "$(dpkg --print-architecture)" in
  amd64) target=x86_64-unknown-linux-musl ;;
  arm64) target=aarch64-unknown-linux-musl ;;
  armhf) target=armv7-unknown-linux-musleabihf ;;
  *) echo "no Kemlock release binary for $(dpkg --print-architecture)" >&2; exit 1 ;;
esac
version="${tag#v}"
archive="kemlock-${version}-${target}.tar.gz"
base="https://github.com/${repo}/releases/download/${tag}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
curl -fsSL -o "$tmp/$archive" "$base/$archive"
curl -fsSL -o "$tmp/SHA256SUMS" "$base/SHA256SUMS"
(cd "$tmp" && grep " $archive\$" SHA256SUMS | sha256sum -c -)
# The cosign signature: SHA256SUMS sits in the same release as the archive, so the SHA-256 alone
# says nothing about who built it. The archive must be signed by this repository's release workflow
# at this tag (a short-lived Fulcio certificate, logged in Rekor), or the install stops. cosign is
# in no Debian package: a pinned release is fetched from Sigstore, kept in /usr/local/lib/kemlock,
# and its SHA-256 is checked against that release's cosign_checksums.txt on every use.
cosign_version="v3.0.2"
# TODO(owner): the SHA-256 of cosign-linux-amd64, -arm64 and -arm for this version. Set them and they
# replace the checksum file that sits beside the binary on the same release page; while the one for
# this machine is empty, the install warns. No network was available to read them when this was written.
cosign_sha256_amd64=""
cosign_sha256_arm64=""
cosign_sha256_arm=""
# The repository's name in the signing certificate, in the case GitHub has it (the URLs here are
# lower case, the identity is compared exactly).
cert_repo="Arsslensoft/Kemlock-Server"
case "$(dpkg --print-architecture)" in
  amd64) cosign_arch=amd64 ;;
  arm64) cosign_arch=arm64 ;;
  armhf) cosign_arch=arm ;;
esac
cosign_asset="cosign-linux-${cosign_arch}"
cosign="/usr/local/lib/kemlock/cosign-${cosign_version}"
cosign_base="https://github.com/sigstore/cosign/releases/download/${cosign_version}"
case "$cosign_arch" in
  amd64) cosign_sha="$cosign_sha256_amd64" ;;
  arm64) cosign_sha="$cosign_sha256_arm64" ;;
  arm) cosign_sha="$cosign_sha256_arm" ;;
esac
if [ -z "$cosign_sha" ]; then
  echo "WARNING: the SHA-256 of $cosign_asset $cosign_version is not pinned in this script; it is checked only against the checksum file of the same Sigstore release page" >&2
  curl -fsSL -o "$tmp/cosign_checksums.txt" "$cosign_base/cosign_checksums.txt"
  cosign_sha="$(awk -v a="$cosign_asset" '$2 == a || $2 == "*" a {print $1; exit}' "$tmp/cosign_checksums.txt")"
fi
[ -n "$cosign_sha" ] || { echo "no checksum for $cosign_asset $cosign_version" >&2; exit 1; }
if [ ! -x "$cosign" ] || [ "$(sha256sum "$cosign" | awk '{print $1}')" != "$cosign_sha" ]; then
  curl -fsSL -o "$tmp/$cosign_asset" "$cosign_base/$cosign_asset"
  [ "$(sha256sum "$tmp/$cosign_asset" | awk '{print $1}')" = "$cosign_sha" ] \
    || { echo "SHA-256 of $cosign_asset $cosign_version does not match its release's checksums" >&2; exit 1; }
  install -d -m 0755 /usr/local/lib/kemlock
  install -m 0755 "$tmp/$cosign_asset" "$cosign.new"
  mv "$cosign.new" "$cosign"
fi
curl -fsSL -o "$tmp/$archive.sigstore.json" "$base/$archive.sigstore.json"
"$cosign" verify-blob "$tmp/$archive" \
  --bundle "$tmp/$archive.sigstore.json" \
  --certificate-identity "https://github.com/${cert_repo}/.github/workflows/release.yml@refs/tags/${tag}" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com >/dev/null \
  || { echo "the cosign signature of $archive does not verify" >&2; exit 1; }
tar -xzf "$tmp/$archive" -C "$tmp"
install -m 0755 "$tmp"/kemlock-*/kemlock-server "$tmp"/kemlock-*/kemlock-cli /usr/local/bin/
# The licence texts the archive carries (releases before they were added have none).
install -d /usr/share/doc/kemlock-server
for f in LICENSE NOTICE THIRD-PARTY-NOTICES.txt; do
  [ ! -f "$tmp"/kemlock-*/"$f" ] || install -m 0644 "$tmp"/kemlock-*/"$f" /usr/share/doc/kemlock-server/
done
echo "installed Kemlock Server ${tag}"
INSTALL
}


if [ -n "$UPDATE" ]; then
  resolve_version
  msg "updating container $UPDATE to $VERSION"
  pct status "$UPDATE" | grep -q running || die "container $UPDATE isn't running"
  # A backup of the data first: the server also copies its SQLite file before a migration.
  pct exec "$UPDATE" -- bash -c "$(install_script)" _ "$REPO" "$VERSION"
  pct exec "$UPDATE" -- systemctl restart kemlock
  msg "done"
  exit 0
fi

resolve_version
[ -n "$CTID" ] || CTID="$(pvesh get /cluster/nextid)"
if [ -z "$STORAGE" ]; then
  STORAGE="$(pvesm status -content rootdir | awk 'NR>1 {print $1; exit}')"
  [ -n "$STORAGE" ] || die "no storage can hold container disks; pass --storage"
fi

msg "template"
pveam update >/dev/null
TEMPLATE="$(pveam available --section system | awk '/debian-12-standard/ {print $2}' | sort -V | tail -n1)"
[ -n "$TEMPLATE" ] || die "no Debian 12 template is available"
if ! pveam list "$TEMPLATE_STORAGE" | grep -q "$TEMPLATE"; then
  pveam download "$TEMPLATE_STORAGE" "$TEMPLATE"
fi

NET="name=eth0,bridge=${BRIDGE},${IPCONFIG}"
[ -z "$GATEWAY" ] || NET="${NET},gw=${GATEWAY}"

msg "creating container $CTID ($HOSTNAME_)"
pct create "$CTID" "${TEMPLATE_STORAGE}:vztmpl/${TEMPLATE}" \
  --hostname "$HOSTNAME_" \
  --cores "$CORES" --memory "$RAM" --swap "$SWAP" \
  --rootfs "${STORAGE}:${DISK}" \
  --net0 "$NET" \
  --unprivileged 1 --features nesting=0 \
  --onboot 1 --ostype debian \
  --tags kemlock
pct start "$CTID"

msg "waiting for the network"
for _ in $(seq 1 30); do
  if pct exec "$CTID" -- getent hosts github.com >/dev/null 2>&1; then break; fi
  sleep 2
done

msg "installing Kemlock Server $VERSION"
pct exec "$CTID" -- bash -c "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends curl ca-certificates >/dev/null"
pct exec "$CTID" -- bash -c "$(install_script)" _ "$REPO" "$VERSION"

msg "configuring the service"
pct exec "$CTID" -- bash -c '
  useradd --system --home-dir /var/lib/kemlock --shell /usr/sbin/nologin kemlock 2>/dev/null || true
  mkdir -p /etc/kemlock
  chmod 0755 /etc/kemlock
'
unit="$(mktemp)"
env_file="$(mktemp)"
trap 'rm -f "$unit" "$env_file"' EXIT
# The unit file at the release's own tag (not the moving main branch): it is what that release ships.
curl -fsSL "https://raw.githubusercontent.com/${REPO}/${VERSION}/deploy/systemd/kemlock.service" -o "$unit"
{
  echo "# Kemlock Server settings: Vaultwarden's names, such as DOMAIN, plus KEMLOCK_*."
  if [ -n "$DOMAIN" ]; then echo "DOMAIN=$DOMAIN"; else echo "#DOMAIN=https://vault.example.com"; fi
  echo "SIGNUPS_ALLOWED=false"
} > "$env_file"
pct push "$CTID" "$unit" /etc/systemd/system/kemlock.service
pct push "$CTID" "$env_file" /etc/kemlock/kemlock.env
pct exec "$CTID" -- bash -c 'systemctl daemon-reload && systemctl enable --now kemlock'

IP="$(pct exec "$CTID" -- bash -c "hostname -I | awk '{print \$1}'" | tr -d '\r\n')"
cat <<DONE

Kemlock Server $VERSION is running in container $CTID.

  Address:      http://${IP}:8080  (put a reverse proxy with TLS in front before real use)
  Settings:     pct exec $CTID -- nano /etc/kemlock/kemlock.env   (then: systemctl restart kemlock)
  Setup code:   pct exec $CTID -- journalctl -u kemlock | grep -i "setup code"
  Update:       bash $0 --update $CTID
  Back up:      /var/lib/kemlock, and keep server.key apart from the backups
DONE
