#!/usr/bin/env bash
# Rebuilds a release from source and compares it with what was published: prints `match`, or the
# files that differ.
#
#   tools/verify.sh v1.4.2                  # the linux/amd64 release archive
#   tools/verify.sh v1.4.2 --arch arm64     # another architecture
#   tools/verify.sh v1.4.2 --image          # the binaries inside ghcr.io/arsslensoft/kemlock-server:1.4.2
#   tools/verify.sh v1.4.2 --source .       # build from this checkout (at that tag) instead of cloning
#
# The rebuild uses what the release used (design, Security: Reproducible builds):
#   - docker/Dockerfile, whose Rust and Node images (and the files copied into its scratch runtime
#     image) are named by digest, whose Zig tarball is checked by SHA-256 and whose cargo-zigbuild
#     is pinned, so the C toolchain aws-lc needs is the same one;
#   - `cargo build --locked`, `--remap-path-prefix` and fat LTO with one codegen unit, set in the
#     Dockerfile;
#   - SOURCE_DATE_EPOCH, the tag's commit time, for the web bundle;
#   - KEMLOCK_GIT_COMMIT, the tag's commit, which the binary reports as the commit of its source;
#   - --no-cache, so nothing comes from a layer you did not build.
# It needs docker with buildx, git, curl, tar and sha256sum. Pass --keep to keep the work folder.
set -euo pipefail

REPO_URL="${KEMLOCK_REPO_URL:-https://github.com/arsslensoft/kemlock-server.git}"
RELEASES="${KEMLOCK_RELEASES_URL:-https://github.com/arsslensoft/kemlock-server/releases/download}"
IMAGE_NAME="${KEMLOCK_IMAGE:-ghcr.io/arsslensoft/kemlock-server}"

tag=""
arch="amd64"
mode="archive"
source_dir=""
keep=0

usage() { sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//'; }
die() { echo "verify: $*" >&2; exit 2; }

while [ $# -gt 0 ]; do
  case "$1" in
    --arch) arch="${2:?--arch needs a value}"; shift 2 ;;
    --image) mode="image"; shift ;;
    --source) source_dir="${2:?--source needs a folder}"; shift 2 ;;
    --keep) keep=1; shift ;;
    -h|--help) usage; exit 0 ;;
    -*) usage >&2; die "unknown flag: $1" ;;
    *) [ -z "$tag" ] || die "one tag only"; tag="$1"; shift ;;
  esac
done
[ -n "$tag" ] || { usage >&2; exit 2; }
version="${tag#v}"

# Architecture -> buildx platform, output folder and Rust target (the same table as release.yml).
case "$arch" in
  amd64)   platform=linux/amd64;   dir=linux_amd64;   target=x86_64-unknown-linux-musl ;;
  arm64)   platform=linux/arm64;   dir=linux_arm64;   target=aarch64-unknown-linux-musl ;;
  armv7)   platform=linux/arm/v7;  dir=linux_arm_v7;  target=armv7-unknown-linux-musleabihf ;;
  armv6)   platform=linux/arm/v6;  dir=linux_arm_v6;  target=arm-unknown-linux-musleabihf ;;
  386)     platform=linux/386;     dir=linux_386;     target=i686-unknown-linux-musl ;;
  ppc64le) platform=linux/ppc64le; dir=linux_ppc64le; target=powerpc64le-unknown-linux-musl ;;
  s390x)   platform=linux/s390x;   dir=linux_s390x;   target=s390x-unknown-linux-musl ;;
  riscv64) platform=linux/riscv64; dir=linux_riscv64; target=riscv64gc-unknown-linux-musl ;;
  *) die "unknown --arch $arch (amd64, arm64, armv7, armv6, 386, ppc64le, s390x, riscv64)" ;;
esac

for tool in docker git curl tar sha256sum; do
  command -v "$tool" >/dev/null || die "$tool is needed"
done
docker buildx version >/dev/null 2>&1 || die "docker buildx is needed"

work="$(mktemp -d)"
cleanup() { if [ "$keep" = 1 ]; then echo "kept $work"; else rm -rf "$work"; fi; }
trap cleanup EXIT
export MSYS_NO_PATHCONV=1

# 1. The source at the tag.
if [ -n "$source_dir" ]; then
  src="$(cd "$source_dir" && pwd)"
  head_tag="$(git -C "$src" describe --tags --exact-match 2>/dev/null || true)"
  [ "$head_tag" = "$tag" ] || die "$src is at '${head_tag:-no tag}', not $tag"
else
  src="$work/src"
  git clone --quiet --depth 1 --branch "$tag" "$REPO_URL" "$src"
fi
epoch="$(git -C "$src" log -1 --format=%ct)"
echo "verify: $tag at $(git -C "$src" rev-parse --short HEAD), SOURCE_DATE_EPOCH=$epoch, $platform"

# 2. Rebuild the binaries with the release's Dockerfile, from nothing cached.
docker buildx build --quiet --no-cache --pull \
  -f "$src/docker/Dockerfile" --target binaries --platform "$platform" \
  --build-arg SOURCE_DATE_EPOCH="$epoch" \
  --build-arg KEMLOCK_GIT_COMMIT="$(git -C "$src" rev-parse HEAD)" \
  --output "type=local,dest=$work/rebuilt" "$src" >/dev/null
rebuilt="$work/rebuilt"
[ -d "$rebuilt/$dir" ] && rebuilt="$rebuilt/$dir"

# 3. What was published.
published="$work/published"
mkdir -p "$published"
if [ "$mode" = image ]; then
  cid="$(docker create --platform "$platform" "$IMAGE_NAME:$version")"
  for f in kemlock-server kemlock-cli; do
    docker cp "$cid:/usr/local/bin/$f" "$published/$f" >/dev/null
  done
  docker rm "$cid" >/dev/null
else
  name="kemlock-$version-$target"
  curl -fsSL -o "$work/$name.tar.gz" "$RELEASES/$tag/$name.tar.gz"
  curl -fsSL -o "$work/SHA256SUMS" "$RELEASES/$tag/SHA256SUMS"
  (cd "$work" && grep " $name.tar.gz\$" SHA256SUMS | sha256sum -c - >/dev/null) \
    || die "the downloaded archive doesn't match the release's SHA256SUMS"
  tar -xzf "$work/$name.tar.gz" -C "$work"
  for f in kemlock-server kemlock-cli; do cp "$work/$name/$f" "$published/$f"; done
fi

# 4. Compare.
differ=()
for f in kemlock-server kemlock-cli; do
  a="$(sha256sum "$rebuilt/$f" | cut -d' ' -f1)"
  b="$(sha256sum "$published/$f" | cut -d' ' -f1)"
  if [ "$a" != "$b" ]; then
    differ+=("$f (rebuilt $a, published $b)")
  fi
done

if [ ${#differ[@]} -eq 0 ]; then
  echo "match"
else
  echo "differ:"
  printf '  %s\n' "${differ[@]}"
  echo "A difference can come from a base image or toolchain that moved: compare the digests in docker/Dockerfile with the ones the release used (the build log), and rebuild again." >&2
  exit 1
fi
