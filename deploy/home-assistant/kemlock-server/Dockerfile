# Home Assistant add-on image: the official Kemlock Server image's binaries on Home Assistant's
# base image.
#
# The official image is built from scratch (no shell), and an add-on needs a shell to turn its
# options (/data/options.json) into settings. Its binaries are static, so this takes them from the
# official image by version and runs them under the base image's s6 and bashio.
#
# The base images are pinned by digest where this can be done by hand: the BUILD_FROM default below
# and the amd64 line of build.yaml. Both are moved by hand: Dependabot's docker parser most likely
# ignores an ARG default (it reads FROM lines), so do not wait for it to propose a new base image.
# When you move one, move the other, and look up the aarch64 and armv7 digests. The aarch64 and
# armv7 base images in build.yaml, and the kemlock-server image copied from below
# (ghcr.io/arsslensoft/kemlock-server:${KEMLOCK_VERSION}), are still tags, not digests.
ARG BUILD_FROM=ghcr.io/home-assistant/amd64-base:3.22@sha256:1967b25b597a43fa46ce3eef5267b525e946d559d0b397c60af717dde15a2696
ARG KEMLOCK_VERSION=1

FROM ghcr.io/arsslensoft/kemlock-server:${KEMLOCK_VERSION} AS kemlock

FROM ${BUILD_FROM}
# The add-on's init (s6) and run.sh start as root, to read the options and fix the ownership of
# /data; run.sh then drops to this user (su-exec) before it starts the server, so the server
# itself never runs as root. The fixed ids keep the ownership of /data the same across rebuilds.
RUN apk add --no-cache su-exec \
    && addgroup -S -g 10001 kemlock \
    && adduser -S -D -H -u 10001 -G kemlock -s /sbin/nologin kemlock
COPY --from=kemlock /usr/local/bin/kemlock-server /usr/local/bin/
COPY --from=kemlock /usr/share/doc/kemlock-server/ /usr/share/doc/kemlock-server/
COPY run.sh /run.sh
RUN chmod a+x /run.sh
CMD ["/run.sh"]
