# Home Assistant add-on image: the official Kemlock Server image's binaries on Home Assistant's
# base image.
#
# The official image is distroless (no shell), and an add-on needs a shell to turn its options
# (/data/options.json) into settings. Its binaries are static, so this takes them from the
# official image by version and runs them under the base image's s6 and bashio.
ARG BUILD_FROM=ghcr.io/home-assistant/amd64-base:3.22@sha256:1967b25b597a43fa46ce3eef5267b525e946d559d0b397c60af717dde15a2696
ARG KEMLOCK_VERSION=1

FROM ghcr.io/arsslensoft/kemlock-server:${KEMLOCK_VERSION} AS kemlock

FROM ${BUILD_FROM}
COPY --from=kemlock /usr/local/bin/kemlock-server /usr/local/bin/
COPY --from=kemlock /usr/share/doc/kemlock-server/ /usr/share/doc/kemlock-server/
COPY run.sh /run.sh
RUN chmod a+x /run.sh
CMD ["/run.sh"]
