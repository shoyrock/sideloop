ARG ALTSERVER_TAG=ng-2026-09-13
ARG ANISETTE_IMAGE=dadoum/anisette-v3-server:latest

# Reuse the same Anisette binary as the original two-container deployment.
FROM ${ANISETTE_IMAGE} AS anisette

# AltServer is built from source with the patches in altserver/. Stock AltServer removes every
# free provisioning profile on the device before installing, which makes iOS forget that the user
# trusted the developer, so each refresh brought back "Untrusted Developer". It also loads each file
# byte by byte and sends it as one packet, so large app binaries time out over Wi-Fi.
FROM ghcr.io/nyamisty/altserver_builder_alpine_aarch64 AS altserver-arm64
FROM ghcr.io/nyamisty/altserver_builder_alpine_amd64 AS altserver-amd64
FROM altserver-${TARGETARCH} AS altserver
ARG ALTSERVER_TAG
ARG BUILD_JOBS=4
COPY altserver/*.patch /tmp/patches/
RUN git clone -q --recursive --depth 1 --shallow-submodules -b "$ALTSERVER_TAG" \
      https://github.com/jaakkopalvaila/AltServer-Linux /src \
 && cd /src && git apply /tmp/patches/*.patch \
 && mkdir build && cd build && make -f ../Makefile -j"${BUILD_JOBS}" \
 && cp AltServer-* /AltServer

FROM debian:trixie-slim

ARG NETMUXD_TAG=v0.4.3

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      libimobiledevice-utils usbmuxd openssl python3 curl ca-certificates coreutils tzdata \
      libplist-2.0-4 supervisor tini \
 && rm -rf /var/lib/apt/lists/*

RUN arch="$(uname -m)" \
 && case "$arch" in aarch64|arm64) arch=aarch64 ;; x86_64) ;; *) echo "unsupported arch $arch"; exit 1 ;; esac \
 && curl -fsSL "https://github.com/jkcoxson/netmuxd/releases/download/${NETMUXD_TAG}/netmuxd-${arch}-unknown-linux-gnu.tar.gz" \
      | tar xz -C /usr/local/bin \
 && chmod +x /usr/local/bin/netmuxd

COPY --from=altserver /AltServer /usr/local/bin/AltServer
COPY --from=anisette /opt/anisette-v3-server /usr/local/bin/anisette-v3-server
COPY scripts/ /usr/local/bin/
COPY sideloop/ /opt/sideloop/
COPY container/supervisord.conf /etc/sideloop/supervisord.conf

# Keep the helper's original service account. Normalize script line endings
# for builds made from a Windows checkout and preserve executable entrypoints.
RUN useradd -ms /bin/bash Alcoholic \
 && sed -i 's/\r$//' /usr/local/bin/*.sh \
 && chmod +x /usr/local/bin/*.sh

ENV DATA_DIR=/data \
    PYTHONPATH=/opt \
    PYTHONUNBUFFERED=1 \
    ANISETTE_SERVER=http://127.0.0.1:6969
WORKDIR /data
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=15s --start-period=5m --retries=3 \
    CMD ["python3", "/usr/local/bin/container-healthcheck.py"]
ENTRYPOINT ["/usr/bin/tini", "-g", "--", "/usr/local/bin/container-entrypoint.sh"]
CMD ["/usr/bin/supervisord", "-c", "/etc/sideloop/supervisord.conf"]
