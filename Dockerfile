ARG ALTSERVER_TAG=ng-2026-09-13
# Base images are pinned by digest; update them deliberately and re-test.
ARG ANISETTE_IMAGE=dadoum/anisette-v3-server@sha256:97f5fd1e6cb060f8fbda65d3e836e056c4d744e32a8372d954faf892fc68b544

# Reuse the same Anisette binary as the original two-container deployment.
FROM ${ANISETTE_IMAGE} AS anisette

# AltServer is built from source with the patches in altserver/. Stock AltServer removes every
# free provisioning profile on the device before installing, which makes iOS forget that the user
# trusted the developer, so each refresh brought back "Untrusted Developer". It also loads each file
# byte by byte and sends it as one packet, so large app binaries time out over Wi-Fi. And it reports
# outdated client identities, which Apple began rejecting in October 2026.
FROM ghcr.io/nyamisty/altserver_builder_alpine_aarch64@sha256:c8f77df8d22e9bf7b668c636fe0a660fb710c1671591c1c3c2d4397192efc5a2 AS altserver-arm64
FROM ghcr.io/nyamisty/altserver_builder_alpine_amd64@sha256:b96e411d23a2c8472942990b72fb902f7f08ce290889d40e46ce80ccb1b77dd7 AS altserver-amd64
FROM altserver-${TARGETARCH} AS altserver
ARG ALTSERVER_TAG
ARG BUILD_JOBS=4
COPY altserver/*.patch /tmp/patches/
RUN git clone -q --recursive --depth 1 --shallow-submodules -b "$ALTSERVER_TAG" \
      https://github.com/jaakkopalvaila/AltServer-Linux /src \
 && cd /src && git apply /tmp/patches/*.patch \
 && mkdir build && cd build && make -f ../Makefile -j"${BUILD_JOBS}" \
 && cp AltServer-* /AltServer

FROM debian:trixie-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f

ARG NETMUXD_TAG=v0.4.3

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      libimobiledevice-utils usbmuxd openssl python3 curl ca-certificates coreutils tzdata \
      libplist-2.0-4 supervisor tini \
 && rm -rf /var/lib/apt/lists/*

# Release archives are verified against checksums recorded for NETMUXD_TAG.
RUN arch="$(uname -m)" \
 && case "$arch" in \
      aarch64|arm64) arch=aarch64; sum=a89d587b094184b41431bc343da6dfa890391ccc7d4b3d6bce02b524f3191ae6 ;; \
      x86_64) sum=85b6598284fc639f2a282584461d05e2090b79bdf3ec949d2a5e5d3dc655dde4 ;; \
      *) echo "unsupported arch $arch"; exit 1 ;; esac \
 && curl -fsSL -o /tmp/netmuxd.tar.gz "https://github.com/jkcoxson/netmuxd/releases/download/${NETMUXD_TAG}/netmuxd-${arch}-unknown-linux-gnu.tar.gz" \
 && echo "$sum  /tmp/netmuxd.tar.gz" | sha256sum -c - \
 && tar xzf /tmp/netmuxd.tar.gz -C /usr/local/bin && rm /tmp/netmuxd.tar.gz \
 && chmod +x /usr/local/bin/netmuxd

COPY --from=altserver /AltServer /usr/local/bin/AltServer
COPY --from=anisette /opt/anisette-v3-server /usr/local/bin/anisette-v3-server
COPY scripts/ /usr/local/bin/
COPY tools/diagnose-auth.py /usr/local/bin/diagnose-auth.py
COPY sideloop/ /opt/sideloop/
COPY container/supervisord.conf /etc/sideloop/supervisord.conf
# gsa.apple.com (Apple sign-in) chains to Apple Root CA, which Debian doesn't ship. AltServer
# verifies that connection, so trust exactly this root, checked against its published fingerprint.
COPY container/apple-root-ca.crt /usr/local/share/ca-certificates/apple-root-ca.crt
RUN openssl x509 -in /usr/local/share/ca-certificates/apple-root-ca.crt -noout -fingerprint -sha256 \
      | grep -qx 'sha256 Fingerprint=B0:B1:73:0E:CB:C7:FF:45:05:14:2C:49:F1:29:5E:6E:DA:6B:CA:ED:7E:2C:68:C5:BE:91:B5:A1:10:01:F0:24' \
 && update-ca-certificates \
 && ln -sf certs/ca-certificates.crt /etc/ssl/cert.pem  # AltServer's LibreSSL reads this path

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
