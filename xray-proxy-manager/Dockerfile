FROM ghcr.io/home-assistant/base:latest

ARG BUILD_ARCH
ARG TARGETARCH
ARG TARGETVARIANT
ARG XRAY_VERSION=v26.7.11
ARG BUILD_VERSION="0.6.0"
ARG RELEASE_TAG="v0.6.0"

LABEL io.hass.version="${BUILD_VERSION}" \
      io.hass.type="app" \
      io.hass.arch="${BUILD_ARCH}" \
      io.hass.name="Xray Proxy Manager" \
      io.hass.description="Управление Xray через два независимых SOCKS5-слота" \
      io.hass.url="https://github.com/serjeleone/xray-proxy-manager" \
      org.opencontainers.image.title="Xray Proxy Manager" \
      org.opencontainers.image.description="Home Assistant app for Xray outbound management with two independent SOCKS5 slots" \
      org.opencontainers.image.source="https://github.com/serjeleone/xray-proxy-manager" \
      org.opencontainers.image.url="https://github.com/serjeleone/xray-proxy-manager" \
      org.opencontainers.image.documentation="https://github.com/serjeleone/xray-proxy-manager/blob/main/xray-proxy-manager/DOCS.md" \
      org.opencontainers.image.version="${RELEASE_TAG}" \
      org.opencontainers.image.authors="serjeleone"

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN apk add --no-cache \
      bash \
      ca-certificates \
      curl \
      openssh-client \
      python3 \
      sshpass \
      tzdata \
      unzip \
    && set -eux; \
    ARCH_KEY="${BUILD_ARCH:-${TARGETARCH}${TARGETVARIANT:-}}"; \
    case "${ARCH_KEY}" in \
      amd64|x86_64) XRAY_ARCH="64" ;; \
      aarch64|arm64|arm64v8) XRAY_ARCH="arm64-v8a" ;; \
      *) echo "Unsupported arch: ${ARCH_KEY}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/xray.zip \
      "https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/Xray-linux-${XRAY_ARCH}.zip"; \
    unzip /tmp/xray.zip -d /tmp/xray; \
    install -m 0755 /tmp/xray/xray /usr/local/bin/xray; \
    mkdir -p /usr/local/share/xray /config; \
    if [ -f /tmp/xray/geoip.dat ]; then install -m 0644 /tmp/xray/geoip.dat /usr/local/share/xray/geoip.dat; fi; \
    if [ -f /tmp/xray/geosite.dat ]; then install -m 0644 /tmp/xray/geosite.dat /usr/local/share/xray/geosite.dat; fi; \
    rm -rf /tmp/xray /tmp/xray.zip

COPY manager.py /manager.py
COPY CHANGELOG.md /CHANGELOG.md
COPY web /web
COPY run.sh /run.sh
RUN chmod 0755 /run.sh /manager.py

CMD ["/run.sh"]
