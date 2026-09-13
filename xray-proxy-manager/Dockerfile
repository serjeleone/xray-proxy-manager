FROM ghcr.io/home-assistant/base:3.24-2026.08.0@sha256:93ef607824e3f27e868f11b10938283a98bf880ed57bcf8eaa81c6c2d521f6f5

ARG BUILD_ARCH
ARG TARGETARCH
ARG TARGETVARIANT
ARG BUILD_VERSION

LABEL io.hass.version="${BUILD_VERSION}" \
      io.hass.type="app" \
      io.hass.arch="${BUILD_ARCH}" \
      io.hass.name="Xray Proxy Manager" \
      io.hass.description="Управление Xray через один или два SOCKS5-слота" \
      io.hass.url="https://github.com/serjeleone/xray-proxy-manager" \
      org.opencontainers.image.title="Xray Proxy Manager" \
      org.opencontainers.image.description="Home Assistant app for Xray outbound management with one or two managed SOCKS5 slots" \
      org.opencontainers.image.source="https://github.com/serjeleone/xray-proxy-manager" \
      org.opencontainers.image.url="https://github.com/serjeleone/xray-proxy-manager" \
      org.opencontainers.image.documentation="https://github.com/serjeleone/xray-proxy-manager/blob/main/xray-proxy-manager/DOCS.md" \
      org.opencontainers.image.version="v${BUILD_VERSION}" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.authors="serjeleone"

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

COPY download-xray.sh xray-release.conf /tmp/xray-install/

RUN apk add --no-cache \
      bash \
      ca-certificates \
      curl \
      openssh-client \
      python3 \
      sshpass \
      tzdata \
      unzip \
    && bash /tmp/xray-install/download-xray.sh /usr/local "${BUILD_ARCH:-${TARGETARCH}${TARGETVARIANT:-}}" \
    && mkdir -p /config \
    && rm -rf /tmp/xray-install

COPY manager.py /manager.py
COPY xpm /xpm
COPY VERSION /VERSION
COPY CHANGELOG.md /CHANGELOG.md
COPY web /web
COPY run.sh /run.sh
RUN chmod 0755 /run.sh /manager.py

ARG BUILD_REF
ENV XPM_BUILD_COMMIT="${BUILD_REF}"
LABEL org.opencontainers.image.revision="${BUILD_REF}"

CMD ["/run.sh"]
