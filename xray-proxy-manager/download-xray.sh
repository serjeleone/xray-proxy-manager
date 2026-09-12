#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "${script_dir}/xray-release.conf"
destination="${1:?Destination directory is required}"
architecture="${2:-$(uname -m)}"
case "${architecture}" in
  amd64|x86_64) archive_arch=64; checksum="${XRAY_SHA256_AMD64}" ;;
  aarch64|arm64|arm64v8) archive_arch=arm64-v8a; checksum="${XRAY_SHA256_AARCH64}" ;;
  *) echo "Unsupported architecture: ${architecture}" >&2; exit 1 ;;
esac

download_dir="$(mktemp -d)"
trap 'rm -rf -- "${download_dir}"' EXIT
archive="${download_dir}/xray.zip"
curl -fsSL --retry 3 --connect-timeout 20 --max-time 180 \
  -o "${archive}" \
  "https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/Xray-linux-${archive_arch}.zip"
printf '%s  %s\n' "${checksum}" "${archive}" | sha256sum -c -
unzip -q "${archive}" -d "${download_dir}/unpacked"
install -d "${destination}/bin" "${destination}/share/xray"
install -m 0755 "${download_dir}/unpacked/xray" "${destination}/bin/xray"
for asset in geoip.dat geosite.dat LICENSE; do
  if [[ -f "${download_dir}/unpacked/${asset}" ]]; then
    install -m 0644 "${download_dir}/unpacked/${asset}" "${destination}/share/xray/${asset}"
  fi
done
