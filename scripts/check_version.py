"""Validate release versions; --write synchronizes the Home Assistant manifest."""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / 'xray-proxy-manager'


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', action='store_true')
    parser.add_argument('--tag', help='Release tag to validate')
    args = parser.parse_args()
    version = (APP / 'VERSION').read_text().strip()
    if not re.fullmatch(r'\d+\.\d+\.\d+', version):
        raise SystemExit('VERSION must contain a semantic version without v')
    tag = f'v{version}'
    manifest_path = APP / 'config.yaml'
    manifest = manifest_path.read_text()
    expected_manifest = re.sub(r'^version:.*$', f'version: "{version}"', manifest, flags=re.M)
    if args.write:
        manifest_path.write_text(expected_manifest)
    elif manifest != expected_manifest:
        raise SystemExit('config.yaml differs from VERSION; run scripts/check_version.py --write')
    first_release = re.search(r'^## (v\S+)', (APP / 'CHANGELOG.md').read_text(), re.M)
    if not first_release or first_release[1] != tag:
        raise SystemExit(f'The first CHANGELOG section must be {tag}')
    sys.path.insert(0, str(APP))
    from xpm.common import ADDON_VERSION
    if ADDON_VERSION != version:
        raise SystemExit('Runtime version differs from VERSION')
    if args.tag and args.tag != tag:
        raise SystemExit(f'Tag {args.tag} differs from {tag}')
    dockerfile = (APP / 'Dockerfile').read_text()
    if 'ARG BUILD_VERSION\n' not in dockerfile or 'COPY VERSION /VERSION' not in dockerfile:
        raise SystemExit('Docker must obtain the application version from VERSION/BUILD_VERSION')
    for name in ('README.md', 'xray-proxy-manager/README.md', 'xray-proxy-manager/DOCS.md'):
        if re.search(r'Текущая версия[^\n]*`v?\d+\.\d+\.\d+`', (ROOT / name).read_text()):
            raise SystemExit(f'{name}: link to VERSION instead of duplicating the version')
    print(version)


if __name__ == '__main__':
    main()
