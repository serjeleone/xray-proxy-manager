#!/usr/bin/env python3
from __future__ import annotations

import copy
from collections import deque
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
import hashlib
import http.server
import json
import os
import re
import shlex
import shutil
import signal
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import parse_qs, quote, urlparse

OPTIONS_PATH = Path('/data/options.json')
WORKDIR = Path('/config')
LEGACY_WORKDIR = Path('/config/xray-proxy-manager')
SUBSCRIPTION_PATH = WORKDIR / 'subscription.json'
CONFIG_PATH = WORKDIR / 'config.json'
SLOT_CONFIG_PATHS = {
    'xray-a': WORKDIR / 'config.xray-a.json',
    'xray-b': WORKDIR / 'config.xray-b.json',
}
LAST_GOOD_CONFIG_PATH = WORKDIR / 'config.last_good.json'
LAST_GOOD_META_PATH = WORKDIR / 'config.last_good.meta.json'
STATE_PATH = WORKDIR / 'state.json'
LATENCY_PATH = WORKDIR / 'latencies.json'
RUNTIME_OPTIONS_PATH = WORKDIR / 'runtime-options.json'
WEB_ROOT = Path('/web')
CHANGELOG_PATH = Path('/CHANGELOG.md')
LOG_PREFIX = '[xray-proxy-manager]'
XRAY_BIN = '/usr/local/bin/xray'
CURL_BIN = '/usr/bin/curl'
SSH_BIN = '/usr/bin/ssh'
SSHPASS_BIN = '/usr/bin/sshpass'
SSH_KEYGEN_BIN = '/usr/bin/ssh-keygen'
DEFAULT_UI_PORT = 8090
WATCHDOG_PORT = 18099
SLOT_TAGS = ('xray-a', 'xray-b')
DEFAULT_SOCKS_TCP_B = 10809
POST_SWITCH_WATCH_SECONDS = 30
ADDON_VERSION = '0.7.3'
DEFAULT_PRIMARY_TEST_URL = 'https://www.gstatic.com/generate_204'
DEFAULT_SECONDARY_TEST_URL = 'https://cp.cloudflare.com/generate_204'

DIRECT_PROTOCOLS = {'freedom', 'blackhole', 'dns', 'loopback'}
DIRECT_TAGS = {
    'direct', 'block', 'blocked', 'dns', 'dns-out', 'dns-outbound',
    'proxy-direct', 'freedom', 'blackhole', 'api', 'metrics'
}
SORT_VALUES = {
    'name-asc', 'name-desc', 'ping-asc', 'ping-desc',
    'protocol-asc', 'protocol-desc',
}
RUNTIME_SETTING_KEYS = {
    'subscription_url',
    'dual_slot_enabled',
    'auto_checker_enabled',
    'auto_switch_best_enabled',
    'auto_switch_preferred_country',
    'auto_switch_excluded',
    'auto_switch_min_ping_delta_ms',
    'auto_check_interval_seconds',
    'auto_check_failures',
    'auto_check_max_latency_ms',
    'auto_best_check_interval_seconds',
    'update_interval_hours',
    'ui_sort',
    'ui_protocol_filter',
    'ui_max_ping_ms',
    'ui_hide_unavailable',
    'ui_hide_excluded',
}
LEGACY_AUTO_SWITCH_EXCLUDED_KEY = 'auto_switch_excluded_countries'
LEGACY_PRIMARY_TEST_KEYS = ('latency_test_url',)
LEGACY_SECONDARY_TEST_KEYS = ('secondary_check_url', 'health_check_url')
RETIRED_OPTION_KEYS = {
    'override_inbounds',
    'disable_observatory',
    'validate_routing_tags',
    'auto_fix_routing_tags',
    'restart_on_runtime_error',
    'auto_add_proxy_direct',
    'router_xray_host',
    'socks_udp_a',
    'socks_udp_b',
}
OUTBOUND_LOG_RE = re.compile(r'\[[^\]\n]*?->\s*([^\]\s]+)\]')
XRAY_READING_CONFIG_RE = re.compile(r'(Reading config:)\s*&\{Name:([^}\s]+)\s+Format:[^}]+\}')
SAFE_RULE_RE = re.compile(r'^[A-Za-z0-9_-]+$')
SAFE_KEY_NAME_RE = re.compile(r'^[A-Za-z0-9._-]+$')
ROUTER_AUTH_METHODS = {'existing_key', 'password', 'generate_key'}
ROUTER_PRIMARY_KEY_DIR = Path('/config/ssh')
ROUTER_SECONDARY_KEY_DIR = WORKDIR / 'ssh'
LOG_BUFFER_MAX_LINES = 2500
LOG_BUFFER: deque[str] = deque(maxlen=LOG_BUFFER_MAX_LINES)
LOG_BUFFER_LOCK = threading.Lock()
TEST_PORT_LOCK = threading.Lock()
RESERVED_TEST_PORTS: set[int] = set()
RELEASE_NOTES_CACHE: dict[str, Any] | None = None
ANSI_ESCAPE_RE = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
ISO_COUNTRY_CODES = {
    'AD', 'AE', 'AF', 'AG', 'AI', 'AL', 'AM', 'AO', 'AQ', 'AR', 'AS', 'AT', 'AU', 'AW', 'AX',
    'AZ', 'BA', 'BB', 'BD', 'BE', 'BF', 'BG', 'BH', 'BI', 'BJ', 'BL', 'BM', 'BN', 'BO',
    'BQ', 'BR', 'BS', 'BT', 'BV', 'BW', 'BY', 'BZ', 'CA', 'CC', 'CD', 'CF', 'CG', 'CH',
    'CI', 'CK', 'CL', 'CM', 'CN', 'CO', 'CR', 'CU', 'CV', 'CW', 'CX', 'CY', 'CZ', 'DE',
    'DJ', 'DK', 'DM', 'DO', 'DZ', 'EC', 'EE', 'EG', 'EH', 'ER', 'ES', 'ET', 'FI', 'FJ',
    'FK', 'FM', 'FO', 'FR', 'GA', 'GB', 'GD', 'GE', 'GF', 'GG', 'GH', 'GI', 'GL', 'GM',
    'GN', 'GP', 'GQ', 'GR', 'GS', 'GT', 'GU', 'GW', 'GY', 'HK', 'HM', 'HN', 'HR', 'HT',
    'HU', 'ID', 'IE', 'IL', 'IM', 'IN', 'IO', 'IQ', 'IR', 'IS', 'IT', 'JE', 'JM', 'JO',
    'JP', 'KE', 'KG', 'KH', 'KI', 'KM', 'KN', 'KP', 'KR', 'KW', 'KY', 'KZ', 'LA', 'LB',
    'LC', 'LI', 'LK', 'LR', 'LS', 'LT', 'LU', 'LV', 'LY', 'MA', 'MC', 'MD', 'ME', 'MF',
    'MG', 'MH', 'MK', 'ML', 'MM', 'MN', 'MO', 'MP', 'MQ', 'MR', 'MS', 'MT', 'MU', 'MV',
    'MW', 'MX', 'MY', 'MZ', 'NA', 'NC', 'NE', 'NF', 'NG', 'NI', 'NL', 'NO', 'NP', 'NR',
    'NU', 'NZ', 'OM', 'PA', 'PE', 'PF', 'PG', 'PH', 'PK', 'PL', 'PM', 'PN', 'PR', 'PS',
    'PT', 'PW', 'PY', 'QA', 'RE', 'RO', 'RS', 'RU', 'RW', 'SA', 'SB', 'SC', 'SD', 'SE',
    'SG', 'SH', 'SI', 'SJ', 'SK', 'SL', 'SM', 'SN', 'SO', 'SR', 'SS', 'ST', 'SV', 'SX',
    'SY', 'SZ', 'TC', 'TD', 'TF', 'TG', 'TH', 'TJ', 'TK', 'TL', 'TM', 'TN', 'TO', 'TR',
    'TT', 'TV', 'TW', 'TZ', 'UA', 'UG', 'UM', 'US', 'UY', 'UZ', 'VA', 'VC', 'VE', 'VG',
    'VI', 'VN', 'VU', 'WF', 'WS', 'YE', 'YT', 'ZA', 'ZM', 'ZW',
}
COUNTRY_NAME_ALIASES = {
    'россия': 'RU', 'russia': 'RU',
    'финляндия': 'FI', 'finland': 'FI',
    'германия': 'DE', 'germany': 'DE',
    'нидерланды': 'NL', 'netherlands': 'NL',
    'швейцария': 'CH', 'switzerland': 'CH',
    'венгрия': 'HU', 'hungary': 'HU',
    'франция': 'FR', 'france': 'FR',
    'швеция': 'SE', 'sweden': 'SE',
    'норвегия': 'NO', 'norway': 'NO',
    'польша': 'PL', 'poland': 'PL',
    'чехия': 'CZ', 'czechia': 'CZ',
    'австрия': 'AT', 'austria': 'AT',
    'дания': 'DK', 'denmark': 'DK',
    'испания': 'ES', 'spain': 'ES',
    'италия': 'IT', 'italy': 'IT',
    'великобритания': 'GB', 'united kingdom': 'GB',
    'сша': 'US', 'usa': 'US', 'united states': 'US',
    'канада': 'CA', 'canada': 'CA',
    'япония': 'JP', 'japan': 'JP',
    'сингапур': 'SG', 'singapore': 'SG',
}


def resolve_test_urls(options: dict[str, Any]) -> tuple[str, str]:
    """Resolve the two probe URLs and migrate legacy option names in memory.

    Old installations may still provide latency_test_url and health_check_url.
    A duplicated legacy pair (the old defaults were both gstatic) is normalized
    to the new gstatic + Cloudflare pair so every check really uses two
    independent endpoints.
    """
    primary = str(
        options.get('primary_test_url')
        or options.get('latency_test_url')
        or DEFAULT_PRIMARY_TEST_URL
    ).strip()
    secondary = str(
        options.get('secondary_test_url')
        or options.get('secondary_check_url')
        or options.get('health_check_url')
        or DEFAULT_SECONDARY_TEST_URL
    ).strip()

    if not primary:
        primary = DEFAULT_PRIMARY_TEST_URL
    if not secondary or secondary == primary:
        secondary = (
            DEFAULT_SECONDARY_TEST_URL
            if primary != DEFAULT_SECONDARY_TEST_URL
            else DEFAULT_PRIMARY_TEST_URL
        )
    return primary, secondary


def migrate_auto_switch_excluded_option(options: dict[str, Any]) -> bool:
    """Move the legacy exclusion key to the current name in place."""
    changed = False
    if 'auto_switch_excluded' not in options and LEGACY_AUTO_SWITCH_EXCLUDED_KEY in options:
        options['auto_switch_excluded'] = options[LEGACY_AUTO_SWITCH_EXCLUDED_KEY]
        changed = True
    if LEGACY_AUTO_SWITCH_EXCLUDED_KEY in options:
        options.pop(LEGACY_AUTO_SWITCH_EXCLUDED_KEY, None)
        changed = True
    return changed


def migrate_test_url_options(options: dict[str, Any]) -> bool:
    """Move legacy endpoint names to primary_test_url/secondary_test_url."""
    changed = False
    if 'primary_test_url' not in options:
        for legacy_key in LEGACY_PRIMARY_TEST_KEYS:
            if legacy_key in options:
                options['primary_test_url'] = options[legacy_key]
                changed = True
                break
    if 'secondary_test_url' not in options:
        for legacy_key in LEGACY_SECONDARY_TEST_KEYS:
            if legacy_key in options:
                options['secondary_test_url'] = options[legacy_key]
                changed = True
                break
    for legacy_key in (*LEGACY_PRIMARY_TEST_KEYS, *LEGACY_SECONDARY_TEST_KEYS):
        if legacy_key in options:
            options.pop(legacy_key, None)
            changed = True
    return changed


def migrate_secondary_test_url_option(options: dict[str, Any]) -> bool:
    """Compatibility wrapper retained for tests and old integrations."""
    return migrate_test_url_options(options)

def normalize_auto_switch_exclusions(value: Any) -> str:
    result: list[str] = []
    seen: set[str] = set()
    for raw_token in re.split(r'[,;\n]+', str(value or '').strip()):
        token = re.sub(r'\s+', ' ', raw_token).strip()
        if not token:
            continue
        if re.fullmatch(r'[A-Za-z]{2}', token):
            normalized = token.upper()
            if normalized not in ISO_COUNTRY_CODES:
                raise ValueError(f'Неизвестный код страны: {normalized}')
            dedupe_key = f'country:{normalized}'
        else:
            if len(token) < 3:
                raise ValueError('Текстовый фрагмент исключения должен содержать не менее 3 символов')
            normalized = token
            dedupe_key = f'text:{normalized.casefold()}'
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        result.append(normalized)
    return ', '.join(result)


def normalize_country_codes(value: Any) -> str:
    # Compatibility alias for existing callers and persisted configurations.
    return normalize_auto_switch_exclusions(value)


def normalize_preferred_country(value: Any) -> str:
    text = str(value or '').strip().upper()
    if not text:
        return ''
    if not re.fullmatch(r'[A-Z]{2}', text) or text not in ISO_COUNTRY_CODES:
        raise ValueError(f'Неизвестный код предпочитаемой страны: {text}')
    return text


def parse_auto_switch_exclusions(value: Any) -> tuple[set[str], list[str]]:
    normalized = normalize_auto_switch_exclusions(value)
    country_codes: set[str] = set()
    fragments: list[str] = []
    for token in (item.strip() for item in normalized.split(',')):
        if not token:
            continue
        if re.fullmatch(r'[A-Z]{2}', token) and token in ISO_COUNTRY_CODES:
            country_codes.add(token)
        else:
            fragments.append(token.casefold())
    return country_codes, fragments


def infer_country_code(*values: Any) -> str:
    texts = [str(value or '') for value in values if str(value or '').strip()]
    for text in texts:
        indicators = [ord(char) - 0x1F1E6 for char in text if 0x1F1E6 <= ord(char) <= 0x1F1FF]
        if len(indicators) >= 2:
            code = chr(65 + indicators[0]) + chr(65 + indicators[1])
            if code in ISO_COUNTRY_CODES:
                return code
    for text in texts:
        match = re.match(r'^\s*([A-Za-z]{2})(?=[^A-Za-z]|$)', text)
        if match and match.group(1).upper() in ISO_COUNTRY_CODES:
            return match.group(1).upper()
    combined = ' '.join(texts).casefold()
    for name, code in COUNTRY_NAME_ALIASES.items():
        if name in combined:
            return code
    for text in texts:
        for token in re.findall(r'(?i)(?:^|[-_.:/])([a-z]{2})(?=[-_.:/]|$)', text):
            code = token.upper()
            if code in ISO_COUNTRY_CODES:
                return code
    return ''


def normalize_xray_log_line(line: str) -> str:
    text = XRAY_READING_CONFIG_RE.sub(r'\1 \2', str(line))
    return re.sub(
        r'(\[Info\])\s+infra/conf/serial:\s+(?=Reading config:)',
        r'\1 ',
        text,
    )


def append_ui_log(line: str) -> None:
    text = ANSI_ESCAPE_RE.sub('', str(line)).rstrip('\r\n')
    if not text:
        return
    with LOG_BUFFER_LOCK:
        LOG_BUFFER.append(text)


def ui_log_snapshot(limit: int = 1000) -> tuple[list[str], int]:
    safe_limit = max(1, min(int(limit), LOG_BUFFER_MAX_LINES))
    with LOG_BUFFER_LOCK:
        total = len(LOG_BUFFER)
        lines = list(LOG_BUFFER)[-safe_limit:]
    return lines, total


def release_notes_payload() -> dict[str, Any]:
    global RELEASE_NOTES_CACHE
    if RELEASE_NOTES_CACHE is not None:
        return copy.deepcopy(RELEASE_NOTES_CACHE)
    items: list[str] = []
    try:
        text = CHANGELOG_PATH.read_text(encoding='utf-8')
        pattern = re.compile(
            rf'^##\s+v?{re.escape(ADDON_VERSION)}\s*$\n(.*?)(?=^##\s+|\Z)',
            re.MULTILINE | re.DOTALL,
        )
        match = pattern.search(text)
        if match:
            items = [
                line[2:].strip()
                for line in match.group(1).splitlines()
                if line.strip().startswith('- ') and line[2:].strip()
            ]
    except OSError:
        pass
    RELEASE_NOTES_CACHE = {'version': f'v{ADDON_VERSION}', 'items': items}
    return copy.deepcopy(RELEASE_NOTES_CACHE)


def log(message: str, *, error: bool = False) -> None:
    stream = sys.stderr if error else sys.stdout
    line = f'{LOG_PREFIX} {message}'
    append_ui_log(f'{time.strftime("%Y-%m-%d %H:%M:%S")} {line}')
    print(line, file=stream, flush=True)


def now_ts() -> int:
    return int(time.time())


def atomic_write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_name(f'.{path.name}.tmp')
    with temp_path.open('w', encoding='utf-8') as file_handle:
        json.dump(payload, file_handle, ensure_ascii=False, indent=2, sort_keys=True)
        file_handle.write('\n')
    os.replace(temp_path, path)


def load_json(path: Path, default: Any) -> Any:
    try:
        with path.open('r', encoding='utf-8') as file_handle:
            return json.load(file_handle)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return copy.deepcopy(default)


def first_text(*values: Any) -> str:
    for value in values:
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ''


def to_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {'1', 'true', 'yes', 'on'}
    return bool(value)


def bounded_int(value: Any, minimum: int, maximum: int, field: str) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f'{field}: требуется целое число') from exc
    if parsed < minimum or parsed > maximum:
        raise ValueError(f'{field}: допустимый диапазон {minimum}–{maximum}')
    return parsed


def extract_endpoint(outbound: dict[str, Any]) -> tuple[str, int | None]:
    settings = outbound.get('settings') or {}

    vnext = settings.get('vnext') or []
    if isinstance(vnext, list) and vnext and isinstance(vnext[0], dict):
        address = str(vnext[0].get('address') or '')
        port = vnext[0].get('port')
        return address, int(port) if str(port).isdigit() else None

    servers = settings.get('servers') or []
    if isinstance(servers, list) and servers and isinstance(servers[0], dict):
        address = str(servers[0].get('address') or servers[0].get('server') or '')
        port = servers[0].get('port')
        return address, int(port) if str(port).isdigit() else None

    address = str(settings.get('address') or settings.get('server') or '')
    port = settings.get('port')
    return address, int(port) if str(port).isdigit() else None


def config_display_name(config: dict[str, Any], index: int) -> str:
    metadata = config.get('metadata') if isinstance(config.get('metadata'), dict) else {}
    return first_text(
        config.get('remarks'),
        config.get('remark'),
        config.get('name'),
        config.get('ps'),
        config.get('title'),
        metadata.get('name'),
        metadata.get('title'),
        f'Профиль {index + 1}',
    )


def ensure_outbound_tags(config: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(config)
    outbounds = result.setdefault('outbounds', [])
    if not isinstance(outbounds, list):
        result['outbounds'] = []
        return result

    used: set[str] = set()
    for index, outbound in enumerate(outbounds):
        if not isinstance(outbound, dict):
            continue
        tag = first_text(outbound.get('tag'))
        if not tag or tag in used:
            base = f'ui-outbound-{index + 1}'
            tag = base
            serial = 2
            while tag in used:
                tag = f'{base}-{serial}'
                serial += 1
            outbound['tag'] = tag
        used.add(tag)
    return result


def walk_objects(value: Any) -> Iterable[dict[str, Any]]:
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from walk_objects(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk_objects(child)


def fix_routing_tags(config: dict[str, Any], enabled: bool) -> dict[str, Any]:
    if not enabled:
        return config
    result = copy.deepcopy(config)
    outbound_tags = {
        item.get('tag') for item in result.get('outbounds', [])
        if isinstance(item, dict) and isinstance(item.get('tag'), str)
    }
    routing = result.get('routing') if isinstance(result.get('routing'), dict) else {}
    balancer_tags = {
        item.get('tag') for item in routing.get('balancers', [])
        if isinstance(item, dict) and isinstance(item.get('tag'), str)
    }
    for obj in walk_objects(result):
        tag = obj.get('outboundTag')
        if isinstance(tag, str) and tag not in outbound_tags and tag in balancer_tags:
            obj['balancerTag'] = tag
            del obj['outboundTag']
    return result


def referenced_outbound_tags(config: dict[str, Any]) -> set[str]:
    references: set[str] = set()
    for obj in walk_objects(config):
        tag = obj.get('outboundTag')
        if isinstance(tag, str) and tag:
            references.add(tag)
    return references


def add_proxy_direct(config: dict[str, Any], enabled: bool) -> dict[str, Any]:
    if not enabled:
        return config
    result = copy.deepcopy(config)
    outbound_tags = {
        item.get('tag') for item in result.get('outbounds', [])
        if isinstance(item, dict) and isinstance(item.get('tag'), str)
    }
    routing = result.get('routing') if isinstance(result.get('routing'), dict) else {}
    balancer_tags = {
        item.get('tag') for item in routing.get('balancers', [])
        if isinstance(item, dict) and isinstance(item.get('tag'), str)
    }
    references = referenced_outbound_tags(result)
    if 'proxy-direct' in references and 'proxy-direct' not in outbound_tags and 'proxy-direct' not in balancer_tags:
        result.setdefault('outbounds', []).append({'tag': 'proxy-direct', 'protocol': 'freedom'})
    return result


def validate_routing_tags(config: dict[str, Any], enabled: bool) -> None:
    if not enabled:
        return
    outbound_tags = {
        item.get('tag') for item in config.get('outbounds', [])
        if isinstance(item, dict) and isinstance(item.get('tag'), str)
    }
    routing = config.get('routing') if isinstance(config.get('routing'), dict) else {}
    balancer_tags = {
        item.get('tag') for item in routing.get('balancers', [])
        if isinstance(item, dict) and isinstance(item.get('tag'), str)
    }
    missing = sorted(
        tag for tag in referenced_outbound_tags(config)
        if tag not in outbound_tags and tag not in balancer_tags
    )
    if missing:
        raise ValueError(f'routing references missing outboundTag(s): {", ".join(missing)}')


@dataclass(frozen=True)
class Candidate:
    id: str
    source_index: int
    outbound_index: int
    outbound_tag: str
    name: str
    protocol: str
    server: str
    port: int | None
    country_code: str
    fingerprint: str

    def public(self, latency: dict[str, Any] | None, active: bool) -> dict[str, Any]:
        payload = asdict(self)
        payload['latency'] = latency
        payload['active'] = active
        return payload


@dataclass
class XraySlot:
    tag: str
    socks_tcp: int
    socks_udp: bool
    config_path: Path
    process: subprocess.Popen[str] | None = None
    log_thread: threading.Thread | None = None
    candidate_id: str = ''
    candidate_name: str = ''
    candidate: Candidate | None = None
    started_at: int | None = None
    intentional_stop: bool = False
    draining: bool = False
    drain_started_at: int | None = None
    drain_zero_since: int | None = None
    drain_protect_until: int | None = None
    drain_connections: int = 0
    drain_tcp_connections: int = 0
    drain_udp_connections: int = 0
    drain_bytes: int = 0
    drain_last_error: str = ''
    drain_degraded_checks: int = 0
    drain_last_latency_ms: int | None = None
    drain_last_checked_at: int | None = None
    drain_new_connections: int = 0
    drain_stalled_connections: int = 0
    drain_known_connection_ids: set[str] = field(default_factory=set, repr=False)
    drain_connection_bytes: dict[str, int] = field(default_factory=dict, repr=False)
    drain_idle_polls: dict[str, int] = field(default_factory=dict, repr=False)
    drain_last_info_at: int | None = None
    drain_last_info_connections: int | None = None
    observed_outbound_tag: str = ''
    observed_outbound_at: int | None = None

    def running(self) -> bool:
        return bool(self.process and self.process.poll() is None)


def migrate_legacy_workdir() -> None:
    if not LEGACY_WORKDIR.exists() or LEGACY_WORKDIR == WORKDIR:
        return
    WORKDIR.mkdir(parents=True, exist_ok=True)
    for source in list(LEGACY_WORKDIR.iterdir()):
        target = WORKDIR / source.name
        if target.exists():
            continue
        shutil.move(str(source), str(target))
    try:
        LEGACY_WORKDIR.rmdir()
    except OSError:
        pass


class XrayManager:
    def __init__(self) -> None:
        migrate_legacy_workdir()
        WORKDIR.mkdir(parents=True, exist_ok=True)
        # Remove the invalidly named temporary file left by 0.3.0, if present.
        CONFIG_PATH.with_suffix('.json.new').unlink(missing_ok=True)

        base_options = load_json(OPTIONS_PATH, {})
        runtime_options = load_json(RUNTIME_OPTIONS_PATH, {})
        if not isinstance(base_options, dict):
            base_options = {}
        if not isinstance(runtime_options, dict):
            runtime_options = {}

        base_changed = migrate_auto_switch_excluded_option(base_options)
        base_changed = migrate_test_url_options(base_options) or base_changed
        runtime_changed = migrate_auto_switch_excluded_option(runtime_options)
        runtime_changed = migrate_test_url_options(runtime_options) or runtime_changed
        for retired_key in RETIRED_OPTION_KEYS:
            if retired_key in base_options:
                base_options.pop(retired_key, None)
                base_changed = True
            if retired_key in runtime_options:
                runtime_options.pop(retired_key, None)
                runtime_changed = True
        if runtime_changed:
            atomic_write_json(RUNTIME_OPTIONS_PATH, runtime_options)

        self.options: dict[str, Any] = copy.deepcopy(base_options)
        for key in RUNTIME_SETTING_KEYS:
            if key in runtime_options:
                self.options[key] = runtime_options[key]

        self.subscription_url = str(self.options.get('subscription_url') or '').strip()
        self.config_index = int(self.options.get('config_index', 0) or 0)
        self.socks_tcp_a = int(self.options.get('socks_tcp_a', 10808))
        self.socks_tcp_b = int(
            self.options.get('socks_tcp_b', DEFAULT_SOCKS_TCP_B)
        )
        self.ui_port = bounded_int(
            self.options.get('ui_port', DEFAULT_UI_PORT), 1, 65535, 'ui_port'
        )
        # SOCKS5 UDP relay always uses the same port number as TCP.
        self.socks_udp_a = True
        self.socks_udp_b = True
        self.dual_slot_enabled = to_bool(self.options.get('dual_slot_enabled', True))
        self.override_inbounds = True
        self.proxy_username = str(self.options.get('proxy_username') or '')
        self.proxy_password = str(self.options.get('proxy_password') or '')
        self.disable_observatory = True
        self.log_level = str(self.options.get('log_level') or 'warning')
        self.user_agent = str(self.options.get('user_agent') or 'Xray Proxy Manager Home Assistant App')
        self.validate_tags = True
        self.auto_fix_tags = True
        self.auto_add_proxy_direct = True
        self.restart_on_runtime_error = True
        self.latency_test_timeout_seconds = max(3, int(self.options.get('latency_test_timeout_seconds', 12) or 12))
        self.latency_test_parallelism = max(
            0, min(32, int(self.options.get('latency_test_parallelism', 0) or 0))
        )
        self.primary_test_url, self.secondary_test_url = resolve_test_urls(self.options)
        if (
            str(base_options.get('primary_test_url') or '').strip() != self.primary_test_url
            or str(base_options.get('secondary_test_url') or '').strip()
            != self.secondary_test_url
        ):
            base_options['primary_test_url'] = self.primary_test_url
            base_options['secondary_test_url'] = self.secondary_test_url
            base_changed = True
        self.options['primary_test_url'] = self.primary_test_url
        self.options['secondary_test_url'] = self.secondary_test_url
        for legacy_key in LEGACY_SECONDARY_TEST_KEYS:
            self.options.pop(legacy_key, None)

        self.selector_control_enabled = to_bool(self.options.get('selector_control_enabled', False))
        self.selector_api_url = str(
            self.options.get('selector_api_url') or 'http://192.168.0.1:9090'
        ).rstrip('/')
        self.selector_api_secret = str(self.options.get('selector_api_secret') or '')
        self.selector_tag = str(self.options.get('selector_tag') or 'xray-active').strip()
        self.selector_status_interval_seconds = max(
            5, int(self.options.get('selector_status_interval_seconds', 10) or 10)
        )
        self.drain_quiet_seconds = max(5, int(self.options.get('drain_quiet_seconds', 30) or 30))
        self.drain_poll_interval_seconds = max(1, int(
            self.options.get('drain_poll_interval_seconds', 2) or 2
        ))
        self.drain_timeout_minutes = max(
            0, int(self.options.get('drain_timeout_minutes', 0) or 0)
        )

        self.router_control_enabled = to_bool(self.options.get('router_control_enabled', True))
        self.router_host = str(self.options.get('router_host') or '192.168.0.1').strip()
        self.router_ssh_port = int(self.options.get('router_ssh_port', 22) or 22)
        self.router_ssh_user = str(self.options.get('router_ssh_user') or 'root').strip()
        self.router_ssh_password = str(self.options.get('router_ssh_password') or '')
        configured_auth_method = str(self.options.get('router_auth_method') or '').strip().lower()
        if not configured_auth_method:
            configured_auth_method = 'password' if self.router_ssh_password else 'existing_key'
        if configured_auth_method not in ROUTER_AUTH_METHODS:
            raise RuntimeError('router_auth_method must be existing_key, password or generate_key.')
        self.router_auth_method = configured_auth_method
        self.router_ssh_key_name = self.normalize_router_key_name(
            self.options.get('router_ssh_key_name') or 'id_ed25519'
        )
        self.router_ssh_key_path_override = str(self.options.get('router_ssh_key_path') or '').strip()
        self.router_ssh_key_path: Path | None = None
        self.router_firewall_rule = str(self.options.get('router_firewall_rule') or 'mark_domains').strip()
        self.router_status_interval_seconds = max(
            5, int(self.options.get('router_status_interval_seconds', 10) or 10)
        )

        self.auto_checker_enabled = True
        self.auto_switch_best_enabled = True
        self.auto_switch_preferred_country = ''
        self.auto_switch_excluded = 'RU'
        self.auto_switch_min_ping_delta_ms = 100
        self.auto_check_interval_seconds = 60
        self.auto_check_failures = 3
        self.auto_check_max_latency_ms = 500
        self.auto_best_check_interval_seconds = 600
        self.auto_check_timeout_seconds = max(3, int(self.options.get('auto_check_timeout_seconds', 12) or 12))
        self.update_interval_hours = 1
        self.ui_sort = 'ping-asc'
        self.ui_protocol_filter = 'all'
        self.ui_max_ping_ms = 1000
        self.ui_hide_unavailable = False
        self.ui_hide_excluded = True
        self._apply_runtime_values(self.options)

        if not self.subscription_url:
            raise RuntimeError('subscription_url is empty. Set it in app configuration.')
        if bool(self.proxy_username) != bool(self.proxy_password):
            raise RuntimeError('proxy_username and proxy_password must be set together, or both left empty.')
        if not SAFE_RULE_RE.fullmatch(self.selector_tag):
            raise RuntimeError('selector_tag contains unsupported characters.')
        if not SAFE_RULE_RE.fullmatch(self.router_firewall_rule):
            raise RuntimeError('router_firewall_rule contains unsupported characters.')
        if self.socks_tcp_b == self.socks_tcp_a:
            raise RuntimeError('socks_tcp_b must differ from socks_tcp_a.')
        if self.ui_port in {self.socks_tcp_a, self.socks_tcp_b}:
            raise RuntimeError('ui_port must differ from both SOCKS slot ports.')
        if self.ui_port == WATCHDOG_PORT:
            raise RuntimeError(f'ui_port must differ from the reserved watchdog port {WATCHDOG_PORT}.')

        self.lock = threading.RLock()
        self.switch_lock = threading.Lock()
        self.router_lock = threading.Lock()
        self.stop_event = threading.Event()
        self.settings_event = threading.Event()
        self.preferred_country_scan_generation = 0
        self.subscription: list[dict[str, Any]] = []
        self.candidates: list[Candidate] = []
        self.active_candidate_id = ''
        self.active_slot_tag = 'xray-a'
        self.switch_generation = 0
        self.selector_reconciliation_pending = False
        self.slots: dict[str, XraySlot] = {
            'xray-a': XraySlot(
                tag='xray-a',
                socks_tcp=self.socks_tcp_a,
                socks_udp=self.socks_udp_a,
                config_path=SLOT_CONFIG_PATHS['xray-a'],
            ),
            'xray-b': XraySlot(
                tag='xray-b',
                socks_tcp=self.socks_tcp_b,
                socks_udp=self.socks_udp_b,
                config_path=SLOT_CONFIG_PATHS['xray-b'],
            ),
        }
        self.state = load_json(STATE_PATH, {
            'active_candidate_id': '',
            'active_slot_tag': 'xray-a',
            'subscription_updated_at': None,
            'subscription_last_attempt_at': None,
            'subscription_last_success_at': None,
            'subscription_last_error_at': None,
            'subscription_error': '',
            'subscription_consecutive_failures': 0,
            'last_switch_at': None,
            'last_switch_reason': '',
            'auto_check_failures': 0,
            'auto_check_last_at': None,
            'auto_best_check_last_at': None,
            'auto_check_last_error': '',
            'jobs': {},
        })
        if not isinstance(self.state, dict):
            self.state = {}
        self.state.setdefault('jobs', {})
        self.state['jobs']['latency'] = {'running': False, 'progress': 0, 'total': 0, 'message': ''}
        self.state['jobs']['refresh'] = {'running': False, 'message': ''}
        self.state['jobs']['switch'] = {'running': False, 'message': ''}
        self.latencies = load_json(LATENCY_PATH, {})
        if not isinstance(self.latencies, dict):
            self.latencies = {}
        self.active_candidate_id = str(self.state.get('active_candidate_id') or '')
        remembered_slot = str(self.state.get('active_slot_tag') or 'xray-a')
        self.active_slot_tag = (
            remembered_slot if self.dual_slot_enabled and remembered_slot in SLOT_TAGS else 'xray-a'
        )
        self.started_at = now_ts()
        self.home_assistant_host = self.detect_home_assistant_host()
        self.next_update_at = (
            now_ts() + self.update_interval_hours * 3600
            if self.update_interval_hours > 0 else None
        )
        self.servers: list[socketserver.BaseServer] = []
        self._xray_version_cache = ''
        self.selector_state: dict[str, Any] = {
            'configured': self.selector_control_enabled,
            'available': False,
            'current': '',
            'error': '',
            'connections_supported': False,
            'last_checked_at': None,
        }
        self.router_state: dict[str, Any] = {
            'configured': self.router_control_enabled,
            'available': False,
            'rule_enabled': None,
            'rule_name': self.router_firewall_rule,
            'rule_section': '',
            'busy': False,
            'desired_rule_enabled': (
                self.state.get('router_rule_desired_enabled')
                if isinstance(self.state.get('router_rule_desired_enabled'), bool)
                else None
            ),
            'last_checked_at': None,
            'error': '',
            'auth_method': self.router_auth_method,
            'key_name': self.router_ssh_key_name if self.router_auth_method != 'password' else '',
            'public_key': '',
        }
        self.prepare_router_auth()
        self.options_migration_pending = bool(base_changed or runtime_changed)
        if self.options_migration_pending:
            migrated, migration_error = self.sync_supervisor_options()
            if migrated:
                log('migrated renamed and retired options in Home Assistant configuration')
                self.options_migration_pending = False
            else:
                log(f'could not persist migrated options to Supervisor: {migration_error}', error=True)

    def _apply_runtime_values(self, source: dict[str, Any]) -> None:
        self.subscription_url = str(source.get('subscription_url') or '').strip()
        self.dual_slot_enabled = to_bool(source.get('dual_slot_enabled', True))
        self.auto_checker_enabled = to_bool(source.get('auto_checker_enabled', True))
        self.auto_switch_best_enabled = to_bool(source.get('auto_switch_best_enabled', True))
        self.auto_switch_preferred_country = normalize_preferred_country(
            source.get('auto_switch_preferred_country', '')
        )
        self.auto_switch_excluded = normalize_auto_switch_exclusions(
            source.get('auto_switch_excluded', 'RU')
        )
        self.auto_switch_min_ping_delta_ms = bounded_int(
            source.get('auto_switch_min_ping_delta_ms', 100), 0, 10000, 'auto_switch_min_ping_delta_ms'
        )
        self.auto_check_interval_seconds = bounded_int(
            source.get('auto_check_interval_seconds', 60), 10, 86400, 'auto_check_interval_seconds'
        )
        self.auto_check_failures = bounded_int(
            source.get('auto_check_failures', 3), 1, 100, 'auto_check_failures'
        )
        self.auto_check_max_latency_ms = bounded_int(
            source.get('auto_check_max_latency_ms', 500), 0, 10000, 'auto_check_max_latency_ms'
        )
        self.auto_best_check_interval_seconds = bounded_int(
            source.get('auto_best_check_interval_seconds', 600), 60, 86400,
            'auto_best_check_interval_seconds',
        )
        self.update_interval_hours = bounded_int(
            source.get('update_interval_hours', 1), 0, 720, 'update_interval_hours'
        )
        sort_value = str(source.get('ui_sort') or 'ping-asc')
        self.ui_sort = sort_value if sort_value in SORT_VALUES else 'ping-asc'
        protocol = str(source.get('ui_protocol_filter') or 'all').strip().upper()
        self.ui_protocol_filter = protocol if protocol else 'ALL'
        if self.ui_protocol_filter == 'ALL':
            self.ui_protocol_filter = 'all'
        self.ui_max_ping_ms = bounded_int(source.get('ui_max_ping_ms', 1000), 0, 10000, 'ui_max_ping_ms')
        self.ui_hide_unavailable = to_bool(source.get('ui_hide_unavailable', False))
        self.ui_hide_excluded = to_bool(source.get('ui_hide_excluded', True))

    def validate_runtime_changes(self, changes: dict[str, Any]) -> dict[str, Any]:
        normalized: dict[str, Any] = {}
        for key, value in changes.items():
            if key not in RUNTIME_SETTING_KEYS:
                raise ValueError(f'Настройка {key} недоступна для изменения из UI')
            if key == 'subscription_url':
                text = str(value or '').strip()
                parsed = urlparse(text)
                if not text or parsed.scheme not in {'http', 'https'} or not parsed.netloc or len(text) > 4096:
                    raise ValueError('Ссылка на подписку должна быть корректным HTTP(S)-адресом')
                normalized[key] = text
            elif key in {
                'dual_slot_enabled', 'auto_checker_enabled', 'auto_switch_best_enabled',
                'ui_hide_unavailable', 'ui_hide_excluded',
            }:
                normalized[key] = to_bool(value)
            elif key == 'auto_switch_preferred_country':
                normalized[key] = normalize_preferred_country(value)
            elif key == 'auto_switch_excluded':
                normalized[key] = normalize_auto_switch_exclusions(value)
            elif key == 'auto_switch_min_ping_delta_ms':
                normalized[key] = bounded_int(value, 0, 10000, key)
            elif key == 'auto_check_interval_seconds':
                normalized[key] = bounded_int(value, 10, 86400, key)
            elif key == 'auto_check_failures':
                normalized[key] = bounded_int(value, 1, 100, key)
            elif key == 'auto_check_max_latency_ms':
                normalized[key] = bounded_int(value, 0, 10000, key)
            elif key == 'auto_best_check_interval_seconds':
                normalized[key] = bounded_int(value, 60, 86400, key)
            elif key == 'update_interval_hours':
                normalized[key] = bounded_int(value, 0, 720, key)
            elif key == 'ui_max_ping_ms':
                normalized[key] = bounded_int(value, 0, 10000, key)
            elif key == 'ui_sort':
                text = str(value)
                if text not in SORT_VALUES:
                    raise ValueError('Неизвестный режим сортировки')
                normalized[key] = text
            elif key == 'ui_protocol_filter':
                text = str(value or 'all').strip().upper()
                if len(text) > 32 or not re.fullmatch(r'[A-Z0-9_-]+|ALL', text):
                    raise ValueError('Некорректный фильтр протокола')
                normalized[key] = 'all' if text == 'ALL' else text
        return normalized

    def update_runtime_settings(self, changes: dict[str, Any]) -> dict[str, Any]:
        normalized = self.validate_runtime_changes(changes)
        if 'dual_slot_enabled' in normalized:
            raise ValueError('Режим слотов изменяется отдельной кнопкой в верхнем блоке')
        with self.lock:
            self.options.update(normalized)
            self.options.pop(LEGACY_AUTO_SWITCH_EXCLUDED_KEY, None)
            runtime_options = load_json(RUNTIME_OPTIONS_PATH, {})
            if not isinstance(runtime_options, dict):
                runtime_options = {}
            runtime_options.update(normalized)
            runtime_options.pop(LEGACY_AUTO_SWITCH_EXCLUDED_KEY, None)
            atomic_write_json(RUNTIME_OPTIONS_PATH, runtime_options)
            self._apply_runtime_values(self.options)
            self.next_update_at = (
                now_ts() + self.update_interval_hours * 3600
                if self.update_interval_hours > 0 else None
            )
            self.settings_event.set()
        supervisor_synced, supervisor_error = self.sync_supervisor_options()
        return {
            'ok': True,
            'restart_required': [],
            'supervisor_synced': supervisor_synced,
            'supervisor_error': supervisor_error,
        }

    def _deferred_preferred_country_scan(self, country: str, generation: int) -> None:
        while not self.stop_event.wait(0.5):
            with self.lock:
                if (
                    generation != self.preferred_country_scan_generation
                    or self.auto_switch_preferred_country != country
                ):
                    return
                running = bool(self.state['jobs']['latency'].get('running'))
            if running:
                continue
            if self.request_latency_test(
                None,
                switch_to_best=True,
                source='preferred-country',
            ):
                return

    def set_preferred_country(self, value: Any) -> dict[str, Any]:
        country = normalize_preferred_country(value)
        settings_result = self.update_runtime_settings({
            'auto_switch_preferred_country': country,
        })
        with self.lock:
            self.preferred_country_scan_generation += 1
            generation = self.preferred_country_scan_generation
            matching = [
                candidate
                for candidate in self.candidates
                if country
                and candidate.country_code == country
                and not self.candidate_is_excluded(candidate)
            ]
            matching_candidates = len(matching)
            cached_healthy: list[tuple[int, str, Candidate]] = []
            cached_latencies = getattr(self, 'latencies', {})
            max_latency_ms = int(getattr(self, 'auto_check_max_latency_ms', 0) or 0)
            for candidate in matching:
                latency = cached_latencies.get(candidate.id) or {}
                latency_ms = latency.get('latency_ms')
                if latency.get('status') != 'ok' or not isinstance(latency_ms, int):
                    continue
                if max_latency_ms > 0 and latency_ms > max_latency_ms:
                    continue
                cached_healthy.append((latency_ms, candidate.name.casefold(), candidate))
            cached_healthy.sort(key=lambda item: (item[0], item[1]))
            immediate_candidate = cached_healthy[0][2] if cached_healthy else None
            current = self.candidate_by_id(getattr(self, 'active_candidate_id', ''))
            if hasattr(self, 'slots') and hasattr(self, 'active_slot_tag'):
                active_slot = self.slots.get(self.active_slot_tag)
                if active_slot is not None and active_slot.candidate is not None:
                    current = active_slot.candidate

        if not country:
            return {
                **settings_result,
                'country': '',
                'switch_started': False,
                'matching_candidates': 0,
                'message': 'Приоритет страны отключён',
            }

        immediate_switched = False
        immediate_error = ''
        should_switch_immediately = bool(
            immediate_candidate is not None
            and (
                current is None
                or current.country_code != country
            )
            and not self.same_outbound(current, immediate_candidate)
        )
        if should_switch_immediately and immediate_candidate is not None:
            try:
                self.restart_xray_for(
                    immediate_candidate,
                    f'preferred country {country} selected from UI',
                    preempt_draining=True,
                )
                immediate_switched = True
            except Exception as exc:
                immediate_error = str(exc)
                log(
                    f'immediate preferred-country switch to {immediate_candidate.name} '
                    f'failed; continuing with full scan: {exc}',
                    error=True,
                )

        switch_started = self.request_latency_test(
            None,
            switch_to_best=True,
            source='preferred-country',
        )
        queued = False
        active_full_switch_scan = False
        if not switch_started:
            with self.lock:
                job = dict(self.state['jobs']['latency'])
                active_full_switch_scan = bool(
                    job.get('running')
                    and job.get('scope') == 'all'
                    and job.get('switch_to_best')
                )
            if not active_full_switch_scan:
                queued = True
                threading.Thread(
                    target=self._deferred_preferred_country_scan,
                    args=(country, generation),
                    daemon=True,
                    name='preferred-country-scan',
                ).start()

        if immediate_switched and immediate_candidate is not None:
            message = (
                f'Активирован {immediate_candidate.name}; запущена полная проверка '
                f'с приоритетом страны {country}'
            )
        elif switch_started:
            message = f'Запущена проверка outbound с приоритетом страны {country}'
        elif active_full_switch_scan:
            message = f'Текущая полная проверка продолжена с приоритетом страны {country}'
        else:
            message = f'Проверка с приоритетом страны {country} поставлена в очередь'
        if immediate_error:
            message += f'; немедленное переключение не выполнено: {immediate_error}'
        if matching_candidates == 0:
            message += '; подходящие серверы этой страны не найдены, будет использован общий список'

        return {
            **settings_result,
            'country': country,
            'switch_started': switch_started or active_full_switch_scan or immediate_switched,
            'immediate_switched': immediate_switched,
            'queued': queued,
            'matching_candidates': matching_candidates,
            'message': message,
        }

    def set_slot_mode(self, dual_slot_enabled: bool) -> dict[str, Any]:
        desired_mode = bool(dual_slot_enabled)
        with self.lock:
            if desired_mode == self.dual_slot_enabled:
                return {'ok': True, 'dual_slot_enabled': desired_mode, 'changed': False}
            current_slot_tag = self.active_slot_tag
            current_candidate = (
                self.slots[current_slot_tag].candidate
                or self.candidate_by_id(self.active_candidate_id)
            )
            if current_candidate is None:
                current_candidate = self.choose_initial_candidate()
            previous_mode = self.dual_slot_enabled
            previous_slot_tag = self.active_slot_tag

        if not self.switch_lock.acquire(blocking=False):
            raise RuntimeError('Переключение режима уже выполняется')
        try:
            with self.lock:
                self.state['jobs']['switch'].update({
                    'running': True,
                    'message': 'Перезапуск Xray для смены режима...',
                })
                self.save_state()
            self.stop_xray()
            with self.lock:
                self.dual_slot_enabled = desired_mode
                self.active_slot_tag = 'xray-a'
                self.active_candidate_id = current_candidate.id
            self.start_initial_candidate(
                current_candidate,
                'slot mode changed from UI',
            )

            with self.lock:
                self.options['dual_slot_enabled'] = desired_mode
                runtime_options = load_json(RUNTIME_OPTIONS_PATH, {})
                if not isinstance(runtime_options, dict):
                    runtime_options = {}
                runtime_options['dual_slot_enabled'] = desired_mode
                atomic_write_json(RUNTIME_OPTIONS_PATH, runtime_options)
                self.save_state()
            supervisor_synced, supervisor_error = self.sync_supervisor_options()
            log(
                'Xray slot mode changed to '
                f'{"dual-slot" if desired_mode else "single-slot"}; processes restarted'
            )
            return {
                'ok': True,
                'dual_slot_enabled': desired_mode,
                'changed': True,
                'supervisor_synced': supervisor_synced,
                'supervisor_error': supervisor_error,
            }
        except Exception:
            try:
                self.stop_xray()
                with self.lock:
                    self.dual_slot_enabled = previous_mode
                    self.active_slot_tag = (
                        previous_slot_tag
                        if previous_mode and previous_slot_tag in SLOT_TAGS
                        else 'xray-a'
                    )
                    self.active_candidate_id = current_candidate.id
                self.start_initial_candidate(
                    current_candidate,
                    'rollback after failed slot mode change',
                )
            except Exception as rollback_exc:
                log(f'could not restore previous slot mode: {rollback_exc}', error=True)
            raise
        finally:
            with self.lock:
                self.state['jobs']['switch'].update({'running': False, 'message': ''})
                self.save_state()
            self.switch_lock.release()

    def sync_supervisor_options(self) -> tuple[bool, str]:
        token = os.environ.get('SUPERVISOR_TOKEN', '').strip()
        if not token:
            return False, 'SUPERVISOR_TOKEN недоступен; настройки сохранены локально'
        request_body = json.dumps({'options': self.options}, ensure_ascii=False).encode('utf-8')
        request = urllib.request.Request(
            'http://supervisor/addons/self/options',
            data=request_body,
            method='POST',
            headers={
                'Authorization': f'Bearer {token}',
                'Content-Type': 'application/json',
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                payload = json.loads(response.read().decode('utf-8') or '{}')
            if payload.get('result') != 'ok':
                return False, str(payload.get('message') or 'Supervisor отклонил настройки')
            return True, ''
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
            log(f'could not sync UI settings to Supervisor: {exc}', error=True)
            return False, f'{exc}; настройки сохранены локально'

    def detect_ingress_port(self) -> int:
        """Read the dynamically assigned Home Assistant Ingress port."""
        token = os.environ.get('SUPERVISOR_TOKEN', '').strip()
        if not token:
            raise RuntimeError('SUPERVISOR_TOKEN is unavailable; cannot determine the Ingress port.')

        last_error = 'unknown error'
        for attempt in range(1, 11):
            request = urllib.request.Request(
                'http://supervisor/addons/self/info',
                headers={'Authorization': f'Bearer {token}'},
            )
            try:
                with urllib.request.urlopen(request, timeout=5) as response:
                    payload = json.loads(response.read().decode('utf-8') or '{}')
                data = payload.get('data') if isinstance(payload, dict) else None
                port = data.get('ingress_port') if isinstance(data, dict) else None
                port = int(port)
                if 1 <= port <= 65535:
                    return port
                last_error = f'invalid port returned by Supervisor: {port}'
            except (TypeError, ValueError, urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
                last_error = str(exc)
            if attempt < 10:
                time.sleep(0.5)

        raise RuntimeError(f'could not determine the Home Assistant Ingress port: {last_error}')

    def detect_home_assistant_host(self) -> str:
        """Return the Home Assistant host address visible to LAN clients."""
        token = os.environ.get('SUPERVISOR_TOKEN', '').strip()
        candidates: list[str] = []
        if token:
            request = urllib.request.Request(
                'http://supervisor/network/info',
                headers={'Authorization': f'Bearer {token}'},
            )
            try:
                with urllib.request.urlopen(request, timeout=5) as response:
                    payload = json.loads(response.read().decode('utf-8') or '{}')
                data = payload.get('data') if isinstance(payload, dict) else None
                interfaces = data.get('interfaces') if isinstance(data, dict) else None
                if isinstance(interfaces, list):
                    ordered = sorted(
                        (item for item in interfaces if isinstance(item, dict)),
                        key=lambda item: not bool(item.get('primary')),
                    )
                    for interface in ordered:
                        ipv4 = interface.get('ipv4')
                        addresses = ipv4.get('address') if isinstance(ipv4, dict) else None
                        if isinstance(addresses, list):
                            candidates.extend(str(item).split('/', 1)[0] for item in addresses)
            except Exception as exc:
                self.debug_log(f'could not read Home Assistant host address from Supervisor: {exc}')

        for address in candidates:
            try:
                parsed = socket.inet_pton(socket.AF_INET, address)
            except OSError:
                continue
            if parsed and not address.startswith('127.') and address != '0.0.0.0':
                return address
        return 'host'

    def save_state(self) -> None:
        self.state['active_candidate_id'] = self.active_candidate_id
        self.state['active_slot_tag'] = self.active_slot_tag
        atomic_write_json(STATE_PATH, self.state)

    def save_latencies(self) -> None:
        atomic_write_json(LATENCY_PATH, self.latencies)

    def debug_log(self, message: str) -> None:
        if getattr(self, 'log_level', '') == 'debug':
            log(f'DEBUG: {message}')

    # ----- External selector control ---------------------------------------------

    def selector_api_request(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        *,
        timeout: int = 12,
    ) -> Any:
        if not self.selector_control_enabled:
            raise RuntimeError('Управление внешним selector отключено в настройках')
        method = method.upper()
        if method not in {'GET', 'PUT'}:
            raise ValueError('Unsupported selector API method')
        if not path.startswith('/'):
            path = f'/{path}'
        url = f'{self.selector_api_url}{path}'
        headers = {'Accept': 'application/json'}
        data: bytes | None = None
        if self.selector_api_secret:
            headers['Authorization'] = f'Bearer {self.selector_api_secret}'
        if payload is not None:
            headers['Content-Type'] = 'application/json'
            data = json.dumps(payload, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
        request = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                raw = response.read().decode('utf-8')
        except urllib.error.HTTPError as exc:
            body = exc.read().decode('utf-8', errors='replace')[:500]
            raise RuntimeError(f'Selector API HTTP {exc.code}: {body or exc.reason}') from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise RuntimeError(f'Selector API недоступен: {exc}') from exc
        if not raw:
            return {}
        try:
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f'Selector API returned invalid JSON: {raw[:300]}') from exc

    def selector_status(self) -> str:
        payload = self.selector_api_request(
            'GET',
            f'/proxies/{quote(self.selector_tag, safe="")}',
        )
        current = str(payload.get('now') or '') if isinstance(payload, dict) else ''
        if current not in SLOT_TAGS:
            raise RuntimeError(
                f'Selector {self.selector_tag} returned unsupported slot: {current or "empty"}'
            )
        return current

    def switch_selector(self, slot_tag: str) -> None:
        if slot_tag not in SLOT_TAGS:
            raise ValueError('Unknown Xray slot')
        self.selector_api_request(
            'PUT',
            f'/proxies/{quote(self.selector_tag, safe="")}',
            {'name': slot_tag},
        )
        current = self.selector_status()
        if current != slot_tag:
            raise RuntimeError(
                f'Selector {self.selector_tag} remained on {current} instead of {slot_tag}'
            )
        if hasattr(self, 'selector_state') and hasattr(self, 'lock'):
            with self.lock:
                self.selector_state.update({
                    'configured': True,
                    'available': True,
                    'current': slot_tag,
                    'error': '',
                    'last_checked_at': now_ts(),
                })
        with self.lock:
            self.selector_state.update({
                'available': True,
                'current': current,
                'error': '',
                'last_checked_at': now_ts(),
            })

    def selector_connections(self) -> list[dict[str, Any]]:
        payload = self.selector_api_request('GET', '/connections', timeout=15)
        connections = payload.get('connections') if isinstance(payload, dict) else None
        if not isinstance(connections, list):
            raise RuntimeError('Selector API /connections response has no connection list')
        return [item for item in connections if isinstance(item, dict)]

    @staticmethod
    def connection_slot_stats(
        connections: list[dict[str, Any]],
        slot_tag: str,
    ) -> tuple[int, int, int, int]:
        count = 0
        tcp_count = 0
        udp_count = 0
        total_bytes = 0
        for item in connections:
            chains = item.get('chains')
            if not isinstance(chains, list) or slot_tag not in chains:
                continue
            count += 1
            metadata = item.get('metadata') if isinstance(item.get('metadata'), dict) else {}
            network = str(metadata.get('network') or item.get('network') or '').lower()
            if network == 'udp':
                udp_count += 1
            else:
                tcp_count += 1
            for key in ('upload', 'download'):
                try:
                    total_bytes += max(0, int(item.get(key) or 0))
                except (TypeError, ValueError):
                    pass
        return count, tcp_count, udp_count, total_bytes

    @staticmethod
    def connection_id(item: dict[str, Any]) -> str:
        return str(item.get('id') or item.get('uuid') or '')

    @staticmethod
    def connection_total_bytes(item: dict[str, Any]) -> int:
        total = 0
        for key in ('upload', 'download'):
            try:
                total += max(0, int(item.get(key) or 0))
            except (TypeError, ValueError):
                pass
        return total

    def connections_for_slot(
        self,
        connections: list[dict[str, Any]],
        slot_tag: str,
    ) -> list[dict[str, Any]]:
        return [
            item for item in connections
            if isinstance(item.get('chains'), list) and slot_tag in item['chains']
        ]

    def connection_summary(self, item: dict[str, Any]) -> str:
        metadata = item.get('metadata') if isinstance(item.get('metadata'), dict) else {}
        source_ip = str(metadata.get('sourceIP') or metadata.get('source_ip') or '?')
        source_port = str(metadata.get('sourcePort') or metadata.get('source_port') or '?')
        destination = (
            str(metadata.get('host') or metadata.get('destinationIP') or metadata.get('destination_ip') or '?')
        )
        destination_port = str(
            metadata.get('destinationPort') or metadata.get('destination_port') or '?'
        )
        network = str(metadata.get('network') or item.get('network') or '?').lower()
        chains = ','.join(str(value) for value in item.get('chains') or [])
        return (
            f'id={self.connection_id(item) or "?"} source={source_ip}:{source_port} '
            f'network={network} destination={destination}:{destination_port} '
            f'chains={chains or "?"} bytes={self.connection_total_bytes(item)}'
        )

    def capture_drain_connection_baseline(self, slot_tag: str) -> None:
        """Capture existing selector flows so later arrivals can be detected."""
        slot = self.slots[slot_tag]
        try:
            connections = self.connections_for_slot(self.selector_connections(), slot_tag)
        except Exception as exc:
            with self.lock:
                slot.drain_known_connection_ids.clear()
                slot.drain_connection_bytes.clear()
                slot.drain_idle_polls.clear()
                slot.drain_last_error = str(exc)
            log(f'could not capture {slot_tag} drain baseline: {exc}', error=True)
            return
        known_ids = {
            self.connection_id(item) for item in connections if self.connection_id(item)
        }
        byte_map = {
            self.connection_id(item): self.connection_total_bytes(item)
            for item in connections if self.connection_id(item)
        }
        with self.lock:
            slot.drain_known_connection_ids = known_ids
            slot.drain_connection_bytes = byte_map
            slot.drain_idle_polls = {connection_id: 0 for connection_id in known_ids}
            slot.drain_new_connections = 0
            slot.drain_stalled_connections = 0
        log(f'{slot_tag} drain baseline captured: {len(known_ids)} selector connections')
        if self.log_level == 'debug':
            for item in connections[:10]:
                self.debug_log(f'{slot_tag} drain baseline: {self.connection_summary(item)}')

    def reconcile_startup_selector(self, current: str) -> None:
        """Resolve an unknown startup selector without surrendering manager state.

        The remembered manager slot is authoritative whenever its Xray process is
        running. The live selector is adopted only when that expected process is
        actually stopped and the reported slot is alive.
        """
        if not self.selector_reconciliation_pending or self.switch_lock.locked():
            return
        with self.lock:
            expected = self.active_slot_tag
            expected_running = self.slots[expected].running()
            current_running = self.slots[current].running()

        if expected_running:
            if current != expected:
                self.switch_selector(expected)
                log(
                    f'startup selector reported {current}; restored manager-expected {expected}',
                    error=True,
                )
            with self.lock:
                self.selector_reconciliation_pending = False
                self.save_state()
            log(f'startup selector confirmed on manager-expected {expected}')
            return

        if not current_running:
            return

        with self.lock:
            previous_slot_tag = self.active_slot_tag
            current_slot = self.slots[current]
            self.active_slot_tag = current
            self.active_candidate_id = current_slot.candidate_id
            current_slot.draining = False
            current_slot.drain_started_at = None
            current_slot.drain_zero_since = None
            current_slot.drain_protect_until = None
            current_slot.drain_degraded_checks = 0
            current_slot.drain_last_latency_ms = None
            current_slot.drain_last_checked_at = None
            current_slot.drain_new_connections = 0
            current_slot.drain_stalled_connections = 0
            current_slot.drain_known_connection_ids.clear()
            current_slot.drain_connection_bytes.clear()
            current_slot.drain_idle_polls.clear()
            self.selector_reconciliation_pending = False
            self.switch_generation += 1
            self.save_state()
        candidate = self.candidate_by_id(current_slot.candidate_id)
        if candidate:
            try:
                self.save_active_config(current, candidate)
            except Exception as exc:
                log(f'could not save adopted selector config: {exc}', error=True)
        log(
            f'adopted live selector slot {current} only because manager-expected '
            f'{previous_slot_tag} was not running',
            error=True,
        )

    def restore_selector_alignment(self, reported_current: str) -> None:
        with self.lock:
            expected = self.active_slot_tag
            expected_running = self.slots[expected].running()
        if reported_current == expected or self.switch_lock.locked():
            return
        if not self.switch_lock.acquire(blocking=False):
            return
        try:
            current = self.selector_status()
            with self.lock:
                expected = self.active_slot_tag
                expected_running = self.slots[expected].running()
                current_running = self.slots[current].running()
            if current == expected:
                return
            if expected_running:
                self.switch_selector(expected)
                log(f'Selector unexpectedly reported {current}; restored {expected}', error=True)
                return
            if current_running:
                with self.lock:
                    current_slot = self.slots[current]
                    self.active_slot_tag = current
                    self.active_candidate_id = current_slot.candidate_id
                    current_slot.draining = False
                    current_slot.drain_started_at = None
                    current_slot.drain_zero_since = None
                    current_slot.drain_protect_until = None
                    current_slot.drain_degraded_checks = 0
                    current_slot.drain_last_latency_ms = None
                    current_slot.drain_last_checked_at = None
                    current_slot.drain_new_connections = 0
                    current_slot.drain_stalled_connections = 0
                    current_slot.drain_known_connection_ids.clear()
                    current_slot.drain_connection_bytes.clear()
                    current_slot.drain_idle_polls.clear()
                    self.switch_generation += 1
                    self.save_state()
                candidate = self.candidate_by_id(self.active_candidate_id)
                if candidate:
                    try:
                        self.save_active_config(current, candidate)
                    except Exception as exc:
                        log(f'could not save adopted selector config: {exc}', error=True)
                log(f'adopted live selector slot {current} because {expected} was not running', error=True)
        except Exception as exc:
            log(f'could not reconcile selector state: {exc}', error=True)
        finally:
            self.switch_lock.release()

    def refresh_selector_status(self) -> None:
        if not self.selector_control_enabled:
            with self.lock:
                self.selector_state.update({
                    'configured': False,
                    'available': False,
                    'current': '',
                    'error': 'Управление selector отключено',
                    'connections_supported': False,
                    'last_checked_at': now_ts(),
                })
            return
        with self.lock:
            was_available = bool(self.selector_state.get('available'))
            first_check = self.selector_state.get('last_checked_at') is None
        try:
            current = self.selector_status()
        except Exception as exc:
            with self.lock:
                self.selector_state.update({
                    'configured': True,
                    'available': False,
                    'error': str(exc),
                    'connections_supported': False,
                    'last_checked_at': now_ts(),
                })
            if was_available or first_check:
                log(
                    f'Selector API unavailable; retry interval reduced to 1 second: {exc}',
                    error=True,
                )
            else:
                self.debug_log(f'Selector API still unavailable: {exc}')
            return

        with self.lock:
            need_connections_check = (
                not bool(self.selector_state.get('connections_supported'))
                or any(slot.draining for slot in self.slots.values())
            )
            self.selector_state.update({
                'configured': True,
                'available': True,
                'current': current,
                'error': '',
                'last_checked_at': now_ts(),
            })
        if not was_available:
            log(f'Selector API connection restored; reported active slot is {current}')
        self.reconcile_startup_selector(current)
        switch_in_progress = self.switch_lock.locked()
        if not self.selector_reconciliation_pending and not switch_in_progress:
            if not was_available:
                # Recovery is treated as a fresh synchronization transaction,
                # not merely as a read. Re-write and re-read the manager's
                # expected slot even when sing-box already reports it. This
                # makes the manager the explicit source of truth after every
                # Clash API outage or sing-box restart.
                with self.lock:
                    expected = self.active_slot_tag
                    expected_running = self.slots[expected].running()
                if expected_running:
                    self.switch_selector(expected)
                    with self.lock:
                        self.selector_state['current'] = expected
                    if current != expected:
                        log(
                            f'Selector API recovery reported {current}; '
                            f'force-synchronized to manager-expected {expected}',
                            error=True,
                        )
                    else:
                        log(
                            f'Selector API recovery force-confirmed manager-expected '
                            f'slot {expected}'
                        )
                else:
                    self.restore_selector_alignment(current)
                    with self.lock:
                        adopted = self.active_slot_tag
                        adopted_running = self.slots[adopted].running()
                    if adopted_running:
                        self.switch_selector(adopted)
                        with self.lock:
                            self.selector_state['current'] = adopted
                        log(
                            f'Selector API recovery force-confirmed adopted slot {adopted}'
                        )
            else:
                self.restore_selector_alignment(current)
        elif switch_in_progress:
            self.debug_log(
                'Selector reconciliation deferred because an outbound switch is in progress'
            )
        if not was_available and not switch_in_progress:
            with self.lock:
                expected = self.active_slot_tag
                draining = next(
                    (tag for tag in SLOT_TAGS if self.slots[tag].draining),
                    None,
                )
        if not need_connections_check:
            return

        try:
            self.selector_connections()
            with self.lock:
                self.selector_state['connections_supported'] = True
        except Exception as exc:
            with self.lock:
                self.selector_state.update({
                    'connections_supported': False,
                    'error': f'Selector API connection tracking unavailable: {exc}',
                })

    def selector_status_wait_seconds(self) -> int:
        with self.lock:
            urgent = self.selector_control_enabled and (
                any(slot.draining for slot in self.slots.values())
                or not bool(self.selector_state.get('available'))
            )
        return 1 if urgent else self.selector_status_interval_seconds

    def selector_status_loop(self) -> None:
        while not self.stop_event.is_set():
            self.refresh_selector_status()
            if self.stop_event.wait(self.selector_status_wait_seconds()):
                break

    # ----- OpenWrt firewall control -------------------------------------------------

    @staticmethod
    def normalize_router_key_name(value: Any) -> str:
        name = str(value or '').strip()
        if name.endswith('.pub'):
            name = name[:-4]
        if not name or name in {'.', '..'} or Path(name).name != name:
            raise RuntimeError('router_ssh_key_name must contain only a file name, without a path.')
        if not SAFE_KEY_NAME_RE.fullmatch(name):
            raise RuntimeError('router_ssh_key_name contains unsupported characters.')
        return name

    def router_key_candidates(self) -> list[Path]:
        candidates: list[Path] = [
            ROUTER_PRIMARY_KEY_DIR / self.router_ssh_key_name,
            ROUTER_SECONDARY_KEY_DIR / self.router_ssh_key_name,
            WORKDIR / self.router_ssh_key_name,
        ]
        if self.router_ssh_key_path_override:
            candidates.append(Path(self.router_ssh_key_path_override))
        candidates.append(WORKDIR / 'router_ssh_key')
        unique: list[Path] = []
        seen: set[str] = set()
        for candidate in candidates:
            key = str(candidate)
            if key not in seen:
                seen.add(key)
                unique.append(candidate)
        return unique

    @staticmethod
    def public_key_path(private_path: Path) -> Path:
        return Path(f'{private_path}.pub')

    def ensure_public_key_file(self, private_path: Path) -> Path:
        public_path = self.public_key_path(private_path)
        result = subprocess.run(
            [SSH_KEYGEN_BIN, '-y', '-f', str(private_path)],
            check=True,
            capture_output=True,
            text=True,
            timeout=20,
        )
        derived_key = result.stdout.strip()
        if not derived_key:
            raise RuntimeError('ssh-keygen did not return a public key')

        existing_key = ''
        if public_path.exists():
            existing_key = public_path.read_text(encoding='utf-8').strip()
        derived_identity = ' '.join(derived_key.split()[:2])
        existing_identity = ' '.join(existing_key.split()[:2])
        if existing_identity != derived_identity:
            public_path.write_text(
                f'{derived_key} xray-proxy-manager@homeassistant\n',
                encoding='utf-8',
            )
        public_path.chmod(0o644)
        return public_path

    def install_generated_key_with_password(self, public_key: str) -> None:
        if not self.router_ssh_password:
            return
        remote_script = (
            'set -e; umask 077; mkdir -p /etc/dropbear; '
            'touch /etc/dropbear/authorized_keys; '
            f'KEY={shlex.quote(public_key)}; '
            'grep -qxF "$KEY" /etc/dropbear/authorized_keys 2>/dev/null || '
            'printf "%s\n" "$KEY" >> /etc/dropbear/authorized_keys; '
            'chmod 600 /etc/dropbear/authorized_keys; echo key-installed'
        )
        command = [
            SSHPASS_BIN, '-e', SSH_BIN,
            '-p', str(self.router_ssh_port),
            '-o', 'ConnectTimeout=6',
            '-o', 'ServerAliveInterval=5',
            '-o', 'ServerAliveCountMax=1',
            '-o', 'StrictHostKeyChecking=accept-new',
            '-o', f'UserKnownHostsFile={WORKDIR / "router_known_hosts"}',
            '-o', 'LogLevel=ERROR',
            '-o', 'BatchMode=no',
            '-o', 'PreferredAuthentications=password,keyboard-interactive',
            f'{self.router_ssh_user}@{self.router_host}',
            remote_script,
        ]
        environment = os.environ.copy()
        environment['SSHPASS'] = self.router_ssh_password
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=20, env=environment
        )
        if result.returncode != 0:
            message = (result.stderr or result.stdout or f'ssh exit {result.returncode}').strip()
            raise RuntimeError(f'Не удалось установить сгенерированный ключ: {message}')

    def prepare_router_auth(self) -> None:
        if not self.router_control_enabled:
            return
        if self.router_auth_method == 'password':
            if not self.router_ssh_password:
                self.router_state['error'] = 'Для password требуется router_ssh_password'
            return
        try:
            key_path: Path | None = None
            for candidate in self.router_key_candidates():
                if candidate.exists() and candidate.is_file():
                    key_path = candidate
                    break

            if key_path is None and self.router_auth_method == 'generate_key':
                key_path = ROUTER_PRIMARY_KEY_DIR / self.router_ssh_key_name
                key_path.parent.mkdir(parents=True, exist_ok=True)
                subprocess.run(
                    [SSH_KEYGEN_BIN, '-q', '-t', 'ed25519', '-N', '', '-C',
                     'xray-proxy-manager@homeassistant', '-f', str(key_path)],
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=20,
                )

            if key_path is None:
                searched = ', '.join(str(item) for item in self.router_key_candidates())
                raise RuntimeError(
                    f'Приватный SSH-ключ {self.router_ssh_key_name} не найден. Проверены: {searched}'
                )

            key_path.chmod(0o600)
            public_path = self.ensure_public_key_file(key_path)
            self.router_ssh_key_path = key_path
            public_key = public_path.read_text(encoding='utf-8').strip()
            self.router_state['public_key'] = public_key
            self.router_state['key_name'] = self.router_ssh_key_name

            if self.router_auth_method == 'generate_key' and self.router_ssh_password:
                self.install_generated_key_with_password(public_key)
        except Exception as exc:
            self.router_state['error'] = f'Не удалось подготовить SSH-доступ: {exc}'
            log(self.router_state['error'], error=True)

    def router_ssh_command(self, remote_command: str) -> tuple[list[str], dict[str, str]]:
        command: list[str] = []
        environment = os.environ.copy()
        use_password = self.router_auth_method == 'password'
        if use_password:
            command.extend([SSHPASS_BIN, '-e'])
            environment['SSHPASS'] = self.router_ssh_password
        command.extend([
            SSH_BIN,
            '-p', str(self.router_ssh_port),
            '-o', 'ConnectTimeout=6',
            '-o', 'ServerAliveInterval=5',
            '-o', 'ServerAliveCountMax=1',
            '-o', 'StrictHostKeyChecking=accept-new',
            '-o', f'UserKnownHostsFile={WORKDIR / "router_known_hosts"}',
            '-o', 'LogLevel=ERROR',
        ])
        if use_password:
            command.extend(['-o', 'BatchMode=no', '-o', 'PreferredAuthentications=password,keyboard-interactive'])
        else:
            if self.router_ssh_key_path is None:
                raise RuntimeError('SSH-ключ для OpenWrt не подготовлен')
            command.extend(['-o', 'BatchMode=yes', '-i', str(self.router_ssh_key_path)])
        command.extend([f'{self.router_ssh_user}@{self.router_host}', remote_command])
        return command, environment

    def run_router_command(self, remote_command: str, timeout: int = 20) -> str:
        if not self.router_control_enabled:
            raise RuntimeError('Управление правилом OpenWrt отключено в настройках')
        if self.router_auth_method == 'password':
            if not self.router_ssh_password:
                raise RuntimeError('Пароль OpenWrt не указан')
        elif self.router_ssh_key_path is None or not self.router_ssh_key_path.exists():
            raise RuntimeError(f'Приватный SSH-ключ {self.router_ssh_key_name} не найден')
        command, environment = self.router_ssh_command(remote_command)
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=environment,
        )
        if result.returncode != 0:
            message = (result.stderr or result.stdout or f'ssh exit {result.returncode}').strip()
            raise RuntimeError(message)
        return result.stdout.strip()

    def router_rule_remote_script(self, desired: bool | None = None) -> str:
        # router_firewall_rule is validated by SAFE_RULE_RE during initialization.
        lines = [
            'set -e',
            f'RULE={shlex.quote(self.router_firewall_rule)}',
            'SECTION="$RULE"',
            'if ! uci -q get "firewall.$SECTION" >/dev/null 2>&1; then',
            r'''  SECTION="$(uci -q show firewall | sed -n "s/^firewall\.\([^=]*\)\.name='$RULE'$/\1/p" | head -n 1)"''',
            'fi',
            '[ -n "$SECTION" ] || { echo "rule-not-found"; exit 4; }',
        ]
        if desired is not None:
            value = '1' if desired else '0'
            lines.extend([
                f'uci set "firewall.$SECTION.enabled={value}"',
                'uci commit firewall',
                'RELOAD_LOG=/tmp/xray-proxy-manager-firewall-reload.log',
                'if ! /etc/init.d/firewall reload >"$RELOAD_LOG" 2>&1; then',
                '  cat "$RELOAD_LOG" >&2',
                '  exit 5',
                'fi',
            ])
        lines.extend([
            'VALUE="$(uci -q get "firewall.$SECTION.enabled" || true)"',
            'if [ "$VALUE" = "0" ]; then',
            '  printf "disabled:%s\n" "$SECTION"',
            'else',
            '  printf "enabled:%s\n" "$SECTION"',
            'fi',
        ])
        return f'sh -c {shlex.quote(chr(10).join(lines))}'

    def refresh_router_status(self) -> None:
        if not self.router_control_enabled:
            with self.lock:
                self.router_state.update({
                    'configured': False,
                    'available': False,
                    'rule_enabled': None,
                    'rule_name': self.router_firewall_rule,
                    'error': 'Управление правилом отключено',
                    'last_checked_at': now_ts(),
                })
            return
        try:
            output = self.run_router_command(self.router_rule_remote_script(), timeout=12)
            match = re.search(r'^(enabled|disabled):(.+)$', output.strip(), re.MULTILINE)
            if not match:
                raise RuntimeError(output or 'OpenWrt вернул неизвестный ответ')
            enabled = match.group(1) == 'enabled'
            section = match.group(2).strip()
            restore_to: bool | None = None
            with self.lock:
                desired = self.router_state.get('desired_rule_enabled')
                if not isinstance(desired, bool):
                    desired = enabled
                    self.router_state['desired_rule_enabled'] = desired
                    self.state['router_rule_desired_enabled'] = desired
                    self.save_state()
                elif desired != enabled and not self.router_state.get('busy'):
                    restore_to = desired
                self.router_state.update({
                    'configured': True,
                    'available': True,
                    'rule_enabled': enabled,
                    'rule_name': self.router_firewall_rule,
                    'rule_section': section,
                    'error': '',
                    'last_checked_at': now_ts(),
                })
            if restore_to is not None:
                log(
                    f'OpenWrt rule {self.router_firewall_rule} changed outside the manager; '
                    f'restoring {"enabled" if restore_to else "disabled"} state'
                )
                self.set_router_rule(restore_to, automatic=True)
        except Exception as exc:
            with self.lock:
                self.router_state.update({
                    'configured': True,
                    'available': False,
                    'rule_enabled': None,
                    'rule_name': self.router_firewall_rule,
                    'error': str(exc),
                    'last_checked_at': now_ts(),
                })

    def set_router_rule(self, enabled: bool, *, automatic: bool = False) -> None:
        if not self.router_lock.acquire(blocking=False):
            raise RuntimeError('Изменение правила уже выполняется')
        try:
            with self.lock:
                self.router_state['busy'] = True
                self.router_state['desired_rule_enabled'] = enabled
                self.state['router_rule_desired_enabled'] = enabled
                self.save_state()
            output = self.run_router_command(self.router_rule_remote_script(enabled), timeout=25)
            match = re.search(r'^(enabled|disabled):(.+)$', output.strip(), re.MULTILINE)
            if not match:
                raise RuntimeError(output or 'OpenWrt вернул неизвестный ответ')
            actual_enabled = match.group(1) == 'enabled'
            if actual_enabled != enabled:
                raise RuntimeError('Правило не перешло в требуемое состояние')
            with self.lock:
                self.router_state.update({
                    'available': True,
                    'rule_enabled': actual_enabled,
                    'rule_name': self.router_firewall_rule,
                    'rule_section': match.group(2).strip(),
                    'desired_rule_enabled': enabled,
                    'error': '',
                    'last_checked_at': now_ts(),
                })
            if automatic:
                log(
                    f'OpenWrt rule {self.router_firewall_rule} automatically restored to '
                    f'{"enabled" if enabled else "disabled"}'
                )
        except Exception as exc:
            with self.lock:
                self.router_state.update({
                    'available': False,
                    'rule_enabled': None,
                    'rule_name': self.router_firewall_rule,
                    'error': str(exc),
                    'last_checked_at': now_ts(),
                })
            raise
        finally:
            with self.lock:
                self.router_state['busy'] = False
            self.router_lock.release()

    def router_status_loop(self) -> None:
        while not self.stop_event.is_set():
            self.refresh_router_status()
            if self.stop_event.wait(self.router_status_interval_seconds):
                break

    # ----- Subscription and Xray configuration -------------------------------------

    def download_subscription_once(self, proxy_slot: str | None = None) -> list[dict[str, Any]]:
        with tempfile.NamedTemporaryFile(prefix='subscription.', suffix='.json', delete=False) as temp_file:
            temp_path = Path(temp_file.name)
        try:
            command = [
                CURL_BIN, '-fSL', '--connect-timeout', '20', '--max-time', '90',
                '--retry', '2', '--retry-delay', '2', '--retry-all-errors',
                '-A', self.user_agent,
            ]
            environment = os.environ.copy()
            for key in (
                'http_proxy', 'https_proxy', 'all_proxy', 'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY',
            ):
                environment.pop(key, None)
            if proxy_slot is None:
                command.extend(['--noproxy', '*'])
                environment['NO_PROXY'] = '*'
                environment['no_proxy'] = '*'
            else:
                slot = self.slots[proxy_slot]
                command.extend(['--socks5-hostname', f'127.0.0.1:{slot.socks_tcp}'])
                if self.proxy_username and self.proxy_password:
                    command.extend(['--proxy-user', f'{self.proxy_username}:{self.proxy_password}'])
            command.extend([self.subscription_url, '-o', str(temp_path)])
            result = subprocess.run(
                command, capture_output=True, text=True, timeout=110, env=environment
            )
            if result.returncode != 0:
                raise RuntimeError((result.stderr or result.stdout or 'curl failed').strip())
            with temp_path.open('r', encoding='utf-8-sig') as file_handle:
                payload = json.load(file_handle)
            if isinstance(payload, dict):
                configs = [payload]
            elif isinstance(payload, list):
                configs = payload
            else:
                raise ValueError('subscription must be a JSON object or array')
            normalized = [item for item in configs if isinstance(item, dict)]
            if not normalized:
                raise ValueError('subscription contains no JSON configuration objects')
            return normalized
        finally:
            temp_path.unlink(missing_ok=True)

    def download_subscription(self) -> list[dict[str, Any]]:
        """Download directly first, then fall back to already running Xray slots."""
        try:
            configs = self.download_subscription_once()
            self.debug_log('subscription downloaded directly without a slot proxy')
            return configs
        except Exception as direct_exc:
            errors = [f'direct: {direct_exc}']
            with self.lock:
                ordered_slots = [self.active_slot_tag] + [
                    tag for tag in SLOT_TAGS if tag != self.active_slot_tag
                ]
                running_slots = [tag for tag in ordered_slots if self.slots[tag].running()]
            if not running_slots:
                raise RuntimeError(str(direct_exc)) from direct_exc
            log(
                'direct subscription download failed; retrying through already running '
                f'Xray slot(s): {", ".join(running_slots)}',
                error=True,
            )
            for slot_tag in running_slots:
                try:
                    configs = self.download_subscription_once(slot_tag)
                    log(f'subscription download succeeded through running Xray slot {slot_tag}')
                    return configs
                except Exception as proxy_exc:
                    errors.append(f'{slot_tag}: {proxy_exc}')
            raise RuntimeError('; '.join(errors)) from direct_exc

    def load_cached_subscription(self) -> list[dict[str, Any]]:
        payload = load_json(SUBSCRIPTION_PATH, None)
        if isinstance(payload, dict):
            return [payload]
        if isinstance(payload, list):
            return [item for item in payload if isinstance(item, dict)]
        return []

    def extract_candidates(self, configs: list[dict[str, Any]]) -> list[Candidate]:
        candidates: list[Candidate] = []
        seen_ids: set[str] = set()
        for source_index, raw_config in enumerate(configs):
            config = ensure_outbound_tags(raw_config)
            profile_name = config_display_name(config, source_index)
            proxy_entries: list[tuple[int, dict[str, Any]]] = []
            for outbound_index, outbound in enumerate(config.get('outbounds') or []):
                if not isinstance(outbound, dict):
                    continue
                protocol = str(outbound.get('protocol') or '').lower()
                tag = str(outbound.get('tag') or '')
                if not protocol or protocol in DIRECT_PROTOCOLS or tag.lower() in DIRECT_TAGS:
                    continue
                proxy_entries.append((outbound_index, outbound))

            if not proxy_entries:
                continue

            multiple = len(proxy_entries) > 1
            for outbound_index, outbound in proxy_entries:
                tag = str(outbound.get('tag') or f'ui-outbound-{outbound_index + 1}')
                protocol = str(outbound.get('protocol') or 'unknown')
                server, port = extract_endpoint(outbound)
                outbound_name = first_text(outbound.get('remarks'), outbound.get('name'), tag)
                name = f'{profile_name} — {outbound_name}' if multiple else profile_name
                if name == f'Профиль {source_index + 1}' and outbound_name:
                    name = outbound_name

                fingerprint_payload = {
                    'profile_name': profile_name,
                    'protocol': protocol,
                    'server': server,
                    'port': port,
                    'outbound': {key: value for key, value in outbound.items() if key != 'tag'},
                }
                fingerprint = hashlib.sha256(
                    json.dumps(
                        fingerprint_payload,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(',', ':'),
                    ).encode('utf-8')
                ).hexdigest()[:20]
                candidate_id = fingerprint
                serial = 2
                while candidate_id in seen_ids:
                    candidate_id = f'{fingerprint}-{serial}'
                    serial += 1
                seen_ids.add(candidate_id)
                candidates.append(Candidate(
                    id=candidate_id,
                    source_index=source_index,
                    outbound_index=outbound_index,
                    outbound_tag=tag,
                    name=name,
                    protocol=protocol.upper(),
                    server=server,
                    port=port,
                    country_code=infer_country_code(name, tag, server),
                    fingerprint=fingerprint,
                ))
        return candidates

    def candidate_by_id(self, candidate_id: str) -> Candidate | None:
        return next((item for item in self.candidates if item.id == candidate_id), None)

    @staticmethod
    def same_outbound(left: Candidate | None, right: Candidate | None) -> bool:
        if left is None or right is None:
            return False
        if left.id and left.id == right.id:
            return True
        if left.fingerprint and left.fingerprint == right.fingerprint:
            return True
        if left.id or right.id or left.fingerprint or right.fingerprint:
            return False
        return (
            left.protocol.casefold(),
            left.server.casefold(),
            left.port,
            left.outbound_tag,
        ) == (
            right.protocol.casefold(),
            right.server.casefold(),
            right.port,
            right.outbound_tag,
        )

    @staticmethod
    def same_candidate_identity(left: Candidate | None, right: Candidate | None) -> bool:
        """Compare concrete subscription entries without merging duplicates.

        Fingerprints intentionally survive subscription refreshes, so two
        duplicate entries can share one fingerprint while having distinct IDs.
        Runtime slot and active-card assignment must prefer the concrete ID.
        """
        if left is None or right is None:
            return False
        if left.id and right.id:
            return left.id == right.id
        return XrayManager.same_outbound(left, right)

    def candidate_by_tag(self, outbound_tag: str, preferred_source: int | None = None) -> Candidate | None:
        matches = [item for item in self.candidates if item.outbound_tag == outbound_tag]
        if preferred_source is not None:
            preferred = next((item for item in matches if item.source_index == preferred_source), None)
            if preferred:
                return preferred
        return matches[0] if matches else None

    def candidate_latency_ms(self, candidate: Candidate | None) -> int | None:
        if candidate is None:
            return None
        data = self.latencies.get(candidate.id) or {}
        latency_ms = data.get('latency_ms')
        if data.get('status') != 'ok' or not isinstance(latency_ms, int):
            return None
        return latency_ms

    def choose_initial_candidate(self, preferred: Candidate | None = None) -> Candidate:
        selected = preferred
        if selected is None:
            remembered = str(self.state.get('active_candidate_id') or '')
            if remembered:
                selected = self.candidate_by_id(remembered)
        if selected is None:
            matching_index = [
                item for item in self.candidates if item.source_index == self.config_index
            ]
            selected = matching_index[0] if matching_index else None
        if selected is None:
            if not self.candidates:
                raise RuntimeError('No proxy outbounds were found in the subscription.')
            selected = self.candidates[0]

        if not self.auto_switch_best_enabled:
            return selected

        allowed = [item for item in self.candidates if not self.candidate_is_excluded(item)]
        if not allowed:
            raise RuntimeError(
                'No proxy outbounds remain after applying configured selection exclusions.'
            )

        healthy = self.sorted_healthy_candidates(exclude_configured_countries=True)
        if self.candidate_is_excluded(selected):
            allowed_for_index = [
                item for item in allowed if item.source_index == self.config_index
            ]
            replacement = healthy[0] if healthy else (
                allowed_for_index[0] if allowed_for_index else allowed[0]
            )
            log(
                f'startup skipped excluded outbound {selected.name} '
                f'[{selected.outbound_tag}]; selected {replacement.name} '
                f'[{replacement.outbound_tag}] instead'
            )
            selected = replacement

        if not healthy:
            return selected
        best = healthy[0]
        if self.same_outbound(selected, best):
            return selected

        selected_latency = self.candidate_latency_ms(selected)
        best_latency = self.candidate_latency_ms(best)
        if best_latency is None:
            return selected

        improvement = (
            selected_latency - best_latency
            if isinstance(selected_latency, int) else None
        )
        preferred_country = getattr(self, 'auto_switch_preferred_country', '')
        preferred_country_switch = bool(
            preferred_country
            and best.country_code == preferred_country
            and selected.country_code != preferred_country
        )
        if preferred_country_switch or selected_latency is None or (
            isinstance(improvement, int)
            and improvement >= self.auto_switch_min_ping_delta_ms
        ):
            previous_latency = f'{selected_latency} ms' if selected_latency is not None else 'unknown'
            if preferred_country_switch:
                log(
                    f'startup selected preferred-country outbound {best.name} '
                    f'[{preferred_country}] ({best_latency} ms) instead of '
                    f'{selected.name} ({previous_latency})'
                )
            else:
                log(
                    f'startup selected cached best outbound {best.name} ({best_latency} ms) '
                    f'instead of {selected.name} ({previous_latency})'
                )
            return best
        return selected

    def patch_inbounds(
        self,
        config: dict[str, Any],
        *,
        test_port: int | None = None,
        slot_tag: str | None = None,
    ) -> dict[str, Any]:
        result = copy.deepcopy(config)
        if test_port is not None:
            listen = '127.0.0.1'
            socks_tcp = test_port
            socks_udp = False
        else:
            if slot_tag not in SLOT_TAGS:
                raise ValueError('slot_tag is required for a runtime Xray configuration')
            slot = self.slots[slot_tag]
            listen = '0.0.0.0'
            socks_tcp = slot.socks_tcp
            socks_udp = slot.socks_udp

        result.setdefault('log', {})['loglevel'] = 'none' if test_port is not None else self.log_level
        socks_settings: dict[str, Any] = {
            'auth': 'noauth',
            'udp': socks_udp,
            'userLevel': 8,
        }
        if test_port is None and self.proxy_username and self.proxy_password:
            socks_settings['auth'] = 'password'
            socks_settings['accounts'] = [{'user': self.proxy_username, 'pass': self.proxy_password}]

        socks_inbound = {
            'tag': 'socks',
            'listen': listen,
            'port': socks_tcp,
            'protocol': 'socks',
            'settings': socks_settings,
            'sniffing': {
                'enabled': True,
                'destOverride': ['http', 'tls'],
                'routeOnly': False,
            },
        }
        if test_port is not None:
            result['inbounds'] = [socks_inbound]
            return result

        if self.override_inbounds:
            result['inbounds'] = [socks_inbound]
            return result

        patched: list[Any] = []
        found_socks = False
        for inbound in result.get('inbounds') or []:
            if not isinstance(inbound, dict):
                patched.append(inbound)
                continue
            item = copy.deepcopy(inbound)
            if item.get('protocol') == 'socks':
                found_socks = True
                item.update(socks_inbound)
            patched.append(item)
        if not found_socks:
            patched.append(socks_inbound)
        result['inbounds'] = patched
        return result

    def build_config(
        self,
        candidate: Candidate,
        *,
        test_port: int | None = None,
        slot_tag: str | None = None,
    ) -> dict[str, Any]:
        if candidate.source_index >= len(self.subscription):
            raise ValueError('candidate source config is no longer available')
        config = ensure_outbound_tags(self.subscription[candidate.source_index])
        outbounds = config.get('outbounds') or []
        if candidate.outbound_index >= len(outbounds) or not isinstance(outbounds[candidate.outbound_index], dict):
            raise ValueError('candidate outbound is no longer available')

        selected_tag = str(outbounds[candidate.outbound_index].get('tag') or candidate.outbound_tag)
        config = self.patch_inbounds(config, test_port=test_port, slot_tag=slot_tag)
        config = fix_routing_tags(config, self.auto_fix_tags)
        config = add_proxy_direct(config, self.auto_add_proxy_direct)

        routing = config.setdefault('routing', {})
        if not isinstance(routing, dict):
            routing = {}
            config['routing'] = routing
        rules = routing.setdefault('rules', [])
        if not isinstance(rules, list):
            rules = []
            routing['rules'] = rules
        inbound_tags = ['socks']
        rules.insert(0, {
            'type': 'field',
            'inboundTag': inbound_tags,
            'outboundTag': selected_tag,
        })
        validate_routing_tags(config, self.validate_tags)
        return config

    def xray_test(self, config_path: Path) -> tuple[bool, str]:
        result = subprocess.run(
            [XRAY_BIN, '-test', '-config', str(config_path)],
            capture_output=True,
            text=True,
            timeout=30,
        )
        output = '\n'.join(part.strip() for part in (result.stdout, result.stderr) if part.strip())
        bad_markers = (
            'Failed to start',
            'not all dependencies are resolved',
            'failed to decode config',
            'Failed to get format',
            'EOF',
        )
        ok = result.returncode == 0 and not any(marker in output for marker in bad_markers)
        return ok, output

    def prepare_slot_config(self, slot_tag: str, candidate: Candidate) -> tuple[Path, bool]:
        """Build and validate a slot config without interrupting the running Xray."""
        slot = self.slots[slot_tag]
        config = self.build_config(candidate, slot_tag=slot_tag)
        temp_path = slot.config_path.with_name(f'{slot.config_path.stem}.new.json')
        atomic_write_json(temp_path, config)
        ok, output = self.xray_test(temp_path)
        if not ok:
            temp_path.unlink(missing_ok=True)
            raise RuntimeError(output or 'xray config validation failed')
        old_bytes = slot.config_path.read_bytes() if slot.config_path.exists() else None
        new_bytes = temp_path.read_bytes()
        changed = old_bytes != new_bytes
        return temp_path, changed

    def install_prepared_slot_config(
        self,
        slot_tag: str,
        candidate: Candidate,
        temp_path: Path,
    ) -> None:
        slot = self.slots[slot_tag]
        os.replace(temp_path, slot.config_path)
        slot.candidate_id = candidate.id
        slot.candidate_name = candidate.name
        slot.candidate = candidate

    def write_slot_config(self, slot_tag: str, candidate: Candidate) -> bool:
        temp_path, changed = self.prepare_slot_config(slot_tag, candidate)
        self.install_prepared_slot_config(slot_tag, candidate, temp_path)
        return changed

    def runtime_config_differs(self, slot_tag: str, candidate: Candidate) -> bool:
        slot = self.slots[slot_tag]
        current = load_json(slot.config_path, {})
        if not isinstance(current, dict) or not current:
            return True
        expected = self.build_config(candidate, slot_tag=slot_tag)
        return current != expected

    def save_active_config(self, slot_tag: str, candidate: Candidate) -> None:
        slot = self.slots[slot_tag]
        if not slot.config_path.exists():
            raise RuntimeError(f'Active configuration for {slot_tag} is missing')
        # config.json and last_good must represent only a successfully activated
        # path, never a merely prepared standby candidate.
        shutil.copy2(slot.config_path, CONFIG_PATH)
        shutil.copy2(slot.config_path, LAST_GOOD_CONFIG_PATH)
        atomic_write_json(LAST_GOOD_META_PATH, {
            'candidate_id': candidate.id,
            'fingerprint': candidate.fingerprint,
            'source_index': candidate.source_index,
            'outbound_tag': candidate.outbound_tag,
            'name': candidate.name,
            'slot_tag': slot_tag,
            'saved_at': now_ts(),
        })

    def clone_slot_config(self, source_tag: str, target_tag: str) -> None:
        source = self.slots[source_tag]
        target = self.slots[target_tag]
        config = load_json(source.config_path, {})
        if not isinstance(config, dict) or not config:
            raise RuntimeError(f'Cannot clone missing configuration from {source_tag}')
        config = self.patch_inbounds(config, slot_tag=target_tag)
        temp_path = target.config_path.with_name(f'{target.config_path.stem}.new.json')
        atomic_write_json(temp_path, config)
        ok, output = self.xray_test(temp_path)
        if not ok:
            temp_path.unlink(missing_ok=True)
            raise RuntimeError(output or f'Cloned configuration for {target_tag} is invalid')
        os.replace(temp_path, target.config_path)
        target.candidate_id = source.candidate_id
        target.candidate_name = source.candidate_name
        target.candidate = source.candidate

    def write_runtime_config(self, candidate: Candidate) -> bool:
        return self.write_slot_config(self.active_slot_tag, candidate)

    def log_xray_output(self, slot_tag: str, process: subprocess.Popen[str]) -> None:
        assert process.stdout is not None
        for line in process.stdout:
            text = normalize_xray_log_line(line.rstrip('\n'))
            match = OUTBOUND_LOG_RE.search(text)
            if match:
                observed_tag = match.group(1)
                with self.lock:
                    slot = self.slots[slot_tag]
                    slot.observed_outbound_tag = observed_tag
                    slot.observed_outbound_at = now_ts()
            if self.disable_observatory and 'app/observatory/burst: error ping ' in text:
                continue
            prefixed = f'[{slot_tag}] {text}'
            append_ui_log(prefixed)
            print(prefixed, flush=True)

    def start_slot(self, slot_tag: str, candidate: Candidate | None = None) -> None:
        slot = self.slots[slot_tag]
        with self.lock:
            if slot.running():
                if candidate is not None and slot.candidate_id != candidate.id:
                    raise RuntimeError(
                        f'{slot_tag} is already running {slot.candidate_name or slot.candidate_id}'
                    )
                return
        if candidate is not None:
            self.write_slot_config(slot_tag, candidate)
        with self.lock:
            if slot.running():
                if candidate is not None and slot.candidate_id != candidate.id:
                    raise RuntimeError(f'{slot_tag} was started concurrently with another outbound')
                return
            if not slot.config_path.exists():
                raise RuntimeError(f'Configuration for {slot_tag} is missing')
            log(f'starting xray-core slot {slot_tag} on SOCKS {slot.socks_tcp}...')
            slot.intentional_stop = False
            slot.observed_outbound_tag = ''
            slot.observed_outbound_at = None
            process = subprocess.Popen(
                [XRAY_BIN, '-config', str(slot.config_path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            slot.process = process
            slot.started_at = now_ts()
            slot.log_thread = threading.Thread(
                target=self.log_xray_output,
                args=(slot_tag, process),
                daemon=True,
            )
            slot.log_thread.start()
            log(f'xray-core slot {slot_tag} pid: {process.pid}')

    def stop_slot(self, slot_tag: str) -> None:
        slot = self.slots[slot_tag]
        with self.lock:
            process = slot.process
            if not process or process.poll() is not None:
                slot.process = None
                slot.draining = False
                slot.drain_zero_since = None
                slot.drain_protect_until = None
                slot.drain_degraded_checks = 0
                slot.drain_last_latency_ms = None
                slot.drain_last_checked_at = None
                slot.drain_new_connections = 0
                slot.drain_stalled_connections = 0
                slot.drain_known_connection_ids.clear()
                slot.drain_connection_bytes.clear()
                slot.drain_idle_polls.clear()
                slot.drain_last_info_at = None
                slot.drain_last_info_connections = None
                return
            slot.intentional_stop = True
            log(f'stopping xray-core slot {slot_tag}...')
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        with self.lock:
            slot.process = None
            slot.draining = False
            slot.drain_started_at = None
            slot.drain_zero_since = None
            slot.drain_protect_until = None
            slot.drain_connections = 0
            slot.drain_tcp_connections = 0
            slot.drain_udp_connections = 0
            slot.drain_bytes = 0
            slot.drain_last_error = ''
            slot.drain_degraded_checks = 0
            slot.drain_last_latency_ms = None
            slot.drain_last_checked_at = None
            slot.drain_new_connections = 0
            slot.drain_stalled_connections = 0
            slot.drain_known_connection_ids.clear()
            slot.drain_connection_bytes.clear()
            slot.drain_idle_polls.clear()
            slot.drain_last_info_at = None
            slot.drain_last_info_connections = None

    def force_stop_draining_slot(self, slot_tag: str = '') -> str:
        with self.lock:
            targets = [slot_tag] if slot_tag else [
                tag for tag in SLOT_TAGS if self.slots[tag].draining
            ]
            if len(targets) != 1 or targets[0] not in SLOT_TAGS:
                raise ValueError('Дренируемый слот не найден')
            target = targets[0]
            slot = self.slots[target]
            if target == self.active_slot_tag:
                raise RuntimeError('Активный слот нельзя завершить принудительно')
            if not slot.draining:
                raise RuntimeError(f'{target} не находится в состоянии дренирования')
            connections = slot.drain_connections
        log(f'force-stopping drained slot {target} with {connections} tracked connections', error=True)
        self.stop_slot(target)
        return target

    def start_xray(self) -> None:
        candidate = self.candidate_by_id(self.active_candidate_id)
        if candidate is not None:
            self.start_initial_candidate(candidate, 'Xray start')
            return

        expected_slot = self.active_slot_tag if self.dual_slot_enabled else 'xray-a'
        if expected_slot not in SLOT_TAGS:
            expected_slot = 'xray-a'
        self.active_slot_tag = expected_slot
        self.start_slot(expected_slot)
        if not self.wait_for_port(
            self.slots[expected_slot].socks_tcp,
            self.slots[expected_slot].process,
            timeout=6.0,
        ):
            self.stop_slot(expected_slot)
            raise RuntimeError(
                f'{expected_slot} did not open SOCKS port {self.slots[expected_slot].socks_tcp}'
            )

        if self.selector_control_enabled:
            try:
                reported = self.selector_status()
                if reported != expected_slot:
                    self.switch_selector(expected_slot)
                    log(
                        f'last-good startup restored selector from {reported} to '
                        f'manager-expected {expected_slot}',
                        error=True,
                    )
                self.selector_reconciliation_pending = False
            except Exception as exc:
                self.selector_reconciliation_pending = True
                log(
                    f'Selector is unavailable during last-good start; manager keeps '
                    f'{expected_slot} as the expected slot: {exc}',
                    error=True,
                )
        self.save_state()

    def stop_xray(self) -> None:
        for slot_tag in SLOT_TAGS:
            self.stop_slot(slot_tag)

    def other_slot_tag(self, slot_tag: str) -> str:
        return 'xray-b' if slot_tag == 'xray-a' else 'xray-a'

    def validation_urls(self) -> list[str]:
        return [self.primary_test_url, self.secondary_test_url]

    def test_url_label(self, url: str) -> str:
        if url == getattr(self, 'primary_test_url', DEFAULT_PRIMARY_TEST_URL):
            return 'primary_test_url'
        if url == getattr(self, 'secondary_test_url', DEFAULT_SECONDARY_TEST_URL):
            return 'secondary_test_url'
        return 'test_url'

    def format_probe_results(self, results: Iterable[tuple[str, float]]) -> str:
        return ', '.join(
            f'{self.test_url_label(url)}={latency:.0f}ms'
            for url, latency in results
        )

    def probe_proxy_urls(
        self,
        host: str,
        port: int,
        timeout_seconds: int,
        *,
        auth: bool,
    ) -> tuple[bool, float | None, list[tuple[str, float]], str]:
        """Probe both configured endpoints in parallel and use the fastest success."""
        urls = self.validation_urls()
        successful: list[tuple[str, float]] = []
        errors: list[tuple[str, str]] = []
        futures: dict[Future[tuple[bool, float | None, str]], str] = {}
        with ThreadPoolExecutor(
            max_workers=len(urls),
            thread_name_prefix='xray-endpoint-probe',
        ) as executor:
            for url in urls:
                futures[executor.submit(
                    self.proxy_curl,
                    host,
                    port,
                    url,
                    timeout_seconds,
                    auth=auth,
                )] = url
            for future in as_completed(futures):
                url = futures[future]
                try:
                    success, latency_ms, error = future.result()
                except Exception as exc:
                    success, latency_ms, error = False, None, str(exc)
                if success and latency_ms is not None:
                    successful.append((url, latency_ms))
                else:
                    errors.append((url, error or 'request failed'))

        order = {url: index for index, url in enumerate(urls)}
        successful.sort(key=lambda item: order.get(item[0], len(order)))
        errors.sort(key=lambda item: order.get(item[0], len(order)))
        if not successful:
            details = '; '.join(
                f'{self.test_url_label(url)}: {error}' for url, error in errors
            )
            return False, None, [], details or 'both test endpoints failed'
        minimum = min(latency for _url, latency in successful)
        return True, minimum, successful, ''

    def probe_slot_health(
        self,
        slot_tag: str,
        *,
        enforce_latency_limit: bool = True,
    ) -> tuple[bool, float | None, list[tuple[str, float]], str]:
        slot = self.slots[slot_tag]
        with self.lock:
            if not slot.running():
                return False, None, [], f'{slot_tag} Xray process is not running'
            port = slot.socks_tcp

        success, minimum, results, error = self.probe_proxy_urls(
            '127.0.0.1',
            port,
            self.auto_check_timeout_seconds,
            auth=True,
        )
        if not success or minimum is None:
            return False, None, results, error
        if (
            enforce_latency_limit
            and self.auto_check_max_latency_ms > 0
            and minimum > self.auto_check_max_latency_ms
        ):
            checks = self.format_probe_results(results)
            return (
                False,
                minimum,
                results,
                f'latency threshold exceeded ({checks}; fastest {minimum:.0f}ms; '
                f'limit {self.auto_check_max_latency_ms}ms)',
            )
        return True, minimum, results, ''

    def validate_slot(
        self,
        slot_tag: str,
        *,
        enforce_latency_limit: bool = True,
    ) -> tuple[float, list[tuple[str, float]]]:
        slot = self.slots[slot_tag]
        if not self.wait_for_port(slot.socks_tcp, slot.process, timeout=6.0):
            raise RuntimeError(f'{slot_tag} did not open SOCKS port {slot.socks_tcp}')
        success, minimum, results, error = self.probe_slot_health(
            slot_tag,
            enforce_latency_limit=enforce_latency_limit,
        )
        if not success or minimum is None:
            raise RuntimeError(f'{slot_tag} validation failed: {error}')
        return minimum, results

    def start_initial_candidate(self, candidate: Candidate, reason: str) -> None:
        expected_slot = self.active_slot_tag if self.dual_slot_enabled else 'xray-a'
        if expected_slot not in SLOT_TAGS:
            expected_slot = 'xray-a'
        self.active_slot_tag = expected_slot
        started_slots: list[str] = []
        try:
            self.start_slot(expected_slot, candidate)
            started_slots.append(expected_slot)
            initial_latency, initial_checks = self.validate_slot(
                expected_slot,
                enforce_latency_limit=False,
            )
            log(
                f'initial {expected_slot} validation: '
                + self.format_probe_results(initial_checks)
                + f'; fastest={initial_latency:.0f}ms'
            )
            if (
                self.auto_check_max_latency_ms > 0
                and initial_latency > self.auto_check_max_latency_ms
            ):
                log(
                    f'initial active slot latency {initial_latency:.0f}ms exceeds '
                    f'{self.auto_check_max_latency_ms}ms; automatic failover will be attempted',
                    error=True,
                )

            if self.selector_control_enabled:
                try:
                    reported = self.selector_status()
                    if reported != expected_slot:
                        self.switch_selector(expected_slot)
                        log(
                            f'startup restored selector from {reported} to manager-expected '
                            f'{expected_slot}',
                            error=True,
                        )
                    self.selector_reconciliation_pending = False
                    with self.lock:
                        self.selector_state.update({
                            'available': True,
                            'current': expected_slot,
                            'error': '',
                        })
                except Exception as exc:
                    self.selector_reconciliation_pending = True
                    log(
                        f'Selector is unavailable during startup; manager keeps '
                        f'{expected_slot} as the expected slot: {exc}',
                        error=True,
                    )
                    with self.lock:
                        self.selector_state.update({
                            'available': False,
                            'error': str(exc),
                        })

            self.active_candidate_id = candidate.id
            self.state['last_switch_at'] = now_ts()
            self.state['last_switch_reason'] = reason
            self.state['auto_check_failures'] = 0
            self.state['auto_check_last_error'] = ''
            self.latencies[candidate.id] = {
                'status': 'ok',
                'latency_ms': int(round(initial_latency)),
                'checked_at': now_ts(),
                'error': '',
            }
            try:
                self.save_latencies()
                self.save_state()
            except Exception as exc:
                log(f'could not persist initial active state: {exc}', error=True)
            try:
                self.save_active_config(expected_slot, candidate)
            except Exception as exc:
                log(f'could not save last-good active config: {exc}', error=True)
            log(f'active outbound: {candidate.name} [{candidate.outbound_tag}] via {expected_slot}')
        except Exception:
            for slot_tag in reversed(started_slots):
                self.stop_slot(slot_tag)
            raise

    def switch_candidate_blue_green(
        self,
        candidate: Candidate,
        reason: str,
        *,
        force_reload: bool = False,
        preempt_draining: bool = False,
        emergency_failover: bool = False,
    ) -> None:
        if not self.dual_slot_enabled:
            raise RuntimeError('Blue-green switching is disabled in single-slot mode')
        if not self.selector_control_enabled:
            raise RuntimeError('Blue-green переключение требует доступного внешнего selector')
        try:
            reported_selector = self.selector_status()
        except Exception as exc:
            raise RuntimeError(
                f'Selector API недоступен; переключение не начато: {exc}'
            ) from exc
        if self.selector_reconciliation_pending:
            self.reconcile_startup_selector(reported_selector)
        if not self.switch_lock.acquire(blocking=False):
            raise RuntimeError('Переключение outbound уже выполняется')
        standby_tag = ''
        old_slot_tag = ''
        selector_switched = False
        state_committed = False
        try:
            current_selector = self.selector_status()
            with self.lock:
                expected_selector = self.active_slot_tag
                expected_running = self.slots[expected_selector].running()
            if current_selector != expected_selector:
                if not expected_running:
                    raise RuntimeError(
                        f'Активный слот {expected_selector} не запущен, а selector указывает '
                        f'на {current_selector}'
                    )
                self.switch_selector(expected_selector)
                log(
                    f'Selector был на {current_selector}; перед переключением '
                    f'восстановлен {expected_selector}',
                    error=True,
                )
            with self.lock:
                self.state['jobs']['switch'].update({
                    'running': True,
                    'message': f'Подготовка {candidate.name}...',
                })
                self.save_state()
                active_slot = self.slots[self.active_slot_tag]
                active_candidate = active_slot.candidate or self.candidate_by_id(self.active_candidate_id)
                if active_slot.running() and self.same_outbound(candidate, active_candidate):
                    return
                old_slot_tag = self.active_slot_tag
                standby_tag = self.other_slot_tag(old_slot_tag)
                standby = self.slots[standby_tag]
                stop_standby = False
                standby_needs_rebuild = (
                    standby.running()
                    and (
                        standby.draining
                        or not self.same_outbound(candidate, standby.candidate)
                        or force_reload
                    )
                )
                if standby_needs_rebuild:
                    if standby.draining and not preempt_draining:
                        raise RuntimeError(
                            f'{standby_tag} ещё обслуживает старые соединения '
                            f'({standby.drain_connections}); автоматическое переключение отложено'
                        )
                    stop_standby = True

            if stop_standby:
                self.stop_slot(standby_tag)
            standby = self.slots[standby_tag]
            if not standby.running():
                self.start_slot(standby_tag, candidate)
            elif not self.same_outbound(candidate, standby.candidate):
                raise RuntimeError(f'{standby_tag} занят другим outbound')

            with self.lock:
                self.state['jobs']['switch']['message'] = f'Проверка {candidate.name}...'
                self.save_state()
            measured_latency, checks = self.validate_slot(standby_tag)
            log(
                f'{standby_tag} passed pre-switch validation: ' +
                self.format_probe_results(checks)
                + f'; fastest={measured_latency:.0f}ms'
            )

            with self.lock:
                self.state['jobs']['switch']['message'] = 'Защита дренируемого слота...'
                self.save_state()
                old_slot_running = self.slots[old_slot_tag].running()
            with self.lock:
                self.state['jobs']['switch']['message'] = 'Переключение selector...'
                self.save_state()
            self.switch_selector(standby_tag)
            selector_switched = True

            switched_at = now_ts()
            rollback_candidate: Candidate | None = None
            generation = 0
            with self.lock:
                old_slot = self.slots[old_slot_tag]
                rollback_candidate = old_slot.candidate or self.candidate_by_id(old_slot.candidate_id)
                self.active_slot_tag = standby_tag
                self.active_candidate_id = candidate.id
                # From this point the in-memory routing state agrees with the
                # already switched selector, so exception cleanup must never stop
                # the new active process.
                state_committed = True
                self.switch_generation += 1
                generation = self.switch_generation
                standby.draining = False
                standby.drain_started_at = None
                standby.drain_zero_since = None
                standby.drain_protect_until = None
                standby.drain_degraded_checks = 0
                standby.drain_last_latency_ms = None
                standby.drain_last_checked_at = None
                standby.drain_new_connections = 0
                standby.drain_stalled_connections = 0
                standby.drain_known_connection_ids.clear()
                standby.drain_connection_bytes.clear()
                standby.drain_idle_polls.clear()
                old_slot.draining = old_slot.running()
                old_slot.drain_started_at = switched_at if old_slot.draining else None
                old_slot.drain_zero_since = None
                old_slot.drain_protect_until = (
                    switched_at + POST_SWITCH_WATCH_SECONDS if old_slot.draining else None
                )
                old_slot.drain_connections = 0
                old_slot.drain_bytes = 0
                old_slot.drain_last_error = ''
                old_slot.drain_degraded_checks = 0
                old_slot.drain_last_latency_ms = None
                old_slot.drain_last_checked_at = None
                old_slot.drain_new_connections = 0
                old_slot.drain_stalled_connections = 0
                old_slot.drain_known_connection_ids.clear()
                old_slot.drain_connection_bytes.clear()
                old_slot.drain_idle_polls.clear()
                old_slot.drain_last_info_at = None
                old_slot.drain_last_info_connections = None
                self.state['last_switch_at'] = switched_at
                self.state['last_switch_reason'] = reason
                self.state['auto_check_failures'] = 0
                self.state['auto_check_last_error'] = ''
                self.latencies[candidate.id] = {
                    'status': 'ok',
                    'latency_ms': int(round(measured_latency)),
                    'checked_at': switched_at,
                    'error': '',
                }
                self.save_latencies()
                self.save_state()
            try:
                self.save_active_config(standby_tag, candidate)
            except Exception as exc:
                log(f'could not save last-good active config: {exc}', error=True)
            log(
                f'active outbound: {candidate.name} [{candidate.outbound_tag}] via {standby_tag}; '
                f'{old_slot_tag} is draining'
            )
            if self.slots[old_slot_tag].draining:
                self.capture_drain_connection_baseline(old_slot_tag)
            if rollback_candidate is not None:
                threading.Thread(
                    target=self.post_switch_watch,
                    args=(
                        generation,
                        standby_tag,
                        old_slot_tag,
                        rollback_candidate,
                        emergency_failover,
                    ),
                    daemon=True,
                ).start()
        except Exception as exc:
            if state_committed:
                log(
                    f'blue-green switch completed, but post-switch bookkeeping failed: {exc}',
                    error=True,
                )
                return
            safe_to_stop_standby = not selector_switched
            if selector_switched and not state_committed and old_slot_tag:
                try:
                    self.switch_selector(old_slot_tag)
                    safe_to_stop_standby = True
                    log(
                        f'switch transaction failed after selector update; '
                        f'selector restored to {old_slot_tag}',
                        error=True,
                    )
                except Exception as rollback_exc:
                    # Do not terminate the process that may already receive new
                    # connections. Reflect the safest known state and leave both
                    # slots running for manual recovery.
                    safe_to_stop_standby = False
                    with self.lock:
                        self.active_slot_tag = standby_tag
                        self.active_candidate_id = candidate.id
                        self.switch_generation += 1
                        old_slot = self.slots[old_slot_tag]
                        old_slot.draining = old_slot.running()
                        old_slot.drain_started_at = now_ts() if old_slot.draining else None
                        old_slot.drain_protect_until = (
                            now_ts() + POST_SWITCH_WATCH_SECONDS if old_slot.draining else None
                        )
                        old_slot.drain_degraded_checks = 0
                        old_slot.drain_last_latency_ms = None
                        old_slot.drain_last_checked_at = None
                        self.save_state()
                    log(
                        f'selector rollback to {old_slot_tag} failed after partial switch: '
                        f'{rollback_exc}; keeping {standby_tag} active and both slots running',
                        error=True,
                    )
            if safe_to_stop_standby and standby_tag and standby_tag != self.active_slot_tag:
                standby = self.slots[standby_tag]
                if standby.running() and not standby.draining:
                    self.stop_slot(standby_tag)
            raise
        finally:
            try:
                with self.lock:
                    self.state['jobs']['switch'].update({'running': False, 'message': ''})
                    self.save_state()
            except Exception as exc:
                log(f'could not persist switch job state: {exc}', error=True)
            self.switch_lock.release()

    def rollback_to_running_slot(
        self,
        generation: int,
        failed_slot_tag: str,
        rollback_slot_tag: str,
        rollback_candidate: Candidate,
        reason: str,
    ) -> bool:
        if failed_slot_tag == rollback_slot_tag:
            raise ValueError('Rollback slot must differ from the failed active slot')
        if not self.switch_lock.acquire(blocking=False):
            raise RuntimeError('Another outbound switch is already running')
        selector_switched = False
        state_committed = False
        try:
            with self.lock:
                if (
                    generation != self.switch_generation
                    or self.active_slot_tag != failed_slot_tag
                ):
                    return False
                rollback_slot = self.slots[rollback_slot_tag]
                if not rollback_slot.running():
                    raise RuntimeError(f'Rollback slot {rollback_slot_tag} is no longer running')

            with self.lock:
                failed_running_before_commit = self.slots[failed_slot_tag].running()
            self.switch_selector(rollback_slot_tag)
            selector_switched = True
            switched_at = now_ts()
            with self.lock:
                failed_slot = self.slots[failed_slot_tag]
                rollback_slot = self.slots[rollback_slot_tag]
                if not rollback_slot.running():
                    raise RuntimeError(
                        f'Rollback slot {rollback_slot_tag} stopped during selector update'
                    )
                self.active_slot_tag = rollback_slot_tag
                self.active_candidate_id = rollback_candidate.id
                rollback_slot.candidate_id = rollback_candidate.id
                rollback_slot.candidate_name = rollback_candidate.name
                rollback_slot.candidate = rollback_candidate
                rollback_slot.draining = False
                rollback_slot.drain_started_at = None
                rollback_slot.drain_zero_since = None
                rollback_slot.drain_protect_until = None
                rollback_slot.drain_last_error = ''
                rollback_slot.drain_degraded_checks = 0
                rollback_slot.drain_last_latency_ms = None
                rollback_slot.drain_last_checked_at = None
                rollback_slot.drain_new_connections = 0
                rollback_slot.drain_stalled_connections = 0
                rollback_slot.drain_known_connection_ids.clear()
                rollback_slot.drain_connection_bytes.clear()
                rollback_slot.drain_idle_polls.clear()

                failed_slot.draining = failed_slot.running()
                failed_slot.drain_started_at = switched_at if failed_slot.draining else None
                failed_slot.drain_zero_since = None
                failed_slot.drain_protect_until = (
                    switched_at + POST_SWITCH_WATCH_SECONDS if failed_slot.draining else None
                )
                failed_slot.drain_connections = 0
                failed_slot.drain_tcp_connections = 0
                failed_slot.drain_udp_connections = 0
                failed_slot.drain_bytes = 0
                failed_slot.drain_last_error = ''
                failed_slot.drain_degraded_checks = 0
                failed_slot.drain_last_latency_ms = None
                failed_slot.drain_last_checked_at = None
                failed_slot.drain_new_connections = 0
                failed_slot.drain_stalled_connections = 0
                failed_slot.drain_known_connection_ids.clear()
                failed_slot.drain_connection_bytes.clear()
                failed_slot.drain_idle_polls.clear()
                failed_slot.drain_last_info_at = None
                failed_slot.drain_last_info_connections = None

                self.switch_generation += 1
                self.state['last_switch_at'] = switched_at
                self.state['last_switch_reason'] = reason
                self.state['auto_check_failures'] = 0
                self.state['auto_check_last_error'] = ''
                state_committed = True
                self.save_state()
            try:
                self.save_active_config(rollback_slot_tag, rollback_candidate)
            except Exception as exc:
                log(f'could not save last-good rollback config: {exc}', error=True)
            log(
                f'rolled back selector to {rollback_slot_tag} ({rollback_candidate.name}); '
                f'{failed_slot_tag} is draining',
                error=True,
            )
            if self.slots[failed_slot_tag].draining:
                self.capture_drain_connection_baseline(failed_slot_tag)
            return True
        except Exception as exc:
            if state_committed:
                log(f'rollback completed, but bookkeeping failed: {exc}', error=True)
                return True
            if selector_switched:
                try:
                    with self.lock:
                        failed_running = self.slots[failed_slot_tag].running()
                    if failed_running:
                        self.switch_selector(failed_slot_tag)
                except Exception as restore_exc:
                    log(
                        f'could not restore selector to {failed_slot_tag} after rollback failure: '
                        f'{restore_exc}',
                        error=True,
                    )
            raise
        finally:
            self.switch_lock.release()

    def post_switch_watch(
        self,
        generation: int,
        active_slot_tag: str,
        rollback_slot_tag: str,
        rollback_candidate: Candidate,
        force_disconnect_rollback: bool = False,
    ) -> None:
        failures = 0
        successes = 0
        deadline = time.monotonic() + POST_SWITCH_WATCH_SECONDS
        while time.monotonic() < deadline and not self.stop_event.wait(5):
            with self.lock:
                if generation != self.switch_generation or self.active_slot_tag != active_slot_tag:
                    return
                slot = self.slots[active_slot_tag]
                if not slot.running():
                    failures += 1
                    error = 'active Xray slot stopped'
                else:
                    error = ''
            if not error:
                success, _latency_ms, _checks, error = self.probe_slot_health(active_slot_tag)
                if success:
                    failures = 0
                    successes += 1
                else:
                    failures += 1
                    successes = 0
            else:
                successes = 0

            if force_disconnect_rollback and successes >= 2:
                with self.lock:
                    still_current = (
                        generation == self.switch_generation
                        and self.active_slot_tag == active_slot_tag
                    )
                    rollback_slot = self.slots[rollback_slot_tag]
                    can_stop = (
                        still_current
                        and rollback_slot.running()
                        and rollback_slot.draining
                    )
                    connections = rollback_slot.drain_connections
                if can_stop:
                    log(
                        f'emergency failover confirmed on {active_slot_tag}; force-stopping '
                        f'degraded {rollback_slot_tag} with {connections} tracked connections',
                        error=True,
                    )
                    try:
                        self.force_stop_draining_slot(rollback_slot_tag)
                    except Exception as exc:
                        log(f'could not force-stop degraded slot {rollback_slot_tag}: {exc}', error=True)
                return

            if failures < 2:
                continue
            log(
                f'post-switch validation failed twice ({error}); rolling back to '
                f'{rollback_candidate.name}',
                error=True,
            )
            try:
                self.rollback_to_running_slot(
                    generation,
                    active_slot_tag,
                    rollback_slot_tag,
                    rollback_candidate,
                    'automatic rollback after post-switch validation errors',
                )
            except Exception as exc:
                log(f'automatic rollback failed: {exc}', error=True)
            return

    def switch_candidate_single_slot(
        self,
        candidate: Candidate,
        reason: str,
        *,
        force_reload: bool = False,
    ) -> None:
        """Restart xray-a in place and intentionally drop all existing flows."""
        if not self.switch_lock.acquire(blocking=False):
            raise RuntimeError('Переключение outbound уже выполняется')
        slot_tag = 'xray-a'
        old_candidate: Candidate | None = None
        old_candidate_id = ''
        old_config: bytes | None = None
        prepared_config: Path | None = None
        try:
            with self.lock:
                self.state['jobs']['switch'].update({
                    'running': True,
                    'message': f'Однослотовое переключение на {candidate.name}...',
                })
                self.save_state()
                slot = self.slots[slot_tag]
                old_candidate = slot.candidate or self.candidate_by_id(self.active_candidate_id)
                old_candidate_id = self.active_candidate_id
                if (
                    slot.running()
                    and self.same_outbound(candidate, old_candidate)
                    and not force_reload
                ):
                    return
                if slot.config_path.exists():
                    old_config = slot.config_path.read_bytes()

            # Validate the replacement while the current Xray is still
            # serving traffic. The unavoidable outage then contains only the
            # process stop/start and port readiness, not config generation or
            # `xray -test`.
            prepared_config, _changed = self.prepare_slot_config(slot_tag, candidate)

            if self.selector_control_enabled:
                try:
                    reported = self.selector_status()
                    if reported != slot_tag:
                        self.switch_selector(slot_tag)
                        log(
                            f'single-slot mode restored selector from {reported} to {slot_tag}',
                            error=True,
                        )
                except Exception as exc:
                    raise RuntimeError(
                        f'Selector API недоступен; однослотовое переключение не начато: {exc}'
                    ) from exc

            log(
                f'single-slot switch is stopping {slot_tag}; all existing TCP/UDP '
                f'connections will be dropped before activating {candidate.name}'
            )
            self.stop_slot(slot_tag)
            self.install_prepared_slot_config(slot_tag, candidate, prepared_config)
            prepared_config = None
            self.start_slot(slot_tag)
            measured_latency, checks = self.validate_slot(slot_tag)
            if self.selector_control_enabled:
                self.switch_selector(slot_tag)
            switched_at = now_ts()
            with self.lock:
                self.active_slot_tag = slot_tag
                self.active_candidate_id = candidate.id
                self.switch_generation += 1
                slot = self.slots[slot_tag]
                slot.draining = False
                self.state['last_switch_at'] = switched_at
                self.state['last_switch_reason'] = reason
                self.state['auto_check_failures'] = 0
                self.state['auto_check_last_error'] = ''
                self.latencies[candidate.id] = {
                    'status': 'ok',
                    'latency_ms': int(round(measured_latency)),
                    'checked_at': switched_at,
                    'error': '',
                }
                self.save_latencies()
                self.save_state()
            self.save_active_config(slot_tag, candidate)
            log(
                f'active outbound: {candidate.name} [{candidate.outbound_tag}] via {slot_tag}; '
                f'single-slot validation: '
                + self.format_probe_results(checks)
                + f'; fastest={measured_latency:.0f}ms'
            )
        except Exception:
            if prepared_config is not None:
                prepared_config.unlink(missing_ok=True)
            try:
                self.stop_slot(slot_tag)
                if old_candidate is not None:
                    if old_config is not None:
                        self.slots[slot_tag].config_path.write_bytes(old_config)
                        self.slots[slot_tag].candidate = old_candidate
                        self.slots[slot_tag].candidate_id = old_candidate.id
                        self.slots[slot_tag].candidate_name = old_candidate.name
                        self.start_slot(slot_tag)
                    else:
                        self.start_slot(slot_tag, old_candidate)
                    self.validate_slot(slot_tag, enforce_latency_limit=False)
                    if self.selector_control_enabled:
                        self.switch_selector(slot_tag)
                    with self.lock:
                        self.active_slot_tag = slot_tag
                        self.active_candidate_id = old_candidate_id or old_candidate.id
                        self.save_state()
                    log(
                        f'single-slot switch failed; restored {old_candidate.name} on {slot_tag}',
                        error=True,
                    )
            except Exception as rollback_exc:
                log(f'single-slot rollback failed: {rollback_exc}', error=True)
            raise
        finally:
            try:
                with self.lock:
                    self.state['jobs']['switch'].update({'running': False, 'message': ''})
                    self.save_state()
            except Exception as exc:
                log(f'could not persist switch job state: {exc}', error=True)
            self.switch_lock.release()

    def restart_xray_for(
        self,
        candidate: Candidate,
        reason: str,
        *,
        force_reload: bool = False,
        preempt_draining: bool = False,
        emergency_failover: bool = False,
    ) -> None:
        with self.lock:
            active_running = self.slots[self.active_slot_tag].running()
        if not active_running:
            self.start_initial_candidate(candidate, reason)
            return
        if not self.dual_slot_enabled:
            self.switch_candidate_single_slot(
                candidate,
                reason,
                force_reload=force_reload,
            )
            return
        self.switch_candidate_blue_green(
            candidate,
            reason,
            force_reload=force_reload,
            preempt_draining=preempt_draining,
            emergency_failover=emergency_failover,
        )

    def local_tcp_connection_count(self, port: int) -> int:
        target = f'{port:04X}'
        count = 0
        for path in (Path('/proc/net/tcp'), Path('/proc/net/tcp6')):
            try:
                lines = path.read_text(encoding='utf-8').splitlines()[1:]
            except OSError:
                continue
            for line in lines:
                fields = line.split()
                if len(fields) < 4:
                    continue
                local = fields[1]
                state = fields[3]
                if ':' not in local or local.rsplit(':', 1)[1].upper() != target:
                    continue
                # TIME_WAIT and CLOSED no longer belong to a live Xray flow and
                # must not keep a drained process running. Other states still
                # represent a connection being established, served, or closed.
                if state not in {'06', '07', '0A'}:
                    count += 1
        return count

    def drain_monitor_loop(self) -> None:
        while not self.stop_event.wait(self.drain_poll_interval_seconds):
            with self.lock:
                draining_tags = [tag for tag in SLOT_TAGS if self.slots[tag].draining]
            if not draining_tags:
                continue
            try:
                connections = self.selector_connections()
                with self.lock:
                    self.selector_state.update({
                        'connections_supported': True,
                        'error': '',
                    })
            except Exception as exc:
                with self.lock:
                    self.selector_state.update({
                        'connections_supported': False,
                        'error': str(exc),
                    })
                    for tag in draining_tags:
                        self.slots[tag].drain_last_error = str(exc)
                continue

            for slot_tag in draining_tags:
                slot = self.slots[slot_tag]
                slot_connections = self.connections_for_slot(connections, slot_tag)
                selector_count, _tcp_count, udp_count, selector_bytes = self.connection_slot_stats(
                    connections, slot_tag
                )
                direct_tcp_count = self.local_tcp_connection_count(slot.socks_tcp)
                # /proc/net/tcp already contains every TCP connection accepted
                # by this SOCKS slot, including connections created by the
                # selector. Add only logical UDP sessions from the selector API
                # to avoid counting selector TCP connections twice.
                total_connections = direct_tcp_count + udp_count
                total_bytes = selector_bytes
                current_ids = {
                    self.connection_id(item) for item in slot_connections
                    if self.connection_id(item)
                }
                current_byte_map = {
                    self.connection_id(item): self.connection_total_bytes(item)
                    for item in slot_connections if self.connection_id(item)
                }
                with self.lock:
                    known_ids = set(slot.drain_known_connection_ids)
                    previous_byte_map = dict(slot.drain_connection_bytes)
                    previous_idle = dict(slot.drain_idle_polls)
                new_ids = current_ids - known_ids
                if new_ids:
                    new_items = [
                        item for item in slot_connections
                        if self.connection_id(item) in new_ids
                    ]
                    with self.lock:
                        slot.drain_new_connections += len(new_ids)
                        slot.drain_known_connection_ids.update(new_ids)
                    log(
                        f'WARNING: {slot_tag} accepted {len(new_ids)} new selector connection(s) '
                        f'while draining; expected active slot is {self.active_slot_tag}',
                        error=True,
                    )
                    for item in new_items[:10]:
                        log(
                            f'{slot_tag} new connection while draining: '
                            f'{self.connection_summary(item)}',
                            error=True,
                        )

                idle_polls: dict[str, int] = {}
                for connection_id in current_ids:
                    current_bytes = current_byte_map.get(connection_id, 0)
                    if previous_byte_map.get(connection_id) == current_bytes:
                        idle_polls[connection_id] = previous_idle.get(connection_id, 0) + 1
                    else:
                        idle_polls[connection_id] = 0
                stalled_ids = {
                    connection_id for connection_id, polls in idle_polls.items()
                    if polls * self.drain_poll_interval_seconds >= 10
                }

                stop_now = False
                info_due = False
                current_time = now_ts()
                with self.lock:
                    previous_bytes = slot.drain_bytes
                    slot.drain_connections = total_connections
                    slot.drain_tcp_connections = direct_tcp_count
                    slot.drain_udp_connections = udp_count
                    slot.drain_bytes = total_bytes
                    slot.drain_last_error = ''
                    slot.drain_connection_bytes = current_byte_map
                    slot.drain_idle_polls = idle_polls
                    slot.drain_stalled_connections = len(stalled_ids)
                    slot.drain_known_connection_ids.update(current_ids)
                    timeout_reached = bool(
                        self.drain_timeout_minutes > 0
                        and slot.drain_started_at
                        and current_time - slot.drain_started_at >= self.drain_timeout_minutes * 60
                    )
                    if timeout_reached:
                        stop_now = True
                    elif total_connections == 0 and total_bytes == previous_bytes:
                        if slot.drain_zero_since is None:
                            slot.drain_zero_since = current_time
                        elif (
                            current_time - slot.drain_zero_since >= self.drain_quiet_seconds
                            and current_time >= int(slot.drain_protect_until or 0)
                        ):
                            stop_now = True
                    else:
                        slot.drain_zero_since = None
                    info_due = (
                        slot.drain_last_info_at is None
                        or current_time - slot.drain_last_info_at >= 30
                        or slot.drain_last_info_connections != total_connections
                        or total_connections == 0
                    )
                    if info_due:
                        slot.drain_last_info_at = current_time
                        slot.drain_last_info_connections = total_connections

                if info_due:
                    log(
                        f'{slot_tag} draining: tracked={total_connections} '
                        f'(tcp={direct_tcp_count}, udp={udp_count}, selector={selector_count}), '
                        f'bytes={total_bytes}, stalled>=10s={len(stalled_ids)}, '
                        f'new-after-switch={slot.drain_new_connections}'
                    )
                if self.log_level == 'debug':
                    for item in slot_connections[:10]:
                        marker = ' stalled' if self.connection_id(item) in stalled_ids else ''
                        self.debug_log(
                            f'{slot_tag} draining connection{marker}: {self.connection_summary(item)}'
                        )

                if stop_now:
                    if self.drain_timeout_minutes > 0 and slot.drain_started_at and (
                        now_ts() - slot.drain_started_at >= self.drain_timeout_minutes * 60
                    ):
                        log(
                            f'{slot_tag} drain timeout of {self.drain_timeout_minutes} min reached; '
                            f'forcing slot stop with {slot.drain_connections} tracked connections',
                            error=True,
                        )
                    else:
                        log(
                            f'{slot_tag} has no tracked connections or traffic for '
                            f'{self.drain_quiet_seconds}s; stopping drained slot'
                        )
                    self.stop_slot(slot_tag)

    def resolve_last_good_candidate(self) -> Candidate | None:
        metadata = load_json(LAST_GOOD_META_PATH, {})
        if isinstance(metadata, dict):
            fingerprint = str(metadata.get('fingerprint') or '')
            if fingerprint:
                match = next((item for item in self.candidates if item.fingerprint == fingerprint), None)
                if match:
                    return match
            candidate_id = str(metadata.get('candidate_id') or '')
            if candidate_id:
                match = self.candidate_by_id(candidate_id)
                if match:
                    return match
            outbound_tag = str(metadata.get('outbound_tag') or '')
            source_index = metadata.get('source_index')
            if outbound_tag:
                match = self.candidate_by_tag(
                    outbound_tag,
                    int(source_index) if isinstance(source_index, int) else None,
                )
                if match:
                    return match

        config = load_json(LAST_GOOD_CONFIG_PATH, {})
        if isinstance(config, dict):
            routing = config.get('routing') if isinstance(config.get('routing'), dict) else {}
            rules = routing.get('rules') if isinstance(routing.get('rules'), list) else []
            if rules and isinstance(rules[0], dict):
                outbound_tag = str(rules[0].get('outboundTag') or '')
                if outbound_tag:
                    return self.candidate_by_tag(outbound_tag)
        return None

    def restore_last_good(self) -> tuple[bool, Candidate | None]:
        if not LAST_GOOD_CONFIG_PATH.exists():
            return False, None
        metadata = load_json(LAST_GOOD_META_PATH, {})
        saved_slot = (
            str(metadata.get('slot_tag') or self.active_slot_tag)
            if isinstance(metadata, dict) else self.active_slot_tag
        )
        if not self.dual_slot_enabled:
            saved_slot = 'xray-a'
        elif saved_slot not in SLOT_TAGS:
            saved_slot = 'xray-a'

        config = load_json(LAST_GOOD_CONFIG_PATH, {})
        if not isinstance(config, dict) or not config:
            log('last good config is empty or malformed', error=True)
            return False, None
        # A 0.4.x last-good file still exposes HTTP directly on 10809. Always
        # rewrite managed inbounds for the selected slot before validating it,
        # so emergency recovery also works after the blue-green port migration.
        config = self.patch_inbounds(config, slot_tag=saved_slot)
        temp_path = self.slots[saved_slot].config_path.with_name(
            f'{self.slots[saved_slot].config_path.stem}.restore.json'
        )
        atomic_write_json(temp_path, config)
        ok, output = self.xray_test(temp_path)
        if not ok:
            temp_path.unlink(missing_ok=True)
            log(f'last good config is invalid after slot migration: {output}', error=True)
            return False, None

        self.active_slot_tag = saved_slot
        os.replace(temp_path, self.slots[saved_slot].config_path)
        shutil.copy2(self.slots[saved_slot].config_path, CONFIG_PATH)
        shutil.copy2(self.slots[saved_slot].config_path, LAST_GOOD_CONFIG_PATH)
        if not isinstance(metadata, dict):
            metadata = {}
        metadata['slot_tag'] = saved_slot
        metadata['migrated_at'] = now_ts()
        atomic_write_json(LAST_GOOD_META_PATH, metadata)

        candidate = self.resolve_last_good_candidate()
        if candidate:
            self.slots[saved_slot].candidate_id = candidate.id
            self.slots[saved_slot].candidate_name = candidate.name
            self.slots[saved_slot].candidate = candidate
        return True, candidate

    def refresh_subscription_sync(self, *, initial: bool = False) -> None:
        attempt_at = now_ts()
        with self.lock:
            self.state['subscription_last_attempt_at'] = attempt_at
            self.save_state()
            old_subscription = self.subscription
            old_candidates = self.candidates
            old_active_id = self.active_candidate_id
            old_active_slot_tag = self.active_slot_tag
            old_active_candidate = (
                self.slots[old_active_slot_tag].candidate
                or self.candidate_by_id(old_active_id)
            )

        downloaded = False
        try:
            configs = self.download_subscription()
            downloaded = True
            download_error = ''
            with self.lock:
                self.state['subscription_consecutive_failures'] = 0
        except Exception as exc:
            download_error = str(exc)
            with self.lock:
                self.state['subscription_consecutive_failures'] = int(
                    self.state.get('subscription_consecutive_failures') or 0
                ) + 1
                self.save_state()
            configs = self.load_cached_subscription()
            if not configs:
                with self.lock:
                    self.state['subscription_error'] = download_error
                    self.state['subscription_last_error_at'] = now_ts()
                    self.save_state()
                raise
            log(
                f'subscription update failed; using cached subscription: {download_error}',
                error=True,
            )

        try:
            candidates = self.extract_candidates(configs)
            if not candidates:
                raise RuntimeError('No usable proxy outbounds were found in the subscription.')

            with self.lock:
                self.subscription = configs
                self.candidates = candidates
                active_slot = self.slots[self.active_slot_tag]
                active_running = active_slot.running()

                selected: Candidate | None = None
                if old_active_candidate is not None:
                    selected = next(
                        (item for item in candidates if item.id == old_active_candidate.id),
                        None,
                    )
                    if selected is None:
                        selected = next(
                            (
                                item for item in candidates
                                if item.fingerprint == old_active_candidate.fingerprint
                            ),
                            None,
                        )
                    if selected is None and old_active_candidate.name:
                        name_matches = [
                            item for item in candidates if item.name == old_active_candidate.name
                        ]
                        if len(name_matches) == 1:
                            selected = name_matches[0]
                if initial:
                    selected = self.choose_initial_candidate(selected)
                elif selected is None and not active_running:
                    selected = self.choose_initial_candidate()

            if initial or not active_running:
                if selected is None:
                    raise RuntimeError('Не удалось выбрать outbound для запуска Xray.')
                self.restart_xray_for(
                    selected,
                    'initial start' if initial else 'start after subscription refresh',
                )
            else:
                with self.lock:
                    active_slot = self.slots[self.active_slot_tag]
                    if selected is not None:
                        active_slot.candidate = selected
                        active_slot.candidate_id = selected.id
                        active_slot.candidate_name = selected.name
                        self.active_candidate_id = selected.id
                    else:
                        # Keep the currently running configuration intact even if
                        # it disappeared from the refreshed subscription.
                        self.active_candidate_id = old_active_id
                    self.rebind_slot_candidates()
                    self.save_state()
                if selected is not None and self.runtime_config_differs(
                    self.active_slot_tag, selected
                ):
                    log(
                        'subscription changed the active outbound configuration; '
                        'the running Xray processes were preserved and the new '
                        'configuration will be applied on the next explicit selection'
                    )

        except Exception:
            with self.lock:
                self.subscription = old_subscription
                self.candidates = old_candidates
                self.active_candidate_id = old_active_id
                self.active_slot_tag = old_active_slot_tag
                self.state['active_candidate_id'] = old_active_id
                self.state['active_slot_tag'] = old_active_slot_tag
                self.state['subscription_error'] = (
                    'Загруженную подписку не удалось применить; предыдущая рабочая '
                    'подписка сохранена.'
                )
                self.state['subscription_last_error_at'] = now_ts()
                self.save_state()
            raise

        with self.lock:
            if downloaded:
                atomic_write_json(SUBSCRIPTION_PATH, configs)
                success_at = now_ts()
                self.state['subscription_updated_at'] = success_at
                self.state['subscription_last_success_at'] = success_at
                self.state['subscription_error'] = ''
                self.state['subscription_consecutive_failures'] = 0
            else:
                self.state['subscription_error'] = download_error
                self.state['subscription_last_error_at'] = now_ts()
            self.save_state()
            self.next_update_at = (
                now_ts() + self.update_interval_hours * 3600
                if self.update_interval_hours > 0 else None
            )

    def refresh_subscription_job(self) -> None:
        try:
            self.refresh_subscription_sync(initial=False)
            message = 'Подписка обновлена'
        except Exception as exc:
            log(f'manual subscription refresh failed: {exc}', error=True)
            message = f'Ошибка: {exc}'
        finally:
            with self.lock:
                # A manual refresh starts a new subscription-update interval even
                # when the current attempt fails, so the periodic loop does not
                # immediately repeat the same request.
                self.next_update_at = (
                    now_ts() + self.update_interval_hours * 3600
                    if self.update_interval_hours > 0 else None
                )
                self.state['jobs']['refresh'].update({'running': False, 'message': message})
                self.save_state()

    def request_refresh(self) -> bool:
        with self.lock:
            if self.state['jobs']['refresh'].get('running'):
                return False
            self.state['jobs']['refresh'].update({'running': True, 'message': 'Обновление подписки...'})
            self.save_state()
            threading.Thread(target=self.refresh_subscription_job, daemon=True).start()
            return True

    # ----- Latency and health checks ------------------------------------------------

    def find_free_port(self) -> int:
        # Temporary Xray instances are started concurrently. Keep selected
        # ephemeral ports reserved in-process until each test has finished so
        # two workers cannot receive the same port between bind() and Xray start.
        with TEST_PORT_LOCK:
            for _attempt in range(100):
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.bind(('127.0.0.1', 0))
                    port = int(sock.getsockname()[1])
                if port not in RESERVED_TEST_PORTS:
                    RESERVED_TEST_PORTS.add(port)
                    return port
        raise RuntimeError('Unable to reserve a temporary SOCKS port')

    def release_test_port(self, port: int) -> None:
        with TEST_PORT_LOCK:
            RESERVED_TEST_PORTS.discard(port)

    def effective_latency_test_parallelism(self, candidate_count: int) -> int:
        if candidate_count <= 1:
            return max(1, candidate_count)
        configured = max(0, int(self.latency_test_parallelism))
        if configured > 0:
            return max(1, min(configured, candidate_count))
        cpu_count = max(1, int(os.cpu_count() or 1))
        automatic = min(8, max(2, cpu_count * 2))
        return max(1, min(automatic, candidate_count))

    def wait_for_port(self, port: int, process: subprocess.Popen[str], timeout: float = 4.0) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if process.poll() is not None:
                return False
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=0.25):
                    return True
            except OSError:
                time.sleep(0.1)
        return False

    def proxy_curl(
        self,
        host: str,
        port: int,
        url: str,
        timeout_seconds: int,
        *,
        auth: bool,
    ) -> tuple[bool, float | None, str]:
        command = [
            CURL_BIN, '-4', '-f', '-sS', '-o', '/dev/null', '-w', '%{time_total}',
            '--socks5-hostname', f'{host}:{port}',
            '--connect-timeout', str(min(5, timeout_seconds)),
            '--max-time', str(timeout_seconds),
        ]
        if auth and self.proxy_username and self.proxy_password:
            command.extend(['--proxy-user', f'{self.proxy_username}:{self.proxy_password}'])
        command.append(url)
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=timeout_seconds + 3)
        except subprocess.TimeoutExpired:
            return False, None, 'timeout'
        if result.returncode != 0:
            return False, None, (result.stderr or f'curl exit {result.returncode}').strip()
        try:
            seconds = float(result.stdout.strip())
        except ValueError:
            return False, None, 'invalid curl timing response'
        return True, seconds * 1000.0, ''

    def test_candidate(self, candidate: Candidate) -> dict[str, Any]:
        port = self.find_free_port()
        try:
            with tempfile.TemporaryDirectory(prefix='xray-latency.') as temp_dir:
                config_path = Path(temp_dir) / 'config.json'
                log_path = Path(temp_dir) / 'xray.log'
                try:
                    config = self.build_config(candidate, test_port=port)
                    atomic_write_json(config_path, config)
                    ok, output = self.xray_test(config_path)
                    if not ok:
                        return {'status': 'error', 'latency_ms': None, 'checked_at': now_ts(), 'error': output[-500:]}

                    with log_path.open('w+', encoding='utf-8') as log_file:
                        process = subprocess.Popen(
                            [XRAY_BIN, '-config', str(config_path)],
                            stdout=log_file,
                            stderr=subprocess.STDOUT,
                            text=True,
                        )
                        try:
                            if not self.wait_for_port(port, process):
                                log_file.flush()
                                log_file.seek(0)
                                error_text = log_file.read()[-500:] or 'temporary xray did not open SOCKS port'
                                return {
                                    'status': 'error',
                                    'latency_ms': None,
                                    'checked_at': now_ts(),
                                    'error': error_text,
                                }
                            success, latency_ms, _checks, error_text = self.probe_proxy_urls(
                                '127.0.0.1',
                                port,
                                self.latency_test_timeout_seconds,
                                auth=False,
                            )
                            if success and latency_ms is not None:
                                return {
                                    'status': 'ok',
                                    'latency_ms': int(round(latency_ms)),
                                    'checked_at': now_ts(),
                                    'error': '',
                                }
                            return {
                                'status': 'error',
                                'latency_ms': None,
                                'checked_at': now_ts(),
                                'error': error_text[-500:],
                            }
                        finally:
                            process.terminate()
                            try:
                                process.wait(timeout=3)
                            except subprocess.TimeoutExpired:
                                process.kill()
                                process.wait(timeout=2)
                except Exception as exc:
                    return {
                        'status': 'error',
                        'latency_ms': None,
                        'checked_at': now_ts(),
                        'error': str(exc)[-500:],
                    }
        finally:
            self.release_test_port(port)

    def test_candidate_for_full_scan(self, candidate: Candidate) -> dict[str, Any]:
        """Measure an already running candidate through its real slot.

        Other candidates still use isolated temporary Xray processes. This keeps
        the full-scan list comparable while ensuring active and draining slot
        values describe the paths that are actually running.
        """
        with self.lock:
            slot = next(
                (
                    item for item in self.slots.values()
                    if item.running() and self.same_outbound(candidate, item.candidate)
                ),
                None,
            )
            port = slot.socks_tcp if slot is not None else None
        if port is None:
            return self.test_candidate(candidate)

        success, latency_ms, _checks, error_text = self.probe_proxy_urls(
            '127.0.0.1',
            port,
            self.latency_test_timeout_seconds,
            auth=True,
        )
        if success and latency_ms is not None:
            return {
                'status': 'ok',
                'latency_ms': int(round(latency_ms)),
                'checked_at': now_ts(),
                'error': '',
            }
        return {
            'status': 'error',
            'latency_ms': None,
            'checked_at': now_ts(),
            'error': error_text[-500:],
        }

    def latency_job(
        self,
        candidate_ids: list[str] | None = None,
        switch_to_best: bool = False,
        source: str = 'manual',
    ) -> None:
        with self.lock:
            candidates = [
                item for item in self.candidates
                if candidate_ids is None or item.id in candidate_ids
            ]
            job = self.state['jobs']['latency']
            workers = self.effective_latency_test_parallelism(len(candidates))
            job.update({
                'running': True,
                'progress': 0,
                'total': len(candidates),
                'message': f'Проверка доступности · параллельно: {workers}',
            })
            self.save_state()

        fresh_results: dict[str, dict[str, Any]] = {}
        final_message = 'Проверка завершена'
        try:
            completed = 0
            futures: dict[Future[dict[str, Any]], Candidate] = {}
            with ThreadPoolExecutor(
                max_workers=workers,
                thread_name_prefix='xray-latency',
            ) as executor:
                for candidate in candidates:
                    if self.stop_event.is_set():
                        break
                    futures[executor.submit(self.test_candidate_for_full_scan, candidate)] = candidate

                for future in as_completed(futures):
                    candidate = futures[future]
                    if self.stop_event.is_set():
                        for pending in futures:
                            pending.cancel()
                        break
                    try:
                        result = future.result()
                    except Exception as exc:
                        result = {
                            'status': 'error',
                            'latency_ms': None,
                            'checked_at': now_ts(),
                            'error': str(exc)[-500:],
                        }
                    fresh_results[candidate.id] = result
                    completed += 1
                    with self.lock:
                        self.latencies[candidate.id] = result
                        self.save_latencies()
                        job = self.state['jobs']['latency']
                        job.update({
                            'progress': completed,
                            'message': f'{candidate.name}: ' + (
                                f'{result["latency_ms"]} мс'
                                if result['status'] == 'ok' else 'недоступен'
                            ),
                        })
                        self.save_state()

            if candidate_ids is None and fresh_results and not self.stop_event.is_set():
                self.handle_draining_full_scan_results(fresh_results)

            if switch_to_best and fresh_results and not self.stop_event.is_set():
                healthy: list[tuple[int, str, Candidate]] = []
                for candidate in candidates:
                    result = fresh_results.get(candidate.id) or {}
                    latency_ms = result.get('latency_ms')
                    if result.get('status') != 'ok' or not isinstance(latency_ms, int):
                        continue
                    if self.auto_check_max_latency_ms > 0 and latency_ms > self.auto_check_max_latency_ms:
                        continue
                    if self.candidate_is_excluded(candidate):
                        continue
                    healthy.append((latency_ms, candidate.name.casefold(), candidate))
                healthy.sort(key=lambda item: (item[0], item[1]))

                if healthy:
                    preferred_country = getattr(self, 'auto_switch_preferred_country', '')
                    preferred_healthy = [
                        item for item in healthy
                        if preferred_country
                        and item[2].country_code == preferred_country
                    ]
                    selection_pool = preferred_healthy or healthy
                    best_latency, _best_name, best_candidate = selection_pool[0]
                    with self.lock:
                        effective, selected, _mismatch = self.effective_active_candidate()
                        current = selected or effective
                        current_result = fresh_results.get(current.id) if current else None
                        current_latency = (
                            current_result.get('latency_ms')
                            if isinstance(current_result, dict) and current_result.get('status') == 'ok'
                            else self.candidate_latency_ms(current)
                        )

                    ping_difference = (
                        current_latency - best_latency
                        if isinstance(current_latency, int) else None
                    )
                    preferred_country_switch = bool(
                        preferred_healthy
                        and current is not None
                        and current.country_code != preferred_country
                    )
                    should_switch = (
                        current is None
                        or (
                            not self.same_outbound(current, best_candidate)
                            and (
                                preferred_country_switch
                                or
                                not isinstance(current_latency, int)
                                or ping_difference >= self.auto_switch_min_ping_delta_ms
                            )
                        )
                    )
                    if should_switch:
                        self.restart_xray_for(
                            best_candidate,
                            f'automatic best latency after {source} check: {best_latency} ms',
                        )
                        final_message = f'Проверка завершена · выбран {best_candidate.name} ({best_latency} мс)'
                        log(
                            f'{source} latency check switched to {best_candidate.name} '
                            f'({best_latency} ms, difference {ping_difference} ms, '
                            f'preferred_country={preferred_country or "none"})'
                        )
                    elif current is not None and self.same_outbound(current, best_candidate):
                        final_message = f'Проверка завершена · текущий outbound оптимален ({current_latency} мс)'
                    elif current is not None and isinstance(ping_difference, int):
                        if ping_difference < 0:
                            final_message = (
                                f'Проверка завершена · текущий outbound быстрее подходящих кандидатов '
                                f'на {-ping_difference} мс'
                            )
                        else:
                            final_message = (
                                f'Проверка завершена · разница {ping_difference} мс меньше порога '
                                f'{self.auto_switch_min_ping_delta_ms} мс'
                            )
                else:
                    excluded_text = self.auto_switch_excluded or 'нет'
                    final_message = (
                        'Проверка завершена · подходящие outbound не найдены '
                        f'(исключения выбора: {excluded_text})'
                    )
        except Exception as exc:
            final_message = f'Ошибка проверки: {exc}'
            log(f'latency job error: {exc}', error=True)
        finally:
            with self.lock:
                self.state['jobs']['latency'].update({'running': False, 'message': final_message})
                if candidate_ids is None and source in {'manual', 'auto-best', 'startup'}:
                    self.state['auto_best_check_last_at'] = now_ts()
                    self.settings_event.set()
                self.save_state()

    def handle_draining_full_scan_results(
        self,
        fresh_results: dict[str, dict[str, Any]],
    ) -> None:
        """Stop a stale one-connection drain after repeated bad full scans.

        The same auto_check_failures setting is intentionally used for active-slot
        failover and for drain tracking. Only complete list scans count;
        single-outbound tests do not alter the counter.
        """
        to_stop: list[tuple[str, int, str]] = []
        with self.lock:
            for slot_tag in SLOT_TAGS:
                slot = self.slots[slot_tag]
                if not slot.running() or not slot.draining:
                    slot.drain_degraded_checks = 0
                    slot.drain_last_latency_ms = None
                    slot.drain_last_checked_at = None
                    continue

                current_candidate = next(
                    (
                        candidate for candidate in self.candidates
                        if self.same_outbound(candidate, slot.candidate)
                    ),
                    None,
                )
                if current_candidate is None:
                    slot.drain_degraded_checks = 0
                    slot.drain_last_latency_ms = None
                    slot.drain_last_checked_at = None
                    continue

                result = fresh_results.get(current_candidate.id)
                if not isinstance(result, dict):
                    continue

                checked_at = int(result.get('checked_at') or now_ts())
                latency_value = result.get('latency_ms')
                latency_ms = latency_value if isinstance(latency_value, int) else None
                degraded = result.get('status') != 'ok'
                if (
                    not degraded
                    and latency_ms is not None
                    and self.auto_check_max_latency_ms > 0
                    and latency_ms > self.auto_check_max_latency_ms
                ):
                    degraded = True

                # Refresh the count after the slot probe has closed so its own
                # short-lived SOCKS connection cannot mask the last real flow.
                current_connections = (
                    self.local_tcp_connection_count(slot.socks_tcp)
                    + slot.drain_udp_connections
                )
                slot.drain_connections = current_connections
                slot.drain_tcp_connections = max(0, current_connections - slot.drain_udp_connections)
                slot.drain_last_latency_ms = latency_ms
                slot.drain_last_checked_at = checked_at
                if degraded and current_connections == 1:
                    slot.drain_degraded_checks += 1
                else:
                    slot.drain_degraded_checks = 0

                if slot.drain_degraded_checks < self.auto_check_failures:
                    continue

                if result.get('status') == 'ok' and latency_ms is not None:
                    reason = (
                        f'{latency_ms}ms exceeds {self.auto_check_max_latency_ms}ms'
                    )
                else:
                    reason = str(result.get('error') or 'outbound is unavailable')
                to_stop.append((slot_tag, slot.drain_degraded_checks, reason))

        for slot_tag, failures, reason in to_stop:
            with self.lock:
                slot = self.slots[slot_tag]
                can_stop = (
                    slot.running()
                    and slot.draining
                    and slot.drain_connections == 1
                    and slot.drain_degraded_checks >= self.auto_check_failures
                )
            if not can_stop:
                continue
            log(
                f'{slot_tag} remained degraded for {failures} consecutive full checks '
                f'with one tracked connection ({reason}); force-stopping drained slot',
                error=True,
            )
            try:
                self.force_stop_draining_slot(slot_tag)
            except Exception as exc:
                log(f'could not stop degraded drained slot {slot_tag}: {exc}', error=True)

    def request_latency_test(
        self,
        candidate_ids: list[str] | None = None,
        switch_to_best: bool = False,
        source: str = 'manual',
    ) -> bool:
        with self.lock:
            if self.state['jobs']['latency'].get('running'):
                return False
            total = len([
                item for item in self.candidates
                if candidate_ids is None or item.id in candidate_ids
            ])
            self.state['jobs']['latency'].update({
                'running': True,
                'progress': 0,
                'total': total,
                'message': 'Проверка доступности...',
                'source': source,
                'scope': 'all' if candidate_ids is None else 'selected',
                'switch_to_best': bool(switch_to_best),
            })
            self.save_state()
            threading.Thread(
                target=self.latency_job,
                args=(candidate_ids, switch_to_best, source),
                daemon=True,
            ).start()
            return True

    def check_active_tunnel(
        self,
    ) -> tuple[bool, float | None, list[tuple[str, float]], str]:
        return self.probe_slot_health(self.active_slot_tag)

    def auto_best_check_due(self, current_time: int | None = None) -> bool:
        interval = max(60, int(self.auto_best_check_interval_seconds))
        try:
            last_check = int(self.state.get('auto_best_check_last_at') or 0)
        except (TypeError, ValueError):
            last_check = 0
        if last_check <= 0:
            return True
        now_value = now_ts() if current_time is None else int(current_time)
        return now_value - last_check >= interval

    def excluded_country_codes(self) -> set[str]:
        country_codes, _fragments = parse_auto_switch_exclusions(
            self.auto_switch_excluded
        )
        return country_codes

    def excluded_outbound_fragments(self) -> list[str]:
        _country_codes, fragments = parse_auto_switch_exclusions(
            self.auto_switch_excluded
        )
        return fragments

    def candidate_is_excluded(self, candidate: Candidate) -> bool:
        country_codes, fragments = parse_auto_switch_exclusions(
            self.auto_switch_excluded
        )
        if candidate.country_code and candidate.country_code in country_codes:
            return True
        haystack = ' '.join((
            candidate.name,
            candidate.outbound_tag,
            candidate.protocol,
            candidate.server,
            candidate.id,
        )).casefold()
        return any(fragment in haystack for fragment in fragments)

    def candidate_country_is_excluded(self, candidate: Candidate) -> bool:
        # Compatibility alias: exclusions now also include text fragments.
        return self.candidate_is_excluded(candidate)

    def sorted_healthy_candidates(self, exclude_configured_countries: bool = False) -> list[Candidate]:
        healthy: list[tuple[int, Candidate]] = []
        for candidate in self.candidates:
            if exclude_configured_countries and self.candidate_is_excluded(candidate):
                continue
            data = self.latencies.get(candidate.id) or {}
            latency_ms = data.get('latency_ms')
            if data.get('status') == 'ok' and isinstance(latency_ms, int):
                if self.auto_check_max_latency_ms > 0 and latency_ms > self.auto_check_max_latency_ms:
                    continue
                healthy.append((latency_ms, candidate))
        healthy.sort(key=lambda item: (item[0], item[1].name.casefold()))
        preferred_country = getattr(self, 'auto_switch_preferred_country', '')
        if preferred_country:
            preferred = [
                item for item in healthy if item[1].country_code == preferred_country
            ]
            if preferred:
                healthy = preferred + [
                    item for item in healthy if item[1].country_code != preferred_country
                ]
        return [item[1] for item in healthy]

    def choose_failover_candidate(self) -> Candidate | None:
        excluded_text = self.auto_switch_excluded or 'нет'
        healthy = self.sorted_healthy_candidates(exclude_configured_countries=True)
        active = self.slots[self.active_slot_tag].candidate or self.candidate_by_id(self.active_candidate_id)
        alternatives = [item for item in healthy if not self.same_outbound(item, active)]
        if alternatives:
            return alternatives[0]

        log(
            'no previous healthy latency result is available outside configured exclusions; '
            f'running a fresh outbound test (configured exclusions: {excluded_text})',
            error=True,
        )
        for candidate in list(self.candidates):
            if self.same_outbound(candidate, active):
                continue
            if self.candidate_is_excluded(candidate):
                log(
                    f'auto-check skipped excluded failover outbound: {candidate.name} '
                    f'[{candidate.country_code}]',
                )
                continue
            result = self.test_candidate(candidate)
            self.latencies[candidate.id] = result
        self.save_latencies()
        healthy = self.sorted_healthy_candidates(exclude_configured_countries=True)
        return next((item for item in healthy if not self.same_outbound(item, active)), None)

    def auto_check_wait_seconds(self, current_time: int | None = None) -> float:
        if not self.auto_checker_enabled:
            return 5.0
        interval = max(10, int(self.auto_check_interval_seconds))
        try:
            last_check = int(self.state.get('auto_check_last_at') or 0)
        except (TypeError, ValueError):
            last_check = 0
        if last_check <= 0:
            return float(interval)
        now_value = now_ts() if current_time is None else int(current_time)
        elapsed = max(0, now_value - last_check)
        return float(max(0, interval - elapsed))

    def auto_checker_loop(self) -> None:
        while not self.stop_event.is_set():
            timeout = self.auto_check_wait_seconds()
            woke_for_settings = self.settings_event.wait(timeout)
            if self.stop_event.is_set():
                break
            if woke_for_settings:
                self.settings_event.clear()
                continue
            if not self.auto_checker_enabled:
                continue
            try:
                success, latency_ms, checks, error = self.check_active_tunnel()
                checked_at = now_ts()
                check_details = self.format_probe_results(checks) or 'both endpoints failed'
                with self.lock:
                    self.state['auto_check_last_at'] = checked_at
                    if success:
                        self.state['auto_check_failures'] = 0
                        self.state['auto_check_last_error'] = ''
                        if self.active_candidate_id and latency_ms is not None:
                            self.latencies[self.active_candidate_id] = {
                                'status': 'ok',
                                'latency_ms': int(round(latency_ms)),
                                'checked_at': checked_at,
                                'error': '',
                            }
                            self.save_latencies()
                        self.save_state()
                    else:
                        failures = int(self.state.get('auto_check_failures') or 0) + 1
                        self.state['auto_check_failures'] = failures
                        self.state['auto_check_last_error'] = error
                        self.save_state()

                if success:
                    log(
                        f'active slot check {self.active_slot_tag}: {check_details}; '
                        f'fastest={latency_ms:.0f}ms; result=ok'
                    )
                    if self.auto_best_check_due(checked_at):
                        accepted = self.request_latency_test(
                            None,
                            switch_to_best=self.auto_switch_best_enabled,
                            source='auto-best',
                        )
                        if not accepted:
                            log('scheduled full outbound check postponed because another latency test is running')
                    continue

                failures = int(self.state.get('auto_check_failures') or 0)
                log(
                    f'active slot check {self.active_slot_tag}: {check_details}; result=failed; '
                    f'auto-check failures={failures}/{self.auto_check_failures}; {error}',
                    error=True,
                )
                if failures < self.auto_check_failures:
                    continue

                candidate = self.choose_failover_candidate()
                if candidate is None:
                    excluded_text = self.auto_switch_excluded or 'нет'
                    log(
                        'auto-check could not find a healthy failover outbound outside configured exclusions: '
                        f'{excluded_text}',
                        error=True,
                    )
                    continue
                self.restart_xray_for(
                    candidate,
                    f'emergency failover after {failures} consecutive degraded checks',
                    preempt_draining=True,
                    emergency_failover=True,
                )
                log(
                    f'auto-check switched to {candidate.name}; old degraded slot will be '
                    'force-stopped after two successful checks',
                    error=True,
                )
            except Exception as exc:
                log(f'auto-check error: {exc}', error=True)

    def periodic_update_loop(self) -> None:
        while not self.stop_event.wait(5):
            if self.update_interval_hours <= 0 or self.next_update_at is None:
                continue
            if now_ts() < self.next_update_at:
                continue
            try:
                self.refresh_subscription_sync(initial=False)
            except Exception as exc:
                log(f'periodic subscription update failed: {exc}', error=True)
                self.next_update_at = now_ts() + self.update_interval_hours * 3600

    def rollback_after_active_exit(self, failed_slot_tag: str) -> bool:
        if not self.dual_slot_enabled:
            return False
        rollback_slot_tag = self.other_slot_tag(failed_slot_tag)
        rollback_slot = self.slots[rollback_slot_tag]
        if not rollback_slot.running():
            return False
        if not self.switch_lock.acquire(blocking=False):
            return False
        try:
            self.switch_selector(rollback_slot_tag)
            with self.lock:
                failed_slot = self.slots[failed_slot_tag]
                failed_slot.process = None
                failed_slot.draining = False
                rollback_slot.draining = False
                rollback_slot.drain_started_at = None
                rollback_slot.drain_zero_since = None
                rollback_slot.drain_protect_until = None
                self.active_slot_tag = rollback_slot_tag
                self.active_candidate_id = rollback_slot.candidate_id
                self.switch_generation += 1
                self.state['last_switch_at'] = now_ts()
                self.state['last_switch_reason'] = 'automatic rollback after active Xray process exit'
                self.state['auto_check_failures'] = 0
                self.state['auto_check_last_error'] = ''
                self.save_state()
            rollback_candidate = (
                rollback_slot.candidate
                or self.candidate_by_id(rollback_slot.candidate_id)
            )
            if rollback_candidate:
                try:
                    self.save_active_config(rollback_slot_tag, rollback_candidate)
                except Exception as exc:
                    log(f'could not save last-good rollback config: {exc}', error=True)
            log(
                f'active slot {failed_slot_tag} exited; selector rolled back to '
                f'{rollback_slot_tag} ({rollback_slot.candidate_name})',
                error=True,
            )
            return True
        except Exception as exc:
            log(f'rollback after active Xray exit failed: {exc}', error=True)
            return False
        finally:
            self.switch_lock.release()

    def xray_monitor_loop(self) -> None:
        while not self.stop_event.wait(1):
            for slot_tag in SLOT_TAGS:
                with self.lock:
                    slot = self.slots[slot_tag]
                    process = slot.process
                    intentional = slot.intentional_stop
                    is_active = slot_tag == self.active_slot_tag
                if process is None or process.poll() is None or intentional:
                    continue
                code = process.returncode
                log(f'xray-core slot {slot_tag} exited unexpectedly with code {code}', error=True)
                if is_active and self.rollback_after_active_exit(slot_tag):
                    continue
                with self.lock:
                    slot.process = None
                    slot.draining = False
                if is_active and self.restart_on_runtime_error:
                    os._exit(1)

    def rebind_slot_candidates(self) -> bool:
        """Bind running slots to objects from the current subscription list.

        Candidate identifiers can change after a subscription refresh even when
        the actual outbound is unchanged. Keeping stale Candidate objects in a
        slot makes the first UI status response unable to mark the active or
        draining card until another operation rewrites the slot state.
        """
        changed = False
        for tag, slot in self.slots.items():
            if not slot.running():
                continue
            match: Candidate | None = None
            if tag == self.active_slot_tag and self.active_candidate_id:
                match = self.candidate_by_id(self.active_candidate_id)
            if match is None and slot.candidate_id:
                match = self.candidate_by_id(slot.candidate_id)
            if match is None and slot.candidate is not None:
                match = next(
                    (item for item in self.candidates if self.same_outbound(item, slot.candidate)),
                    None,
                )
            if match is None and slot.candidate_name:
                match = next(
                    (item for item in self.candidates if item.name == slot.candidate_name),
                    None,
                )
            if match is None and slot.observed_outbound_tag:
                match = self.candidate_by_tag(slot.observed_outbound_tag)
            if match is None:
                continue
            if slot.candidate_id != match.id or slot.candidate is not match:
                changed = True
            slot.candidate = match
            slot.candidate_id = match.id
            slot.candidate_name = match.name
            if tag == self.active_slot_tag and self.active_candidate_id != match.id:
                self.active_candidate_id = match.id
                self.state['active_candidate_id'] = match.id
                changed = True
        return changed

    def effective_active_candidate(self) -> tuple[Candidate | None, Candidate | None, bool]:
        active_slot = self.slots[self.active_slot_tag]
        selected = self.candidate_by_id(self.active_candidate_id) or active_slot.candidate
        observed = None
        if active_slot.observed_outbound_tag:
            preferred_source = selected.source_index if selected else None
            observed = self.candidate_by_tag(active_slot.observed_outbound_tag, preferred_source)

        # The generated runtime rule explicitly selects active_candidate_id.
        # Runtime log observations remain diagnostic only: they can include
        # auxiliary traffic and must not clear the UI selection or re-enable
        # the Select button for the already configured outbound.
        effective = selected or observed
        mismatch = bool(observed and selected and observed.id != selected.id)
        return effective, selected, mismatch

    def status_payload(self) -> dict[str, Any]:
        with self.lock:
            if self.rebind_slot_candidates():
                self.save_state()
            active_slot = self.slots[self.active_slot_tag]
            process_running = active_slot.running()
            active, selected, mismatch = self.effective_active_candidate()
            effective_id = active.id if active else ''
            active_slot_candidate = active_slot.candidate or selected or active
            candidates = []
            for item in self.candidates:
                assigned_slots = [
                    tag for tag, slot in self.slots.items()
                    if slot.running() and self.same_candidate_identity(
                        item,
                        slot.candidate or self.candidate_by_id(slot.candidate_id),
                    )
                ]
                draining_slots = [
                    tag for tag in assigned_slots if self.slots[tag].draining
                ]
                is_active = self.same_candidate_identity(item, active_slot_candidate)
                payload = item.public(self.latencies.get(item.id), is_active)
                payload['slot_tags'] = assigned_slots
                payload['draining_slots'] = draining_slots
                payload['draining'] = bool(draining_slots)
                payload['excluded'] = self.candidate_is_excluded(item)
                candidates.append(payload)
            protocols = sorted({item.protocol for item in self.candidates})
            available_count = sum(
                1 for item in self.candidates
                if (self.latencies.get(item.id) or {}).get('status') == 'ok'
            )
            unavailable_count = sum(
                1 for item in self.candidates
                if (self.latencies.get(item.id) or {}).get('status') == 'error'
            )
            slots_payload = {}
            for tag, slot in self.slots.items():
                slots_payload[tag] = {
                    'tag': tag,
                    'running': slot.running(),
                    'active': tag == self.active_slot_tag,
                    'draining': slot.draining,
                    'candidate_id': slot.candidate_id,
                    'candidate_name': slot.candidate_name,
                    'candidate_fingerprint': slot.candidate.fingerprint if slot.candidate else '',
                    'candidate_outbound_tag': slot.candidate.outbound_tag if slot.candidate else '',
                    'candidate_protocol': slot.candidate.protocol if slot.candidate else '',
                    'candidate_server': slot.candidate.server if slot.candidate else '',
                    'candidate_port': slot.candidate.port if slot.candidate else None,
                    'socks_tcp': slot.socks_tcp,
                    'socks_udp': slot.socks_udp,
                    'started_at': slot.started_at,
                    'drain_started_at': slot.drain_started_at,
                    'drain_zero_since': slot.drain_zero_since,
                    'drain_protect_until': slot.drain_protect_until,
                    'drain_connections': slot.drain_connections,
                    'drain_tcp_connections': slot.drain_tcp_connections,
                    'drain_udp_connections': slot.drain_udp_connections,
                    'drain_bytes': slot.drain_bytes,
                    'drain_last_error': slot.drain_last_error,
                    'drain_degraded_checks': slot.drain_degraded_checks,
                    'drain_last_latency_ms': slot.drain_last_latency_ms,
                    'drain_last_checked_at': slot.drain_last_checked_at,
                    'drain_new_connections': slot.drain_new_connections,
                    'drain_stalled_connections': slot.drain_stalled_connections,
                    'observed_outbound_tag': slot.observed_outbound_tag,
                    'observed_outbound_at': slot.observed_outbound_at,
                }
            return {
                'version': ADDON_VERSION,
                'home_assistant_host': getattr(self, 'home_assistant_host', 'host'),
                'release_notes': release_notes_payload(),
                'xray_version': self.xray_version(),
                'started_at': self.started_at,
                'xray_running': process_running,
                'active': active.public(self.latencies.get(active.id), True) if active else None,
                'selected_active': selected.public(self.latencies.get(selected.id), selected.id == effective_id) if selected else None,
                'observed_outbound_tag': active_slot.observed_outbound_tag,
                'observed_outbound_at': active_slot.observed_outbound_at,
                'route_mismatch': mismatch,
                'candidates': candidates,
                'protocols': protocols,
                'availability': {
                    'available': available_count,
                    'unavailable': unavailable_count,
                    'untested': max(0, len(self.candidates) - available_count - unavailable_count),
                    'total': len(self.candidates),
                },
                'subscription': {
                    'updated_at': self.state.get('subscription_updated_at'),
                    'last_attempt_at': self.state.get('subscription_last_attempt_at'),
                    'last_success_at': self.state.get('subscription_last_success_at') or self.state.get('subscription_updated_at'),
                    'last_error_at': self.state.get('subscription_last_error_at'),
                    'error': self.state.get('subscription_error') or '',
                    'consecutive_failures': int(
                        self.state.get('subscription_consecutive_failures') or 0
                    ),
                    'next_update_at': self.next_update_at,
                    'url': self.subscription_url,
                    'update_interval_hours': self.update_interval_hours,
                },
                'jobs': copy.deepcopy(self.state.get('jobs') or {}),
                'auto_checker': {
                    'enabled': self.auto_checker_enabled,
                    'switch_to_best': self.auto_switch_best_enabled,
                    'preferred_country': getattr(self, 'auto_switch_preferred_country', ''),
                    'excluded': self.auto_switch_excluded,
                    'min_ping_delta_ms': self.auto_switch_min_ping_delta_ms,
                    'interval_seconds': self.auto_check_interval_seconds,
                    'failure_threshold': self.auto_check_failures,
                    'max_latency_ms': self.auto_check_max_latency_ms,
                    'best_check_interval_seconds': self.auto_best_check_interval_seconds,
                    'current_failures': int(self.state.get('auto_check_failures') or 0),
                    'last_check_at': self.state.get('auto_check_last_at'),
                    'last_best_check_at': self.state.get('auto_best_check_last_at'),
                    'last_error': self.state.get('auto_check_last_error') or '',
                    'last_switch_at': self.state.get('last_switch_at'),
                    'last_switch_reason': self.state.get('last_switch_reason') or '',
                },
                'ui_settings': {
                    'port': getattr(self, 'ui_port', DEFAULT_UI_PORT),
                    'sort': self.ui_sort,
                    'protocol_filter': self.ui_protocol_filter,
                    'max_ping_ms': self.ui_max_ping_ms,
                    'hide_unavailable': self.ui_hide_unavailable,
                    'hide_excluded': self.ui_hide_excluded,
                },
                'selector': copy.deepcopy(self.selector_state),
                'router': copy.deepcopy(self.router_state),
                'blue_green': {
                    'mode': 'dual' if self.dual_slot_enabled else 'single',
                    'dual_slot_enabled': self.dual_slot_enabled,
                    'active_slot': self.active_slot_tag,
                    'selector_tag': self.selector_tag,
                    'drain_quiet_seconds': self.drain_quiet_seconds,
                    'drain_timeout_minutes': self.drain_timeout_minutes,
                    'slots': slots_payload,
                },
                'primary_test_url': self.primary_test_url,
                'secondary_test_url': self.secondary_test_url,
            }

    def xray_version(self) -> str:
        if self._xray_version_cache:
            return self._xray_version_cache
        try:
            result = subprocess.run([XRAY_BIN, 'version'], capture_output=True, text=True, timeout=5)
            lines = (result.stdout or result.stderr).splitlines()
            self._xray_version_cache = lines[0].strip() if lines else 'unknown'
        except Exception:
            self._xray_version_cache = 'unknown'
        return self._xray_version_cache

    def select_candidate(self, candidate_id: str) -> None:
        with self.lock:
            candidate = self.candidate_by_id(candidate_id)
            if candidate is None:
                raise ValueError('Outbound не найден')
            already_active = (
                candidate.id == self.active_candidate_id
                and self.slots[self.active_slot_tag].running()
            )
        if already_active:
            return
        self.restart_xray_for(
            candidate,
            'manual selection from UI',
            preempt_draining=True,
        )

    def initialize(self) -> None:
        cached = self.load_cached_subscription()
        if cached:
            self.subscription = cached
            self.candidates = self.extract_candidates(cached)
        try:
            self.refresh_subscription_sync(initial=True)
        except Exception as exc:
            log(f'initial subscription update failed: {exc}', error=True)
            if cached and self.candidates:
                candidate = self.choose_initial_candidate()
                try:
                    self.restart_xray_for(candidate, 'cached subscription fallback')
                except Exception as cached_error:
                    log(f'cached subscription could not be applied: {cached_error}', error=True)
                    restored, restored_candidate = self.restore_last_good()
                    if not restored:
                        raise
                    if restored_candidate:
                        self.start_initial_candidate(restored_candidate, 'last-good recovery')
                    else:
                        self.active_candidate_id = ''
                        self.save_state()
                        self.start_xray()
            else:
                restored, restored_candidate = self.restore_last_good()
                if not restored:
                    raise
                if restored_candidate:
                    self.start_initial_candidate(restored_candidate, 'last-good recovery')
                else:
                    self.active_candidate_id = ''
                    self.save_state()
                    self.start_xray()

    def run(self) -> None:
        self.initialize()
        if self.auto_checker_enabled:
            accepted = self.request_latency_test(
                None,
                switch_to_best=self.auto_switch_best_enabled,
                source='startup',
            )
            if accepted:
                log(
                    'startup latency check started in background '
                    f'(parallelism {self.effective_latency_test_parallelism(len(self.candidates))})'
                )
        threading.Thread(target=self.auto_checker_loop, daemon=True).start()
        threading.Thread(target=self.periodic_update_loop, daemon=True).start()
        threading.Thread(target=self.xray_monitor_loop, daemon=True).start()
        threading.Thread(target=self.drain_monitor_loop, daemon=True).start()
        threading.Thread(target=self.selector_status_loop, daemon=True).start()
        threading.Thread(target=self.router_status_loop, daemon=True).start()

        handler_factory = lambda *args, **kwargs: WebHandler(self, *args, **kwargs)
        ingress_port = self.detect_ingress_port()
        if ingress_port == WATCHDOG_PORT:
            raise RuntimeError(
                f'Home Assistant assigned the reserved watchdog port {WATCHDOG_PORT} to Ingress; '
                'restart the app so Supervisor assigns another port.'
            )

        if ingress_port == self.ui_port:
            ui_server = ThreadingHTTPServer(('0.0.0.0', self.ui_port), handler_factory)
            self.servers.append(ui_server)
            threading.Thread(target=ui_server.serve_forever, daemon=True).start()
            log(
                f'web UI is listening on 0.0.0.0:{self.ui_port}; '
                'Home Assistant Ingress uses the same port'
            )
        else:
            ui_server = ThreadingHTTPServer(('127.0.0.1', self.ui_port), handler_factory)
            self.servers.append(ui_server)
            threading.Thread(target=ui_server.serve_forever, daemon=True).start()

            ingress_server = ThreadingTCPProxyServer(
                ('0.0.0.0', ingress_port),
                target_host='127.0.0.1',
                target_port=self.ui_port,
            )
            self.servers.append(ingress_server)
            threading.Thread(target=ingress_server.serve_forever, daemon=True).start()
            log(
                f'web UI is listening on 127.0.0.1:{self.ui_port}; '
                f'Home Assistant Ingress proxy is listening on 0.0.0.0:{ingress_port}'
            )

        watchdog_server = ThreadingHTTPServer(('0.0.0.0', WATCHDOG_PORT), handler_factory)
        self.servers.append(watchdog_server)
        threading.Thread(target=watchdog_server.serve_forever, daemon=True).start()
        log(f'watchdog health endpoint is listening on 0.0.0.0:{WATCHDOG_PORT}')

        while not self.stop_event.wait(1):
            pass

    def shutdown(self) -> None:
        self.stop_event.set()
        self.settings_event.set()
        for server in list(self.servers):
            try:
                server.shutdown()
                server.server_close()
            except Exception:
                pass
        self.servers.clear()
        self.stop_xray()


class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class IngressTCPProxyHandler(socketserver.BaseRequestHandler):
    @staticmethod
    def forward_stream(source: socket.socket, target: socket.socket) -> None:
        try:
            while True:
                data = source.recv(65536)
                if not data:
                    break
                target.sendall(data)
        except (ConnectionError, OSError):
            pass
        finally:
            try:
                target.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    def handle(self) -> None:
        server = self.server
        target_host = getattr(server, 'target_host', '127.0.0.1')
        target_port = int(getattr(server, 'target_port', 0) or 0)
        try:
            upstream = socket.create_connection((target_host, target_port), timeout=5)
        except OSError:
            return

        client = self.request
        client.settimeout(None)
        upstream.settimeout(None)
        request_thread = threading.Thread(
            target=self.forward_stream,
            args=(client, upstream),
            daemon=True,
        )
        request_thread.start()
        try:
            self.forward_stream(upstream, client)
        finally:
            try:
                upstream.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            upstream.close()
            request_thread.join(timeout=1)


class ThreadingTCPProxyServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        server_address: tuple[str, int],
        *,
        target_host: str,
        target_port: int,
    ) -> None:
        self.target_host = target_host
        self.target_port = target_port
        super().__init__(server_address, IngressTCPProxyHandler)


class WebHandler(http.server.BaseHTTPRequestHandler):
    server_version = f'XrayProxyManager/{ADDON_VERSION}'

    def __init__(self, manager: XrayManager, *args: Any, **kwargs: Any) -> None:
        self.manager = manager
        super().__init__(*args, **kwargs)

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def ingress_client_allowed(self) -> bool:
        address = str(self.client_address[0] or '')
        if address.startswith('::ffff:'):
            address = address[7:]
        return address in {'172.30.32.2', '127.0.0.1', '::1'}

    def reject_non_ingress_client(self) -> bool:
        if self.ingress_client_allowed():
            return False
        self.send_error(403, 'Web UI is available only through Home Assistant Ingress')
        return True

    def send_json(self, payload: Any, status: int = 200) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def read_json(self) -> dict[str, Any]:
        length = int(self.headers.get('Content-Length') or 0)
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        payload = json.loads(raw.decode('utf-8'))
        return payload if isinstance(payload, dict) else {}

    def send_static(self, relative: str, content_type: str) -> None:
        path = (WEB_ROOT / relative).resolve()
        if WEB_ROOT.resolve() not in path.parents and path != WEB_ROOT.resolve():
            self.send_error(404)
            return
        try:
            body = path.read_bytes()
        except FileNotFoundError:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header('Content-Type', content_type)
        self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0')
        self.send_header('Pragma', 'no-cache')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path.rstrip('/') or '/'
        if path.endswith('/api/health'):
            status = self.manager.status_payload()
            xray_running = bool(status.get('xray_running'))
            healthy = xray_running
            self.send_json({
                'ok': healthy,
                'xray_running': xray_running,
            }, 200 if healthy else 503)
            return
        if self.reject_non_ingress_client():
            return
        if path.endswith('/api/status'):
            self.send_json(self.manager.status_payload())
            return
        if path.endswith('/api/logs'):
            query = parse_qs(parsed.query)
            try:
                limit = int((query.get('limit') or ['1000'])[0])
            except (TypeError, ValueError):
                limit = 1000
            lines, total = ui_log_snapshot(limit)
            self.send_json({
                'lines': lines,
                'count': len(lines),
                'total': total,
                'limit': max(1, min(limit, LOG_BUFFER_MAX_LINES)),
                'generated_at': now_ts(),
            })
            return
        if path.endswith('/app.js'):
            self.send_static('app.js', 'application/javascript; charset=utf-8')
            return
        if path.endswith('/style.css'):
            self.send_static('style.css', 'text/css; charset=utf-8')
            return
        if path.endswith('/favicon.svg'):
            self.send_static('favicon.svg', 'image/svg+xml')
            return
        self.send_static('index.html', 'text/html; charset=utf-8')

    def do_POST(self) -> None:
        if self.reject_non_ingress_client():
            return
        path = urlparse(self.path).path.rstrip('/')
        try:
            payload = self.read_json()
            if path.endswith('/api/select'):
                self.manager.select_candidate(str(payload.get('id') or ''))
                self.send_json({'ok': True})
                return
            if path.endswith('/api/test'):
                candidate_id = str(payload.get('id') or '')
                accepted = self.manager.request_latency_test([candidate_id] if candidate_id else None)
                self.send_json({'ok': accepted}, 202 if accepted else 409)
                return
            if path.endswith('/api/refresh'):
                accepted = self.manager.request_refresh()
                self.send_json({'ok': accepted}, 202 if accepted else 409)
                return
            if path.endswith('/api/mode'):
                desired = payload.get('dual_slot_enabled')
                if not isinstance(desired, bool):
                    raise ValueError('Не указан режим слотов')
                self.send_json(self.manager.set_slot_mode(desired))
                return
            if path.endswith('/api/preferred-country'):
                self.send_json(self.manager.set_preferred_country(payload.get('country')))
                return
            if path.endswith('/api/settings'):
                changes = payload.get('changes') if isinstance(payload.get('changes'), dict) else payload
                self.send_json(self.manager.update_runtime_settings(changes))
                return
            if path.endswith('/api/traffic'):
                desired = payload.get('enabled')
                if not isinstance(desired, bool):
                    current = self.manager.router_state.get('rule_enabled')
                    if not isinstance(current, bool):
                        raise ValueError('Состояние правила OpenWrt неизвестно')
                    desired = not current
                self.manager.set_router_rule(desired)
                self.send_json({'ok': True, 'enabled': desired})
                return
            if path.endswith('/api/drain/stop'):
                stopped = self.manager.force_stop_draining_slot(str(payload.get('slot') or ''))
                self.send_json({'ok': True, 'slot': stopped})
                return
            self.send_json({'ok': False, 'error': 'not found'}, 404)
        except Exception as exc:
            log(f'web API error: {exc}', error=True)
            self.send_json({'ok': False, 'error': str(exc)}, 400)


def main() -> int:
    manager: XrayManager | None = None
    try:
        manager = XrayManager()

        def handle_signal(_signum: int, _frame: Any) -> None:
            if manager:
                manager.shutdown()

        signal.signal(signal.SIGTERM, handle_signal)
        signal.signal(signal.SIGINT, handle_signal)
        manager.run()
        return 0
    except Exception as exc:
        log(f'fatal error: {exc}', error=True)
        traceback.print_exc()
        return 1
    finally:
        if manager:
            manager.shutdown()


if __name__ == '__main__':
    raise SystemExit(main())
