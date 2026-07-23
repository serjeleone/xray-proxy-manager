#!/usr/bin/env python3
from __future__ import annotations

import copy
from collections import deque
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
from dataclasses import asdict, dataclass
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
UI_PORT = 8099
SLOT_TAGS = ('xray-a', 'xray-b')
DEFAULT_SOCKS_TCP_B = 10809
POST_SWITCH_WATCH_SECONDS = 30
ADDON_VERSION = '0.6.3'

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
    'auto_checker_enabled',
    'auto_switch_best_enabled',
    'auto_switch_excluded_countries',
    'auto_switch_min_ping_delta_ms',
    'auto_check_interval_seconds',
    'auto_check_failures',
    'update_interval_hours',
    'ui_sort',
    'ui_protocol_filter',
    'ui_max_ping_ms',
    'ui_hide_unavailable',
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
        self.options: dict[str, Any] = copy.deepcopy(base_options)
        for key in RUNTIME_SETTING_KEYS:
            if key in runtime_options:
                self.options[key] = runtime_options[key]

        self.subscription_url = str(self.options.get('subscription_url') or '').strip()
        self.config_index = int(self.options.get('config_index', 0) or 0)
        self.listen_lan = to_bool(self.options.get('listen_lan', True))
        self.socks_tcp_a = int(self.options.get('socks_tcp_a', 10808))
        self.socks_tcp_b = int(
            self.options.get('socks_tcp_b', DEFAULT_SOCKS_TCP_B)
        )
        self.socks_udp_a = to_bool(self.options.get('socks_udp_a', True))
        self.socks_udp_b = to_bool(self.options.get('socks_udp_b', True))
        self.override_inbounds = to_bool(self.options.get('override_inbounds', True))
        self.proxy_username = str(self.options.get('proxy_username') or '')
        self.proxy_password = str(self.options.get('proxy_password') or '')
        self.disable_observatory = to_bool(self.options.get('disable_observatory', True))
        self.log_level = str(self.options.get('log_level') or 'warning')
        self.user_agent = str(self.options.get('user_agent') or 'Xray Proxy Manager Home Assistant App')
        self.validate_tags = to_bool(self.options.get('validate_routing_tags', True))
        self.auto_fix_tags = to_bool(self.options.get('auto_fix_routing_tags', True))
        self.auto_add_proxy_direct = to_bool(self.options.get('auto_add_proxy_direct', True))
        self.restart_on_runtime_error = to_bool(self.options.get('restart_on_runtime_error', True))
        self.latency_test_timeout_seconds = max(3, int(self.options.get('latency_test_timeout_seconds', 12) or 12))
        self.latency_test_url = str(self.options.get('latency_test_url') or 'https://www.gstatic.com/generate_204')
        self.health_check_url = str(self.options.get('health_check_url') or self.latency_test_url)

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
        self.auto_switch_excluded_countries = 'RU'
        self.auto_switch_min_ping_delta_ms = 100
        self.auto_check_interval_seconds = 600
        self.auto_check_failures = 3
        self.auto_check_timeout_seconds = max(3, int(self.options.get('auto_check_timeout_seconds', 12) or 12))
        self.update_interval_hours = 1
        self.ui_sort = 'ping-asc'
        self.ui_protocol_filter = 'all'
        self.ui_max_ping_ms = 1000
        self.ui_hide_unavailable = False
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
        if not self.override_inbounds:
            raise RuntimeError(
                'override_inbounds must be enabled for blue-green mode; otherwise '
                'subscription inbounds can collide between the two Xray processes.'
            )

        self.lock = threading.RLock()
        self.switch_lock = threading.Lock()
        self.router_lock = threading.Lock()
        self.stop_event = threading.Event()
        self.settings_event = threading.Event()
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
            'last_switch_at': None,
            'last_switch_reason': '',
            'auto_check_failures': 0,
            'auto_check_last_at': None,
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
        self.active_slot_tag = remembered_slot if remembered_slot in SLOT_TAGS else 'xray-a'
        self.started_at = now_ts()
        self.next_update_at = (
            now_ts() + self.update_interval_hours * 3600
            if self.update_interval_hours > 0 else None
        )
        self.server: socketserver.TCPServer | None = None
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
            'last_checked_at': None,
            'error': '',
            'auth_method': self.router_auth_method,
            'key_name': self.router_ssh_key_name if self.router_auth_method != 'password' else '',
            'public_key': '',
        }
        self.prepare_router_auth()

    def _apply_runtime_values(self, source: dict[str, Any]) -> None:
        self.subscription_url = str(source.get('subscription_url') or '').strip()
        self.auto_checker_enabled = to_bool(source.get('auto_checker_enabled', True))
        self.auto_switch_best_enabled = to_bool(source.get('auto_switch_best_enabled', True))
        self.auto_switch_excluded_countries = normalize_auto_switch_exclusions(
            source.get('auto_switch_excluded_countries', 'RU')
        )
        self.auto_switch_min_ping_delta_ms = bounded_int(
            source.get('auto_switch_min_ping_delta_ms', 100), 0, 10000, 'auto_switch_min_ping_delta_ms'
        )
        self.auto_check_interval_seconds = bounded_int(
            source.get('auto_check_interval_seconds', 600), 10, 86400, 'auto_check_interval_seconds'
        )
        self.auto_check_failures = bounded_int(
            source.get('auto_check_failures', 3), 1, 100, 'auto_check_failures'
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
            elif key in {'auto_checker_enabled', 'auto_switch_best_enabled', 'ui_hide_unavailable'}:
                normalized[key] = to_bool(value)
            elif key == 'auto_switch_excluded_countries':
                normalized[key] = normalize_auto_switch_exclusions(value)
            elif key == 'auto_switch_min_ping_delta_ms':
                normalized[key] = bounded_int(value, 0, 10000, key)
            elif key == 'auto_check_interval_seconds':
                normalized[key] = bounded_int(value, 10, 86400, key)
            elif key == 'auto_check_failures':
                normalized[key] = bounded_int(value, 1, 100, key)
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
        with self.lock:
            self.options.update(normalized)
            runtime_options = load_json(RUNTIME_OPTIONS_PATH, {})
            if not isinstance(runtime_options, dict):
                runtime_options = {}
            runtime_options.update(normalized)
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

    def save_state(self) -> None:
        self.state['active_candidate_id'] = self.active_candidate_id
        self.state['active_slot_tag'] = self.active_slot_tag
        atomic_write_json(STATE_PATH, self.state)

    def save_latencies(self) -> None:
        atomic_write_json(LATENCY_PATH, self.latencies)

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

    def reconcile_startup_selector(self, current: str) -> None:
        if not self.selector_reconciliation_pending or self.switch_lock.locked():
            return
        with self.lock:
            current_slot = self.slots[current]
            if not current_slot.running():
                return
            previous_slot_tag = self.active_slot_tag
            self.active_slot_tag = current
            self.active_candidate_id = current_slot.candidate_id
            duplicate_tag = self.other_slot_tag(current)
            duplicate = self.slots[duplicate_tag]
            duplicate_running = duplicate.running()
            if duplicate_running:
                duplicate.draining = True
                duplicate.drain_started_at = now_ts()
                duplicate.drain_zero_since = None
                duplicate.drain_protect_until = None
            self.selector_reconciliation_pending = False
            self.save_state()
        candidate = self.candidate_by_id(current_slot.candidate_id)
        if candidate:
            try:
                self.save_active_config(current, candidate)
            except Exception as exc:
                log(f'could not save reconciled last-good config: {exc}', error=True)
        if previous_slot_tag != current:
            log(f'startup selector reconciled from {previous_slot_tag} to {current}')
        elif duplicate_running:
            log(f'startup selector confirmed on {current}; extra slot will drain')
        else:
            log(f'startup selector confirmed on {current}')

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
        self.reconcile_startup_selector(current)
        if not self.selector_reconciliation_pending:
            self.restore_selector_alignment(current)
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

    def selector_status_loop(self) -> None:
        while not self.stop_event.is_set():
            self.refresh_selector_status()
            if self.stop_event.wait(self.selector_status_interval_seconds):
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
            with self.lock:
                self.router_state.update({
                    'configured': True,
                    'available': True,
                    'rule_enabled': enabled,
                    'rule_name': self.router_firewall_rule,
                    'rule_section': section,
                    'error': '',
                    'last_checked_at': now_ts(),
                })
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

    def set_router_rule(self, enabled: bool) -> None:
        if not self.router_lock.acquire(blocking=False):
            raise RuntimeError('Изменение правила уже выполняется')
        try:
            with self.lock:
                self.router_state['busy'] = True
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
                    'error': '',
                    'last_checked_at': now_ts(),
                })
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

    def download_subscription(self) -> list[dict[str, Any]]:
        with tempfile.NamedTemporaryFile(prefix='subscription.', suffix='.json', delete=False) as temp_file:
            temp_path = Path(temp_file.name)
        try:
            command = [
                CURL_BIN, '-fSL', '--connect-timeout', '20', '--max-time', '90',
                '--retry', '2', '--retry-delay', '2', '--retry-all-errors',
                '-A', self.user_agent,
                self.subscription_url,
                '-o', str(temp_path),
            ]
            result = subprocess.run(command, capture_output=True, text=True, timeout=110)
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
        if left.id == right.id or left.fingerprint == right.fingerprint:
            return True
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

        healthy = self.sorted_healthy_candidates(exclude_configured_countries=True)
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
        if selected_latency is None or (
            isinstance(improvement, int)
            and improvement >= self.auto_switch_min_ping_delta_ms
        ):
            previous_latency = f'{selected_latency} ms' if selected_latency is not None else 'unknown'
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
            listen = '0.0.0.0' if self.listen_lan else '127.0.0.1'
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

    def write_slot_config(self, slot_tag: str, candidate: Candidate) -> bool:
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
        os.replace(temp_path, slot.config_path)
        slot.candidate_id = candidate.id
        slot.candidate_name = candidate.name
        slot.candidate = candidate
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

        source_slot_tag = self.active_slot_tag
        preferred_slot = source_slot_tag
        selector_known = False
        if self.selector_control_enabled:
            try:
                preferred_slot = self.selector_status()
                selector_known = True
            except Exception as exc:
                log(f'Selector is unavailable during last-good start: {exc}', error=True)
        if preferred_slot not in SLOT_TAGS:
            preferred_slot = source_slot_tag
        if preferred_slot != source_slot_tag:
            self.clone_slot_config(source_slot_tag, preferred_slot)
        self.active_slot_tag = preferred_slot
        self.start_slot(preferred_slot)
        if not self.wait_for_port(
            self.slots[preferred_slot].socks_tcp,
            self.slots[preferred_slot].process,
            timeout=6.0,
        ):
            self.stop_slot(preferred_slot)
            raise RuntimeError(
                f'{preferred_slot} did not open SOCKS port {self.slots[preferred_slot].socks_tcp}'
            )

        if self.selector_control_enabled and not selector_known:
            safety_slot_tag = self.other_slot_tag(preferred_slot)
            self.clone_slot_config(preferred_slot, safety_slot_tag)
            self.start_slot(safety_slot_tag)
            if not self.wait_for_port(
                self.slots[safety_slot_tag].socks_tcp,
                self.slots[safety_slot_tag].process,
                timeout=6.0,
            ):
                self.stop_slot(safety_slot_tag)
                self.stop_slot(preferred_slot)
                raise RuntimeError(
                    f'{safety_slot_tag} did not open SOCKS port '
                    f'{self.slots[safety_slot_tag].socks_tcp}'
                )
            self.selector_reconciliation_pending = True
            log(
                'selector state is unknown during last-good recovery; both slots '
                'were started for safety',
                error=True,
            )
        self.save_state()

    def stop_xray(self) -> None:
        for slot_tag in SLOT_TAGS:
            self.stop_slot(slot_tag)

    def other_slot_tag(self, slot_tag: str) -> str:
        return 'xray-b' if slot_tag == 'xray-a' else 'xray-a'

    def validation_urls(self) -> list[str]:
        urls: list[str] = []
        for url in (
            self.health_check_url,
            self.latency_test_url,
            'https://cp.cloudflare.com/generate_204',
        ):
            text = str(url or '').strip()
            if text and text not in urls:
                urls.append(text)
        return urls[:2]

    def validate_slot(self, slot_tag: str) -> tuple[float, list[tuple[str, float]]]:
        slot = self.slots[slot_tag]
        if not self.wait_for_port(slot.socks_tcp, slot.process, timeout=6.0):
            raise RuntimeError(f'{slot_tag} did not open SOCKS port {slot.socks_tcp}')
        results: list[tuple[str, float]] = []
        for url in self.validation_urls():
            success, latency_ms, error = self.proxy_curl(
                '127.0.0.1',
                slot.socks_tcp,
                url,
                self.auto_check_timeout_seconds,
                auth=True,
            )
            if not success or latency_ms is None:
                raise RuntimeError(f'{slot_tag} validation failed for {url}: {error}')
            results.append((url, latency_ms))
        average = sum(item[1] for item in results) / max(1, len(results))
        return average, results

    def start_initial_candidate(self, candidate: Candidate, reason: str) -> None:
        preferred_slot = self.active_slot_tag
        selector_known = False
        if self.selector_control_enabled:
            try:
                preferred_slot = self.selector_status()
                selector_known = True
                with self.lock:
                    self.selector_state.update({
                        'available': True,
                        'current': preferred_slot,
                        'error': '',
                    })
            except Exception as exc:
                log(f'Selector is unavailable during startup: {exc}', error=True)
                with self.lock:
                    self.selector_state.update({
                        'available': False,
                        'error': str(exc),
                    })
        self.active_slot_tag = preferred_slot if preferred_slot in SLOT_TAGS else 'xray-a'
        started_slots: list[str] = []
        try:
            self.start_slot(self.active_slot_tag, candidate)
            started_slots.append(self.active_slot_tag)
            average, _checks = self.validate_slot(self.active_slot_tag)

            if self.selector_control_enabled and not selector_known:
                self.selector_reconciliation_pending = True
                log('selector state is unknown; startup keeps only the remembered active slot', error=True)

            self.active_candidate_id = candidate.id
            self.state['last_switch_at'] = now_ts()
            self.state['last_switch_reason'] = reason
            self.state['auto_check_failures'] = 0
            self.state['auto_check_last_error'] = ''
            self.latencies[candidate.id] = {
                'status': 'ok',
                'latency_ms': int(round(average)),
                'checked_at': now_ts(),
                'error': '',
            }
            try:
                self.save_latencies()
                self.save_state()
            except Exception as exc:
                log(f'could not persist initial active state: {exc}', error=True)
            try:
                self.save_active_config(self.active_slot_tag, candidate)
            except Exception as exc:
                log(f'could not save last-good active config: {exc}', error=True)
            log(f'active outbound: {candidate.name} [{candidate.outbound_tag}] via {self.active_slot_tag}')
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
    ) -> None:
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
            average, checks = self.validate_slot(standby_tag)
            log(
                f'{standby_tag} passed pre-switch validation: ' +
                ', '.join(f'{url}={latency:.0f}ms' for url, latency in checks)
            )

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
                old_slot.draining = old_slot.running()
                old_slot.drain_started_at = switched_at if old_slot.draining else None
                old_slot.drain_zero_since = None
                old_slot.drain_protect_until = (
                    switched_at + POST_SWITCH_WATCH_SECONDS if old_slot.draining else None
                )
                old_slot.drain_connections = 0
                old_slot.drain_bytes = 0
                old_slot.drain_last_error = ''
                self.state['last_switch_at'] = switched_at
                self.state['last_switch_reason'] = reason
                self.state['auto_check_failures'] = 0
                self.state['auto_check_last_error'] = ''
                self.latencies[candidate.id] = {
                    'status': 'ok',
                    'latency_ms': int(round(average)),
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
            if rollback_candidate is not None:
                threading.Thread(
                    target=self.post_switch_watch,
                    args=(
                        generation,
                        standby_tag,
                        old_slot_tag,
                        rollback_candidate,
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
    ) -> None:
        failures = 0
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
                success, _latency_ms, error = self.proxy_curl(
                    '127.0.0.1',
                    self.slots[active_slot_tag].socks_tcp,
                    self.health_check_url,
                    self.auto_check_timeout_seconds,
                    auth=True,
                )
                failures = 0 if success else failures + 1
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

    def restart_xray_for(
        self,
        candidate: Candidate,
        reason: str,
        *,
        force_reload: bool = False,
        preempt_draining: bool = False,
    ) -> None:
        with self.lock:
            active_running = self.slots[self.active_slot_tag].running()
        if not active_running:
            self.start_initial_candidate(candidate, reason)
            return
        self.switch_candidate_blue_green(
            candidate,
            reason,
            force_reload=force_reload,
            preempt_draining=preempt_draining,
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
                _selector_count, _tcp_count, udp_count, selector_bytes = self.connection_slot_stats(
                    connections, slot_tag
                )
                direct_tcp_count = self.local_tcp_connection_count(slot.socks_tcp)
                # /proc/net/tcp already contains every TCP connection accepted
                # by this SOCKS slot, including connections created by the
                # selector. Add only logical UDP sessions from the selector API
                # to avoid counting selector TCP connections twice.
                total_connections = direct_tcp_count + udp_count
                total_bytes = selector_bytes
                stop_now = False
                with self.lock:
                    previous_bytes = slot.drain_bytes
                    slot.drain_connections = total_connections
                    slot.drain_tcp_connections = direct_tcp_count
                    slot.drain_udp_connections = udp_count
                    slot.drain_bytes = total_bytes
                    slot.drain_last_error = ''
                    current_time = now_ts()
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
        if saved_slot not in SLOT_TAGS:
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
            old_candidate = (
                self.candidate_by_id(old_active_id) if old_active_id else None
            ) or self.slots[self.active_slot_tag].candidate
            old_fingerprint = old_candidate.fingerprint if old_candidate else ''
            old_name = old_candidate.name if old_candidate else ''

        downloaded = False
        try:
            configs = self.download_subscription()
            error = ''
            downloaded = True
        except Exception as exc:
            configs = self.load_cached_subscription()
            error = str(exc)
            if not configs:
                with self.lock:
                    self.state['subscription_error'] = error
                    self.state['subscription_last_error_at'] = now_ts()
                    self.save_state()
                raise
            log(f'subscription update failed; using cached subscription: {error}', error=True)

        candidates = self.extract_candidates(configs)
        if not candidates:
            raise RuntimeError('No usable proxy outbounds were found in the subscription.')

        with self.lock:
            self.subscription = configs
            self.candidates = candidates
            selected = None
            if old_fingerprint:
                selected = next((item for item in candidates if item.fingerprint == old_fingerprint), None)
            if selected is None and old_name:
                selected = next((item for item in candidates if item.name == old_name), None)
            if initial:
                selected = self.choose_initial_candidate(selected)
            elif selected is None:
                selected = self.choose_initial_candidate()
            active_slot_tag = self.active_slot_tag
            active_running = self.slots[active_slot_tag].running()
            same_candidate = selected.id == self.active_candidate_id

        force_reload = False
        with self.lock:
            active_candidate = self.slots[active_slot_tag].candidate or old_candidate
            same_outbound = self.same_outbound(selected, active_candidate)
        if downloaded and not initial and same_outbound and active_running:
            force_reload = self.runtime_config_differs(active_slot_tag, selected)
            if force_reload:
                log(
                    'subscription changed the active outbound configuration; '
                    'reload is deferred until a different outbound is selected'
                )
        should_apply = (
            initial
            or not same_outbound
            or not active_running
        )

        try:
            if should_apply:
                self.restart_xray_for(
                    selected,
                    'initial start' if initial else 'subscription refresh',
                    force_reload=force_reload,
                )
            else:
                with self.lock:
                    self.active_candidate_id = selected.id
                    active_slot = self.slots[self.active_slot_tag]
                    active_slot.candidate_id = selected.id
                    active_slot.candidate_name = selected.name
                    active_slot.candidate = selected
                    self.save_state()
        except Exception:
            with self.lock:
                self.subscription = old_subscription
                self.candidates = old_candidates
                self.active_candidate_id = old_active_id
                self.state['active_candidate_id'] = old_active_id
                self.state['subscription_error'] = (
                    'Downloaded subscription could not be applied; previous working subscription was preserved.'
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
            else:
                self.state['subscription_error'] = error
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
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(('127.0.0.1', 0))
            return int(sock.getsockname()[1])

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
                        success, latency_ms, error_text = self.proxy_curl(
                            '127.0.0.1',
                            port,
                            self.latency_test_url,
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
            job.update({'running': True, 'progress': 0, 'total': len(candidates), 'message': 'Проверка доступности...'})
            self.save_state()

        fresh_results: dict[str, dict[str, Any]] = {}
        final_message = 'Проверка завершена'
        try:
            for index, candidate in enumerate(candidates, start=1):
                if self.stop_event.is_set():
                    break
                result = self.test_candidate(candidate)
                fresh_results[candidate.id] = result
                with self.lock:
                    self.latencies[candidate.id] = result
                    self.save_latencies()
                    job = self.state['jobs']['latency']
                    job.update({
                        'progress': index,
                        'message': f'{candidate.name}: ' + (
                            f'{result["latency_ms"]} мс' if result['status'] == 'ok' else 'недоступен'
                        ),
                    })
                    self.save_state()

            if source == 'auto-check':
                with self.lock:
                    self.state['auto_check_last_at'] = now_ts()
                    self.save_state()

            if switch_to_best and fresh_results and not self.stop_event.is_set():
                healthy: list[tuple[int, str, Candidate]] = []
                for candidate in candidates:
                    result = fresh_results.get(candidate.id) or {}
                    latency_ms = result.get('latency_ms')
                    if result.get('status') != 'ok' or not isinstance(latency_ms, int):
                        continue
                    if self.candidate_is_excluded(candidate):
                        continue
                    healthy.append((latency_ms, candidate.name.casefold(), candidate))
                healthy.sort(key=lambda item: (item[0], item[1]))

                if healthy:
                    best_latency, _best_name, best_candidate = healthy[0]
                    with self.lock:
                        effective, selected, _mismatch = self.effective_active_candidate()
                        current = selected or effective
                        current_result = fresh_results.get(current.id) if current else None
                        current_latency = (
                            current_result.get('latency_ms')
                            if isinstance(current_result, dict) and current_result.get('status') == 'ok'
                            else None
                        )

                    ping_difference = (
                        current_latency - best_latency
                        if isinstance(current_latency, int) else None
                    )
                    should_switch = (
                        current is None
                        or (
                            not self.same_outbound(current, best_candidate)
                            and (
                                not isinstance(current_latency, int)
                                or ping_difference >= self.auto_switch_min_ping_delta_ms
                            )
                        )
                    )
                    if should_switch:
                        self.restart_xray_for(
                            best_candidate,
                            f'automatic best latency after periodic check: {best_latency} ms',
                        )
                        final_message = f'Проверка завершена · выбран {best_candidate.name} ({best_latency} мс)'
                        log(
                            f'periodic latency check switched to {best_candidate.name} '
                            f'({best_latency} ms, difference {ping_difference} ms)'
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
                    excluded_text = self.auto_switch_excluded_countries or 'нет'
                    final_message = (
                        'Проверка завершена · подходящие outbound не найдены '
                        f'(исключения автоматики: {excluded_text})'
                    )
        except Exception as exc:
            final_message = f'Ошибка проверки: {exc}'
            log(f'latency job error: {exc}', error=True)
        finally:
            with self.lock:
                self.state['jobs']['latency'].update({'running': False, 'message': final_message})
                if source == 'manual':
                    # Wake the periodic checker after the manual test has fully
                    # completed. Its next wait therefore starts from this moment.
                    self.state['auto_check_last_at'] = now_ts()
                    self.settings_event.set()
                self.save_state()

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
            })
            self.save_state()
            threading.Thread(
                target=self.latency_job,
                args=(candidate_ids, switch_to_best, source),
                daemon=True,
            ).start()
            return True

    def check_active_tunnel(self) -> tuple[bool, float | None, str]:
        active_port = self.slots[self.active_slot_tag].socks_tcp
        return self.proxy_curl(
            '127.0.0.1',
            active_port,
            self.health_check_url,
            self.auto_check_timeout_seconds,
            auth=True,
        )

    def excluded_country_codes(self) -> set[str]:
        country_codes, _fragments = parse_auto_switch_exclusions(
            self.auto_switch_excluded_countries
        )
        return country_codes

    def excluded_outbound_fragments(self) -> list[str]:
        _country_codes, fragments = parse_auto_switch_exclusions(
            self.auto_switch_excluded_countries
        )
        return fragments

    def candidate_is_excluded(self, candidate: Candidate) -> bool:
        country_codes, fragments = parse_auto_switch_exclusions(
            self.auto_switch_excluded_countries
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
            if data.get('status') == 'ok' and isinstance(data.get('latency_ms'), int):
                healthy.append((data['latency_ms'], candidate))
        healthy.sort(key=lambda item: (item[0], item[1].name.casefold()))
        return [item[1] for item in healthy]

    def choose_failover_candidate(self) -> Candidate | None:
        excluded_text = self.auto_switch_excluded_countries or 'нет'
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
                success, latency_ms, error = self.check_active_tunnel()
                checked_at = now_ts()
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
                    if self.auto_switch_best_enabled:
                        accepted = self.request_latency_test(
                            None,
                            switch_to_best=True,
                            source='auto-check',
                        )
                        if not accepted:
                            log('periodic outbound check skipped because another latency test is running')
                    continue

                failures = int(self.state.get('auto_check_failures') or 0)
                log(f'auto-check failed ({failures}/{self.auto_check_failures}): {error}', error=True)
                if failures < self.auto_check_failures:
                    continue

                candidate = self.choose_failover_candidate()
                if candidate is None:
                    excluded_text = self.auto_switch_excluded_countries or 'нет'
                    log(
                        'auto-check could not find a healthy failover outbound outside configured exclusions: '
                        f'{excluded_text}',
                        error=True,
                    )
                    continue
                self.restart_xray_for(candidate, f'auto failover after {failures} consecutive errors')
                log(f'auto-check switched to {candidate.name}', error=True)
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
            if match is None and slot.candidate is not None:
                match = next(
                    (item for item in self.candidates if self.same_outbound(item, slot.candidate)),
                    None,
                )
            if match is None and slot.candidate_id:
                match = self.candidate_by_id(slot.candidate_id)
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
                    if slot.running() and self.same_outbound(item, slot.candidate or self.candidate_by_id(slot.candidate_id))
                ]
                draining_slots = [
                    tag for tag in assigned_slots if self.slots[tag].draining
                ]
                is_active = self.same_outbound(item, active_slot_candidate)
                payload = item.public(self.latencies.get(item.id), is_active)
                payload['slot_tags'] = assigned_slots
                payload['draining_slots'] = draining_slots
                payload['draining'] = bool(draining_slots)
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
                    'observed_outbound_tag': slot.observed_outbound_tag,
                    'observed_outbound_at': slot.observed_outbound_at,
                }
            return {
                'version': ADDON_VERSION,
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
                    'next_update_at': self.next_update_at,
                    'url': self.subscription_url,
                    'update_interval_hours': self.update_interval_hours,
                },
                'jobs': copy.deepcopy(self.state.get('jobs') or {}),
                'auto_checker': {
                    'enabled': self.auto_checker_enabled,
                    'switch_to_best': self.auto_switch_best_enabled,
                    'excluded_countries': self.auto_switch_excluded_countries,
                    'min_ping_delta_ms': self.auto_switch_min_ping_delta_ms,
                    'interval_seconds': self.auto_check_interval_seconds,
                    'failure_threshold': self.auto_check_failures,
                    'current_failures': int(self.state.get('auto_check_failures') or 0),
                    'last_check_at': self.state.get('auto_check_last_at'),
                    'last_error': self.state.get('auto_check_last_error') or '',
                    'last_switch_at': self.state.get('last_switch_at'),
                    'last_switch_reason': self.state.get('last_switch_reason') or '',
                },
                'ui_settings': {
                    'sort': self.ui_sort,
                    'protocol_filter': self.ui_protocol_filter,
                    'max_ping_ms': self.ui_max_ping_ms,
                    'hide_unavailable': self.ui_hide_unavailable,
                },
                'selector': copy.deepcopy(self.selector_state),
                'router': copy.deepcopy(self.router_state),
                'blue_green': {
                    'active_slot': self.active_slot_tag,
                    'selector_tag': self.selector_tag,
                    'drain_quiet_seconds': self.drain_quiet_seconds,
                    'drain_timeout_minutes': self.drain_timeout_minutes,
                    'slots': slots_payload,
                },
                'latency_test_url': self.latency_test_url,
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
        threading.Thread(target=self.auto_checker_loop, daemon=True).start()
        threading.Thread(target=self.periodic_update_loop, daemon=True).start()
        threading.Thread(target=self.xray_monitor_loop, daemon=True).start()
        threading.Thread(target=self.drain_monitor_loop, daemon=True).start()
        threading.Thread(target=self.selector_status_loop, daemon=True).start()
        threading.Thread(target=self.router_status_loop, daemon=True).start()

        handler_factory = lambda *args, **kwargs: WebHandler(self, *args, **kwargs)
        self.server = ThreadingHTTPServer(('0.0.0.0', UI_PORT), handler_factory)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        log(f'web UI is listening on 0.0.0.0:{UI_PORT}')

        while not self.stop_event.wait(1):
            pass

    def shutdown(self) -> None:
        self.stop_event.set()
        self.settings_event.set()
        if self.server:
            self.server.shutdown()
        self.stop_xray()


class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class WebHandler(http.server.BaseHTTPRequestHandler):
    server_version = f'XrayProxyManager/{ADDON_VERSION}'

    def __init__(self, manager: XrayManager, *args: Any, **kwargs: Any) -> None:
        self.manager = manager
        super().__init__(*args, **kwargs)

    def log_message(self, fmt: str, *args: Any) -> None:
        return

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
