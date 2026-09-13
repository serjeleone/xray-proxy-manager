from __future__ import annotations

import copy
from collections import deque
import math
import os
import re
import sys
import threading
import time
from dataclasses import field
from pathlib import Path
from typing import Any


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


ADAPTIVE_DRAIN_GRACE_SECONDS = 5


ADAPTIVE_DRAIN_IDLE_POLLS = 3


ADAPTIVE_DRAIN_HARD_TIMEOUT_SECONDS = 30


SWITCHING_PRESETS = {'smooth', 'adaptive', 'forced'}


ADDON_VERSION = (Path(__file__).resolve().parents[1] / 'VERSION').read_text(encoding='utf-8').strip()


ADDON_COMMIT = os.environ.get('XPM_BUILD_COMMIT', '').strip()[:7]


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
    'switching_preset',
    'auto_switch_preferred_country',
    'auto_switch_preferred_protocol',
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


LOG_TIMESTAMP_RE = re.compile(r'^(\d{4})[/-](\d{2})[/-](\d{2})[ T](\d{2}:\d{2}:\d{2})(?:\.\d+)?\s+')


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


def normalize_switching_preset(value: Any) -> str:
    preset = str(value or 'smooth').strip().lower()
    if preset not in SWITCHING_PRESETS:
        raise ValueError('switching_preset must be smooth, adaptive or forced')
    return preset


def normalize_preferred_protocol(value: Any) -> str:
    text = str(value or '').strip().upper()
    if not text:
        return ''
    if len(text) > 32 or not re.fullmatch(r'[A-Z0-9][A-Z0-9+._-]*', text):
        raise ValueError(f'Некорректный предпочитаемый протокол: {text}')
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
            rf'^##\s+(?:Версия\s+)?v?{re.escape(ADDON_VERSION)}\s*$\n(.*?)(?=^##\s+|\Z)',
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


def log(message: str, *, error: bool = False, prefix: str = LOG_PREFIX) -> None:
    """Write identical, complete lines to the UI and container output."""
    stream = sys.stderr if error else sys.stdout
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
    lines = []
    for text in ANSI_ESCAPE_RE.sub('', str(message)).splitlines():
        text = normalize_xray_log_line(text).rstrip()
        if not text.strip():
            continue
        match = LOG_TIMESTAMP_RE.match(text)
        if match:
            year, month, day, clock = match.groups()
            timestamp = f'{year}-{month}-{day} {clock}'
            text = text[match.end():]
        lines.append(f'{timestamp} {prefix} {text}')
    if lines:
        # The same lock keeps messages from concurrent slot readers intact in
        # both destinations, including multiline failures and tracebacks.
        with LOG_BUFFER_LOCK:
            LOG_BUFFER.extend(lines)
            print('\n'.join(lines), file=stream, flush=True)


def now_ts() -> int:
    return int(time.time())


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


def bounded_float(value: Any, minimum: float, maximum: float, field: str) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f'{field}: требуется число') from exc
    if not math.isfinite(parsed):
        raise ValueError(f'{field}: требуется конечное число')
    if parsed < minimum or parsed > maximum:
        raise ValueError(f'{field}: допустимый диапазон {minimum:g}–{maximum:g}')
    return parsed
