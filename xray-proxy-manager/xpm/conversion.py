from __future__ import annotations

import copy
from typing import Any
from . import common as xpm_common


SING_BOX_PROFILE_NAME = 'Sing-box subscription'


SING_BOX_DOWNLOAD_FILENAME = f'{SING_BOX_PROFILE_NAME}.json'


SING_BOX_SUPPORTED_PROTOCOLS = {'vless', 'vmess', 'trojan', 'shadowsocks', 'socks', 'http'}


SING_BOX_SUPPORTED_TRANSPORTS = {'tcp', 'raw', 'ws', 'grpc', 'http', 'h2', 'httpupgrade'}


SING_BOX_FINGERPRINTS = {
    'chrome', 'firefox', 'edge', 'safari', '360', 'qq', 'ios', 'android', 'random', 'randomized'
}


SING_BOX_CHROME_FINGERPRINT_ALIASES = {
    'chrome_psk', 'chrome_psk_shuffle', 'chrome_padding_psk_shuffle',
    'chrome_pq', 'chrome_pq_psk',
}


def _sing_box_nonempty(value: Any) -> bool:
    return value is not None and value != '' and value != [] and value != {}


def _sing_box_compact(value: Any) -> Any:
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in value.items():
            compacted = _sing_box_compact(item)
            if _sing_box_nonempty(compacted):
                result[key] = compacted
        return result
    if isinstance(value, list):
        return [_sing_box_compact(item) for item in value]
    return value


def _sing_box_as_array(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _sing_box_as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in {'1', 'true', 'yes', 'on'}
    return False


def _sing_box_as_number(value: Any) -> int | float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            number = float(text) if any(char in text for char in '.eE') else int(text)
        except ValueError:
            return None
        return number
    return None


def _sing_box_lower(value: Any) -> str:
    return str(value if value is not None else '').lower()


def _sing_box_profiles(source: Any) -> list[dict[str, Any]]:
    if isinstance(source, dict):
        return [source]
    if isinstance(source, list):
        return [item for item in source if isinstance(item, dict)]
    return []


def _sing_box_profile_name(profile: dict[str, Any], profile_index: int) -> str:
    value = profile.get('remarks') or profile.get('name') or profile.get('tag') or f'Profile {profile_index + 1}'
    return str(value)


def _sing_box_proxy_outbounds(profile: dict[str, Any]) -> list[dict[str, Any]]:
    outbounds = profile.get('outbounds')
    if not isinstance(outbounds, list):
        return []
    return [
        outbound for outbound in outbounds
        if isinstance(outbound, dict)
        and _sing_box_lower(outbound.get('protocol')) in SING_BOX_SUPPORTED_PROTOCOLS
    ]


def _sing_box_transport_name(outbound: dict[str, Any]) -> str:
    stream = outbound.get('streamSettings')
    if not isinstance(stream, dict):
        stream = {}
    return _sing_box_lower(stream.get('network') or 'tcp')


def _sing_box_transport_reason(outbound: dict[str, Any]) -> str:
    network = _sing_box_transport_name(outbound)
    if network not in SING_BOX_SUPPORTED_TRANSPORTS:
        return f'unsupported transport: {network}'
    if network in {'tcp', 'raw'}:
        stream = outbound.get('streamSettings')
        stream = stream if isinstance(stream, dict) else {}
        tcp = stream.get('tcpSettings')
        tcp = tcp if isinstance(tcp, dict) else {}
        header = tcp.get('header')
        header = header if isinstance(header, dict) else {}
        if _sing_box_lower(header.get('type') or 'none') != 'none':
            return 'TCP header camouflage is not supported by sing-box'
    return ''


def _sing_box_first_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, list) and value and isinstance(value[0], dict):
        return value[0]
    return {}


def _sing_box_endpoint_ok(outbound: dict[str, Any]) -> bool:
    protocol = _sing_box_lower(outbound.get('protocol'))
    settings = outbound.get('settings')
    settings = settings if isinstance(settings, dict) else {}
    if protocol in {'vless', 'vmess'}:
        server = _sing_box_first_dict(settings.get('vnext'))
        user = _sing_box_first_dict(server.get('users'))
        return bool(str(server.get('address') or '')) and _sing_box_as_number(server.get('port')) is not None and bool(str(user.get('id') or ''))
    if protocol in {'trojan', 'shadowsocks', 'socks', 'http'}:
        server = _sing_box_first_dict(settings.get('servers'))
        has_endpoint = bool(str(server.get('address') or server.get('server') or '')) and _sing_box_as_number(server.get('port')) is not None
        if not has_endpoint:
            return False
        if protocol == 'trojan':
            return bool(str(server.get('password') or ''))
        if protocol == 'shadowsocks':
            return bool(str(server.get('method') or '')) and bool(str(server.get('password') or ''))
        return True
    return False


def _sing_box_normalize_fingerprint(value: Any) -> str:
    fingerprint = _sing_box_lower(value)
    if fingerprint in SING_BOX_FINGERPRINTS:
        return fingerprint
    if fingerprint in SING_BOX_CHROME_FINGERPRINT_ALIASES:
        return 'chrome'
    return ''


def _sing_box_make_tls(outbound: dict[str, Any]) -> dict[str, Any] | None:
    stream = outbound.get('streamSettings')
    stream = stream if isinstance(stream, dict) else {}
    security = _sing_box_lower(stream.get('security') or 'none')
    tls = stream.get('tlsSettings')
    tls = tls if isinstance(tls, dict) else {}
    reality = stream.get('realitySettings')
    reality = reality if isinstance(reality, dict) else {}

    if security == 'tls':
        fingerprint = _sing_box_normalize_fingerprint(tls.get('fingerprint') or stream.get('fingerprint'))
        return _sing_box_compact({
            'enabled': True,
            'server_name': tls.get('serverName') or tls.get('server_name') or '',
            'insecure': _sing_box_as_bool(tls.get('allowInsecure', tls.get('insecure', False))),
            'alpn': _sing_box_as_array(tls.get('alpn')),
            'utls': {'enabled': True, 'fingerprint': fingerprint} if fingerprint else None,
        })
    if security == 'reality':
        fingerprint = _sing_box_normalize_fingerprint(reality.get('fingerprint') or stream.get('fingerprint'))
        return _sing_box_compact({
            'enabled': True,
            'server_name': reality.get('serverName') or reality.get('server_name') or '',
            'alpn': _sing_box_as_array(reality.get('alpn')),
            'utls': {'enabled': True, 'fingerprint': fingerprint} if fingerprint else None,
            'reality': {
                'enabled': True,
                'public_key': reality.get('publicKey') or reality.get('public_key') or '',
                'short_id': reality.get('shortId') or reality.get('short_id') or '',
            },
        })
    return None


def _sing_box_make_transport(outbound: dict[str, Any]) -> dict[str, Any] | None:
    stream = outbound.get('streamSettings')
    stream = stream if isinstance(stream, dict) else {}
    network = _sing_box_lower(stream.get('network') or 'tcp')

    if network == 'ws':
        ws = stream.get('wsSettings')
        ws = ws if isinstance(ws, dict) else {}
        headers = ws.get('headers')
        headers = copy.deepcopy(headers) if isinstance(headers, dict) else {}
        host = str(ws.get('host') or headers.get('Host') or headers.get('host') or '')
        headers.pop('Host', None)
        headers.pop('host', None)
        if host:
            headers['Host'] = host
        return _sing_box_compact({
            'type': 'ws',
            'path': ws.get('path') or '',
            'headers': headers,
            'max_early_data': _sing_box_as_number(ws.get('maxEarlyData', ws.get('max_early_data', 0))),
            'early_data_header_name': ws.get('earlyDataHeaderName') or ws.get('early_data_header_name') or '',
        })
    if network == 'grpc':
        grpc = stream.get('grpcSettings')
        grpc = grpc if isinstance(grpc, dict) else {}
        return _sing_box_compact({
            'type': 'grpc',
            'service_name': grpc.get('serviceName') or grpc.get('service_name') or '',
            'idle_timeout': grpc.get('idleTimeout') or grpc.get('idle_timeout') or '',
            'ping_timeout': grpc.get('healthCheckTimeout') or grpc.get('ping_timeout') or '',
            'permit_without_stream': _sing_box_as_bool(grpc.get('permitWithoutStream', grpc.get('permit_without_stream', False))),
        })
    if network in {'http', 'h2'}:
        http_settings = stream.get('httpSettings')
        http_settings = http_settings if isinstance(http_settings, dict) else {}
        headers = http_settings.get('headers')
        headers = headers if isinstance(headers, dict) else {}
        return _sing_box_compact({
            'type': 'http',
            'host': _sing_box_as_array(http_settings.get('host')),
            'path': http_settings.get('path') or '',
            'method': http_settings.get('method') or '',
            'headers': copy.deepcopy(headers),
        })
    if network == 'httpupgrade':
        upgrade = stream.get('httpupgradeSettings') or stream.get('httpUpgradeSettings')
        upgrade = upgrade if isinstance(upgrade, dict) else {}
        headers = upgrade.get('headers')
        headers = headers if isinstance(headers, dict) else {}
        return _sing_box_compact({
            'type': 'httpupgrade',
            'host': upgrade.get('host') or '',
            'path': upgrade.get('path') or '',
            'headers': copy.deepcopy(headers),
        })
    return None


def _sing_box_make_node(entry: dict[str, Any]) -> dict[str, Any] | None:
    outbound = entry['outbound']
    protocol = _sing_box_lower(outbound.get('protocol'))
    tag = entry['tag']
    settings = outbound.get('settings')
    settings = settings if isinstance(settings, dict) else {}

    if protocol in {'vless', 'vmess'}:
        server = _sing_box_first_dict(settings.get('vnext'))
        user = _sing_box_first_dict(server.get('users'))
        node: dict[str, Any] = {
            'type': protocol,
            'tag': tag,
            'server': server.get('address'),
            'server_port': _sing_box_as_number(server.get('port')),
            'uuid': user.get('id'),
        }
        if protocol == 'vless':
            node['flow'] = user.get('flow') or ''
        else:
            node['security'] = user.get('security') or 'auto'
            node['alter_id'] = _sing_box_as_number(user.get('alterId', user.get('alter_id', 0)))
        node['tls'] = _sing_box_make_tls(outbound)
        node['transport'] = _sing_box_make_transport(outbound)
        return _sing_box_compact(node)

    server = _sing_box_first_dict(settings.get('servers'))
    if protocol == 'trojan':
        return _sing_box_compact({
            'type': 'trojan',
            'tag': tag,
            'server': server.get('address') or server.get('server'),
            'server_port': _sing_box_as_number(server.get('port')),
            'password': server.get('password'),
            'tls': _sing_box_make_tls(outbound),
            'transport': _sing_box_make_transport(outbound),
        })
    if protocol == 'shadowsocks':
        return _sing_box_compact({
            'type': 'shadowsocks',
            'tag': tag,
            'server': server.get('address') or server.get('server'),
            'server_port': _sing_box_as_number(server.get('port')),
            'method': server.get('method'),
            'password': server.get('password'),
            'plugin': server.get('plugin') or '',
            'plugin_opts': server.get('pluginOpts') or server.get('plugin_opts') or '',
        })
    user = _sing_box_first_dict(server.get('users'))
    if protocol == 'socks':
        return _sing_box_compact({
            'type': 'socks',
            'tag': tag,
            'server': server.get('address') or server.get('server'),
            'server_port': _sing_box_as_number(server.get('port')),
            'version': '4' if str(server.get('version', 5)) == '4' else '5',
            'username': user.get('user') or user.get('username') or '',
            'password': user.get('pass') or user.get('password') or '',
        })
    if protocol == 'http':
        return _sing_box_compact({
            'type': 'http',
            'tag': tag,
            'server': server.get('address') or server.get('server'),
            'server_port': _sing_box_as_number(server.get('port')),
            'username': user.get('user') or user.get('username') or '',
            'password': user.get('pass') or user.get('password') or '',
            'tls': _sing_box_make_tls(outbound),
        })
    return None


def convert_xray_subscription_to_sing_box(
    source: Any,
    *,
    test_url: str = xpm_common.DEFAULT_PRIMARY_TEST_URL,
    test_interval: str = '5m',
    test_tolerance: int = 50,
) -> tuple[dict[str, Any], dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for profile_index, profile in enumerate(_sing_box_profiles(source)):
        outbounds = _sing_box_proxy_outbounds(profile)
        profile_name = _sing_box_profile_name(profile, profile_index)
        for outbound_index, outbound in enumerate(outbounds):
            outbound_name = str(outbound.get('remarks') or outbound.get('name') or outbound.get('tag') or profile_name)
            name = f'{profile_name} — {outbound_name}' if len(outbounds) > 1 else outbound_name
            entries.append({
                'profile_index': profile_index,
                'outbound_index': outbound_index,
                'outbound': outbound,
                'name': name,
            })

    for index, entry in enumerate(entries, start=1):
        entry['tag'] = f'{index} - {entry["name"]}'

    nodes: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    for entry in entries:
        outbound = entry['outbound']
        transport_error = _sing_box_transport_reason(outbound)
        if transport_error or not _sing_box_endpoint_ok(outbound):
            skipped.append({
                'name': entry['name'],
                'protocol': outbound.get('protocol') or 'unknown',
                'reason': transport_error or 'required endpoint or credential field is missing',
            })
            continue
        node = _sing_box_make_node(entry)
        if node is not None:
            nodes.append(node)

    if not nodes:
        details = '; '.join(
            f'{item["name"]} [{item["protocol"]}]: {item["reason"]}' for item in skipped
        )
        message = 'No supported proxy outbounds could be converted.'
        if details:
            message += f' {details}'
        raise ValueError(message)

    node_tags = [str(node['tag']) for node in nodes]
    config = _sing_box_compact({
        'log': {'level': 'error', 'timestamp': True},
        'inbounds': [
            {
                'type': 'socks',
                'tag': 'socks-in',
                'listen': '127.0.0.1',
                'listen_port': 1080,
            },
        ],
        'outbounds': nodes + [
            {
                'type': 'urltest',
                'tag': 'auto',
                'outbounds': node_tags,
                'url': test_url,
                'interval': test_interval,
                'tolerance': test_tolerance,
                'interrupt_exist_connections': True,
            },
            {
                'type': 'selector',
                'tag': 'proxy',
                'outbounds': ['auto', *node_tags],
                'default': 'auto',
                'interrupt_exist_connections': True,
            },
            {'type': 'direct', 'tag': 'direct'},
            {'type': 'block', 'tag': 'block'},
        ],
        'route': {
            'auto_detect_interface': True,
            'final': 'proxy',
        },
    })
    metadata = {
        'name': SING_BOX_PROFILE_NAME,
        'filename': SING_BOX_DOWNLOAD_FILENAME,
        'converted_count': len(nodes),
        'skipped': skipped,
    }
    return config, metadata
