from __future__ import annotations

import copy
from typing import Any, Iterable
from . import common as xpm_common


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
    return xpm_common.first_text(
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
        tag = xpm_common.first_text(outbound.get('tag'))
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
