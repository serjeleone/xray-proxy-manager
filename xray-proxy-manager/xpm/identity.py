from __future__ import annotations

import copy
import hashlib
import json
from typing import Any
from . import config as xpm_config


def config_hash(value: Any) -> str:
    return hashlib.sha256(json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(',', ':'),
    ).encode('utf-8')).hexdigest()


def technical_outbound(outbound: dict[str, Any]) -> dict[str, Any]:
    return {
        key: copy.deepcopy(value) for key, value in outbound.items()
        if key not in {'tag', 'remarks', 'remark', 'name', 'ps', 'title', 'metadata'}
    }


def candidate_identity_key(outbound: dict[str, Any]) -> str:
    """Endpoint and account identity; transport/routing changes are revisions."""
    server, port = xpm_config.extract_endpoint(outbound)
    settings = outbound.get('settings') or {}
    endpoint = next(iter(settings.get('vnext') or settings.get('servers') or [settings]), {})
    users = endpoint.get('users') or [endpoint]
    accounts = [{
        key: user[key] for key in ('id', 'user', 'username', 'password', 'method')
        if key in user
    } for user in users if isinstance(user, dict)]
    return config_hash({
        'protocol': str(outbound.get('protocol') or '').lower(),
        'server': server.casefold().rstrip('.'), 'port': port,
        'accounts': sorted(accounts, key=config_hash),
    })


def candidate_config_revision(config: dict[str, Any], selected_tag: str) -> str:
    """Hash effective technical configuration, canonicalizing outbound tag labels."""
    config = copy.deepcopy(config)
    for key in ('remarks', 'remark', 'name', 'ps', 'title', 'metadata', 'inbounds',
                'api', 'stats', 'metrics', 'observatory', 'burstObservatory'):
        config.pop(key, None)
    config.pop('log', None)
    outbounds = config.get('outbounds') or []
    by_tag = {item.get('tag'): item for item in outbounds if isinstance(item, dict)}

    def canonical_references(value: Any, resolve) -> Any:
        if isinstance(value, list):
            return [canonical_references(item, resolve) for item in value]
        if not isinstance(value, dict):
            return value
        result = {key: canonical_references(item, resolve) for key, item in value.items()}
        for key in ('outboundTag', 'dialerProxy', 'fallbackTag'):
            if isinstance(result.get(key), str):
                result[key] = resolve(result[key])
        proxy = result.get('proxySettings')
        if isinstance(proxy, dict) and isinstance(proxy.get('tag'), str):
            proxy['tag'] = resolve(proxy['tag'])
        return result

    def node_signature(tag: str, stack: tuple[str, ...] = ()) -> Any:
        if tag not in by_tag:
            return tag
        if tag in stack:
            return {'cycle': len(stack) - stack.index(tag)}
        return canonical_references(
            technical_outbound(by_tag[tag]),
            lambda reference: node_signature(reference, (*stack, tag)),
        )

    tags = {tag: config_hash(node_signature(tag)) for tag in by_tag}
    for item in outbounds:
        if not isinstance(item, dict):
            continue
        tag = item.get('tag')
        technical = technical_outbound(item)
        item.clear()
        item.update(technical)
        item['tag'] = tags.get(tag, tag)
    config = canonical_references(config, lambda tag: tags.get(tag, tag))
    # Balancer selectors are tag prefixes. Hash the nodes they actually select.
    for balancer in (config.get('routing') or {}).get('balancers', []):
        if isinstance(balancer, dict) and isinstance(balancer.get('selector'), list):
            prefixes = balancer['selector']
            balancer['selector'] = sorted({
                signature for tag, signature in tags.items()
                if any(tag.startswith(prefix) for prefix in prefixes)
            })
    outbounds = config['outbounds']
    config['outbounds'] = sorted(outbounds, key=config_hash)
    return config_hash({'config': config, 'selected': tags.get(selected_tag, selected_tag)})
