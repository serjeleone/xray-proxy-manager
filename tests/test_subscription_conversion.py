from __future__ import annotations

import pytest


def _vnext(protocol, *, tag, address, port, uuid, stream=None, **user_extra):
    user = {"id": uuid, **user_extra}
    outbound = {
        "tag": tag,
        "protocol": protocol,
        "settings": {"vnext": [{"address": address, "port": port, "users": [user]}]},
    }
    if stream is not None:
        outbound["streamSettings"] = stream
    return outbound


def _server(protocol, *, tag, address, port, stream=None, **server_extra):
    outbound = {
        "tag": tag,
        "protocol": protocol,
        "settings": {"servers": [{"address": address, "port": port, **server_extra}]},
    }
    if stream is not None:
        outbound["streamSettings"] = stream
    return outbound


def test_convert_subscription_protocols_transports_tls_and_groups(m):
    source = [{
        "remarks": "Main profile",
        "outbounds": [
            _vnext(
                "vless",
                tag="reality",
                address="reality.example",
                port="443",
                uuid="11111111-1111-1111-1111-111111111111",
                flow="xtls-rprx-vision",
                stream={
                    "network": "tcp",
                    "security": "reality",
                    "realitySettings": {
                        "serverName": "www.example.com",
                        "publicKey": "public-key",
                        "shortId": "abcd",
                        "fingerprint": "chrome_pq",
                        "alpn": "h2",
                    },
                },
            ),
            _vnext(
                "vmess",
                tag="websocket",
                address="ws.example",
                port=443,
                uuid="22222222-2222-2222-2222-222222222222",
                security="auto",
                alterId="0",
                stream={
                    "network": "ws",
                    "security": "tls",
                    "tlsSettings": {
                        "serverName": "cdn.example",
                        "allowInsecure": "yes",
                        "alpn": ["http/1.1"],
                        "fingerprint": "firefox",
                    },
                    "wsSettings": {
                        "path": "/ws",
                        "headers": {"Host": "edge.example", "X-Test": "1"},
                        "maxEarlyData": "2048",
                        "earlyDataHeaderName": "Sec-WebSocket-Protocol",
                    },
                },
            ),
            _server(
                "trojan",
                tag="grpc",
                address="trojan.example",
                port=443,
                password="secret",
                stream={
                    "network": "grpc",
                    "security": "tls",
                    "tlsSettings": {"server_name": "trojan.example", "insecure": 0},
                    "grpcSettings": {
                        "serviceName": "svc",
                        "idleTimeout": "30s",
                        "healthCheckTimeout": "10s",
                        "permitWithoutStream": 1,
                    },
                },
            ),
            _server(
                "shadowsocks",
                tag="ss",
                address="ss.example",
                port=8388,
                method="2022-blake3-aes-128-gcm",
                password="ss-secret",
                plugin="obfs-local",
                pluginOpts="obfs=http",
            ),
            _server(
                "socks",
                tag="socks",
                address="socks.example",
                port=1080,
                version=4,
                users=[{"username": "user", "password": "pass"}],
            ),
            _vnext(
                "vless",
                tag="h2",
                address="h2.example",
                port=443,
                uuid="55555555-5555-5555-5555-555555555555",
                stream={
                    "network": "h2",
                    "httpSettings": {
                        "host": ["h2.example"],
                        "path": "/tunnel",
                        "method": "PUT",
                        "headers": {"X-Test": ["yes"]},
                    },
                },
            ),
            _server(
                "http",
                tag="http",
                address="http.example",
                port=8080,
                users=[{"user": "alice", "pass": "pw"}],
                stream={
                    "network": "h2",
                    "security": "tls",
                    "tlsSettings": {"serverName": "http.example", "fingerprint": "unknown"},
                    "httpSettings": {
                        "host": ["h2.example"],
                        "path": "/tunnel",
                        "method": "PUT",
                        "headers": {"X-Test": ["yes"]},
                    },
                },
            ),
            _vnext(
                "vless",
                tag="upgrade",
                address="upgrade.example",
                port=443,
                uuid="33333333-3333-3333-3333-333333333333",
                stream={
                    "network": "httpupgrade",
                    "httpUpgradeSettings": {
                        "host": "upgrade-host.example",
                        "path": "/upgrade",
                        "headers": {"X-Up": "1"},
                    },
                },
            ),
            {"tag": "direct", "protocol": "freedom"},
        ],
    }]

    config, metadata = m.convert_xray_subscription_to_sing_box(
        source,
        test_url="https://probe.example/204",
        test_interval="10m",
        test_tolerance=75,
    )

    assert metadata == {
        "name": "Sing-box subscription",
        "filename": "Sing-box subscription.json",
        "converted_count": 8,
        "skipped": [],
    }
    assert config["log"] == {"level": "error", "timestamp": True}
    assert config["inbounds"] == [{
        "type": "socks",
        "tag": "socks-in",
        "listen": "127.0.0.1",
        "listen_port": 1080,
    }]
    nodes = config["outbounds"][:-4]
    assert [node["type"] for node in nodes] == [
        "vless", "vmess", "trojan", "shadowsocks", "socks", "vless", "http", "vless"
    ]
    assert nodes[0]["flow"] == "xtls-rprx-vision"
    assert nodes[0]["tls"]["utls"]["fingerprint"] == "chrome"
    assert nodes[0]["tls"]["reality"] == {
        "enabled": True,
        "public_key": "public-key",
        "short_id": "abcd",
    }
    assert nodes[1]["alter_id"] == 0
    assert nodes[1]["tls"]["insecure"] is True
    assert nodes[1]["transport"] == {
        "type": "ws",
        "path": "/ws",
        "headers": {"X-Test": "1", "Host": "edge.example"},
        "max_early_data": 2048,
        "early_data_header_name": "Sec-WebSocket-Protocol",
    }
    assert nodes[2]["transport"]["permit_without_stream"] is True
    assert nodes[3]["plugin_opts"] == "obfs=http"
    assert nodes[4]["version"] == "4"
    assert nodes[4]["username"] == "user"
    assert nodes[5]["transport"]["type"] == "http"
    assert nodes[5]["transport"]["host"] == ["h2.example"]
    assert "utls" not in nodes[6]["tls"]
    assert nodes[7]["transport"] == {
        "type": "httpupgrade",
        "host": "upgrade-host.example",
        "path": "/upgrade",
        "headers": {"X-Up": "1"},
    }

    auto, selector, direct, block = config["outbounds"][-4:]
    node_tags = [node["tag"] for node in nodes]
    assert auto == {
        "type": "urltest",
        "tag": "auto",
        "outbounds": node_tags,
        "url": "https://probe.example/204",
        "interval": "10m",
        "tolerance": 75,
        "interrupt_exist_connections": True,
    }
    assert selector["outbounds"] == ["auto", *node_tags]
    assert selector["interrupt_exist_connections"] is True
    assert direct == {"type": "direct", "tag": "direct"}
    assert block == {"type": "block", "tag": "block"}
    assert config["route"] == {"auto_detect_interface": True, "final": "proxy"}

    # Legacy field aliases and fallback naming are covered in the same conversion scenario.
    source = {
        "name": "Fallback profile",
        "outbounds": [
            _vnext(
                "vmess",
                tag="",
                address="legacy.example",
                port="8443.0",
                uuid="44444444-4444-4444-4444-444444444444",
                alter_id="1e1",
                stream={
                    "network": "ws",
                    "fingerprint": "chrome_padding_psk_shuffle",
                    "security": "tls",
                    "tlsSettings": {"server_name": "legacy.example", "insecure": "on"},
                    "wsSettings": {
                        "host": "new-host.example",
                        "headers": {"host": "old-host.example"},
                        "max_early_data": 512,
                        "early_data_header_name": "X-Early",
                    },
                },
            )
        ],
    }

    config, metadata = m.convert_xray_subscription_to_sing_box(source)
    node = config["outbounds"][0]
    assert metadata["converted_count"] == 1
    assert node["tag"] == "1 - Fallback profile"
    assert node["server_port"] == 8443.0
    assert node["alter_id"] == 10.0
    assert node["tls"]["insecure"] is True
    assert node["tls"]["utls"]["fingerprint"] == "chrome"
    assert node["transport"]["headers"] == {"Host": "new-host.example"}

    # Unsupported or incomplete nodes are skipped while valid nodes remain exportable.
    source = [{
        "tag": "Bad profile",
        "outbounds": [
            _vnext(
                "vless", tag="xhttp", address="xhttp.example", port=443, uuid="id",
                stream={"network": "xhttp"},
            ),
            _vnext(
                "vless", tag="camouflage", address="tcp.example", port=443, uuid="id",
                stream={"network": "raw", "tcpSettings": {"header": {"type": "http"}}},
            ),
            _server("trojan", tag="missing-password", address="trojan.example", port=443),
            _server("shadowsocks", tag="missing-method", address="ss.example", port=8388, password="secret"),
            _server("socks", tag="valid", address="socks.example", port="1080", users=[]),
        ],
    }]

    config, metadata = m.convert_xray_subscription_to_sing_box(source)
    assert metadata["converted_count"] == 1
    assert config["outbounds"][0]["type"] == "socks"
    assert [item["reason"] for item in metadata["skipped"]] == [
        "unsupported transport: xhttp",
        "TCP header camouflage is not supported by sing-box",
        "required endpoint or credential field is missing",
        "required endpoint or credential field is missing",
    ]


def test_convert_subscription_rejects_invalid_sources_and_reports_error_details(m):
    for source in (None, "not-json-object", {"outbounds": []}):
        with pytest.raises(ValueError, match="No supported proxy outbounds could be converted."):
            m.convert_xray_subscription_to_sing_box(source)

    source = {
        "remarks": "Only bad",
        "outbounds": [
            _vnext(
                "vless", tag="broken", address="broken.example", port="not-a-port", uuid="id",
                stream={"network": "tcp"},
            )
        ],
    }
    with pytest.raises(ValueError) as error:
        m.convert_xray_subscription_to_sing_box(source)
    message = str(error.value)
    assert "broken [vless]" in message
    assert "required endpoint or credential field is missing" in message


def test_manager_sing_box_subscription_uses_current_then_cached_subscription(m, manager_factory, monkeypatch):
    instance = manager_factory()
    source = {
        "remarks": "Current",
        "outbounds": [
            _server("socks", tag="node", address="socks.example", port=1080),
            _vnext(
                "vless", tag="skip", address="skip.example", port=443, uuid="id",
                stream={"network": "xhttp"},
            ),
        ],
    }
    instance.subscription = [source]
    messages = []
    monkeypatch.setattr(m, "log", lambda message, **_kwargs: messages.append(message))

    config, metadata = instance.sing_box_subscription()
    assert config["outbounds"][-4]["url"] == instance.primary_test_url
    assert metadata["converted_count"] == 1
    assert "1 outbound(s), 1 skipped" in messages[0]
    assert "sing-box conversion skipped" in messages[1]

    instance.subscription = []
    instance.load_cached_subscription = lambda: [source]
    _, cached_metadata = instance.sing_box_subscription()
    assert cached_metadata["converted_count"] == 1

    instance.load_cached_subscription = lambda: []
    with pytest.raises(RuntimeError, match="Текущая подписка пуста"):
        instance.sing_box_subscription()
