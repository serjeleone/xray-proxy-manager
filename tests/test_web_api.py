from __future__ import annotations

import json
import socket
import threading
import urllib.error
import urllib.request
from types import SimpleNamespace

import pytest

pytestmark = pytest.mark.integration


class FakeManager:
    def __init__(self):
        self.calls = []
        self.router_state = {"rule_enabled": True}
    def status_payload(self): return {"xray_running": True, "value": 1}
    def select_candidate(self, value): self.calls.append(("select", value))
    def request_latency_test(self, ids=None): self.calls.append(("test", ids)); return True
    def request_refresh(self): self.calls.append(("refresh",)); return True
    def set_slot_mode(self, desired): self.calls.append(("mode", desired)); return {"ok": True, "dual_slot_enabled": desired}
    def set_preferred_country(self, value): self.calls.append(("country", value)); return {"ok": True}
    def set_selection_preferences(self, country, protocol): self.calls.append(("preferences", country, protocol)); return {"ok": True}
    def update_runtime_settings(self, changes): self.calls.append(("settings", changes)); return {"ok": True, "restart_required": []}
    def set_router_rule(self, desired): self.calls.append(("traffic", desired))
    def force_stop_draining_slot(self, slot): self.calls.append(("drain", slot)); return slot or "xray-b"


@pytest.fixture
def web_server(m, isolated_paths, monkeypatch):
    manager = FakeManager()
    handler = lambda *args, **kwargs: m.WebHandler(manager, *args, **kwargs)
    server = m.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        yield manager, base
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def get_json(url):
    with urllib.request.urlopen(url, timeout=3) as response:
        return response.status, json.loads(response.read())


def post_json(url, payload):
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=3) as response:
        return response.status, json.loads(response.read())


def test_health_status_logs_and_static_routes(m, web_server):
    manager, base = web_server
    status, payload = get_json(f"{base}/api/health")
    assert status == 200 and payload == {"ok": True, "xray_running": True}
    status, payload = get_json(f"{base}/api/status")
    assert payload["value"] == 1
    m.append_ui_log("one")
    status, payload = get_json(f"{base}/api/logs?limit=1")
    assert payload["lines"] == ["one"]
    with urllib.request.urlopen(f"{base}/app.js") as response:
        assert response.headers["Content-Type"].startswith("application/javascript")
        assert response.read() == b"app"
    with urllib.request.urlopen(f"{base}/") as response:
        assert response.read() == b"index"


def test_health_returns_503_when_xray_is_down(m, web_server):
    manager, base = web_server
    manager.status_payload = lambda: {"xray_running": False}
    with pytest.raises(urllib.error.HTTPError) as error:
        urllib.request.urlopen(f"{base}/api/health")
    assert error.value.code == 503
    assert json.loads(error.value.read())["ok"] is False


@pytest.mark.parametrize(
    ("path", "payload", "expected_call", "expected_status"),
    [
        ("/api/select", {"id": "c1"}, ("select", "c1"), 200),
        ("/api/test", {"id": "c1"}, ("test", ["c1"]), 202),
        ("/api/test", {}, ("test", None), 202),
        ("/api/refresh", {}, ("refresh",), 202),
        ("/api/mode", {"dual_slot_enabled": False}, ("mode", False), 200),
        ("/api/preferred-country", {"country": "NL"}, ("country", "NL"), 200),
        ("/api/preferences", {"country": "NL", "protocol": "VLESS"}, ("preferences", "NL", "VLESS"), 200),
        ("/api/settings", {"changes": {"ui_sort": "name-asc"}}, ("settings", {"ui_sort": "name-asc"}), 200),
        ("/api/traffic", {"enabled": False}, ("traffic", False), 200),
        ("/api/drain/stop", {"slot": "xray-b"}, ("drain", "xray-b"), 200),
    ],
)
def test_post_routes_dispatch_to_manager(web_server, path, payload, expected_call, expected_status):
    manager, base = web_server
    status, response = post_json(f"{base}{path}", payload)
    assert status == expected_status
    assert response["ok"] is True
    assert manager.calls[-1] == expected_call


def test_post_conflicts_validation_errors_and_unknown_route(web_server):
    manager, base = web_server
    manager.request_latency_test = lambda ids=None: False
    with pytest.raises(urllib.error.HTTPError) as conflict:
        post_json(f"{base}/api/test", {})
    assert conflict.value.code == 409
    with pytest.raises(urllib.error.HTTPError) as invalid:
        post_json(f"{base}/api/mode", {"dual_slot_enabled": "no"})
    assert invalid.value.code == 400
    assert "режим" in json.loads(invalid.value.read())["error"]
    with pytest.raises(urllib.error.HTTPError) as missing:
        post_json(f"{base}/unknown", {})
    assert missing.value.code == 404


def test_traffic_route_toggles_known_state_when_value_missing(web_server):
    manager, base = web_server
    status, response = post_json(f"{base}/api/traffic", {})
    assert response["enabled"] is False
    assert manager.calls[-1] == ("traffic", False)
    manager.router_state["rule_enabled"] = None
    with pytest.raises(urllib.error.HTTPError) as invalid:
        post_json(f"{base}/api/traffic", {})
    assert "неизвестно" in json.loads(invalid.value.read())["error"]


def test_web_handler_ingress_allowlist_and_json_helpers(m):
    handler = m.WebHandler.__new__(m.WebHandler)
    handler.client_address = ("::ffff:127.0.0.1", 1234)
    assert handler.ingress_client_allowed()
    handler.client_address = ("192.168.1.2", 1234)
    assert not handler.ingress_client_allowed()


def test_ingress_forward_stream_and_proxy_server_configuration(m):
    left, right = socket.socketpair()
    target_left, target_right = socket.socketpair()
    try:
        handler = m.IngressTCPProxyHandler.__new__(m.IngressTCPProxyHandler)
        right.sendall(b"payload")
        right.shutdown(socket.SHUT_WR)
        handler.forward_stream(left, target_left)
        assert target_right.recv(64) == b"payload"
    finally:
        for sock in (left, right, target_left, target_right):
            sock.close()
    server = m.ThreadingTCPProxyServer(("127.0.0.1", 0), target_host="127.0.0.1", target_port=8090)
    try:
        assert server.target_host == "127.0.0.1"
        assert server.target_port == 8090
    finally:
        server.server_close()


def test_ingress_proxy_handler_relays_both_directions(m, monkeypatch):
    client, client_peer = socket.socketpair()
    upstream, upstream_peer = socket.socketpair()
    for sock in (client, client_peer, upstream, upstream_peer):
        sock.settimeout(2)

    monkeypatch.setattr(m.socket, "create_connection", lambda *_args, **_kwargs: upstream)
    handler = m.IngressTCPProxyHandler.__new__(m.IngressTCPProxyHandler)
    handler.server = SimpleNamespace(target_host="127.0.0.1", target_port=8090)
    handler.request = client
    worker = threading.Thread(target=handler.handle)

    try:
        worker.start()
        client_peer.sendall(b"request")
        assert upstream_peer.recv(64) == b"request"
        upstream_peer.sendall(b"response")
        upstream_peer.shutdown(socket.SHUT_WR)
        assert client_peer.recv(64) == b"response"
        client_peer.shutdown(socket.SHUT_WR)
        worker.join(timeout=2)
        assert not worker.is_alive()
    finally:
        for sock in (client, client_peer, upstream_peer):
            try:
                sock.close()
            except OSError:
                pass
