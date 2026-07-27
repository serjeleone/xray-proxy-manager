from __future__ import annotations

import io
import json
import urllib.error

import pytest


class UrlResponse:
    def __init__(self, payload):
        self.payload = payload
    def __enter__(self): return self
    def __exit__(self, *args): return False
    def read(self):
        if isinstance(self.payload, bytes): return self.payload
        return json.dumps(self.payload).encode()


def test_selector_api_request_success_and_validation(m, manager_factory, monkeypatch):
    instance = manager_factory()
    captured = {}
    def urlopen(request, timeout):
        captured.update(url=request.full_url, method=request.method, data=request.data, headers=dict(request.header_items()), timeout=timeout)
        return UrlResponse({"ok": True})
    monkeypatch.setattr(m.urllib.request, "urlopen", urlopen)
    assert instance.selector_api_request("put", "proxies/tag", {"name": "xray-a"}, timeout=2) == {"ok": True}
    assert captured["url"].endswith("/proxies/tag")
    assert captured["method"] == "PUT"
    assert json.loads(captured["data"]) == {"name": "xray-a"}
    assert captured["headers"]["Authorization"] == "Bearer secret"
    instance.selector_control_enabled = False
    with pytest.raises(RuntimeError, match="отключено"):
        instance.selector_api_request("GET", "/x")
    instance.selector_control_enabled = True
    with pytest.raises(ValueError, match="Unsupported"):
        instance.selector_api_request("POST", "/x")


def test_selector_api_request_errors(m, manager_factory, monkeypatch):
    instance = manager_factory()
    error = urllib.error.HTTPError("http://x", 500, "bad", {}, io.BytesIO(b"failure"))
    monkeypatch.setattr(m.urllib.request, "urlopen", lambda *a, **k: (_ for _ in ()).throw(error))
    with pytest.raises(RuntimeError, match="HTTP 500: failure"):
        instance.selector_api_request("GET", "/x")
    monkeypatch.setattr(m.urllib.request, "urlopen", lambda *a, **k: (_ for _ in ()).throw(urllib.error.URLError("down")))
    with pytest.raises(RuntimeError, match="недоступен"):
        instance.selector_api_request("GET", "/x")
    monkeypatch.setattr(m.urllib.request, "urlopen", lambda *a, **k: UrlResponse(b"not-json"))
    with pytest.raises(RuntimeError, match="invalid JSON"):
        instance.selector_api_request("GET", "/x")
    monkeypatch.setattr(m.urllib.request, "urlopen", lambda *a, **k: UrlResponse(b""))
    assert instance.selector_api_request("GET", "/x") == {}


def test_selector_status_switch_and_connections(m, manager_factory):
    instance = manager_factory()
    calls = []
    responses = iter([{"now": "xray-a"}, {}, {"now": "xray-b"}, {"connections": [{"id": "1"}, "bad"]}])
    instance.selector_api_request = lambda *args, **kwargs: calls.append((args, kwargs)) or next(responses)
    assert instance.selector_status() == "xray-a"
    instance.switch_selector("xray-b")
    assert instance.selector_state["current"] == "xray-b"
    assert instance.selector_connections() == [{"id": "1"}]
    with pytest.raises(ValueError):
        instance.switch_selector("other")
    instance.selector_api_request = lambda *a, **k: {"now": "bad"}
    with pytest.raises(RuntimeError, match="unsupported slot"):
        instance.selector_status()
    instance.selector_api_request = lambda *a, **k: {}
    with pytest.raises(RuntimeError, match="no connection list"):
        instance.selector_connections()


def test_connection_helpers(m, manager_factory):
    instance = manager_factory()
    connections = [
        {"id": "1", "chains": ["xray-a"], "metadata": {"network": "tcp"}, "upload": 10, "download": 20},
        {"uuid": "2", "chains": ["xray-a"], "metadata": {"network": "udp"}, "upload": -1, "download": "5"},
        {"id": "3", "chains": ["xray-b"], "upload": "bad"},
    ]
    assert m.XrayManager.connection_slot_stats(connections, "xray-a") == (2, 1, 1, 35)
    assert m.XrayManager.connection_id(connections[1]) == "2"
    assert m.XrayManager.connection_total_bytes(connections[1]) == 5
    assert instance.connections_for_slot(connections, "xray-b") == [connections[2]]
    summary = instance.connection_summary({
        "id": "7", "chains": ["xray-a"], "metadata": {
            "sourceIP": "10.0.0.2", "sourcePort": 1234, "host": "example.org", "destinationPort": 443, "network": "tcp"
        }, "upload": 1, "download": 2,
    })
    assert "source=10.0.0.2:1234" in summary
    assert "destination=example.org:443" in summary
    assert "bytes=3" in summary


def test_capture_drain_connection_baseline_success_and_error(m, manager_factory):
    instance = manager_factory()
    instance.log_level = "debug"
    instance.selector_connections = lambda: [
        {"id": "1", "chains": ["xray-a"], "upload": 2, "download": 3},
        {"id": "2", "chains": ["xray-b"]},
    ]
    instance.capture_drain_connection_baseline("xray-a")
    slot = instance.slots["xray-a"]
    assert slot.drain_known_connection_ids == {"1"}
    assert slot.drain_connection_bytes == {"1": 5}
    assert slot.drain_idle_polls == {"1": 0}
    instance.selector_connections = lambda: (_ for _ in ()).throw(RuntimeError("down"))
    instance.capture_drain_connection_baseline("xray-a")
    assert slot.drain_known_connection_ids == set()
    assert slot.drain_last_error == "down"


def test_restore_selector_alignment_restores_expected_or_adopts_live(m, manager_factory, candidate_factory):
    expected = candidate_factory("expected")
    live = candidate_factory("live")
    instance = manager_factory([expected, live])
    instance.active_slot_tag = "xray-a"
    instance.active_candidate_id = expected.id
    instance.slots["xray-a"].process = type("P", (), {"poll": lambda self: None})()
    instance.slots["xray-a"].candidate = expected
    instance.selector_status = lambda: "xray-b"
    switched = []
    instance.switch_selector = switched.append
    instance.restore_selector_alignment("xray-b")
    assert switched == ["xray-a"]

    instance.slots["xray-a"].process = None
    instance.slots["xray-b"].process = type("P", (), {"poll": lambda self: None})()
    instance.slots["xray-b"].candidate = live
    instance.slots["xray-b"].candidate_id = live.id
    instance.selector_status = lambda: "xray-b"
    saved = []
    instance.save_active_config = lambda slot, candidate: saved.append((slot, candidate.id))
    instance.restore_selector_alignment("xray-b")
    assert instance.active_slot_tag == "xray-b"
    assert instance.active_candidate_id == live.id
    assert saved == [("xray-b", live.id)]


def test_refresh_selector_status_disabled_unavailable_and_available(m, manager_factory):
    instance = manager_factory()
    instance.selector_control_enabled = False
    instance.refresh_selector_status()
    assert instance.selector_state["configured"] is False
    assert "отключено" in instance.selector_state["error"]

    instance.selector_control_enabled = True
    instance.selector_status = lambda: (_ for _ in ()).throw(RuntimeError("down"))
    instance.refresh_selector_status()
    assert instance.selector_state["available"] is False
    assert instance.selector_state["error"] == "down"

    instance.selector_state["available"] = True
    instance.selector_status = lambda: "xray-a"
    instance.selector_connections = lambda: []
    instance.reconcile_startup_selector = lambda current: None
    instance.restore_selector_alignment = lambda current: None
    instance.refresh_selector_status()
    assert instance.selector_state["available"] is True
    assert instance.selector_state["current"] == "xray-a"
    assert instance.selector_state["connections_supported"] is True


def test_selector_wait_and_loop(m, manager_factory):
    instance = manager_factory()
    instance.selector_state["available"] = False
    assert instance.selector_status_wait_seconds() == 1
    instance.selector_state["available"] = True
    assert instance.selector_status_wait_seconds() == 10

    calls = []
    class Event:
        def __init__(self): self.count = 0
        def is_set(self): return self.count > 0
        def wait(self, seconds): self.count += 1; return True
    instance.stop_event = Event()
    instance.refresh_selector_status = lambda: calls.append(True)
    instance.selector_status_loop()
    assert calls == [True]
