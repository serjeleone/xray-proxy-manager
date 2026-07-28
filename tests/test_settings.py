from __future__ import annotations

import json
import threading
from pathlib import Path

import pytest


def test_manager_initialization_loads_runtime_options_and_state(m, isolated_paths, write_options, monkeypatch):
    write_options(
        auto_switch_preferred_country="nl",
        auto_switch_preferred_protocol="vless",
        auto_switch_excluded_countries="ru, node",
        secondary_check_url="https://legacy-secondary/",
        router_auth_method="existing_key",
    )
    isolated_paths.RUNTIME_OPTIONS_PATH.write_text(json.dumps({
        "ui_sort": "name-desc",
        "auto_check_failures": 4,
    }), encoding="utf-8")
    monkeypatch.setattr(m.XrayManager, "prepare_router_auth", lambda self: None)
    monkeypatch.setattr(m.XrayManager, "detect_home_assistant_host", lambda self: "ha.local")
    monkeypatch.setattr(m.XrayManager, "sync_supervisor_options", lambda self: (True, ""))

    instance = m.XrayManager()
    assert instance.subscription_url == "https://subscription.example/list"
    assert instance.auto_switch_preferred_country == "NL"
    assert instance.auto_switch_preferred_protocol == "VLESS"
    assert instance.auto_switch_excluded == "RU, node"
    assert instance.auto_check_failures == 4
    assert instance.ui_sort == "name-desc"
    assert instance.secondary_test_url == "https://legacy-secondary/"
    assert instance.slots["xray-a"].socks_tcp == 10808
    assert instance.slots["xray-b"].socks_tcp == 10809
    assert instance.state["jobs"]["latency"]["running"] is False


@pytest.mark.parametrize(
    "overrides, message",
    [
        ({"subscription_url": ""}, "subscription_url is empty"),
        ({"proxy_username": "user", "proxy_password": ""}, "must be set together"),
        ({"selector_tag": "bad tag"}, "unsupported characters"),
        ({"router_firewall_rule": "bad rule"}, "unsupported characters"),
        ({"socks_tcp_b": 10808}, "must differ"),
        ({"ui_port": 10808}, "must differ"),
        ({"ui_port": 18099}, "reserved watchdog"),
        ({"router_auth_method": "invalid"}, "router_auth_method"),
    ],
)
def test_manager_initialization_rejects_invalid_configuration(
    m, isolated_paths, write_options, monkeypatch, overrides, message
):
    write_options(**overrides)
    monkeypatch.setattr(m.XrayManager, "prepare_router_auth", lambda self: None)
    monkeypatch.setattr(m.XrayManager, "detect_home_assistant_host", lambda self: "ha.local")
    with pytest.raises(RuntimeError, match=message):
        m.XrayManager()


def test_apply_and_validate_runtime_values(m, manager_factory):
    instance = manager_factory()
    instance._apply_runtime_values({
        "subscription_url": " https://new.example/list ",
        "dual_slot_enabled": "false",
        "auto_checker_enabled": "yes",
        "auto_switch_best_enabled": 0,
        "auto_switch_preferred_country": "fi",
        "auto_switch_preferred_protocol": "trojan",
        "auto_switch_excluded": "RU, bad node",
        "auto_switch_min_ping_delta_ms": "12",
        "auto_check_interval_seconds": "20",
        "auto_check_failures": "5",
        "auto_check_max_latency_ms": "0",
        "auto_best_check_interval_seconds": "120",
        "update_interval_hours": "0",
        "ui_sort": "unknown",
        "ui_protocol_filter": "vless",
        "ui_max_ping_ms": "300",
        "ui_hide_unavailable": "on",
        "ui_hide_excluded": "off",
    })
    assert instance.subscription_url == "https://new.example/list"
    assert instance.dual_slot_enabled is False
    assert instance.auto_checker_enabled is True
    assert instance.auto_switch_best_enabled is False
    assert instance.auto_switch_preferred_country == "FI"
    assert instance.auto_switch_preferred_protocol == "TROJAN"
    assert instance.auto_switch_excluded == "RU, bad node"
    assert instance.ui_sort == "ping-asc"
    assert instance.ui_protocol_filter == "VLESS"
    assert instance.ui_hide_unavailable is True
    assert instance.ui_hide_excluded is False

    valid = instance.validate_runtime_changes({
        "subscription_url": "https://valid.example/sub",
        "auto_checker_enabled": "true",
        "auto_switch_preferred_country": "nl",
        "auto_switch_preferred_protocol": "vless",
        "auto_switch_excluded": "RU, node text",
        "auto_switch_min_ping_delta_ms": 0,
        "auto_check_interval_seconds": 10,
        "auto_check_failures": 1,
        "auto_check_max_latency_ms": 10000,
        "auto_best_check_interval_seconds": 60,
        "update_interval_hours": 720,
        "ui_max_ping_ms": 0,
        "ui_sort": "name-asc",
        "ui_protocol_filter": "all",
        "ui_hide_unavailable": True,
        "ui_hide_excluded": False,
    })
    assert valid["auto_switch_preferred_country"] == "NL"
    assert valid["auto_switch_preferred_protocol"] == "VLESS"
    assert valid["ui_protocol_filter"] == "all"


@pytest.mark.parametrize(
    "changes",
    [
        {"unknown": 1},
        {"subscription_url": "ftp://bad"},
        {"ui_sort": "bad"},
        {"ui_protocol_filter": "bad protocol!"},
        {"auto_check_failures": 0},
    ],
)
def test_validate_runtime_changes_rejects_invalid_input(m, manager_factory, changes):
    with pytest.raises(ValueError):
        manager_factory().validate_runtime_changes(changes)


def test_update_runtime_settings_persists_and_signals(m, manager_factory, isolated_paths, monkeypatch):
    instance = manager_factory()
    monkeypatch.setattr(m, "RUNTIME_OPTIONS_PATH", isolated_paths.RUNTIME_OPTIONS_PATH)
    result = instance.update_runtime_settings({
        "ui_sort": "name-desc",
        "auto_check_failures": 7,
    })
    assert result["ok"] is True
    assert instance.ui_sort == "name-desc"
    assert instance.auto_check_failures == 7
    assert instance.settings_event.is_set()
    persisted = json.loads(isolated_paths.RUNTIME_OPTIONS_PATH.read_text(encoding="utf-8"))
    assert persisted["ui_sort"] == "name-desc"
    with pytest.raises(ValueError, match="отдельной кнопкой"):
        instance.update_runtime_settings({"dual_slot_enabled": False})


def test_preference_scoring_country_has_priority(m, manager_factory, candidate_factory):
    both = candidate_factory("both", country="NL", protocol="VLESS")
    country = candidate_factory("country", country="NL", protocol="TROJAN")
    protocol = candidate_factory("protocol", country="DE", protocol="VLESS")
    instance = manager_factory([protocol, country, both])
    instance.auto_switch_preferred_country = "NL"
    instance.auto_switch_preferred_protocol = "VLESS"
    assert instance.candidate_preference_score(None) == (0, 0, 0)
    assert instance.candidate_preference_score(both) == (3, 1, 1)
    assert instance.candidate_preference_score(country) == (2, 1, 0)
    assert instance.candidate_preference_score(protocol) == (1, 0, 1)
    assert sorted(instance.candidates, key=instance.candidate_preference_sort_key) == [both, country, protocol]


def test_set_selection_preferences_switches_cached_best_and_starts_scan(
    m, manager_factory, candidate_factory, monkeypatch
):
    current = candidate_factory("current", country="DE", protocol="VLESS")
    best = candidate_factory("best", country="NL", protocol="VLESS")
    instance = manager_factory([current, best])
    instance.active_candidate_id = current.id
    instance.slots["xray-a"].candidate = current
    instance.latencies = {
        best.id: {"status": "ok", "latency_ms": 80},
        current.id: {"status": "ok", "latency_ms": 20},
    }
    updated: list[dict] = []
    def update(changes):
        updated.append(changes)
        instance.auto_switch_preferred_country = changes["auto_switch_preferred_country"]
        instance.auto_switch_preferred_protocol = changes["auto_switch_preferred_protocol"]
        return {"ok": True, "restart_required": [], "supervisor_synced": True, "supervisor_error": ""}
    instance.update_runtime_settings = update
    switched: list[tuple[str, str, bool]] = []
    instance.restart_xray_for = lambda candidate, reason, preempt_draining=False, **_: switched.append(
        (candidate.id, reason, preempt_draining)
    )
    instance.request_latency_test = lambda *_, **__: True

    result = instance.set_selection_preferences("nl", "vless")
    assert updated == [{
        "auto_switch_preferred_country": "NL",
        "auto_switch_preferred_protocol": "VLESS",
    }]
    assert switched[0][0] == best.id
    assert switched[0][2] is True
    assert result["immediate_switched"] is True
    assert result["matching_candidates"] == 2
    assert result["switch_started"] is True


def test_set_selection_preferences_disable_and_wrapper_calls(m, manager_factory, monkeypatch):
    instance = manager_factory()
    instance.update_runtime_settings = lambda changes: {"ok": True}
    instance.request_latency_test = lambda *_, **__: False
    result = instance.set_selection_preferences("", "")
    assert result["message"] == "Приоритет страны и протокола отключён"
    calls = []
    instance.set_selection_preferences = lambda country, protocol, **kwargs: calls.append((country, protocol, kwargs)) or {}
    instance.auto_switch_preferred_protocol = "VLESS"
    instance.auto_switch_preferred_country = "NL"
    instance.set_preferred_country("FI")
    instance.set_preferred_protocol("TROJAN")
    assert calls == [
        ("FI", "VLESS", {"source": "preferred-country"}),
        ("NL", "TROJAN", {"source": "preferred-protocol"}),
    ]


def test_deferred_preference_scan_waits_until_latency_job_is_free(m, manager_factory):
    instance = manager_factory()
    instance.auto_switch_preferred_country = "NL"
    instance.auto_switch_preferred_protocol = "VLESS"
    instance.preference_scan_generation = 2
    instance.state["jobs"]["latency"]["running"] = False
    calls = []
    instance.request_latency_test = lambda *args, **kwargs: calls.append((args, kwargs)) or True

    waits = iter([False])
    instance.stop_event = type("Event", (), {"wait": lambda self, _: next(waits)})()
    instance._deferred_preference_scan("NL", "VLESS", 2, "source")
    assert calls[0][1] == {"switch_to_best": True, "source": "source"}


def test_set_slot_mode_noop_success_and_rollback(m, manager_factory, candidate_factory, isolated_paths, monkeypatch):
    candidate = candidate_factory("active")
    instance = manager_factory([candidate])
    instance.active_candidate_id = candidate.id
    instance.slots["xray-a"].candidate = candidate
    assert instance.set_slot_mode(True) == {"ok": True, "dual_slot_enabled": True, "changed": False}

    monkeypatch.setattr(m, "RUNTIME_OPTIONS_PATH", isolated_paths.RUNTIME_OPTIONS_PATH)
    stopped = []
    started = []
    instance.stop_xray = lambda: stopped.append(instance.dual_slot_enabled)
    instance.start_initial_candidate = lambda item, reason, *, source="internal": started.append((item.id, reason, source, instance.dual_slot_enabled))
    result = instance.set_slot_mode(False)
    assert result["changed"] is True
    assert instance.dual_slot_enabled is False
    assert stopped == [True]
    assert started[0][:3] == (candidate.id, "slot mode changed from UI", "slot_mode_ui")
    assert json.loads(isolated_paths.RUNTIME_OPTIONS_PATH.read_text())["dual_slot_enabled"] is False

    instance.dual_slot_enabled = True
    instance.active_slot_tag = "xray-a"
    calls = 0
    def failing_start(item, reason, *, source="internal"):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("start failed")
    instance.start_initial_candidate = failing_start
    with pytest.raises(RuntimeError, match="start failed"):
        instance.set_slot_mode(False)
    assert instance.dual_slot_enabled is True


def test_sync_supervisor_options(m, manager_factory, monkeypatch):
    instance = manager_factory()
    monkeypatch.delenv("SUPERVISOR_TOKEN", raising=False)
    ok, error = m.XrayManager.sync_supervisor_options(instance)
    assert not ok and "SUPERVISOR_TOKEN" in error

    monkeypatch.setenv("SUPERVISOR_TOKEN", "token")
    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def read(self): return b'{"result":"ok"}'
    captured = {}
    def urlopen(request, timeout):
        captured["request"] = request
        captured["timeout"] = timeout
        return Response()
    monkeypatch.setattr(m.urllib.request, "urlopen", urlopen)
    assert m.XrayManager.sync_supervisor_options(instance) == (True, "")
    assert captured["request"].get_header("Authorization") == "Bearer token"


def test_detect_ingress_port_and_home_assistant_host(m, manager_factory, monkeypatch, tmp_path):
    instance = manager_factory()
    monkeypatch.setenv("SUPERVISOR_TOKEN", "token")
    class Response:
        def __init__(self, payload): self.payload = payload
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def read(self): return json.dumps(self.payload).encode()
    responses = iter([
        Response({"data": {"ingress_port": 8123}}),
        Response({"data": {"interfaces": [
            {"primary": False, "ipv4": {"address": ["127.0.0.1/8"]}},
            {"primary": True, "ipv4": {"address": ["192.168.1.10/24"]}},
        ]}}),
    ])
    monkeypatch.setattr(m.urllib.request, "urlopen", lambda *a, **k: next(responses))
    assert instance.detect_ingress_port() == 8123
    assert instance.detect_home_assistant_host() == "192.168.1.10"
    monkeypatch.delenv("SUPERVISOR_TOKEN", raising=False)
    assert instance.detect_home_assistant_host() == "host"
