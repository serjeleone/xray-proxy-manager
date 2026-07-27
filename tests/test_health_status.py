from __future__ import annotations

import json
import socket
import subprocess
import threading
import time
from pathlib import Path

import pytest

from conftest import DummyProcess


def test_last_good_resolution_and_restore(m, manager_factory, candidate_factory, isolated_paths, monkeypatch):
    first = candidate_factory("first", fingerprint="fp", outbound_tag="tag")
    instance = manager_factory([first])
    monkeypatch.setattr(m, "LAST_GOOD_META_PATH", isolated_paths.LAST_GOOD_META_PATH)
    monkeypatch.setattr(m, "LAST_GOOD_CONFIG_PATH", isolated_paths.LAST_GOOD_CONFIG_PATH)
    monkeypatch.setattr(m, "CONFIG_PATH", isolated_paths.CONFIG_PATH)
    isolated_paths.LAST_GOOD_META_PATH.write_text(json.dumps({"fingerprint": "fp", "slot_tag": "xray-b"}))
    isolated_paths.LAST_GOOD_CONFIG_PATH.write_text(json.dumps({"routing": {"rules": [{"outboundTag": "tag"}]}}))
    assert instance.resolve_last_good_candidate() is first
    instance.patch_inbounds = lambda config, slot_tag: {**config, "inbounds": [{"port": instance.slots[slot_tag].socks_tcp}]}
    instance.xray_test = lambda path: (True, "")
    restored, candidate = instance.restore_last_good()
    assert restored and candidate is first
    assert instance.active_slot_tag == "xray-b"
    assert instance.slots["xray-b"].candidate is first


def test_restore_last_good_missing_or_invalid(m, manager_factory, isolated_paths, monkeypatch):
    instance = manager_factory()
    monkeypatch.setattr(m, "LAST_GOOD_META_PATH", isolated_paths.LAST_GOOD_META_PATH)
    monkeypatch.setattr(m, "LAST_GOOD_CONFIG_PATH", isolated_paths.LAST_GOOD_CONFIG_PATH)
    assert instance.restore_last_good() == (False, None)
    isolated_paths.LAST_GOOD_CONFIG_PATH.write_text("{}")
    assert instance.restore_last_good() == (False, None)


def test_refresh_subscription_preserves_running_removed_candidate(m, manager_factory, candidate_factory, isolated_paths, monkeypatch):
    old = candidate_factory("old", fingerprint="old")
    new = candidate_factory("new", fingerprint="new")
    instance = manager_factory([old])
    instance.subscription = [{"old": True}]
    instance.active_candidate_id = old.id
    slot = instance.slots["xray-a"]
    slot.process = DummyProcess()
    slot.candidate = old
    slot.candidate_id = old.id
    instance.download_subscription = lambda: [{"new": True}]
    instance.extract_candidates = lambda configs: [new]
    instance.rebind_slot_candidates = lambda: False
    instance.runtime_config_differs = lambda *a: False
    monkeypatch.setattr(m, "SUBSCRIPTION_PATH", isolated_paths.SUBSCRIPTION_PATH)
    instance.refresh_subscription_sync(initial=False)
    assert instance.active_candidate_id == old.id
    assert slot.candidate is old
    assert instance.candidates == [new]
    assert instance.state["subscription_error"] == ""


def test_refresh_subscription_uses_cache_and_rolls_back_on_parse_failure(m, manager_factory, candidate_factory):
    old = candidate_factory("old")
    instance = manager_factory([old])
    instance.subscription = [{"old": True}]
    instance.download_subscription = lambda: (_ for _ in ()).throw(RuntimeError("network"))
    instance.load_cached_subscription = lambda: [{"cached": True}]
    instance.extract_candidates = lambda configs: (_ for _ in ()).throw(RuntimeError("bad subscription"))
    with pytest.raises(RuntimeError, match="bad subscription"):
        instance.refresh_subscription_sync()
    assert instance.subscription == [{"old": True}]
    assert instance.candidates == [old]


def test_refresh_job_and_request_refresh(m, manager_factory, monkeypatch):
    instance = manager_factory()
    instance.refresh_subscription_sync = lambda **kwargs: None
    instance.refresh_subscription_job()
    assert instance.state["jobs"]["refresh"]["message"] == "Подписка обновлена"
    class Thread:
        def __init__(self, target, daemon): self.target = target
        def start(self): pass
    monkeypatch.setattr(m.threading, "Thread", Thread)
    assert instance.request_refresh() is True
    assert instance.state["jobs"]["refresh"]["running"] is True
    assert instance.request_refresh() is False


def test_port_reservation_parallelism_wait_and_proxy_curl(m, manager_factory, monkeypatch):
    instance = manager_factory()
    port = instance.find_free_port()
    assert port in m.RESERVED_TEST_PORTS
    instance.release_test_port(port)
    assert port not in m.RESERVED_TEST_PORTS
    instance.latency_test_parallelism = 3
    assert instance.effective_latency_test_parallelism(0) == 1
    assert instance.effective_latency_test_parallelism(2) == 2
    assert instance.effective_latency_test_parallelism(10) == 3

    process = DummyProcess()
    monkeypatch.setattr(m.socket, "create_connection", lambda *a, **k: object())
    class Context:
        def __enter__(self): return self
        def __exit__(self, *a): return False
    monkeypatch.setattr(m.socket, "create_connection", lambda *a, **k: Context())
    assert instance.wait_for_port(1, process, timeout=0.1)
    process.dead = True
    assert not instance.wait_for_port(1, process, timeout=0.1)

    monkeypatch.setattr(m.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess([], 0, "0.123", ""))
    assert instance.proxy_curl("127.0.0.1", 10808, "https://x", 3, auth=False) == (True, 123.0, "")
    monkeypatch.setattr(m.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess([], 1, "", "failed"))
    assert instance.proxy_curl("127.0.0.1", 10808, "https://x", 3, auth=False)[0] is False


def test_candidate_test_success_and_running_slot_path(m, manager_factory, candidate_factory, monkeypatch):
    candidate = candidate_factory("node")
    instance = manager_factory([candidate])
    instance.find_free_port = lambda: 19000
    released = []
    instance.release_test_port = released.append
    instance.build_config = lambda *a, **k: {"ok": True}
    instance.xray_test = lambda path: (True, "")
    instance.wait_for_port = lambda *a, **k: True
    instance.probe_proxy_urls = lambda *a, **k: (True, 45.4, [], "")
    monkeypatch.setattr(m.subprocess, "Popen", lambda *a, **k: DummyProcess())
    result = instance.test_candidate(candidate)
    assert result["status"] == "ok" and result["latency_ms"] == 45
    assert released == [19000]

    slot = instance.slots["xray-a"]
    slot.process = DummyProcess()
    slot.candidate = candidate
    instance.probe_proxy_urls = lambda *a, **k: (True, 30.0, [], "")
    assert instance.test_candidate_for_full_scan(candidate)["latency_ms"] == 30
    assert instance.test_running_slot_for_full_scan("xray-a")["status"] == "ok"


def test_request_latency_test_tracks_subscription_and_runtime_slots(m, manager_factory, candidate_factory, monkeypatch):
    current = candidate_factory("current")
    stale = candidate_factory("stale")
    instance = manager_factory([current])
    slot = instance.slots["xray-a"]
    slot.process = DummyProcess()
    slot.candidate = stale
    slot.candidate_id = stale.id
    class Thread:
        def __init__(self, *a, **k): pass
        def start(self): pass
    monkeypatch.setattr(m.threading, "Thread", Thread)
    assert instance.request_latency_test(None, switch_to_best=True, source="manual")
    assert instance.state["jobs"]["latency"]["total"] == 2
    assert instance.latency_checking_ids == {current.id, "slot:xray-a"}
    assert not instance.request_latency_test()


def test_draining_results_reset_and_force_stop_threshold(m, manager_factory, candidate_factory):
    candidate = candidate_factory("drain")
    instance = manager_factory([])
    slot = instance.slots["xray-b"]
    slot.process = DummyProcess()
    slot.candidate = candidate
    slot.candidate_id = candidate.id
    slot.draining = True
    instance.auto_check_failures = 2
    stopped = []
    instance.force_stop_draining_slot = lambda tag="": stopped.append(tag) or tag
    error = {"slot:xray-b": {"status": "error", "latency_ms": None, "checked_at": 1, "error": "timeout"}}
    ok = {"slot:xray-b": {"status": "ok", "latency_ms": 50, "checked_at": 2, "error": ""}}
    instance.handle_draining_full_scan_results(error)
    instance.handle_draining_full_scan_results(ok)
    assert slot.drain_degraded_checks == 0
    instance.handle_draining_full_scan_results(error)
    instance.handle_draining_full_scan_results(error)
    assert stopped == ["xray-b"]


def test_exclusions_sorting_failover_and_timing(m, manager_factory, candidate_factory):
    active = candidate_factory("active", country="DE")
    excluded = candidate_factory("ru", country="RU")
    text_excluded = candidate_factory("blocked-node", country="NL", name="blocked server")
    best = candidate_factory("best", country="FI")
    instance = manager_factory([active, excluded, text_excluded, best])
    instance.auto_switch_excluded = "RU, blocked"
    instance.active_candidate_id = active.id
    instance.slots["xray-a"].candidate = active
    instance.latencies = {
        active.id: {"status": "ok", "latency_ms": 100},
        excluded.id: {"status": "ok", "latency_ms": 10},
        text_excluded.id: {"status": "ok", "latency_ms": 20},
        best.id: {"status": "ok", "latency_ms": 40},
    }
    assert instance.excluded_country_codes() == {"RU"}
    assert instance.excluded_outbound_fragments() == ["blocked"]
    assert instance.candidate_is_excluded(excluded)
    assert instance.candidate_country_is_excluded(text_excluded)
    assert instance.sorted_healthy_candidates(True) == [best, active]
    assert instance.choose_failover_candidate() is best
    instance.state["auto_best_check_last_at"] = 100
    instance.auto_best_check_interval_seconds = 60
    assert instance.auto_best_check_due(160)
    instance.state["auto_check_last_at"] = 100
    instance.auto_check_interval_seconds = 60
    assert instance.auto_check_wait_seconds(130) == 30.0
    instance.auto_checker_enabled = False
    assert instance.auto_check_wait_seconds(130) == 5.0


def test_check_draining_slots_health_updates_latency(m, manager_factory, candidate_factory):
    candidate = candidate_factory("draining")
    instance = manager_factory()
    slot = instance.slots["xray-b"]
    slot.process = DummyProcess()
    slot.candidate = candidate
    slot.candidate_id = candidate.id
    slot.draining = True
    instance.test_running_slot_for_full_scan = lambda tag: {"status": "ok", "latency_ms": 33, "checked_at": 1, "error": ""}
    handled = []
    instance.handle_draining_full_scan_results = handled.append
    instance.check_draining_slots_health()
    assert instance.latencies[candidate.id]["latency_ms"] == 33
    assert handled and candidate.id in handled[0]


def test_rollback_after_active_exit_and_rebind_slots(m, manager_factory, candidate_factory):
    rollback = candidate_factory("rollback", fingerprint="fp")
    refreshed = candidate_factory("refreshed", fingerprint="fp")
    instance = manager_factory([refreshed])
    instance.active_slot_tag = "xray-b"
    failed = instance.slots["xray-b"]
    old = instance.slots["xray-a"]
    old.process = DummyProcess()
    old.candidate = rollback
    old.candidate_id = rollback.id
    old.draining = True
    switched = []
    instance.switch_selector = switched.append
    assert instance.rollback_after_active_exit("xray-b")
    assert instance.active_slot_tag == "xray-a"
    assert switched == ["xray-a"]
    assert instance.rebind_slot_candidates()
    assert old.candidate is refreshed
    assert old.candidate_id == refreshed.id


def test_effective_active_candidate_and_status_payload_keep_running_removed_outbound(m, manager_factory, candidate_factory):
    current = candidate_factory("current", country="DE")
    stale = candidate_factory("stale", country="NL")
    instance = manager_factory([current])
    slot = instance.slots["xray-a"]
    slot.process = DummyProcess()
    slot.candidate = stale
    slot.candidate_id = stale.id
    instance.active_candidate_id = stale.id
    effective, subscription_candidate, mismatch = instance.effective_active_candidate()
    assert effective is stale and subscription_candidate is stale and mismatch is False
    payload = instance.status_payload()
    active_card = next(item for item in payload["candidates"] if item["active"])
    assert active_card["name"] == stale.name
    assert active_card["id"] == "slot:xray-a"
    assert active_card["slot_tags"] == ["xray-a"]
    assert any(item["id"] == current.id for item in payload["candidates"])
    assert payload["blue_green"]["active_slot"] == "xray-a"
    assert payload["release_notes"]["version"] == "v0.7.4"


def test_xray_version_select_initialize_and_shutdown(m, manager_factory, candidate_factory, monkeypatch):
    candidate = candidate_factory("node")
    instance = manager_factory([candidate])
    instance._xray_version_cache = ""
    monkeypatch.setattr(m.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess([], 0, "Xray 1.2\nrest", ""))
    assert instance.xray_version() == "Xray 1.2"
    instance.slots["xray-a"].process = DummyProcess()
    instance.active_candidate_id = candidate.id
    calls = []
    instance.restart_xray_for = lambda *a, **k: calls.append((a, k))
    instance.select_candidate(candidate.id)
    assert calls == []
    instance.active_candidate_id = "other"
    instance.select_candidate(candidate.id)
    assert calls and calls[0][1]["preempt_draining"] is True
    with pytest.raises(ValueError, match="не найден"):
        instance.select_candidate("missing")

    instance = manager_factory()
    instance.load_cached_subscription = lambda: []
    instance.refresh_subscription_sync = lambda **k: None
    instance.initialize()
    server = type("Server", (), {"shutdown": lambda self: setattr(self, "down", True), "server_close": lambda self: setattr(self, "closed", True)})()
    instance.servers = [server]
    stopped = []
    instance.stop_xray = lambda: stopped.append(True)
    instance.shutdown()
    assert instance.stop_event.is_set() and instance.settings_event.is_set()
    assert instance.servers == [] and stopped == [True]
