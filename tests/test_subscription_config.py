from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest


def test_download_subscription_once_direct_and_proxy(m, manager_factory, monkeypatch):
    instance = manager_factory()
    captured = []
    def run(command, **kwargs):
        captured.append((command, kwargs))
        output_path = Path(command[-1])
        output_path.write_text(json.dumps({"outbounds": [{"protocol": "vless"}]}), encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, "", "")
    monkeypatch.setattr(m.subprocess, "run", run)
    result = instance.download_subscription_once()
    assert len(result) == 1
    assert "--noproxy" in captured[0][0]
    result = instance.download_subscription_once("xray-a")
    assert len(result) == 1
    assert "--socks5-hostname" in captured[1][0]

    instance.proxy_username = "u"
    instance.proxy_password = "p"
    instance.download_subscription_once("xray-a")
    assert "--proxy-user" in captured[2][0]


def test_download_subscription_once_rejects_curl_and_payload_errors(m, manager_factory, monkeypatch):
    instance = manager_factory()
    monkeypatch.setattr(m.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess([], 1, "", "curl failed"))
    with pytest.raises(RuntimeError, match="curl failed"):
        instance.download_subscription_once()

    def write_payload(payload):
        def run(command, **kwargs):
            Path(command[-1]).write_text(json.dumps(payload), encoding="utf-8")
            return subprocess.CompletedProcess(command, 0, "", "")
        return run
    monkeypatch.setattr(m.subprocess, "run", write_payload("bad"))
    with pytest.raises(ValueError, match="object or array"):
        instance.download_subscription_once()
    monkeypatch.setattr(m.subprocess, "run", write_payload([1, "x"]))
    with pytest.raises(ValueError, match="no JSON"):
        instance.download_subscription_once()


def test_download_subscription_falls_back_to_running_slots(m, manager_factory):
    instance = manager_factory()
    class Process:
        def poll(self): return None
    instance.slots["xray-a"].process = Process()
    calls = []
    def download(slot=None):
        calls.append(slot)
        if slot is None:
            raise RuntimeError("direct down")
        return [{"slot": slot}]
    instance.download_subscription_once = download
    assert instance.download_subscription() == [{"slot": "xray-a"}]
    assert calls == [None, "xray-a"]
    instance.slots["xray-a"].process = None
    with pytest.raises(RuntimeError, match="direct down"):
        instance.download_subscription()


def test_load_cached_subscription(m, manager_factory, isolated_paths, monkeypatch):
    instance = manager_factory()
    monkeypatch.setattr(m, "SUBSCRIPTION_PATH", isolated_paths.SUBSCRIPTION_PATH)
    isolated_paths.SUBSCRIPTION_PATH.write_text(json.dumps({"a": 1}), encoding="utf-8")
    assert instance.load_cached_subscription() == [{"a": 1}]
    isolated_paths.SUBSCRIPTION_PATH.write_text(json.dumps([{"a": 1}, 2]), encoding="utf-8")
    assert instance.load_cached_subscription() == [{"a": 1}]
    isolated_paths.SUBSCRIPTION_PATH.write_text("null", encoding="utf-8")
    assert instance.load_cached_subscription() == []


def test_extract_candidates_filters_direct_and_preserves_duplicate_entries(m, manager_factory):
    instance = manager_factory()
    configs = [{
        "remarks": "🇫🇮 Profile",
        "outbounds": [
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "node", "protocol": "vless", "settings": {"vnext": [{"address": "fi.example", "port": 443}]}},
            {"tag": "node-2", "protocol": "vless", "settings": {"vnext": [{"address": "fi.example", "port": 443}]}},
        ],
    }]
    candidates = instance.extract_candidates(configs)
    assert len(candidates) == 2
    assert candidates[0].name == "🇫🇮 Profile — node"
    assert candidates[0].protocol == "VLESS"
    assert candidates[0].country_code == "FI"
    assert candidates[0].id != candidates[1].id
    assert candidates[0].fingerprint == candidates[1].fingerprint


def test_candidate_lookup_identity_and_latency(m, manager_factory, candidate_factory):
    first = candidate_factory("first", fingerprint="same", outbound_tag="tag", source_index=0)
    refreshed = candidate_factory("refreshed", fingerprint="same", outbound_tag="tag", source_index=1)
    other = candidate_factory("other", fingerprint="different", outbound_tag="tag", source_index=1)
    instance = manager_factory([first, refreshed, other])
    assert instance.candidate_by_id("first") is first
    assert instance.candidate_by_tag("tag", preferred_source=1) is refreshed
    assert instance.candidate_by_tag("missing") is None
    assert instance.slot_candidate_id("xray-a") == "slot:xray-a"
    assert m.XrayManager.same_outbound(first, refreshed)
    assert not m.XrayManager.same_candidate_identity(first, refreshed)
    assert m.XrayManager.same_candidate_identity(first, first)
    assert not m.XrayManager.same_outbound(first, other)
    assert not m.XrayManager.same_outbound(None, first)
    instance.latencies[first.id] = {"status": "ok", "latency_ms": 42}
    assert instance.candidate_latency_ms(first) == 42
    instance.latencies[first.id] = {"status": "error", "latency_ms": 42}
    assert instance.candidate_latency_ms(first) is None


def test_running_slot_lookup(m, manager_factory, candidate_factory):
    candidate = candidate_factory("running")
    instance = manager_factory([candidate])
    class Process:
        def poll(self): return None
    slot = instance.slots["xray-a"]
    slot.process = Process()
    slot.candidate = candidate
    slot.candidate_id = candidate.id
    assert instance.running_slot_by_candidate_id("slot:xray-a") is slot
    assert instance.running_slot_by_candidate_id(candidate.id) is slot
    assert instance.running_slot_by_candidate_id("missing") is None


def test_choose_initial_candidate_respects_remembered_exclusion_preference_and_delta(
    m, manager_factory, candidate_factory
):
    selected = candidate_factory("selected", country="DE", source_index=0)
    excluded = candidate_factory("excluded", country="RU", source_index=0)
    best = candidate_factory("best", country="NL", source_index=1)
    instance = manager_factory([excluded, selected, best])
    instance.state["active_candidate_id"] = selected.id
    instance.latencies = {
        selected.id: {"status": "ok", "latency_ms": 300},
        best.id: {"status": "ok", "latency_ms": 100},
    }
    instance.auto_switch_preferred_country = "NL"
    assert instance.choose_initial_candidate() is best
    instance.auto_switch_preferred_country = ""
    instance.auto_switch_min_ping_delta_ms = 250
    assert instance.choose_initial_candidate() is selected
    instance.state["active_candidate_id"] = excluded.id
    assert instance.choose_initial_candidate() is best
    instance.candidates = []
    with pytest.raises(RuntimeError, match="No proxy"):
        instance.choose_initial_candidate()


def test_patch_inbounds_for_test_runtime_auth_and_preserve_mode(m, manager_factory):
    instance = manager_factory()
    config = {"inbounds": [{"protocol": "http", "port": 80}, {"protocol": "socks", "port": 1}]}
    test_config = instance.patch_inbounds(config, test_port=19000)
    assert test_config["inbounds"][0]["listen"] == "127.0.0.1"
    assert test_config["inbounds"][0]["settings"]["udp"] is False
    assert test_config["log"]["loglevel"] == "none"

    instance.proxy_username = "user"
    instance.proxy_password = "pass"
    runtime = instance.patch_inbounds(config, slot_tag="xray-a")
    assert runtime["inbounds"] == [runtime["inbounds"][0]]
    assert runtime["inbounds"][0]["listen"] == "0.0.0.0"
    assert runtime["inbounds"][0]["settings"]["auth"] == "password"

    instance.override_inbounds = False
    preserved = instance.patch_inbounds(config, slot_tag="xray-a")
    assert preserved["inbounds"][0]["protocol"] == "http"
    assert preserved["inbounds"][1]["port"] == 10808
    with pytest.raises(ValueError, match="slot_tag"):
        instance.patch_inbounds(config)


def test_build_config_selects_outbound_and_validates_indexes(m, manager_factory):
    instance = manager_factory()
    instance.subscription = [{
        "outbounds": [
            {"tag": "node", "protocol": "vless", "settings": {"vnext": [{"address": "a", "port": 443}]}},
            {"tag": "direct", "protocol": "freedom"},
        ],
        "routing": {"rules": []},
    }]
    candidate = instance.extract_candidates(instance.subscription)[0]
    config = instance.build_config(candidate, slot_tag="xray-a")
    assert config["routing"]["rules"][0]["outboundTag"] == "node"
    assert config["inbounds"][0]["port"] == 10808
    bad_source = type(candidate)(**{**candidate.__dict__, "source_index": 9})
    with pytest.raises(ValueError, match="source config"):
        instance.build_config(bad_source, slot_tag="xray-a")
    bad_outbound = type(candidate)(**{**candidate.__dict__, "outbound_index": 9})
    with pytest.raises(ValueError, match="outbound"):
        instance.build_config(bad_outbound, slot_tag="xray-a")


def test_xray_test_prepare_install_write_and_diff(m, manager_factory, candidate_factory, monkeypatch, tmp_path):
    instance = manager_factory()
    candidate = candidate_factory("c")
    instance.subscription = [candidate_factory("c").__dict__]  # replaced below by build stub
    monkeypatch.setattr(m.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess([], 0, "Configuration OK", ""))
    ok, output = instance.xray_test(tmp_path / "config.json")
    assert ok and "Configuration OK" in output
    monkeypatch.setattr(m.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess([], 0, "EOF", ""))
    assert instance.xray_test(tmp_path / "config.json")[0] is False

    instance.build_config = lambda *_args, **_kwargs: {"value": 1}
    instance.xray_test = lambda path: (True, "")
    temp, changed = instance.prepare_slot_config("xray-a", candidate)
    assert changed is True and temp.exists()
    instance.install_prepared_slot_config("xray-a", candidate, temp)
    assert instance.slots["xray-a"].candidate is candidate
    assert instance.runtime_config_differs("xray-a", candidate) is False
    instance.build_config = lambda *_args, **_kwargs: {"value": 2}
    assert instance.runtime_config_differs("xray-a", candidate) is True

    instance.prepare_slot_config = lambda *_args: (tmp_path / "prepared.json", True)
    (tmp_path / "prepared.json").write_text("{}")
    assert instance.write_slot_config("xray-a", candidate) is True


def test_prepare_slot_config_removes_invalid_temp(m, manager_factory, candidate_factory):
    instance = manager_factory()
    candidate = candidate_factory()
    instance.build_config = lambda *a, **k: {"x": 1}
    instance.xray_test = lambda path: (False, "invalid")
    with pytest.raises(RuntimeError, match="invalid"):
        instance.prepare_slot_config("xray-a", candidate)
    assert not instance.slots["xray-a"].config_path.with_name("a.new.json").exists()


def test_save_active_clone_and_write_runtime_config(m, manager_factory, candidate_factory, isolated_paths, monkeypatch):
    instance = manager_factory()
    candidate = candidate_factory("active")
    monkeypatch.setattr(m, "CONFIG_PATH", isolated_paths.CONFIG_PATH)
    monkeypatch.setattr(m, "LAST_GOOD_CONFIG_PATH", isolated_paths.LAST_GOOD_CONFIG_PATH)
    monkeypatch.setattr(m, "LAST_GOOD_META_PATH", isolated_paths.LAST_GOOD_META_PATH)
    source = instance.slots["xray-a"]
    source.config_path.write_text(json.dumps({"inbounds": [], "value": 1}), encoding="utf-8")
    source.candidate = candidate
    source.candidate_id = candidate.id
    source.candidate_name = candidate.name
    instance.save_active_config("xray-a", candidate)
    assert isolated_paths.CONFIG_PATH.exists()
    assert json.loads(isolated_paths.LAST_GOOD_META_PATH.read_text())["candidate_id"] == candidate.id

    instance.xray_test = lambda path: (True, "")
    instance.clone_slot_config("xray-a", "xray-b")
    assert instance.slots["xray-b"].candidate is candidate
    assert json.loads(instance.slots["xray-b"].config_path.read_text())["inbounds"][0]["port"] == 10809
    instance.active_slot_tag = "xray-b"
    called = []
    instance.write_slot_config = lambda slot, item: called.append((slot, item.id)) or True
    assert instance.write_runtime_config(candidate) is True
    assert called == [("xray-b", candidate.id)]


def test_save_active_and_clone_missing_config_fail(m, manager_factory, candidate_factory):
    instance = manager_factory()
    candidate = candidate_factory()
    with pytest.raises(RuntimeError, match="missing"):
        instance.save_active_config("xray-a", candidate)
    with pytest.raises(RuntimeError, match="Cannot clone"):
        instance.clone_slot_config("xray-a", "xray-b")
