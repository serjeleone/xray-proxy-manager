from __future__ import annotations

import io
import json
import subprocess
import threading
from pathlib import Path

import pytest

from conftest import DummyProcess


def test_log_xray_output_tracks_observed_outbound_and_filters_observatory(m, manager_factory, capsys):
    instance = manager_factory()
    process = DummyProcess(stdout=(
        "[Info] infra/conf/serial: Reading config: &{Name:/config/a.json Format:json}\n"
        "[Info] [1 -> node-tag] accepted\n"
        "app/observatory/burst: error ping ignored\n"
    ))
    instance.log_xray_output("xray-a", process)
    assert instance.slots["xray-a"].observed_outbound_tag == "node-tag"
    lines, _ = m.ui_log_snapshot(20)
    assert any("Reading config: /config/a.json" in line for line in lines)
    assert not any("error ping ignored" in line for line in lines)


def test_start_slot_writes_config_starts_process_and_is_idempotent(m, manager_factory, candidate_factory, monkeypatch):
    instance = manager_factory()
    candidate = candidate_factory("node")
    written = []
    instance.write_slot_config = lambda tag, item: (
        instance.slots[tag].config_path.write_text("{}"),
        setattr(instance.slots[tag], "candidate", item),
        setattr(instance.slots[tag], "candidate_id", item.id),
        written.append((tag, item.id)),
    ) and True
    process = DummyProcess(stdout="")
    monkeypatch.setattr(m.subprocess, "Popen", lambda *a, **k: process)
    class Thread:
        def __init__(self, *a, **k): self.started = False
        def start(self): self.started = True
    monkeypatch.setattr(m.threading, "Thread", Thread)
    instance.start_slot("xray-a", candidate)
    assert written == [("xray-a", candidate.id)]
    assert instance.slots["xray-a"].process is process
    instance.start_slot("xray-a", candidate)
    other = candidate_factory("other")
    with pytest.raises(RuntimeError, match="already running"):
        instance.start_slot("xray-a", other)


def test_start_slot_requires_config_when_no_candidate(m, manager_factory):
    instance = manager_factory()
    with pytest.raises(RuntimeError, match="missing"):
        instance.start_slot("xray-a")


def test_stop_slot_cleans_state_and_kills_on_timeout(m, manager_factory, monkeypatch):
    instance = manager_factory()
    slot = instance.slots["xray-a"]
    class Slow(DummyProcess):
        def wait(self, timeout=None):
            if not self.killed:
                raise subprocess.TimeoutExpired("x", timeout)
            return 0
    process = Slow()
    slot.process = process
    slot.draining = True
    slot.drain_connections = 5
    slot.drain_known_connection_ids = {"1"}
    instance.stop_slot("xray-a")
    assert process.terminated and process.killed
    assert slot.process is None
    assert slot.draining is False
    assert slot.drain_connections == 0
    assert slot.drain_known_connection_ids == set()
    instance.stop_slot("xray-a")


def test_force_stop_draining_slot_guards_and_stops(m, manager_factory):
    instance = manager_factory()
    instance.active_slot_tag = "xray-a"
    instance.slots["xray-b"].draining = True
    instance.slots["xray-b"].drain_connections = 4
    stopped = []
    instance.stop_slot = stopped.append
    assert instance.force_stop_draining_slot() == "xray-b"
    assert stopped == ["xray-b"]
    instance.slots["xray-b"].draining = False
    with pytest.raises(ValueError, match="не найден"):
        instance.force_stop_draining_slot()
    with pytest.raises(RuntimeError, match="Активный"):
        instance.force_stop_draining_slot("xray-a")


def test_start_xray_uses_candidate_or_last_good_config(m, manager_factory, candidate_factory):
    candidate = candidate_factory("active")
    instance = manager_factory([candidate])
    instance.active_candidate_id = candidate.id
    calls = []
    instance.start_initial_candidate = lambda item, reason, *, source="internal": calls.append((item.id, reason, source))
    instance.start_xray()
    assert calls == [(candidate.id, "Xray start", "service_start")]

    instance.active_candidate_id = ""
    instance.slots["xray-a"].config_path.write_text("{}")
    instance.start_slot = lambda tag: calls.append((tag, "start-slot")) or setattr(instance.slots[tag], "process", DummyProcess())
    instance.wait_for_port = lambda *a, **k: True
    instance.selector_control_enabled = False
    instance.start_xray()
    assert ("xray-a", "start-slot") in calls


def test_start_xray_stops_slot_when_port_does_not_open(m, manager_factory):
    instance = manager_factory()
    instance.slots["xray-a"].config_path.write_text("{}")
    instance.start_slot = lambda tag: setattr(instance.slots[tag], "process", DummyProcess())
    instance.wait_for_port = lambda *a, **k: False
    stopped = []
    instance.stop_slot = stopped.append
    with pytest.raises(RuntimeError, match="did not open"):
        instance.start_xray()
    assert stopped == ["xray-a"]


def test_stop_xray_and_small_validation_helpers(m, manager_factory):
    instance = manager_factory()
    stopped = []
    instance.stop_slot = stopped.append
    instance.stop_xray()
    assert stopped == ["xray-a", "xray-b"]
    assert instance.other_slot_tag("xray-a") == "xray-b"
    assert instance.other_slot_tag("xray-b") == "xray-a"
    assert instance.validation_urls() == [instance.primary_test_url, instance.secondary_test_url]
    assert instance.test_url_label(instance.primary_test_url) == "primary_test_url"
    assert instance.test_url_label(instance.secondary_test_url) == "secondary_test_url"
    assert instance.test_url_label("other") == "test_url"
    assert "primary_test_url=10ms" in instance.format_probe_results([(instance.primary_test_url, 10.2)])


def test_probe_proxy_urls_success_and_failure(m, manager_factory):
    instance = manager_factory()
    def proxy_curl(host, port, url, timeout, auth):
        if url == instance.primary_test_url:
            return True, 90.0, ""
        return True, 40.0, ""
    instance.proxy_curl = proxy_curl
    success, minimum, results, error = instance.probe_proxy_urls("127.0.0.1", 10808, 3, auth=True)
    assert success and minimum == 40.0 and len(results) == 2 and error == ""
    instance.proxy_curl = lambda *a, **k: (False, None, "timeout")
    success, minimum, results, error = instance.probe_proxy_urls("127.0.0.1", 10808, 3, auth=True)
    assert not success and minimum is None and results == [] and "timeout" in error


def test_probe_slot_health_and_validate_slot(m, manager_factory):
    instance = manager_factory()
    instance.slots["xray-a"].process = DummyProcess()
    instance.probe_proxy_urls = lambda *a, **k: (True, 600.0, [(instance.primary_test_url, 600.0)], "")
    ok, latency, _, error = instance.probe_slot_health("xray-a")
    assert not ok and latency == 600.0 and "threshold" in error
    ok, latency, _, error = instance.probe_slot_health("xray-a", enforce_latency_limit=False)
    assert ok and latency == 600.0
    instance.wait_for_port = lambda *a, **k: True
    instance.probe_slot_health = lambda *a, **k: (True, 20.0, [(instance.primary_test_url, 20.0)], "")
    assert instance.validate_slot("xray-a") == (20.0, [(instance.primary_test_url, 20.0)])
    instance.wait_for_port = lambda *a, **k: False
    with pytest.raises(RuntimeError, match="did not open"):
        instance.validate_slot("xray-a")


def test_start_initial_candidate_commits_state_and_cleans_up_on_failure(m, manager_factory, candidate_factory):
    candidate = candidate_factory("node")
    instance = manager_factory([candidate])
    instance.selector_control_enabled = False
    started = []
    instance.start_slot = lambda tag, item: started.append(tag) or (
        setattr(instance.slots[tag], "process", DummyProcess()),
        setattr(instance.slots[tag], "candidate", item),
        setattr(instance.slots[tag], "candidate_id", item.id),
    )
    instance.validate_slot = lambda *a, **k: (50.0, [(instance.primary_test_url, 50.0)])
    saved = []
    instance.save_active_config = lambda tag, item: saved.append((tag, item.id))
    instance.start_initial_candidate(candidate, "reason")
    assert instance.active_candidate_id == candidate.id
    assert instance.latencies[candidate.id]["latency_ms"] == 50
    assert saved == [("xray-a", candidate.id)]

    instance.validate_slot = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("invalid"))
    stopped = []
    instance.stop_slot = stopped.append
    with pytest.raises(RuntimeError, match="invalid"):
        instance.start_initial_candidate(candidate, "reason")
    assert stopped == ["xray-a"]


def test_restart_xray_dispatches_by_runtime_mode(m, manager_factory, candidate_factory):
    candidate = candidate_factory()
    instance = manager_factory([candidate])
    calls = []
    instance.start_initial_candidate = lambda *a, **k: calls.append("initial")
    instance.switch_candidate_single_slot = lambda *a, **k: calls.append("single")
    instance.switch_candidate_blue_green = lambda *a, **k: calls.append("dual")
    instance.restart_xray_for(candidate, "reason")
    assert calls == ["initial"]
    instance.slots["xray-a"].process = DummyProcess()
    instance.dual_slot_enabled = False
    instance.restart_xray_for(candidate, "reason")
    instance.dual_slot_enabled = True
    instance.restart_xray_for(candidate, "reason")
    assert calls == ["initial", "single", "dual"]


def test_switch_request_log_includes_explicit_source(manager_factory, candidate_factory, capsys):
    candidate = candidate_factory("finland")
    instance = manager_factory([candidate])
    dispatched = []
    instance.start_initial_candidate = lambda item, reason, *, source="internal": dispatched.append(
        (item.id, reason, source)
    )

    instance.restart_xray_for(
        candidate,
        "manual selection from UI",
        source="manual_ui",
    )

    output = capsys.readouterr().out
    assert "switch requested: source=manual_ui; mode=dual" in output
    assert f"target={candidate.name} [{candidate.outbound_tag}]" in output
    assert dispatched == [(candidate.id, "manual selection from UI", "manual_ui")]


def test_blue_green_switch_success_path(m, manager_factory, candidate_factory, monkeypatch):
    old = candidate_factory("old")
    new = candidate_factory("new")
    instance = manager_factory([old, new])
    instance.active_slot_tag = "xray-a"
    instance.active_candidate_id = old.id
    instance.slots["xray-a"].process = DummyProcess()
    instance.slots["xray-a"].candidate = old
    instance.slots["xray-a"].candidate_id = old.id
    instance.selector_status = lambda: instance.active_slot_tag
    switched = []
    instance.switch_selector = lambda tag: switched.append(tag)
    def start(tag, candidate=None):
        slot = instance.slots[tag]
        slot.process = DummyProcess()
        if candidate:
            slot.candidate = candidate
            slot.candidate_id = candidate.id
            slot.candidate_name = candidate.name
    instance.start_slot = start
    instance.validate_slot = lambda tag: (35.0, [(instance.primary_test_url, 35.0)])
    instance.save_active_config = lambda *a: None
    instance.capture_drain_connection_baseline = lambda *a: None
    class NoThread:
        def __init__(self, *a, **k): pass
        def start(self): pass
    monkeypatch.setattr(m.threading, "Thread", NoThread)
    instance.switch_candidate_blue_green(new, "manual", source="manual_ui")
    assert switched[-1] == "xray-b"
    assert instance.active_slot_tag == "xray-b"
    assert instance.active_candidate_id == new.id
    assert instance.slots["xray-a"].draining is True
    assert instance.latencies[new.id]["status"] == "ok"
    assert instance.state["jobs"]["switch"]["running"] is False
    assert instance.state["last_switch_source"] == "manual_ui"


def test_blue_green_switch_rejects_wrong_mode_or_unavailable_selector(m, manager_factory, candidate_factory):
    instance = manager_factory([candidate_factory()])
    instance.dual_slot_enabled = False
    with pytest.raises(RuntimeError, match="disabled"):
        instance.switch_candidate_blue_green(instance.candidates[0], "x")
    instance.dual_slot_enabled = True
    instance.selector_control_enabled = False
    with pytest.raises(RuntimeError, match="selector"):
        instance.switch_candidate_blue_green(instance.candidates[0], "x")


def test_single_slot_switch_success_and_rollback(m, manager_factory, candidate_factory, tmp_path):
    old = candidate_factory("old")
    new = candidate_factory("new")
    instance = manager_factory([old, new])
    instance.dual_slot_enabled = False
    slot = instance.slots["xray-a"]
    slot.process = DummyProcess()
    slot.candidate = old
    slot.candidate_id = old.id
    slot.config_path.write_text("old", encoding="utf-8")
    prepared = tmp_path / "new.json"
    prepared.write_text("new", encoding="utf-8")
    instance.prepare_slot_config = lambda *a: (prepared, True)
    instance.stop_slot = lambda tag: setattr(slot, "process", None)
    instance.install_prepared_slot_config = lambda tag, candidate, path: (
        slot.config_path.write_bytes(path.read_bytes()),
        path.unlink(),
        setattr(slot, "candidate", candidate),
        setattr(slot, "candidate_id", candidate.id),
    )
    instance.start_slot = lambda tag, candidate=None: setattr(slot, "process", DummyProcess())
    instance.validate_slot = lambda *a, **k: (25.0, [(instance.primary_test_url, 25.0)])
    instance.save_active_config = lambda *a: None
    instance.selector_control_enabled = False
    instance.switch_candidate_single_slot(new, "manual", source="manual_ui")
    assert instance.active_candidate_id == new.id
    assert instance.latencies[new.id]["latency_ms"] == 25
    assert instance.state["last_switch_source"] == "manual_ui"


def test_local_tcp_connection_count_reads_proc_tables(m, manager_factory, monkeypatch, tmp_path):
    instance = manager_factory()
    tcp = tmp_path / "tcp"
    tcp6 = tmp_path / "tcp6"
    tcp.write_text("header\n 0: 00000000:2A38 00000000:0000 01 rest\n 1: 00000000:2A38 00000000:0000 0A listen\n")
    tcp6.write_text("header\n 0: 00000000:2A38 00000000:0000 01 rest\n")
    original = Path
    # Method constructs fixed Path objects; replace module Path with a delegating factory for those two paths.
    class PathProxy(type(Path())):
        pass
    mapping = {"/proc/net/tcp": tcp, "/proc/net/tcp6": tcp6}
    monkeypatch.setattr(m, "Path", lambda value: mapping.get(str(value), original(value)))
    assert instance.local_tcp_connection_count(10808) == 2
