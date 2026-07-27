from __future__ import annotations

from types import SimpleNamespace

import pytest


class WaitSequence:
    def __init__(self, *results: bool) -> None:
        self.results = list(results)
        self.set_called = False

    def wait(self, _timeout: float | None = None) -> bool:
        if self.results:
            return self.results.pop(0)
        return True

    def is_set(self) -> bool:
        return self.set_called

    def set(self) -> None:
        self.set_called = True


class IsSetSequence:
    def __init__(self, *results: bool) -> None:
        self.results = list(results)

    def is_set(self) -> bool:
        if self.results:
            return self.results.pop(0)
        return True

    def wait(self, _timeout: float | None = None) -> bool:
        return self.is_set()

    def set(self) -> None:
        self.results = [True]


class SettingsWait:
    def __init__(self, result: bool = False) -> None:
        self.result = result
        self.cleared = False

    def wait(self, _timeout: float | None = None) -> bool:
        return self.result

    def clear(self) -> None:
        self.cleared = True

    def set(self) -> None:
        return


def test_reconcile_startup_selector_restores_expected_or_adopts_live(
    manager_factory, candidate_factory,
):
    expected = candidate_factory("expected")
    live = candidate_factory("live")
    instance = manager_factory([expected, live])
    instance.selector_reconciliation_pending = True
    instance.active_slot_tag = "xray-a"
    instance.active_candidate_id = expected.id
    instance.slots["xray-a"].process = SimpleNamespace(poll=lambda: None)
    instance.slots["xray-b"].process = SimpleNamespace(poll=lambda: None)
    instance.slots["xray-b"].candidate_id = live.id
    instance.slots["xray-b"].candidate = live
    switched: list[str] = []
    instance.switch_selector = switched.append

    instance.reconcile_startup_selector("xray-b")
    assert switched == ["xray-a"]
    assert instance.active_slot_tag == "xray-a"
    assert instance.selector_reconciliation_pending is False

    instance.selector_reconciliation_pending = True
    instance.slots["xray-a"].process = None
    saved: list[tuple[str, str]] = []
    instance.save_active_config = lambda slot, item: saved.append((slot, item.id))
    instance.reconcile_startup_selector("xray-b")
    assert instance.active_slot_tag == "xray-b"
    assert instance.active_candidate_id == live.id
    assert saved == [("xray-b", live.id)]


def test_periodic_update_loop_runs_due_refresh_and_reschedules_after_error(
    m, manager_factory, monkeypatch,
):
    instance = manager_factory()
    instance.next_update_at = 1
    instance.stop_event = WaitSequence(False, True)
    calls: list[bool] = []
    instance.refresh_subscription_sync = lambda initial=False: calls.append(initial)
    monkeypatch.setattr(m, "now_ts", lambda: 100)
    instance.periodic_update_loop()
    assert calls == [False]

    instance.stop_event = WaitSequence(False, True)
    instance.next_update_at = 1
    instance.update_interval_hours = 2
    instance.refresh_subscription_sync = lambda **_kwargs: (_ for _ in ()).throw(RuntimeError("offline"))
    instance.periodic_update_loop()
    assert instance.next_update_at == 100 + 2 * 3600


def test_xray_monitor_loop_rolls_back_or_clears_exited_process(manager_factory):
    instance = manager_factory()
    dead = SimpleNamespace(poll=lambda: 7, returncode=7)
    instance.slots["xray-a"].process = dead
    instance.active_slot_tag = "xray-a"
    instance.stop_event = WaitSequence(False, True)
    rollbacks: list[str] = []
    instance.rollback_after_active_exit = lambda slot: rollbacks.append(slot) or True
    instance.xray_monitor_loop()
    assert rollbacks == ["xray-a"]

    instance.stop_event = WaitSequence(False, True)
    instance.slots["xray-a"].process = dead
    instance.restart_on_runtime_error = False
    instance.rollback_after_active_exit = lambda _slot: False
    instance.xray_monitor_loop()
    assert instance.slots["xray-a"].process is None


def test_drain_monitor_stops_quiet_slot(manager_factory, monkeypatch):
    instance = manager_factory()
    slot = instance.slots["xray-a"]
    slot.draining = True
    slot.drain_zero_since = 1
    slot.drain_protect_until = 0
    slot.drain_bytes = 0
    instance.drain_quiet_seconds = 0
    instance.stop_event = WaitSequence(False, True)
    instance.selector_connections = lambda: []
    instance.connections_for_slot = lambda _items, _tag: []
    instance.connection_slot_stats = lambda _items, _tag: (0, 0, 0, 0)
    instance.local_tcp_connection_count = lambda _port: 0
    monkeypatch.setattr("xray_proxy_manager_test_module.now_ts", lambda: 100)
    stopped: list[str] = []
    instance.stop_slot = stopped.append

    instance.drain_monitor_loop()
    assert stopped == ["xray-a"]
    assert instance.selector_state["connections_supported"] is True


def test_auto_checker_loop_success_updates_latency_and_schedules_full_scan(
    manager_factory, candidate_factory,
):
    active = candidate_factory("active")
    instance = manager_factory([active])
    instance.active_candidate_id = active.id
    instance.slots["xray-a"].candidate_id = active.id
    instance.stop_event = IsSetSequence(False, False, True)
    instance.settings_event = SettingsWait(False)
    instance.auto_check_wait_seconds = lambda: 0
    drain_checks: list[bool] = []
    instance.check_draining_slots_health = lambda: drain_checks.append(True)
    instance.check_active_tunnel = lambda: (True, 48.6, [{"url": "test", "ok": True}], "")
    instance.format_probe_results = lambda _checks: "primary=49ms"
    instance.auto_best_check_due = lambda _timestamp: True
    scans: list[dict] = []
    instance.request_latency_test = lambda *args, **kwargs: scans.append({"args": args, "kwargs": kwargs}) or True

    instance.auto_checker_loop()
    assert drain_checks == [True]
    assert instance.state["auto_check_failures"] == 0
    assert instance.latencies[active.id]["latency_ms"] == 49
    assert scans[0]["kwargs"]["source"] == "auto-best"
    assert active.id not in instance.latency_checking_ids


def test_auto_checker_loop_threshold_triggers_emergency_failover(
    manager_factory, candidate_factory,
):
    active = candidate_factory("active")
    backup = candidate_factory("backup")
    instance = manager_factory([active, backup])
    instance.active_candidate_id = active.id
    instance.slots["xray-a"].candidate_id = active.id
    instance.state["auto_check_failures"] = instance.auto_check_failures - 1
    instance.stop_event = IsSetSequence(False, False, True)
    instance.settings_event = SettingsWait(False)
    instance.auto_check_wait_seconds = lambda: 0
    instance.check_draining_slots_health = lambda: None
    instance.check_active_tunnel = lambda: (False, None, [], "timeout")
    instance.format_probe_results = lambda _checks: ""
    instance.choose_failover_candidate = lambda: backup
    switched: list[tuple] = []
    instance.restart_xray_for = lambda *args, **kwargs: switched.append((args, kwargs))

    instance.auto_checker_loop()
    assert instance.state["auto_check_failures"] == instance.auto_check_failures
    assert instance.latencies[active.id]["status"] == "error"
    assert switched[0][0][0] is backup
    assert switched[0][1]["emergency_failover"] is True


def test_run_starts_background_workers_and_all_servers(m, manager_factory, monkeypatch):
    instance = manager_factory()
    instance.stop_event = WaitSequence(True)
    instance.initialize = lambda: None
    instance.request_latency_test = lambda *args, **kwargs: True
    instance.effective_latency_test_parallelism = lambda _count: 2
    instance.detect_ingress_port = lambda: 8124
    started_targets: list[str] = []

    class FakeThread:
        def __init__(self, target, daemon=True):
            self.target = target
            self.daemon = daemon

        def start(self):
            started_targets.append(getattr(self.target, "__name__", "serve_forever"))

    class FakeServer:
        def __init__(self, address, *args, **kwargs):
            self.address = address
            self.args = args
            self.kwargs = kwargs

        def serve_forever(self):
            return

        def shutdown(self):
            return

        def server_close(self):
            return

    monkeypatch.setattr(m.threading, "Thread", FakeThread)
    monkeypatch.setattr(m, "ThreadingHTTPServer", FakeServer)
    monkeypatch.setattr(m, "ThreadingTCPProxyServer", FakeServer)

    instance.run()
    assert len(instance.servers) == 3
    assert {server.address for server in instance.servers} == {
        ("127.0.0.1", instance.ui_port),
        ("0.0.0.0", 8124),
        ("0.0.0.0", m.WATCHDOG_PORT),
    }
    assert len(started_targets) == 9  # six workers and three servers


def test_run_rejects_watchdog_port_for_ingress(m, manager_factory, monkeypatch):
    instance = manager_factory()
    instance.initialize = lambda: None
    instance.request_latency_test = lambda *args, **kwargs: False
    instance.detect_ingress_port = lambda: m.WATCHDOG_PORT
    monkeypatch.setattr(m.threading, "Thread", lambda *args, **kwargs: SimpleNamespace(start=lambda: None))
    with pytest.raises(RuntimeError, match="reserved watchdog port"):
        instance.run()


def test_main_registers_signals_runs_and_always_shuts_down(m, monkeypatch):
    calls: list[str] = []
    handlers: list = []

    class FakeManager:
        def run(self):
            calls.append("run")

        def shutdown(self):
            calls.append("shutdown")

    monkeypatch.setattr(m, "XrayManager", FakeManager)
    monkeypatch.setattr(m.signal, "signal", lambda _sig, handler: handlers.append(handler))
    assert m.main() == 0
    assert calls == ["run", "shutdown"]
    handlers[0](0, None)
    assert calls[-1] == "shutdown"

    class FailingManager(FakeManager):
        def run(self):
            raise RuntimeError("boom")

    monkeypatch.setattr(m, "XrayManager", FailingManager)
    monkeypatch.setattr(m.traceback, "print_exc", lambda: None)
    assert m.main() == 1


def test_latency_job_checks_candidates_and_applies_weighted_preference(
    manager_factory, candidate_factory,
):
    current = candidate_factory("current", country="US", protocol="VLESS")
    preferred = candidate_factory("preferred", country="FI", protocol="TROJAN")
    instance = manager_factory([current, preferred])
    instance.active_slot_tag = "xray-a"
    instance.active_candidate_id = current.id
    instance.slots["xray-a"].process = SimpleNamespace(poll=lambda: None)
    instance.slots["xray-a"].candidate = current
    instance.slots["xray-a"].candidate_id = current.id
    instance.slots["xray-a"].candidate_name = current.name
    instance.auto_switch_preferred_country = "FI"
    instance.auto_switch_preferred_protocol = "VLESS"
    instance.auto_switch_min_ping_delta_ms = 100
    results = {
        current.id: {"status": "ok", "latency_ms": 40, "checked_at": 10, "error": ""},
        preferred.id: {"status": "ok", "latency_ms": 75, "checked_at": 10, "error": ""},
    }
    instance.test_candidate_for_full_scan = lambda item: dict(results[item.id])
    draining_results: list[dict] = []
    instance.handle_draining_full_scan_results = lambda fresh: draining_results.append(dict(fresh))
    switched: list[tuple] = []
    instance.restart_xray_for = lambda *args, **kwargs: switched.append((args, kwargs))

    instance.latency_job(switch_to_best=True, source="manual")

    assert instance.state["jobs"]["latency"]["running"] is False
    assert instance.state["jobs"]["latency"]["progress"] == 2
    assert instance.latencies[current.id]["latency_ms"] == 40
    assert instance.latencies[preferred.id]["latency_ms"] == 75
    assert draining_results and set(draining_results[0]) == {current.id, preferred.id}
    assert switched[0][0][0] is preferred  # country preference outweighs protocol/ping
    assert instance.latency_checking_ids == set()
    assert instance.state["auto_best_check_last_at"] is not None


def test_latency_job_records_candidate_and_runtime_slot_errors(
    manager_factory, candidate_factory,
):
    candidate = candidate_factory("candidate")
    runtime = candidate_factory("runtime")
    instance = manager_factory([candidate])
    slot = instance.slots["xray-b"]
    slot.process = SimpleNamespace(poll=lambda: None)
    slot.candidate = runtime
    slot.candidate_id = runtime.id
    slot.candidate_name = runtime.name
    instance.test_candidate_for_full_scan = lambda _item: (_ for _ in ()).throw(RuntimeError("candidate down"))
    instance.test_running_slot_for_full_scan = lambda _tag: (_ for _ in ()).throw(RuntimeError("slot down"))
    instance.handle_draining_full_scan_results = lambda _fresh: None

    instance.latency_job(candidate_ids=[candidate.id, "slot:xray-b"])

    assert instance.latencies[candidate.id]["status"] == "error"
    assert instance.latencies["slot:xray-b"]["status"] == "error"
    assert "candidate down" in instance.latencies[candidate.id]["error"]
    assert "slot down" in instance.latencies["slot:xray-b"]["error"]
    assert instance.state["jobs"]["latency"]["progress"] == 2


def test_rollback_to_running_slot_commits_selector_and_drain_state(
    manager_factory, candidate_factory,
):
    failed = candidate_factory("failed")
    rollback = candidate_factory("rollback")
    instance = manager_factory([failed, rollback])
    instance.active_slot_tag = "xray-b"
    instance.active_candidate_id = failed.id
    instance.switch_generation = 4
    for tag, item in (("xray-a", rollback), ("xray-b", failed)):
        slot = instance.slots[tag]
        slot.process = SimpleNamespace(poll=lambda: None)
        slot.candidate = item
        slot.candidate_id = item.id
        slot.candidate_name = item.name
    selectors: list[str] = []
    instance.switch_selector = selectors.append
    saved: list[tuple[str, str]] = []
    instance.save_active_config = lambda tag, item: saved.append((tag, item.id))
    baselines: list[str] = []
    instance.capture_drain_connection_baseline = baselines.append

    assert instance.rollback_to_running_slot(4, "xray-b", "xray-a", rollback, "validation failed") is True
    assert selectors == ["xray-a"]
    assert instance.active_slot_tag == "xray-a"
    assert instance.active_candidate_id == rollback.id
    assert instance.slots["xray-a"].draining is False
    assert instance.slots["xray-b"].draining is True
    assert instance.switch_generation == 5
    assert instance.state["last_switch_reason"] == "validation failed"
    assert saved == [("xray-a", rollback.id)]
    assert baselines == ["xray-b"]


def test_post_switch_watch_rolls_back_after_two_failures(
    manager_factory, candidate_factory,
):
    rollback = candidate_factory("rollback")
    instance = manager_factory([rollback])
    instance.active_slot_tag = "xray-b"
    instance.switch_generation = 3
    instance.slots["xray-b"].process = SimpleNamespace(poll=lambda: None)
    instance.stop_event = WaitSequence(False, False)
    instance.probe_slot_health = lambda _tag: (False, None, [], "probe failed")
    rollbacks: list[tuple] = []
    instance.rollback_to_running_slot = lambda *args: rollbacks.append(args) or True

    instance.post_switch_watch(3, "xray-b", "xray-a", rollback)
    assert len(rollbacks) == 1
    assert rollbacks[0][:4] == (3, "xray-b", "xray-a", rollback)


def test_post_switch_watch_force_stops_degraded_rollback_after_recovery(
    manager_factory, candidate_factory,
):
    rollback = candidate_factory("rollback")
    instance = manager_factory([rollback])
    instance.active_slot_tag = "xray-b"
    instance.switch_generation = 3
    instance.slots["xray-b"].process = SimpleNamespace(poll=lambda: None)
    instance.slots["xray-a"].process = SimpleNamespace(poll=lambda: None)
    instance.slots["xray-a"].draining = True
    instance.slots["xray-a"].drain_connections = 7
    instance.stop_event = WaitSequence(False, False)
    instance.probe_slot_health = lambda _tag: (True, 40, [], "")
    stopped: list[str] = []
    instance.force_stop_draining_slot = lambda tag: stopped.append(tag) or tag

    instance.post_switch_watch(
        3, "xray-b", "xray-a", rollback, force_disconnect_rollback=True,
    )
    assert stopped == ["xray-a"]
