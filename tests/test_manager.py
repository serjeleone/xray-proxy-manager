from __future__ import annotations

import importlib.util
import sys
import threading
import time
import unittest
from pathlib import Path


MANAGER_PATH = Path(__file__).parents[1] / "xray-proxy-manager" / "manager.py"
SPEC = importlib.util.spec_from_file_location("xray_proxy_manager_test_module", MANAGER_PATH)
assert SPEC and SPEC.loader
manager = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = manager
SPEC.loader.exec_module(manager)


class DummyProcess:
    def __init__(self) -> None:
        self.dead = False

    def poll(self) -> int | None:
        return 0 if self.dead else None


def candidate(candidate_id: str, host: str, *, fingerprint: str | None = None):
    return manager.Candidate(
        id=candidate_id,
        name=candidate_id,
        source_index=0,
        outbound_index=0,
        outbound_tag=candidate_id,
        protocol="VLESS",
        server=host,
        port=443,
        country_code="",
        fingerprint=fingerprint or candidate_id,
    )


class ManagerLogicTests(unittest.TestCase):
    def test_same_outbound_survives_candidate_id_refresh(self) -> None:
        old = candidate("old", "198.51.100.10", fingerprint="stable")
        refreshed = candidate("new", "198.51.100.10", fingerprint="stable")
        different = candidate("different", "198.51.100.11")
        self.assertTrue(manager.XrayManager.same_outbound(old, refreshed))
        self.assertFalse(manager.XrayManager.same_outbound(old, different))

    def test_slots_use_independent_ports_and_udp_flags(self) -> None:
        instance = manager.XrayManager.__new__(manager.XrayManager)
        instance.subscription = [{"outbounds": [{"tag": "proxy", "protocol": "freedom"}]}]
        instance.slots = {
            "xray-a": manager.XraySlot("xray-a", 10808, True, Path("/tmp/a.json")),
            "xray-b": manager.XraySlot("xray-b", 10809, False, Path("/tmp/b.json")),
        }
        instance.log_level = "warning"
        instance.proxy_username = ""
        instance.proxy_password = ""
        instance.override_inbounds = True
        instance.auto_fix_tags = True
        instance.auto_add_proxy_direct = True
        instance.validate_tags = True
        selected = manager.Candidate(
            id="proxy",
            name="proxy",
            source_index=0,
            outbound_index=0,
            outbound_tag="proxy",
            protocol="freedom",
            server="",
            port=None,
            country_code="",
            fingerprint="proxy",
        )
        config_a = instance.build_config(selected, slot_tag="xray-a")
        config_b = instance.build_config(selected, slot_tag="xray-b")
        self.assertEqual(config_a["inbounds"][0]["listen"], "0.0.0.0")
        self.assertEqual(config_a["inbounds"][0]["port"], 10808)
        self.assertIs(config_a["inbounds"][0]["settings"]["udp"], True)
        self.assertEqual(config_b["inbounds"][0]["port"], 10809)
        self.assertIs(config_b["inbounds"][0]["settings"]["udp"], False)

    def test_draining_badge_is_remapped_after_subscription_refresh(self) -> None:
        stale = candidate("old-id", "198.51.100.20", fingerprint="stable-old")
        refreshed = candidate("new-id", "198.51.100.20", fingerprint="stable-old")
        active = candidate("active", "198.51.100.30")
        instance = manager.XrayManager.__new__(manager.XrayManager)
        instance.lock = threading.RLock()
        instance.dual_slot_enabled = True
        instance.candidates = [refreshed, active]
        instance.latencies = {}
        instance.active_slot_tag = "xray-b"
        instance.active_candidate_id = active.id
        instance.started_at = int(time.time())
        instance.state = {"jobs": {}, "auto_check_failures": 0}
        instance.next_update_at = None
        instance.subscription_url = ""
        instance.update_interval_hours = 1
        instance.auto_checker_enabled = True
        instance.auto_switch_best_enabled = True
        instance.auto_switch_excluded = "new-id"
        instance.auto_switch_min_ping_delta_ms = 100
        instance.auto_check_interval_seconds = 60
        instance.auto_check_failures = 2
        instance.auto_check_max_latency_ms = 500
        instance.auto_best_check_interval_seconds = 600
        instance.ui_sort = "ping-asc"
        instance.ui_protocol_filter = "all"
        instance.ui_max_ping_ms = 1000
        instance.ui_hide_unavailable = False
        instance.ui_hide_excluded = True
        instance.selector_state = {}
        instance.router_state = {}
        instance.selector_tag = "xray-active"
        instance.drain_quiet_seconds = 30
        instance.drain_timeout_minutes = 0
        instance.primary_test_url = "https://primary.example/"
        instance.secondary_test_url = "https://secondary.example/"
        instance._xray_version_cache = "Xray test"
        instance.slots = {
            "xray-a": manager.XraySlot(
                "xray-a", 10808, True, Path("/tmp/a"), process=DummyProcess(),
                candidate_id=stale.id, candidate_name=stale.name, candidate=stale,
                draining=True, drain_connections=1,
            ),
            "xray-b": manager.XraySlot(
                "xray-b", 10809, True, Path("/tmp/b"), process=DummyProcess(),
                candidate_id=active.id, candidate_name=active.name, candidate=active,
            ),
        }
        instance.candidate_by_id = lambda candidate_id: next(
            (item for item in instance.candidates if item.id == candidate_id), None
        )
        instance.save_state = lambda: None
        instance.effective_active_candidate = lambda: (active, active, False)
        payload = instance.status_payload()
        item = next(item for item in payload["candidates"] if item["id"] == refreshed.id)
        self.assertEqual(item["slot_tags"], ["xray-a"])
        self.assertEqual(item["draining_slots"], ["xray-a"])
        self.assertIs(item["draining"], True)
        self.assertIs(item["excluded"], True)
        self.assertIs(payload["ui_settings"]["hide_excluded"], True)

    def test_status_rebinds_active_slot_before_first_ui_render(self) -> None:
        stale = candidate("old-active-id", "198.51.100.40", fingerprint="stable-active")
        refreshed = candidate("new-active-id", "198.51.100.40", fingerprint="stable-active")
        other = candidate("other", "198.51.100.41")
        instance = manager.XrayManager.__new__(manager.XrayManager)
        instance.lock = threading.RLock()
        instance.dual_slot_enabled = True
        instance.candidates = [other, refreshed]
        instance.latencies = {}
        instance.active_slot_tag = "xray-a"
        instance.active_candidate_id = stale.id
        instance.started_at = int(time.time())
        instance.state = {"jobs": {}, "auto_check_failures": 0, "active_candidate_id": stale.id}
        instance.next_update_at = None
        instance.subscription_url = ""
        instance.update_interval_hours = 1
        instance.auto_checker_enabled = True
        instance.auto_switch_best_enabled = True
        instance.auto_switch_excluded = "RU"
        instance.auto_switch_min_ping_delta_ms = 100
        instance.auto_check_interval_seconds = 60
        instance.auto_check_failures = 2
        instance.auto_check_max_latency_ms = 500
        instance.auto_best_check_interval_seconds = 600
        instance.ui_sort = "ping-asc"
        instance.ui_protocol_filter = "all"
        instance.ui_max_ping_ms = 1000
        instance.ui_hide_unavailable = False
        instance.ui_hide_excluded = True
        instance.selector_state = {}
        instance.router_state = {}
        instance.selector_tag = "xray-active"
        instance.drain_quiet_seconds = 30
        instance.drain_timeout_minutes = 0
        instance.primary_test_url = "https://primary.example/"
        instance.secondary_test_url = "https://secondary.example/"
        instance._xray_version_cache = "Xray test"
        instance.slots = {
            "xray-a": manager.XraySlot(
                "xray-a", 10808, True, Path("/tmp/a"), process=DummyProcess(),
                candidate_id=stale.id, candidate_name=stale.name, candidate=stale,
            ),
            "xray-b": manager.XraySlot("xray-b", 10809, True, Path("/tmp/b")),
        }
        instance.save_state = lambda: None

        payload = instance.status_payload()

        active_item = next(item for item in payload["candidates"] if item["id"] == refreshed.id)
        self.assertIs(active_item["active"], True)
        self.assertEqual(active_item["slot_tags"], ["xray-a"])
        self.assertEqual(instance.active_candidate_id, refreshed.id)
        self.assertEqual(instance.state["active_candidate_id"], refreshed.id)
        self.assertIs(instance.slots["xray-a"].candidate, refreshed)

    def test_legacy_exclusion_setting_is_migrated_to_new_name(self) -> None:
        options = {"auto_switch_excluded_countries": "RU, Лучший сервер"}

        changed = manager.migrate_auto_switch_excluded_option(options)

        self.assertTrue(changed)
        self.assertEqual(options["auto_switch_excluded"], "RU, Лучший сервер")
        self.assertNotIn("auto_switch_excluded_countries", options)

    def test_current_exclusion_setting_takes_precedence_during_migration(self) -> None:
        options = {
            "auto_switch_excluded": "FI",
            "auto_switch_excluded_countries": "RU",
        }

        manager.migrate_auto_switch_excluded_option(options)

        self.assertEqual(options["auto_switch_excluded"], "FI")
        self.assertNotIn("auto_switch_excluded_countries", options)

    def test_auto_switch_exclusions_support_country_codes_and_text_fragments(self) -> None:
        normalized = manager.normalize_auto_switch_exclusions(
            "ru, Лучший  сервер, ЛУЧШИЙ СЕРВЕР"
        )
        self.assertEqual(normalized, "RU, Лучший сервер")

        instance = manager.XrayManager.__new__(manager.XrayManager)
        instance.auto_switch_excluded = normalized

        country_candidate = candidate("country", "198.51.100.50")
        country_candidate = manager.Candidate(
            **{**country_candidate.__dict__, "country_code": "RU", "name": "Обычный сервер"}
        )
        phrase_candidate = manager.Candidate(
            **{**candidate("phrase", "198.51.100.51").__dict__, "name": "Лучший сервер ⚡⚡"}
        )
        short_code_substring = manager.Candidate(
            **{**candidate("substring", "198.51.100.52").__dict__, "name": "True route", "country_code": "US"}
        )

        self.assertTrue(instance.candidate_is_excluded(country_candidate))
        self.assertTrue(instance.candidate_is_excluded(phrase_candidate))
        self.assertFalse(instance.candidate_is_excluded(short_code_substring))

    def test_legacy_duplicate_test_urls_migrate_to_independent_pair(self) -> None:
        primary, secondary = manager.resolve_test_urls({
            "latency_test_url": manager.DEFAULT_PRIMARY_TEST_URL,
            "health_check_url": manager.DEFAULT_PRIMARY_TEST_URL,
        })
        self.assertEqual(primary, manager.DEFAULT_PRIMARY_TEST_URL)
        self.assertEqual(secondary, manager.DEFAULT_SECONDARY_TEST_URL)

    def test_new_test_url_names_take_precedence_over_legacy_names(self) -> None:
        primary, secondary = manager.resolve_test_urls({
            "primary_test_url": "https://primary.example/",
            "secondary_test_url": "https://secondary.example/",
            "latency_test_url": "https://legacy-primary.example/",
            "health_check_url": "https://legacy-secondary.example/",
        })
        self.assertEqual(primary, "https://primary.example/")
        self.assertEqual(secondary, "https://secondary.example/")

    def test_startup_does_not_restore_excluded_remembered_outbound(self) -> None:
        excluded = manager.Candidate(
            **{
                **candidate("excluded", "198.51.100.53").__dict__,
                "name": "🇪🇺 🚀Авто | Лучший сервер ⚡⚡",
            }
        )
        allowed = manager.Candidate(
            **{
                **candidate("allowed", "198.51.100.54").__dict__,
                "name": "🇫🇮 Финляндия",
            }
        )
        instance = manager.XrayManager.__new__(manager.XrayManager)
        instance.candidates = [excluded, allowed]
        instance.state = {"active_candidate_id": excluded.id}
        instance.config_index = 0
        instance.auto_switch_best_enabled = True
        instance.auto_switch_excluded = "RU, Обходы белых списков, Лучший сервер"
        instance.auto_switch_min_ping_delta_ms = 100
        instance.auto_check_max_latency_ms = 500
        instance.latencies = {}

        selected = instance.choose_initial_candidate()

        self.assertEqual(selected.id, allowed.id)

    def test_manual_selection_reuses_draining_standby(self) -> None:
        active = candidate("active", "198.51.100.1")
        old = candidate("old", "198.51.100.2")
        new = candidate("new", "198.51.100.3")
        instance = manager.XrayManager.__new__(manager.XrayManager)
        instance.selector_control_enabled = True
        instance.dual_slot_enabled = True
        instance.selector_reconciliation_pending = False
        instance.switch_lock = threading.Lock()
        instance.lock = threading.RLock()
        instance.active_slot_tag = "xray-a"
        instance.active_candidate_id = active.id
        instance.slots = {
            "xray-a": manager.XraySlot(
                "xray-a", 10808, True, Path("/tmp/a"), process=DummyProcess(),
                candidate_id=active.id, candidate_name=active.name, candidate=active,
            ),
            "xray-b": manager.XraySlot(
                "xray-b", 10809, True, Path("/tmp/b"), process=DummyProcess(),
                candidate_id=old.id, candidate_name=old.name, candidate=old,
                draining=True, drain_connections=2,
            ),
        }
        instance.state = {
            "jobs": {"switch": {"running": False, "message": ""}},
            "last_switch_at": None,
            "last_switch_reason": "",
            "auto_check_failures": 0,
            "auto_check_last_error": "",
        }
        instance.latencies = {}
        instance.switch_generation = 0
        instance.candidates = [active, old, new]
        instance.selector_status = lambda: "xray-a"
        switched: list[str] = []
        switch_events: list[tuple[str, str, str | None]] = []
        def record_selector(tag: str) -> None:
            switched.append(tag)
            switch_events.append(("selector", tag, None))
        def record_guard(expected: str, *, blocked_slot=None, required=False) -> bool:
            switch_events.append(("guard", expected, blocked_slot))
            return True
        instance.switch_selector = record_selector
        instance.sync_router_slot_state = record_guard
        instance.capture_drain_connection_baseline = lambda *_args, **_kwargs: None
        instance.validate_slot = lambda _tag: (100.0, [("https://example.com", 100.0)])
        instance.save_state = lambda: None
        instance.save_latencies = lambda: None
        instance.save_active_config = lambda *_args: None
        instance.post_switch_watch = lambda *_args: None
        instance.candidate_by_id = lambda candidate_id: next(
            (item for item in instance.candidates if item.id == candidate_id), None
        )
        instance.other_slot_tag = lambda tag: "xray-b" if tag == "xray-a" else "xray-a"
        stopped: list[str] = []

        def stop_slot(tag: str) -> None:
            stopped.append(tag)
            slot = instance.slots[tag]
            slot.process = None
            slot.draining = False

        def start_slot(tag: str, selected) -> None:
            slot = instance.slots[tag]
            slot.process = DummyProcess()
            slot.candidate = selected
            slot.candidate_id = selected.id
            slot.candidate_name = selected.name
            slot.draining = False

        instance.stop_slot = stop_slot
        instance.start_slot = start_slot

        with self.assertRaisesRegex(RuntimeError, "отложено"):
            instance.switch_candidate_blue_green(new, "automatic", preempt_draining=False)
        self.assertEqual(stopped, [])

        instance.switch_candidate_blue_green(new, "manual", preempt_draining=True)
        self.assertEqual(stopped, ["xray-b"])
        self.assertEqual(switched[-1], "xray-b")
        self.assertEqual(instance.active_slot_tag, "xray-b")
        self.assertEqual(instance.active_candidate_id, new.id)
        self.assertIs(instance.slots["xray-a"].draining, True)
        guard_index = switch_events.index(("guard", "xray-b", "xray-a"))
        selector_index = switch_events.index(("selector", "xray-b", None))
        self.assertLess(guard_index, selector_index)

    def test_startup_prefers_cached_faster_candidate_over_remembered(self) -> None:
        remembered = candidate("remembered", "198.51.100.60")
        faster = candidate("faster", "198.51.100.61")
        instance = manager.XrayManager.__new__(manager.XrayManager)
        instance.candidates = [remembered, faster]
        instance.state = {"active_candidate_id": remembered.id}
        instance.config_index = 0
        instance.auto_switch_best_enabled = True
        instance.auto_switch_excluded = "RU, Обходы белых списков"
        instance.auto_switch_min_ping_delta_ms = 100
        instance.auto_check_max_latency_ms = 500
        instance.latencies = {
            remembered.id: {"status": "ok", "latency_ms": 343},
            faster.id: {"status": "ok", "latency_ms": 141},
        }

        selected = instance.choose_initial_candidate()

        self.assertEqual(selected.id, faster.id)

    def test_startup_keeps_remembered_candidate_below_ping_threshold(self) -> None:
        remembered = candidate("remembered", "198.51.100.62")
        faster = candidate("faster", "198.51.100.63")
        instance = manager.XrayManager.__new__(manager.XrayManager)
        instance.candidates = [remembered, faster]
        instance.state = {"active_candidate_id": remembered.id}
        instance.config_index = 0
        instance.auto_switch_best_enabled = True
        instance.auto_switch_excluded = "RU"
        instance.auto_switch_min_ping_delta_ms = 100
        instance.auto_check_max_latency_ms = 500
        instance.latencies = {
            remembered.id: {"status": "ok", "latency_ms": 220},
            faster.id: {"status": "ok", "latency_ms": 141},
        }

        selected = instance.choose_initial_candidate()

        self.assertEqual(selected.id, remembered.id)

    def test_auto_checker_resumes_existing_interval_after_restart(self) -> None:
        instance = manager.XrayManager.__new__(manager.XrayManager)
        instance.auto_checker_enabled = True
        instance.auto_check_interval_seconds = 600
        instance.state = {"auto_check_last_at": 1_000}

        self.assertEqual(instance.auto_check_wait_seconds(1_450), 150.0)
        self.assertEqual(instance.auto_check_wait_seconds(1_700), 0.0)


    def test_config_index_is_fallback_without_memory_or_latency(self) -> None:
        first = candidate("first", "198.51.100.70")
        indexed = manager.Candidate(
            **{**candidate("indexed", "198.51.100.71").__dict__, "source_index": 2}
        )
        instance = manager.XrayManager.__new__(manager.XrayManager)
        instance.candidates = [first, indexed]
        instance.state = {}
        instance.config_index = 2
        instance.auto_switch_best_enabled = True
        instance.auto_switch_excluded = "RU"
        instance.auto_switch_min_ping_delta_ms = 100
        instance.auto_check_max_latency_ms = 500
        instance.latencies = {}

        selected = instance.choose_initial_candidate()

        self.assertEqual(selected.id, indexed.id)

    def test_latency_parallelism_uses_configured_or_automatic_limit(self) -> None:
        instance = manager.XrayManager.__new__(manager.XrayManager)
        instance.latency_test_parallelism = 3
        self.assertEqual(instance.effective_latency_test_parallelism(10), 3)
        self.assertEqual(instance.effective_latency_test_parallelism(2), 2)

        instance.latency_test_parallelism = 0
        original_cpu_count = manager.os.cpu_count
        manager.os.cpu_count = lambda: 4
        try:
            self.assertEqual(instance.effective_latency_test_parallelism(20), 8)
            self.assertEqual(instance.effective_latency_test_parallelism(3), 3)
        finally:
            manager.os.cpu_count = original_cpu_count

    def test_latency_job_runs_in_parallel_and_resets_best_check_interval_after_completion(self) -> None:
        instance = manager.XrayManager.__new__(manager.XrayManager)
        instance.lock = threading.RLock()
        instance.candidates = [candidate(f"candidate-{index}", f"198.51.100.{80 + index}") for index in range(6)]
        instance.latencies = {}
        instance.latency_test_parallelism = 3
        instance.stop_event = threading.Event()
        instance.settings_event = threading.Event()
        instance.state = {
            "jobs": {"latency": {"running": False, "progress": 0, "total": 0, "message": ""}},
            "auto_check_last_at": 0,
            "auto_best_check_last_at": 0,
        }
        instance.save_state = lambda: None
        instance.save_latencies = lambda: None
        active = 0
        maximum = 0
        counter_lock = threading.Lock()

        def fake_test(selected):
            nonlocal active, maximum
            with counter_lock:
                active += 1
                maximum = max(maximum, active)
            time.sleep(0.04)
            with counter_lock:
                active -= 1
            return {
                "status": "ok",
                "latency_ms": 100,
                "checked_at": int(time.time()),
                "error": "",
            }

        instance.test_candidate = fake_test
        instance.test_candidate_for_full_scan = fake_test
        instance.handle_draining_full_scan_results = lambda _results: None
        before = int(time.time())
        instance.latency_job(None, switch_to_best=False, source="startup")

        self.assertGreater(maximum, 1)
        self.assertLessEqual(maximum, 3)
        self.assertEqual(instance.state["jobs"]["latency"]["progress"], 6)
        self.assertGreaterEqual(instance.state["auto_best_check_last_at"], before)
        self.assertTrue(instance.settings_event.is_set())


    def test_active_probe_uses_fastest_successful_endpoint(self) -> None:
        instance = manager.XrayManager.__new__(manager.XrayManager)
        instance.lock = threading.RLock()
        instance.auto_check_timeout_seconds = 12
        instance.auto_check_max_latency_ms = 500
        instance.primary_test_url = "https://primary.example/"
        instance.secondary_test_url = "https://secondary.example/"
        instance.slots = {
            "xray-a": manager.XraySlot(
                "xray-a", 10808, True, Path("/tmp/a"), process=DummyProcess()
            ),
        }
        values = {
            instance.primary_test_url: (True, 620.0, ""),
            instance.secondary_test_url: (True, 155.0, ""),
        }
        instance.proxy_curl = lambda _host, _port, url, _timeout, **_kwargs: values[url]

        success, latency_ms, checks, error = instance.probe_slot_health("xray-a")

        self.assertTrue(success)
        self.assertEqual(latency_ms, 155.0)
        self.assertEqual(len(checks), 2)
        self.assertEqual(error, "")

    def test_active_probe_succeeds_when_only_one_endpoint_is_available(self) -> None:
        instance = manager.XrayManager.__new__(manager.XrayManager)
        instance.lock = threading.RLock()
        instance.auto_check_timeout_seconds = 12
        instance.auto_check_max_latency_ms = 500
        instance.primary_test_url = "https://primary.example/"
        instance.secondary_test_url = "https://secondary.example/"
        instance.slots = {
            "xray-a": manager.XraySlot(
                "xray-a", 10808, True, Path("/tmp/a"), process=DummyProcess()
            ),
        }
        values = {
            instance.primary_test_url: (False, None, "timeout"),
            instance.secondary_test_url: (True, 180.0, ""),
        }
        instance.proxy_curl = lambda _host, _port, url, _timeout, **_kwargs: values[url]

        success, latency_ms, checks, error = instance.probe_slot_health("xray-a")

        self.assertTrue(success)
        self.assertEqual(latency_ms, 180.0)
        self.assertEqual(checks, [(instance.secondary_test_url, 180.0)])
        self.assertEqual(error, "")

    def test_active_probe_rejects_when_fastest_endpoint_exceeds_limit(self) -> None:
        instance = manager.XrayManager.__new__(manager.XrayManager)
        instance.lock = threading.RLock()
        instance.auto_check_timeout_seconds = 12
        instance.auto_check_max_latency_ms = 500
        instance.primary_test_url = "https://primary.example/"
        instance.secondary_test_url = "https://secondary.example/"
        instance.slots = {
            "xray-a": manager.XraySlot(
                "xray-a", 10808, True, Path("/tmp/a"), process=DummyProcess()
            ),
        }
        values = {
            instance.primary_test_url: (True, 620.0, ""),
            instance.secondary_test_url: (True, 710.0, ""),
        }
        instance.proxy_curl = lambda _host, _port, url, _timeout, **_kwargs: values[url]

        success, latency_ms, checks, error = instance.probe_slot_health("xray-a")

        self.assertFalse(success)
        self.assertEqual(latency_ms, 620.0)
        self.assertEqual(len(checks), 2)
        self.assertIn("limit 500ms", error)

    def test_full_scan_schedule_is_independent_from_active_check(self) -> None:
        instance = manager.XrayManager.__new__(manager.XrayManager)
        instance.auto_best_check_interval_seconds = 600
        instance.state = {
            "auto_check_last_at": 1_500,
            "auto_best_check_last_at": 1_000,
        }

        self.assertFalse(instance.auto_best_check_due(1_599))
        self.assertTrue(instance.auto_best_check_due(1_600))
        instance.state["auto_check_last_at"] = 9_999
        self.assertTrue(instance.auto_best_check_due(1_600))

    def test_emergency_post_switch_watch_force_stops_old_slot_after_two_successes(self) -> None:
        active = candidate("active", "198.51.100.90")
        old = candidate("old", "198.51.100.91")
        instance = manager.XrayManager.__new__(manager.XrayManager)
        instance.lock = threading.RLock()
        instance.stop_event = threading.Event()
        instance.switch_generation = 4
        instance.active_slot_tag = "xray-b"
        instance.slots = {
            "xray-a": manager.XraySlot(
                "xray-a", 10808, True, Path("/tmp/a"), process=DummyProcess(),
                candidate=old, draining=True, drain_connections=7,
            ),
            "xray-b": manager.XraySlot(
                "xray-b", 10809, True, Path("/tmp/b"), process=DummyProcess(),
                candidate=active,
            ),
        }
        instance.probe_slot_health = lambda _tag: (True, 120.0, [], "")
        stopped: list[str] = []
        instance.force_stop_draining_slot = lambda tag="": stopped.append(tag) or tag
        original_wait = instance.stop_event.wait
        instance.stop_event.wait = lambda _seconds: False
        original_monotonic = manager.time.monotonic
        ticks = iter([0.0, 0.0, 5.0, 5.0, 10.0])
        manager.time.monotonic = lambda: next(ticks)
        try:
            instance.post_switch_watch(4, "xray-b", "xray-a", old, True)
        finally:
            manager.time.monotonic = original_monotonic
            instance.stop_event.wait = original_wait

        self.assertEqual(stopped, ["xray-a"])

    def test_manager_restores_expected_selector_while_slot_is_running(self) -> None:
        instance = manager.XrayManager.__new__(manager.XrayManager)
        instance.lock = threading.RLock()
        instance.switch_lock = threading.Lock()
        instance.active_slot_tag = "xray-b"
        instance.active_candidate_id = "active"
        instance.selector_reconciliation_pending = False
        instance.switch_generation = 0
        instance.state = {}
        instance.slots = {
            "xray-a": manager.XraySlot(
                "xray-a", 10808, True, Path("/tmp/a"), process=DummyProcess(), draining=True
            ),
            "xray-b": manager.XraySlot(
                "xray-b", 10809, True, Path("/tmp/b"), process=DummyProcess()
            ),
        }
        instance.selector_status = lambda: "xray-a"
        restored: list[str] = []
        instance.switch_selector = restored.append
        instance.save_state = lambda: None

        instance.restore_selector_alignment("xray-a")

        self.assertEqual(restored, ["xray-b"])
        self.assertEqual(instance.active_slot_tag, "xray-b")

    def test_manager_adopts_selector_only_when_expected_slot_is_stopped(self) -> None:
        live = candidate("live", "198.51.100.101")
        instance = manager.XrayManager.__new__(manager.XrayManager)
        instance.lock = threading.RLock()
        instance.switch_lock = threading.Lock()
        instance.active_slot_tag = "xray-b"
        instance.active_candidate_id = "stopped"
        instance.selector_reconciliation_pending = False
        instance.switch_generation = 0
        instance.state = {}
        instance.slots = {
            "xray-a": manager.XraySlot(
                "xray-a", 10808, True, Path("/tmp/a"), process=DummyProcess(),
                candidate=live, candidate_id=live.id, candidate_name=live.name,
            ),
            "xray-b": manager.XraySlot("xray-b", 10809, True, Path("/tmp/b")),
        }
        instance.selector_status = lambda: "xray-a"
        instance.candidate_by_id = lambda value: live if value == live.id else None
        instance.save_active_config = lambda *_args: None
        instance.save_state = lambda: None
        instance.sync_router_slot_state = lambda *_args, **_kwargs: True
        switched: list[str] = []
        instance.switch_selector = switched.append

        instance.restore_selector_alignment("xray-a")

        self.assertEqual(switched, [])
        self.assertEqual(instance.active_slot_tag, "xray-a")
        self.assertEqual(instance.active_candidate_id, live.id)

    def test_selector_poll_interval_is_dynamic(self) -> None:
        instance = manager.XrayManager.__new__(manager.XrayManager)
        instance.lock = threading.RLock()
        instance.selector_control_enabled = True
        instance.selector_status_interval_seconds = 10
        instance.selector_state = {"available": True}
        instance.slots = {
            "xray-a": manager.XraySlot("xray-a", 10808, True, Path("/tmp/a")),
            "xray-b": manager.XraySlot("xray-b", 10809, True, Path("/tmp/b")),
        }

        self.assertEqual(instance.selector_status_wait_seconds(), 10)
        instance.selector_state["available"] = False
        self.assertEqual(instance.selector_status_wait_seconds(), 1)
        instance.selector_state["available"] = True
        instance.slots["xray-a"].draining = True
        self.assertEqual(instance.selector_status_wait_seconds(), 1)

    def test_selector_api_recovery_force_writes_expected_slot_even_when_already_reported(self) -> None:
        instance = manager.XrayManager.__new__(manager.XrayManager)
        instance.lock = threading.RLock()
        instance.switch_lock = threading.Lock()
        instance.selector_control_enabled = True
        instance.selector_reconciliation_pending = False
        instance.active_slot_tag = "xray-b"
        instance.selector_state = {
            "available": False,
            "last_checked_at": 1,
            "connections_supported": True,
        }
        instance.slots = {
            "xray-a": manager.XraySlot("xray-a", 10808, True, Path("/tmp/a")),
            "xray-b": manager.XraySlot(
                "xray-b", 10809, True, Path("/tmp/b"), process=DummyProcess()
            ),
        }
        instance.selector_status = lambda: "xray-b"
        written: list[str] = []
        instance.switch_selector = written.append
        instance.reconcile_startup_selector = lambda _current: None
        instance.restore_selector_alignment = lambda _current: None
        instance.sync_router_slot_state = lambda *_args, **_kwargs: True
        instance.selector_connections = lambda: []

        instance.refresh_selector_status()

        self.assertEqual(written, ["xray-b"])
        self.assertTrue(instance.selector_state["available"])
        self.assertEqual(instance.selector_state["current"], "xray-b")

    def test_selector_api_recovery_does_not_interfere_with_switch_transaction(self) -> None:
        instance = manager.XrayManager.__new__(manager.XrayManager)
        instance.lock = threading.RLock()
        instance.switch_lock = threading.Lock()
        instance.switch_lock.acquire()
        instance.selector_control_enabled = True
        instance.selector_reconciliation_pending = False
        instance.active_slot_tag = "xray-a"
        instance.selector_state = {
            "available": False,
            "last_checked_at": 1,
            "connections_supported": True,
        }
        instance.slots = {
            "xray-a": manager.XraySlot(
                "xray-a", 10808, True, Path("/tmp/a"), process=DummyProcess()
            ),
            "xray-b": manager.XraySlot(
                "xray-b", 10809, True, Path("/tmp/b"), process=DummyProcess()
            ),
        }
        instance.selector_status = lambda: "xray-b"
        written: list[str] = []
        instance.switch_selector = written.append
        instance.reconcile_startup_selector = lambda _current: None
        instance.restore_selector_alignment = lambda _current: None
        instance.sync_router_slot_state = lambda *_args, **_kwargs: True
        instance.selector_connections = lambda: []
        try:
            instance.refresh_selector_status()
        finally:
            instance.switch_lock.release()

        self.assertEqual(written, [])

    def test_router_drain_guard_blocks_only_new_connections_to_old_slot(self) -> None:
        instance = manager.XrayManager.__new__(manager.XrayManager)
        instance.router_xray_ip = manager.ipaddress.ip_address("192.0.2.10")
        instance.slots = {
            "xray-a": manager.XraySlot("xray-a", 10808, True, Path("/tmp/a")),
            "xray-b": manager.XraySlot("xray-b", 10809, True, Path("/tmp/b")),
        }

        script = instance.router_slot_state_remote_script("xray-b", "xray-a")

        self.assertIn("ct state new tcp dport 10808", script)
        self.assertIn("ct state new udp dport 10808", script)
        self.assertNotIn("dport 10809", script)
        self.assertIn("active-slot", script)
        self.assertIn("xray-b", script)

    def test_active_exit_rollback_clears_old_guard_before_selector_switch(self) -> None:
        rollback_candidate = candidate("rollback", "198.51.100.105")
        instance = manager.XrayManager.__new__(manager.XrayManager)
        instance.lock = threading.RLock()
        instance.switch_lock = threading.Lock()
        instance.dual_slot_enabled = True
        instance.active_slot_tag = "xray-b"
        instance.active_candidate_id = "failed"
        instance.switch_generation = 1
        instance.state = {
            "last_switch_at": None,
            "last_switch_reason": "",
            "auto_check_failures": 2,
            "auto_check_last_error": "failed",
        }
        instance.slots = {
            "xray-a": manager.XraySlot(
                "xray-a", 10808, True, Path("/tmp/a"), process=DummyProcess(),
                candidate=rollback_candidate, candidate_id=rollback_candidate.id,
                candidate_name=rollback_candidate.name, draining=True, drain_guarded=True,
            ),
            "xray-b": manager.XraySlot("xray-b", 10809, True, Path("/tmp/b")),
        }
        events: list[tuple[str, object]] = []
        instance.sync_router_slot_state = lambda expected, **kwargs: (
            events.append(("guard", expected, kwargs.get("blocked_slot"))) or True
        )
        instance.switch_selector = lambda tag: events.append(("selector", tag))
        instance.save_state = lambda: None
        instance.save_active_config = lambda *_args: None
        instance.candidate_by_id = lambda value: (
            rollback_candidate if value == rollback_candidate.id else None
        )

        restored = instance.rollback_after_active_exit("xray-b")

        self.assertTrue(restored)
        self.assertEqual(
            events[:2],
            [("guard", "xray-a", None), ("selector", "xray-a")],
        )
        self.assertEqual(instance.active_slot_tag, "xray-a")

    def test_single_slot_switch_stops_existing_slot_before_restart(self) -> None:
        old = candidate("old", "198.51.100.110")
        new = candidate("new", "198.51.100.111")
        instance = manager.XrayManager.__new__(manager.XrayManager)
        instance.lock = threading.RLock()
        instance.switch_lock = threading.Lock()
        instance.selector_control_enabled = False
        instance.active_slot_tag = "xray-a"
        instance.active_candidate_id = old.id
        instance.switch_generation = 0
        instance.latencies = {}
        instance.state = {
            "jobs": {"switch": {"running": False, "message": ""}},
            "last_switch_at": None,
            "last_switch_reason": "",
            "auto_check_failures": 0,
            "auto_check_last_error": "",
        }
        instance.slots = {
            "xray-a": manager.XraySlot(
                "xray-a", 10808, True, Path("/tmp/nonexistent-xpm-a.json"),
                process=DummyProcess(), candidate=old,
                candidate_id=old.id, candidate_name=old.name,
            ),
            "xray-b": manager.XraySlot("xray-b", 10809, True, Path("/tmp/nonexistent-xpm-b.json")),
        }
        instance.candidates = [old, new]
        instance.candidate_by_id = lambda value: next(
            (item for item in instance.candidates if item.id == value), None
        )
        events: list[tuple[str, str]] = []
        def stop_slot(tag: str) -> None:
            events.append(("stop", tag))
            instance.slots[tag].process = None
        def start_slot(tag: str, selected=None) -> None:
            events.append(("start", tag))
            slot = instance.slots[tag]
            slot.process = DummyProcess()
            if selected is not None:
                slot.candidate = selected
                slot.candidate_id = selected.id
                slot.candidate_name = selected.name
        prepared_path = Path("/tmp/xpm-test-prepared.json")
        def prepare_slot_config(tag: str, selected):
            events.append(("prepare", tag))
            return prepared_path, True
        def install_prepared_slot_config(tag: str, selected, _path: Path) -> None:
            events.append(("install", tag))
            slot = instance.slots[tag]
            slot.candidate = selected
            slot.candidate_id = selected.id
            slot.candidate_name = selected.name
        instance.stop_slot = stop_slot
        instance.start_slot = start_slot
        instance.prepare_slot_config = prepare_slot_config
        instance.install_prepared_slot_config = install_prepared_slot_config
        instance.validate_slot = lambda _tag: (125.0, [("https://example.test", 125.0)])
        instance.save_state = lambda: None
        instance.save_latencies = lambda: None
        instance.save_active_config = lambda *_args: None
        instance.sync_router_slot_state = lambda *_args, **_kwargs: True

        instance.switch_candidate_single_slot(new, "manual")

        self.assertEqual(
            events[:4],
            [
                ("prepare", "xray-a"),
                ("stop", "xray-a"),
                ("install", "xray-a"),
                ("start", "xray-a"),
            ],
        )
        self.assertEqual(instance.active_slot_tag, "xray-a")
        self.assertEqual(instance.active_candidate_id, new.id)

    def test_legacy_test_url_keys_migrate_and_are_removed(self) -> None:
        options = {
            "latency_test_url": "https://primary.example/",
            "secondary_check_url": "https://secondary.example/",
        }

        changed = manager.migrate_test_url_options(options)

        self.assertTrue(changed)
        self.assertEqual(options["primary_test_url"], "https://primary.example/")
        self.assertEqual(options["secondary_test_url"], "https://secondary.example/")
        self.assertNotIn("latency_test_url", options)
        self.assertNotIn("secondary_check_url", options)

    def test_repeated_subscription_failure_retries_through_next_healthy_outbound(self) -> None:
        alternative = candidate("alternative", "198.51.100.120")
        instance = manager.XrayManager.__new__(manager.XrayManager)
        instance.dual_slot_enabled = True
        instance.choose_subscription_recovery_candidate = lambda: alternative
        calls: list[tuple[str, object]] = []
        def restart(selected, reason, **kwargs):
            calls.append(("restart", selected.id, reason, kwargs))
        instance.restart_xray_for = restart
        instance.wait_for_forced_drain_drop = lambda: calls.append(("drop", True))
        instance.download_subscription = lambda: [{"outbounds": []}]

        result, selected = instance.retry_subscription_after_route_change("first failure")

        self.assertEqual(result, [{"outbounds": []}])
        self.assertIs(selected, alternative)
        self.assertEqual(calls[0][0:2], ("restart", alternative.id))
        self.assertTrue(calls[0][3]["preempt_draining"])
        self.assertTrue(calls[0][3]["emergency_failover"])
        self.assertEqual(calls[1], ("drop", True))

    def test_subscription_route_recovery_does_not_switch_back_to_failed_outbound(self) -> None:
        failed = candidate("failed", "198.51.100.130", fingerprint="failed-fp")
        recovery = candidate("recovery", "198.51.100.131", fingerprint="recovery-fp")
        refreshed_failed = candidate(
            "failed-new-id", "198.51.100.130", fingerprint="failed-fp"
        )
        refreshed_recovery = candidate(
            "recovery-new-id", "198.51.100.131", fingerprint="recovery-fp"
        )
        instance = manager.XrayManager.__new__(manager.XrayManager)
        instance.lock = threading.RLock()
        instance.dual_slot_enabled = True
        instance.stop_event = threading.Event()
        instance.update_interval_hours = 1
        instance.next_update_at = None
        instance.subscription = [{"old": True}]
        instance.candidates = [failed, recovery]
        instance.active_candidate_id = failed.id
        instance.active_slot_tag = "xray-a"
        instance.state = {
            "subscription_consecutive_failures": 1,
            "jobs": {"refresh": {"running": False, "message": ""}},
        }
        instance.slots = {
            "xray-a": manager.XraySlot(
                "xray-a", 10808, True, Path("/tmp/a"), process=DummyProcess(),
                candidate=failed, candidate_id=failed.id, candidate_name=failed.name,
            ),
            "xray-b": manager.XraySlot("xray-b", 10809, True, Path("/tmp/b")),
        }
        attempts = iter([
            RuntimeError("route failed"),
            [{"new": True}],
        ])

        def download():
            result = next(attempts)
            if isinstance(result, Exception):
                raise result
            return result

        instance.download_subscription = download
        instance.load_cached_subscription = lambda: [{"old": True}]
        instance.extract_candidates = lambda _configs: [refreshed_failed, refreshed_recovery]
        instance.choose_subscription_recovery_candidate = lambda: recovery
        instance.wait_for_forced_drain_drop = lambda: None
        instance.runtime_config_differs = lambda *_args: False
        instance.save_state = lambda: None
        restart_calls: list[str] = []

        def restart(selected, _reason, **_kwargs):
            restart_calls.append(selected.fingerprint)
            slot = instance.slots[instance.active_slot_tag]
            slot.candidate = selected
            slot.candidate_id = selected.id
            slot.candidate_name = selected.name
            instance.active_candidate_id = selected.id

        instance.restart_xray_for = restart
        original_atomic_write = manager.atomic_write_json
        manager.atomic_write_json = lambda *_args, **_kwargs: None
        try:
            instance.refresh_subscription_sync(initial=False)
        finally:
            manager.atomic_write_json = original_atomic_write

        self.assertEqual(restart_calls, ["recovery-fp"])
        self.assertEqual(instance.active_candidate_id, refreshed_recovery.id)
        self.assertIs(instance.slots["xray-a"].candidate, refreshed_recovery)
        self.assertEqual(instance.state["subscription_consecutive_failures"], 0)


if __name__ == "__main__":
    unittest.main()
