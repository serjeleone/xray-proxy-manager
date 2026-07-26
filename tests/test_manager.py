from __future__ import annotations

import importlib.util
import os
import socket
import sys
import threading
import time
import unittest
from pathlib import Path

import yaml


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

    def test_same_outbound_does_not_merge_distinct_same_endpoint_profiles(self) -> None:
        first = candidate("first", "198.51.100.10", fingerprint="profile-one")
        second = manager.Candidate(
            **{
                **candidate("second", "198.51.100.10", fingerprint="profile-two").__dict__,
                "outbound_tag": first.outbound_tag,
            }
        )

        self.assertFalse(manager.XrayManager.same_outbound(first, second))

    def test_concrete_candidate_identity_does_not_merge_duplicate_entries(self) -> None:
        first = candidate("duplicate", "198.51.100.10", fingerprint="shared")
        second = candidate("duplicate-2", "198.51.100.10", fingerprint="shared")

        self.assertTrue(manager.XrayManager.same_outbound(first, second))
        self.assertFalse(manager.XrayManager.same_candidate_identity(first, second))

    def test_slots_use_independent_ports_with_udp_always_enabled(self) -> None:
        instance = manager.XrayManager.__new__(manager.XrayManager)
        instance.subscription = [{"outbounds": [{"tag": "proxy", "protocol": "freedom"}]}]
        instance.slots = {
            "xray-a": manager.XraySlot("xray-a", 10808, True, Path("/tmp/a.json")),
            "xray-b": manager.XraySlot("xray-b", 10809, True, Path("/tmp/b.json")),
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
        self.assertIs(config_b["inbounds"][0]["settings"]["udp"], True)

    def test_addon_has_one_tcp_udp_port_setting_per_slot(self) -> None:
        config_path = Path(__file__).parents[1] / "xray-proxy-manager" / "config.yaml"
        config = yaml.safe_load(config_path.read_text(encoding="utf-8"))

        self.assertTrue(config["host_network"])
        self.assertEqual(config["ingress_port"], 0)
        self.assertEqual(
            config["watchdog"],
            f"http://[HOST]:{manager.WATCHDOG_PORT}/api/health",
        )
        self.assertNotIn("ports", config)
        self.assertEqual(config["options"]["ui_port"], manager.DEFAULT_UI_PORT)
        self.assertEqual(config["schema"]["ui_port"], "port")
        self.assertEqual(config["options"]["socks_tcp_a"], 10808)
        self.assertEqual(config["options"]["socks_tcp_b"], 10809)
        self.assertNotIn("socks_udp_a", config["options"])
        self.assertNotIn("socks_udp_b", config["options"])
        self.assertNotIn("socks_udp_a", config["schema"])
        self.assertNotIn("socks_udp_b", config["schema"])

    def test_preferred_country_change_starts_full_best_scan(self) -> None:
        instance = manager.XrayManager.__new__(manager.XrayManager)
        instance.lock = threading.RLock()
        instance.preferred_country_scan_generation = 0
        instance.auto_switch_preferred_country = ""
        nl = manager.Candidate(**{**candidate("nl", "198.51.100.10").__dict__, "country_code": "NL"})
        de = manager.Candidate(**{**candidate("de", "198.51.100.11").__dict__, "country_code": "DE"})
        instance.candidates = [nl, de]
        instance.state = {"jobs": {"latency": {"running": False}}}
        instance.candidate_is_excluded = lambda _item: False
        instance.update_runtime_settings = lambda changes: (
            setattr(instance, "auto_switch_preferred_country", changes["auto_switch_preferred_country"])
            or {"ok": True, "restart_required": []}
        )
        calls = []
        instance.request_latency_test = lambda ids, switch_to_best=False, source="manual": (
            calls.append((ids, switch_to_best, source)) or True
        )

        result = instance.set_preferred_country("nl")

        self.assertEqual(instance.auto_switch_preferred_country, "NL")
        self.assertEqual(calls, [(None, True, "preferred-country")])
        self.assertTrue(result["switch_started"])
        self.assertEqual(result["matching_candidates"], 1)

    def test_preferred_country_change_immediately_switches_to_cached_healthy_candidate(self) -> None:
        instance = manager.XrayManager.__new__(manager.XrayManager)
        instance.lock = threading.RLock()
        instance.preferred_country_scan_generation = 0
        instance.auto_switch_preferred_country = ""
        nl = manager.Candidate(**{**candidate("nl", "198.51.100.10").__dict__, "country_code": "NL"})
        de = manager.Candidate(**{**candidate("de", "198.51.100.11").__dict__, "country_code": "DE"})
        instance.candidates = [nl, de]
        instance.active_candidate_id = de.id
        instance.latencies = {
            nl.id: {"status": "ok", "latency_ms": 150},
            de.id: {"status": "ok", "latency_ms": 100},
        }
        instance.auto_check_max_latency_ms = 500
        instance.state = {"jobs": {"latency": {"running": False}}}
        instance.candidate_is_excluded = lambda _item: False
        instance.update_runtime_settings = lambda changes: (
            setattr(instance, "auto_switch_preferred_country", changes["auto_switch_preferred_country"])
            or {"ok": True, "restart_required": []}
        )
        switches = []
        instance.restart_xray_for = lambda selected, reason, **kwargs: switches.append(
            (selected.id, reason, kwargs)
        )
        scans = []
        instance.request_latency_test = lambda ids, switch_to_best=False, source="manual": (
            scans.append((ids, switch_to_best, source)) or True
        )

        result = instance.set_preferred_country("NL")

        self.assertEqual(switches[0][0], "nl")
        self.assertTrue(switches[0][2]["preempt_draining"])
        self.assertEqual(scans, [(None, True, "preferred-country")])
        self.assertTrue(result["immediate_switched"])
        self.assertTrue(result["switch_started"])

    def test_ingress_proxy_forwards_large_responses_without_truncation(self) -> None:
        payload = b"x" * 512_000
        target = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        target.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        target.bind(("127.0.0.1", 0))
        target.listen(1)
        target_host, target_port = target.getsockname()

        def serve_target() -> None:
            connection, _address = target.accept()
            with connection:
                request = bytearray()
                while b"\r\n\r\n" not in request:
                    chunk = connection.recv(4096)
                    if not chunk:
                        return
                    request.extend(chunk)
                header = (
                    b"HTTP/1.0 200 OK\r\n"
                    b"Content-Type: application/octet-stream\r\n"
                    + f"Content-Length: {len(payload)}\r\n".encode("ascii")
                    + b"Connection: close\r\n\r\n"
                )
                connection.sendall(header + payload)

        target_thread = threading.Thread(target=serve_target, daemon=True)
        target_thread.start()
        proxy = manager.ThreadingTCPProxyServer(
            ("127.0.0.1", 0),
            target_host=target_host,
            target_port=target_port,
        )
        proxy_thread = threading.Thread(target=proxy.serve_forever, daemon=True)
        proxy_thread.start()
        try:
            with socket.create_connection(proxy.server_address, timeout=5) as client:
                client.sendall(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
                received = bytearray()
                while True:
                    chunk = client.recv(65536)
                    if not chunk:
                        break
                    received.extend(chunk)
            header, body = bytes(received).split(b"\r\n\r\n", 1)
            self.assertIn(f"Content-Length: {len(payload)}".encode("ascii"), header)
            self.assertEqual(body, payload)
        finally:
            proxy.shutdown()
            proxy.server_close()
            target.close()
            target_thread.join(timeout=1)

    def test_web_ui_accepts_only_ingress_and_loopback_clients(self) -> None:
        handler = manager.WebHandler.__new__(manager.WebHandler)
        for address in ("172.30.32.2", "127.0.0.1", "::1", "::ffff:127.0.0.1"):
            handler.client_address = (address, 12345)
            self.assertTrue(handler.ingress_client_allowed(), address)
        handler.client_address = ("192.168.0.20", 12345)
        self.assertFalse(handler.ingress_client_allowed())

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

    def test_status_marks_only_one_duplicate_entry_as_active(self) -> None:
        first = candidate("duplicate", "198.51.100.50", fingerprint="shared")
        second = candidate("duplicate-2", "198.51.100.50", fingerprint="shared")
        instance = manager.XrayManager.__new__(manager.XrayManager)
        instance.lock = threading.RLock()
        instance.dual_slot_enabled = True
        instance.candidates = [first, second]
        instance.latencies = {}
        instance.active_slot_tag = "xray-a"
        instance.active_candidate_id = first.id
        instance.started_at = int(time.time())
        instance.state = {"jobs": {}, "auto_check_failures": 0, "active_candidate_id": first.id}
        instance.next_update_at = None
        instance.subscription_url = ""
        instance.update_interval_hours = 1
        instance.auto_checker_enabled = True
        instance.auto_switch_best_enabled = True
        instance.auto_switch_preferred_country = ""
        instance.auto_switch_excluded = "RU"
        instance.auto_switch_min_ping_delta_ms = 100
        instance.auto_check_interval_seconds = 60
        instance.auto_check_failures = 3
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
                candidate_id=first.id, candidate_name=first.name, candidate=first,
            ),
            "xray-b": manager.XraySlot("xray-b", 10809, True, Path("/tmp/b")),
        }
        instance.save_state = lambda: None

        payload = instance.status_payload()

        active_ids = [item["id"] for item in payload["candidates"] if item["active"]]
        self.assertEqual(active_ids, [first.id])
        duplicate = next(item for item in payload["candidates"] if item["id"] == second.id)
        self.assertEqual(duplicate["slot_tags"], [])

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
        switch_events: list[tuple[str, str]] = []
        def record_selector(tag: str) -> None:
            switched.append(tag)
            switch_events.append(("selector", tag))
        instance.switch_selector = record_selector
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
        self.assertEqual(switch_events[-1], ("selector", "xray-b"))

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

    def test_startup_prioritizes_eligible_preferred_country(self) -> None:
        current = manager.Candidate(
            **{
                **candidate("current", "198.51.100.62").__dict__,
                "country_code": "FI",
            }
        )
        preferred = manager.Candidate(
            **{
                **candidate("preferred", "198.51.100.63").__dict__,
                "country_code": "NL",
            }
        )
        instance = manager.XrayManager.__new__(manager.XrayManager)
        instance.candidates = [current, preferred]
        instance.state = {"active_candidate_id": current.id}
        instance.config_index = 0
        instance.auto_switch_best_enabled = True
        instance.auto_switch_preferred_country = "NL"
        instance.auto_switch_excluded = ""
        instance.auto_switch_min_ping_delta_ms = 500
        instance.auto_check_max_latency_ms = 500
        instance.latencies = {
            current.id: {"status": "ok", "latency_ms": 80},
            preferred.id: {"status": "ok", "latency_ms": 140},
        }

        selected = instance.choose_initial_candidate()

        self.assertEqual(selected.id, preferred.id)

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

    def test_latency_job_prioritizes_eligible_preferred_country(self) -> None:
        current = manager.Candidate(
            **{
                **candidate("current", "198.51.100.150").__dict__,
                "country_code": "FI",
            }
        )
        preferred = manager.Candidate(
            **{
                **candidate("preferred", "198.51.100.151").__dict__,
                "country_code": "NL",
            }
        )
        instance = manager.XrayManager.__new__(manager.XrayManager)
        instance.lock = threading.RLock()
        instance.candidates = [current, preferred]
        instance.latencies = {}
        instance.latency_test_parallelism = 1
        instance.stop_event = threading.Event()
        instance.settings_event = threading.Event()
        instance.auto_check_max_latency_ms = 500
        instance.auto_switch_preferred_country = "NL"
        instance.auto_switch_excluded = ""
        instance.auto_switch_min_ping_delta_ms = 500
        instance.state = {
            "jobs": {"latency": {"running": False, "progress": 0, "total": 0, "message": ""}},
            "auto_check_last_at": 0,
            "auto_best_check_last_at": 0,
        }
        results = {
            current.id: {"status": "ok", "latency_ms": 80, "checked_at": int(time.time()), "error": ""},
            preferred.id: {"status": "ok", "latency_ms": 140, "checked_at": int(time.time()), "error": ""},
        }
        instance.test_candidate_for_full_scan = lambda selected: results[selected.id]
        instance.handle_draining_full_scan_results = lambda _results: None
        instance.effective_active_candidate = lambda: (current, current, False)
        instance.save_state = lambda: None
        instance.save_latencies = lambda: None
        switched: list[str] = []
        instance.restart_xray_for = lambda selected, _reason: switched.append(selected.id)

        instance.latency_job(None, switch_to_best=True, source="test")

        self.assertEqual(switched, [preferred.id])


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
        instance.selector_connections = lambda: []
        try:
            instance.refresh_selector_status()
        finally:
            instance.switch_lock.release()

        self.assertEqual(written, [])

    def test_subscription_download_falls_back_to_running_active_slot(self) -> None:
        instance = manager.XrayManager.__new__(manager.XrayManager)
        instance.lock = threading.RLock()
        instance.active_slot_tag = "xray-a"
        instance.slots = {
            "xray-a": manager.XraySlot(
                "xray-a", 10808, True, Path("/tmp/a"), process=DummyProcess()
            ),
            "xray-b": manager.XraySlot(
                "xray-b", 10809, True, Path("/tmp/b"), process=DummyProcess()
            ),
        }
        instance.debug_log = lambda *_args, **_kwargs: None
        calls: list[str | None] = []

        def download_once(slot_tag=None):
            calls.append(slot_tag)
            if slot_tag is None:
                raise RuntimeError("direct unavailable")
            if slot_tag == "xray-a":
                return [{"outbounds": [{"tag": "proxy"}]}]
            raise AssertionError("the second slot should not be used after success")

        instance.download_subscription_once = download_once

        result = instance.download_subscription()

        self.assertEqual(result, [{"outbounds": [{"tag": "proxy"}]}])
        self.assertEqual(calls, [None, "xray-a"])

    def test_direct_subscription_download_bypasses_proxy_environment(self) -> None:
        instance = manager.XrayManager.__new__(manager.XrayManager)
        instance.user_agent = "test-agent"
        instance.subscription_url = "https://subscription.example/config.json"
        instance.proxy_username = ""
        instance.proxy_password = ""
        captured: dict[str, object] = {}
        original_run = manager.subprocess.run
        original_proxy = os.environ.get("HTTPS_PROXY")
        os.environ["HTTPS_PROXY"] = "http://proxy.invalid:3128"

        def fake_run(command, **kwargs):
            captured["command"] = list(command)
            captured["env"] = dict(kwargs.get("env") or {})
            output_path = Path(command[command.index("-o") + 1])
            output_path.write_text('{"outbounds": [{"tag": "proxy"}]}', encoding="utf-8")
            return type("Result", (), {"returncode": 0, "stdout": "", "stderr": ""})()

        manager.subprocess.run = fake_run
        try:
            result = instance.download_subscription_once()
        finally:
            manager.subprocess.run = original_run
            if original_proxy is None:
                os.environ.pop("HTTPS_PROXY", None)
            else:
                os.environ["HTTPS_PROXY"] = original_proxy

        command = captured["command"]
        environment = captured["env"]
        self.assertEqual(result, [{"outbounds": [{"tag": "proxy"}]}])
        self.assertIn("--noproxy", command)
        self.assertEqual(command[command.index("--noproxy") + 1], "*")
        self.assertNotIn("--socks5-hostname", command)
        self.assertNotIn("HTTPS_PROXY", environment)
        self.assertEqual(environment.get("NO_PROXY"), "*")

    def test_router_status_restores_persisted_rule_state(self) -> None:
        instance = manager.XrayManager.__new__(manager.XrayManager)
        instance.lock = threading.RLock()
        instance.router_control_enabled = True
        instance.router_firewall_rule = "mark_domains"
        instance.router_state = {
            "desired_rule_enabled": True,
            "busy": False,
        }
        instance.state = {"router_rule_desired_enabled": True}
        instance.save_state = lambda: None
        instance.run_router_command = lambda *_args, **_kwargs: "disabled:mark_domains"
        restored: list[tuple[bool, bool]] = []
        instance.set_router_rule = lambda enabled, *, automatic=False: restored.append(
            (enabled, automatic)
        )

        instance.refresh_router_status()

        self.assertEqual(restored, [(True, True)])

    def test_active_exit_rollback_switches_selector_to_running_slot(self) -> None:
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
                candidate_name=rollback_candidate.name, draining=True,
            ),
            "xray-b": manager.XraySlot("xray-b", 10809, True, Path("/tmp/b")),
        }
        events: list[tuple[str, object]] = []
        instance.switch_selector = lambda tag: events.append(("selector", tag))
        instance.save_state = lambda: None
        instance.save_active_config = lambda *_args: None
        instance.candidate_by_id = lambda value: (
            rollback_candidate if value == rollback_candidate.id else None
        )

        restored = instance.rollback_after_active_exit("xray-b")

        self.assertTrue(restored)
        self.assertEqual(events[0], ("selector", "xray-a"))
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

    def test_subscription_download_tries_second_running_slot_after_first_failure(self) -> None:
        instance = manager.XrayManager.__new__(manager.XrayManager)
        instance.lock = threading.RLock()
        instance.active_slot_tag = "xray-a"
        instance.slots = {
            "xray-a": manager.XraySlot(
                "xray-a", 10808, True, Path("/tmp/a"), process=DummyProcess()
            ),
            "xray-b": manager.XraySlot(
                "xray-b", 10809, True, Path("/tmp/b"), process=DummyProcess()
            ),
        }
        instance.debug_log = lambda *_args, **_kwargs: None
        calls: list[str | None] = []

        def download_once(slot_tag=None):
            calls.append(slot_tag)
            if slot_tag in (None, "xray-a"):
                raise RuntimeError(f"failed via {slot_tag or 'direct'}")
            return [{"outbounds": [{"tag": "proxy-b"}]}]

        instance.download_subscription_once = download_once

        result = instance.download_subscription()

        self.assertEqual(result, [{"outbounds": [{"tag": "proxy-b"}]}])
        self.assertEqual(calls, [None, "xray-a", "xray-b"])

    def test_subscription_refresh_preserves_running_xray_process(self) -> None:
        active = candidate("active", "198.51.100.130", fingerprint="active-fp")
        refreshed = candidate(
            "active-new-id", "198.51.100.130", fingerprint="active-fp"
        )
        instance = manager.XrayManager.__new__(manager.XrayManager)
        instance.lock = threading.RLock()
        instance.dual_slot_enabled = True
        instance.stop_event = threading.Event()
        instance.update_interval_hours = 1
        instance.next_update_at = None
        instance.subscription = [{"old": True}]
        instance.candidates = [active]
        instance.active_candidate_id = active.id
        instance.active_slot_tag = "xray-a"
        instance.state = {
            "subscription_consecutive_failures": 1,
            "jobs": {"refresh": {"running": False, "message": ""}},
        }
        instance.slots = {
            "xray-a": manager.XraySlot(
                "xray-a", 10808, True, Path("/tmp/a"), process=DummyProcess(),
                candidate=active, candidate_id=active.id, candidate_name=active.name,
            ),
            "xray-b": manager.XraySlot("xray-b", 10809, True, Path("/tmp/b")),
        }
        running_process = instance.slots["xray-a"].process
        instance.download_subscription = lambda: [{"new": True}]
        instance.extract_candidates = lambda _configs: [refreshed]
        instance.runtime_config_differs = lambda *_args: False
        instance.save_state = lambda: None
        instance.rebind_slot_candidates = lambda: False
        instance.restart_xray_for = lambda *_args, **_kwargs: self.fail(
            "subscription refresh must not restart Xray while the active process is running"
        )
        original_atomic_write = manager.atomic_write_json
        manager.atomic_write_json = lambda *_args, **_kwargs: None
        try:
            instance.refresh_subscription_sync(initial=False)
        finally:
            manager.atomic_write_json = original_atomic_write

        self.assertIs(instance.slots["xray-a"].process, running_process)
        self.assertEqual(instance.active_candidate_id, refreshed.id)
        self.assertIs(instance.slots["xray-a"].candidate, refreshed)
        self.assertEqual(instance.state["subscription_consecutive_failures"], 0)


if __name__ == "__main__":
    unittest.main()
