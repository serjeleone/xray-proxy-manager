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
        instance.listen_lan = True
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
        instance.auto_switch_excluded_countries = "RU"
        instance.auto_switch_min_ping_delta_ms = 100
        instance.auto_check_interval_seconds = 600
        instance.auto_check_failures = 3
        instance.ui_sort = "ping-asc"
        instance.ui_protocol_filter = "all"
        instance.ui_max_ping_ms = 1000
        instance.ui_hide_unavailable = False
        instance.selector_state = {}
        instance.router_state = {}
        instance.selector_tag = "xray-active"
        instance.drain_quiet_seconds = 30
        instance.drain_timeout_minutes = 0
        instance.latency_test_url = "https://example.com/"
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

    def test_status_rebinds_active_slot_before_first_ui_render(self) -> None:
        stale = candidate("old-active-id", "198.51.100.40", fingerprint="stable-active")
        refreshed = candidate("new-active-id", "198.51.100.40", fingerprint="stable-active")
        other = candidate("other", "198.51.100.41")
        instance = manager.XrayManager.__new__(manager.XrayManager)
        instance.lock = threading.RLock()
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
        instance.auto_switch_excluded_countries = "RU"
        instance.auto_switch_min_ping_delta_ms = 100
        instance.auto_check_interval_seconds = 600
        instance.auto_check_failures = 3
        instance.ui_sort = "ping-asc"
        instance.ui_protocol_filter = "all"
        instance.ui_max_ping_ms = 1000
        instance.ui_hide_unavailable = False
        instance.selector_state = {}
        instance.router_state = {}
        instance.selector_tag = "xray-active"
        instance.drain_quiet_seconds = 30
        instance.drain_timeout_minutes = 0
        instance.latency_test_url = "https://example.com/"
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

    def test_manual_selection_reuses_draining_standby(self) -> None:
        active = candidate("active", "198.51.100.1")
        old = candidate("old", "198.51.100.2")
        new = candidate("new", "198.51.100.3")
        instance = manager.XrayManager.__new__(manager.XrayManager)
        instance.selector_control_enabled = True
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
        instance.switch_selector = switched.append
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


if __name__ == "__main__":
    unittest.main()
