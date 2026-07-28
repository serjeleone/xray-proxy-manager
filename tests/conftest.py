from __future__ import annotations

import importlib.util
import io
import json
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable

import pytest

ROOT = Path(__file__).parents[1]
MANAGER_PATH = ROOT / "xray-proxy-manager" / "manager.py"
SPEC = importlib.util.spec_from_file_location("xray_proxy_manager_test_module", MANAGER_PATH)
assert SPEC and SPEC.loader
manager = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = manager
SPEC.loader.exec_module(manager)


class DummyProcess:
    def __init__(self, *, running: bool = True, returncode: int = 0, stdout: str = "") -> None:
        self.dead = not running
        self.returncode = returncode
        self.stdout = io.StringIO(stdout)
        self.pid = 4242
        self.terminated = False
        self.killed = False
        self.wait_calls: list[float | None] = []

    def poll(self) -> int | None:
        return self.returncode if self.dead else None

    def terminate(self) -> None:
        self.terminated = True
        self.dead = True

    def kill(self) -> None:
        self.killed = True
        self.dead = True

    def wait(self, timeout: float | None = None) -> int:
        self.wait_calls.append(timeout)
        self.dead = True
        return self.returncode


@pytest.fixture(scope="session")
def m():
    return manager


@pytest.fixture
def candidate_factory(m):
    def make(
        candidate_id: str = "candidate-1",
        host: str = "198.51.100.10",
        *,
        name: str | None = None,
        fingerprint: str | None = None,
        country: str = "",
        protocol: str = "VLESS",
        source_index: int = 0,
        outbound_index: int = 0,
        outbound_tag: str | None = None,
    ):
        return m.Candidate(
            id=candidate_id,
            name=name or candidate_id,
            source_index=source_index,
            outbound_index=outbound_index,
            outbound_tag=outbound_tag or candidate_id,
            protocol=protocol,
            server=host,
            port=443,
            country_code=country,
            fingerprint=fingerprint or candidate_id,
        )
    return make


@pytest.fixture
def manager_factory(m, candidate_factory, tmp_path):
    def make(candidates=None):
        instance = m.XrayManager.__new__(m.XrayManager)
        instance.options = {}
        instance.lock = threading.RLock()
        instance.switch_lock = threading.Lock()
        instance.router_lock = threading.Lock()
        instance.stop_event = threading.Event()
        instance.settings_event = threading.Event()
        instance.preference_scan_generation = 0
        instance.subscription_url = "https://subscription.example/list"
        instance.subscription = []
        instance.candidates = list(candidates or [])
        instance.active_candidate_id = ""
        instance.active_slot_tag = "xray-a"
        instance.switch_generation = 0
        instance.selector_reconciliation_pending = False
        instance.socks_tcp_a = 10808
        instance.socks_tcp_b = 10809
        instance.socks_udp_a = True
        instance.socks_udp_b = True
        instance.ui_port = 8090
        instance.dual_slot_enabled = True
        instance.override_inbounds = True
        instance.proxy_username = ""
        instance.proxy_password = ""
        instance.disable_observatory = True
        instance.log_level = "warning"
        instance.user_agent = "test-agent"
        instance.validate_tags = True
        instance.auto_fix_tags = True
        instance.auto_add_proxy_direct = True
        instance.restart_on_runtime_error = True
        instance.latency_test_timeout_seconds = 3
        instance.latency_test_parallelism = 2
        instance.primary_test_url = "https://primary.example/generate_204"
        instance.secondary_test_url = "https://secondary.example/generate_204"
        instance.selector_control_enabled = True
        instance.selector_api_url = "http://127.0.0.1:9090"
        instance.selector_api_secret = "secret"
        instance.selector_tag = "xray-active"
        instance.selector_status_interval_seconds = 10
        instance.drain_quiet_seconds = 5
        instance.drain_poll_interval_seconds = 1
        instance.drain_timeout_minutes = 0
        instance.router_control_enabled = True
        instance.router_host = "192.0.2.1"
        instance.router_ssh_port = 22
        instance.router_ssh_user = "root"
        instance.router_ssh_password = ""
        instance.router_auth_method = "existing_key"
        instance.router_ssh_key_name = "id_ed25519"
        instance.router_ssh_key_path_override = ""
        instance.router_ssh_key_path = tmp_path / "id_ed25519"
        instance.router_firewall_rule = "mark_domains"
        instance.router_status_interval_seconds = 10
        instance.auto_checker_enabled = True
        instance.auto_switch_best_enabled = True
        instance.auto_switch_preferred_country = ""
        instance.auto_switch_preferred_protocol = ""
        instance.auto_switch_excluded = "RU"
        instance.auto_switch_min_ping_delta_ms = 100
        instance.auto_check_interval_seconds = 60
        instance.auto_check_failures = 3
        instance.auto_check_max_latency_ms = 500
        instance.auto_best_check_interval_seconds = 600
        instance.auto_check_timeout_seconds = 3
        instance.update_interval_hours = 1
        instance.ui_sort = "ping-asc"
        instance.ui_protocol_filter = "all"
        instance.ui_max_ping_ms = 1000
        instance.ui_hide_unavailable = False
        instance.ui_hide_excluded = True
        instance.config_index = 0
        instance.state = {
            "active_candidate_id": "",
            "active_slot_tag": "xray-a",
            "subscription_updated_at": None,
            "subscription_last_attempt_at": None,
            "subscription_last_success_at": None,
            "subscription_last_error_at": None,
            "subscription_error": "",
            "subscription_consecutive_failures": 0,
            "last_switch_at": None,
            "last_switch_reason": "",
            "auto_check_failures": 0,
            "auto_check_last_at": None,
            "auto_best_check_last_at": None,
            "auto_check_last_error": "",
            "router_rule_desired_enabled": None,
            "jobs": {
                "latency": {"running": False, "progress": 0, "total": 0, "message": ""},
                "refresh": {"running": False, "message": ""},
                "switch": {"running": False, "message": ""},
            },
        }
        instance.latencies = {}
        instance.latency_checking_ids = set()
        instance.started_at = int(time.time())
        instance.home_assistant_host = "homeassistant.local"
        instance.next_update_at = int(time.time()) + 3600
        instance.servers = []
        instance._xray_version_cache = "Xray test"
        instance.selector_state = {
            "configured": True,
            "available": False,
            "current": "",
            "error": "",
            "connections_supported": False,
            "last_checked_at": None,
        }
        instance.router_state = {
            "configured": True,
            "available": False,
            "rule_enabled": None,
            "rule_name": "mark_domains",
            "rule_section": "",
            "busy": False,
            "desired_rule_enabled": None,
            "last_checked_at": None,
            "error": "",
            "auth_method": "existing_key",
            "key_name": "id_ed25519",
            "public_key": "",
        }
        instance.slots = {
            "xray-a": m.XraySlot("xray-a", 10808, True, tmp_path / "a.json"),
            "xray-b": m.XraySlot("xray-b", 10809, True, tmp_path / "b.json"),
        }
        instance.save_state = lambda: None
        instance.save_latencies = lambda: None
        instance.sync_supervisor_options = lambda: (True, "")
        return instance
    return make


@pytest.fixture
def isolated_paths(m, monkeypatch, tmp_path):
    data = tmp_path / "data"
    work = tmp_path / "config"
    web = tmp_path / "web"
    data.mkdir()
    work.mkdir()
    web.mkdir()
    (web / "index.html").write_text("index", encoding="utf-8")
    (web / "app.js").write_text("app", encoding="utf-8")
    (web / "style.css").write_text("style", encoding="utf-8")
    (web / "favicon.svg").write_text("svg", encoding="utf-8")
    changelog = tmp_path / "CHANGELOG.md"
    changelog.write_text("## v0.7.5\n\n- Change one\n- Change two\n", encoding="utf-8")

    paths = {
        "OPTIONS_PATH": data / "options.json",
        "WORKDIR": work,
        "LEGACY_WORKDIR": tmp_path / "legacy",
        "SUBSCRIPTION_PATH": work / "subscription.json",
        "CONFIG_PATH": work / "config.json",
        "LAST_GOOD_CONFIG_PATH": work / "config.last_good.json",
        "LAST_GOOD_META_PATH": work / "config.last_good.meta.json",
        "STATE_PATH": work / "state.json",
        "LATENCY_PATH": work / "latencies.json",
        "RUNTIME_OPTIONS_PATH": work / "runtime-options.json",
        "WEB_ROOT": web,
        "CHANGELOG_PATH": changelog,
    }
    for key, value in paths.items():
        monkeypatch.setattr(m, key, value)
    monkeypatch.setattr(m, "SLOT_CONFIG_PATHS", {
        "xray-a": work / "config.xray-a.json",
        "xray-b": work / "config.xray-b.json",
    })
    m.RELEASE_NOTES_CACHE = None
    m.LOG_BUFFER.clear()
    m.RESERVED_TEST_PORTS.clear()
    return SimpleNamespace(**paths)


@pytest.fixture
def write_options(isolated_paths):
    def write(**overrides):
        options = {
            "subscription_url": "https://subscription.example/list",
            "router_control_enabled": False,
            "selector_control_enabled": False,
            "socks_tcp_a": 10808,
            "socks_tcp_b": 10809,
            "ui_port": 8090,
        }
        options.update(overrides)
        isolated_paths.OPTIONS_PATH.write_text(json.dumps(options), encoding="utf-8")
        return options
    return write
