from __future__ import annotations

import copy
import json
from collections.abc import Callable
from urllib.parse import urlparse

import pytest
from playwright.sync_api import Page, Route, expect

pytestmark = pytest.mark.ui


def candidate(
    candidate_id: str,
    name: str,
    protocol: str,
    *,
    latency: dict | None = None,
    active: bool = False,
    slot_tags: list[str] | None = None,
    draining_slots: list[str] | None = None,
    checking: bool = False,
    excluded: bool = False,
    server: str = "203.0.113.10",
) -> dict:
    return {
        "id": candidate_id,
        "name": name,
        "protocol": protocol,
        "server": server,
        "port": 443,
        "outbound_tag": candidate_id,
        "country_code": "FI",
        "latency": latency,
        "active": active,
        "slot_tags": slot_tags or [],
        "draining_slots": draining_slots or [],
        "checking": checking,
        "excluded": excluded,
    }


def base_payload() -> dict:
    candidates = [
        candidate(
            "active-id", "Active Finland", "VLESS",
            latency={"status": "ok", "latency_ms": 82, "checked_at": 1_700_000_000},
            active=True, slot_tags=["xray-b"],
        ),
        candidate(
            "drain-id", "Draining Germany", "TROJAN",
            latency={"status": "error", "error": "timeout", "checked_at": 1_700_000_000},
            slot_tags=["xray-a"], draining_slots=["xray-a"],
        ),
        candidate(
            "vless-id", "Regular VLESS", "VLESS",
            latency={"status": "ok", "latency_ms": 140, "checked_at": 1_700_000_000},
        ),
        candidate(
            "vmess-id", "Regular VMESS", "VMESS",
            latency={"status": "ok", "latency_ms": 120, "checked_at": 1_700_000_000},
        ),
    ]
    return {
        "version": "0.8.0",
        "xray_version": "Xray 26.7.28",
        "xray_running": True,
        "home_assistant_host": "192.0.2.250",
        "active": {
            "id": "active-id", "name": "Active Finland", "protocol": "VLESS",
            "server": "154.222.9.64", "port": 443,
        },
        "candidates": candidates,
        "protocols": ["VLESS", "TROJAN", "VMESS", "VLESS"],
        "countries": ["FI", "DE", "FI"],
        "availability": {"available": 3, "unavailable": 1, "untested": 0},
        "blue_green": {
            "mode": "dual", "dual_slot_enabled": True, "active_slot": "xray-b",
            "slots": {
                "xray-a": {
                    "tag": "xray-a", "socks_tcp": 10808, "running": True,
                    "draining": True, "drain_connections": 14,
                },
                "xray-b": {
                    "tag": "xray-b", "socks_tcp": 10809, "running": True,
                    "draining": False, "drain_connections": 0,
                },
            },
        },
        "selector": {
            "configured": True, "available": True, "current": "xray-b",
            "connections_supported": True, "error": "",
        },
        "router": {
            "configured": True, "available": True, "rule_enabled": True,
            "rule_name": "mark_domains", "rule_section": "mark_domains", "busy": False,
        },
        "auto_checker": {
            "enabled": True, "switch_to_best": True, "switching_preset": "smooth",
            "interval_seconds": 60, "best_check_interval_seconds": 600,
            "failure_threshold": 3, "current_failures": 0, "max_latency_ms": 500,
            "preferred_country": "FI", "preferred_protocol": "VLESS",
            "excluded": "RU", "min_ping_delta_ms": 100,
            "last_check_at": 1_700_000_000, "last_best_check_at": 1_700_000_000,
            "last_error": "",
        },
        "subscription": {
            "url": "https://subscription.example/list", "update_interval_hours": 1,
            "last_attempt_at": 1_700_000_000, "last_success_at": 1_700_000_000,
            "last_error_at": None, "error": "", "next_update_at": 1_700_003_600,
        },
        "ui_settings": {
            "sort": "ping-asc", "protocol_filter": "all", "max_ping_ms": 1000,
            "hide_unavailable": False, "hide_excluded": True,
        },
        "jobs": {
            "latency": {"running": False, "progress": 0, "total": 0, "message": ""},
            "refresh": {"running": False, "message": ""},
            "switch": {"running": False, "message": ""},
        },
        "release_notes": {"version": "0.8.0", "items": ["Тестовая версия"]},
    }


class ApiHarness:
    def __init__(self, payload: dict):
        self.payload = payload
        self.requests: list[dict] = []
        self.status_requests = 0
        self.logs = ["first line", "proxy connected", "last line"]
        self.cors_headers = {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type",
        }
        self.responses: dict[str, dict | Callable[[dict], dict]] = {
            "/api/settings": {"restart_required": [], "supervisor_synced": True},
            "/api/preferences": {"message": "Предпочтения сохранены"},
        }

    def handler(self, route: Route) -> None:
        request = route.request
        parsed = urlparse(request.url)
        path = parsed.path
        if request.method == "OPTIONS":
            route.fulfill(status=204, headers=self.cors_headers)
            return
        if request.method == "GET" and path == "/api/status":
            self.status_requests += 1
            route.fulfill(json=self.payload, headers=self.cors_headers)
            return
        if request.method == "GET" and path == "/api/logs":
            route.fulfill(json={"lines": self.logs, "total": len(self.logs)}, headers=self.cors_headers)
            return
        body = json.loads(request.post_data or "{}")
        self.requests.append({"method": request.method, "path": path, "body": body})
        response = self.responses.get(path, {})
        if callable(response):
            response = response(body)
        if path == "/api/settings" and "changes" in body:
            changes = body["changes"]
            ui_map = {
                "ui_sort": "sort", "ui_protocol_filter": "protocol_filter",
                "ui_max_ping_ms": "max_ping_ms", "ui_hide_unavailable": "hide_unavailable",
                "ui_hide_excluded": "hide_excluded",
            }
            for source, target in ui_map.items():
                if source in changes:
                    self.payload["ui_settings"][target] = changes[source]
        route.fulfill(json=response, headers=self.cors_headers)


def open_app(page: Page, web_app_html: str, payload: dict | None = None) -> ApiHarness:
    harness = ApiHarness(copy.deepcopy(payload or base_payload()))
    page.route("**/api/**", harness.handler)
    page.set_content(web_app_html, wait_until="networkidle")
    expect(page.locator("#versionBadge")).to_have_text("v0.8.0")
    return harness



def wait_for_requests(page: Page, harness: ApiHarness, expected: int) -> None:
    for _ in range(100):
        if len(harness.requests) >= expected:
            return
        page.wait_for_timeout(25)
    assert len(harness.requests) >= expected

def card_names(page: Page) -> list[str]:
    return page.locator("#outboundList .outbound-title").all_text_contents()


def test_initial_render_exposes_runtime_state_and_dynamic_preferences(page: Page, web_app_html: str) -> None:
    open_app(page, web_app_html)

    expect(page.locator("#xrayState")).to_have_text("Xray работает · Двухслотовый режим")
    expect(page.locator("#activeMeta")).to_contain_text("192.0.2.250:10809 (SOCKS)")
    expect(page.locator("#selectorHint")).to_have_text(
        "Текущий активный селектор: [xray-b] · Завершение соединений селектора [xray-a] в количестве: 14 шт."
    )
    assert card_names(page)[:2] == ["Active Finland", "Draining Germany"]
    expect(page.locator("#outboundList")).not_to_contain_text("Только в слоте")
    assert page.locator("#autoSwitchPreferredProtocol option").all_text_contents() == [
        "Без приоритета", "TROJAN", "VLESS", "VMESS"
    ]


def test_active_and_draining_candidates_bypass_filters_and_remain_pinned(page: Page, web_app_html: str) -> None:
    payload = base_payload()
    payload["ui_settings"].update({
        "protocol_filter": "VMESS", "hide_unavailable": True, "max_ping_ms": 125,
    })
    open_app(page, web_app_html, payload)

    assert card_names(page) == ["Active Finland", "Draining Germany", "Regular VMESS"]
    expect(page.locator("#candidateCount")).to_contain_text("Показано 3 из 4")


def test_recheck_replaces_stale_unavailable_state(page: Page, web_app_html: str) -> None:
    payload = base_payload()
    payload["candidates"][1]["checking"] = True
    open_app(page, web_app_html, payload)

    draining = page.locator("#outboundList .outbound-card").filter(has_text="Draining Germany")
    expect(draining.locator(".ping")).to_have_text("проверяется…")
    expect(draining).not_to_have_class("unavailable")


def test_outbound_and_runtime_buttons_send_expected_commands(page: Page, web_app_html: str) -> None:
    harness = open_app(page, web_app_html)

    page.locator("#testAllButton").click()
    page.locator('[data-test="vless-id"]').click()
    page.locator('[data-select="vless-id"]').click()
    page.locator('#outboundList [data-stop-slot="xray-a"]').click()

    wait_for_requests(page, harness, 4)
    assert harness.requests == [
        {"method": "POST", "path": "/api/test", "body": {}},
        {"method": "POST", "path": "/api/test", "body": {"id": "vless-id"}},
        {"method": "POST", "path": "/api/select", "body": {"id": "vless-id"}},
        {"method": "POST", "path": "/api/drain/stop", "body": {"slot": "xray-a"}},
    ]


def test_traffic_and_slot_mode_controls_send_explicit_desired_state(page: Page, web_app_html: str) -> None:
    harness = open_app(page, web_app_html)

    page.locator("#trafficButton").click()
    page.once("dialog", lambda dialog: dialog.accept())
    page.locator("#slotModeButton").click()

    wait_for_requests(page, harness, 2)
    assert harness.requests == [
        {"method": "POST", "path": "/api/traffic", "body": {"enabled": False}},
        {"method": "POST", "path": "/api/mode", "body": {"dual_slot_enabled": False}},
    ]


def test_auto_checker_save_separates_runtime_settings_and_preferences(page: Page, web_app_html: str) -> None:
    harness = open_app(page, web_app_html)

    page.locator("#autoCheckFailures").fill("5")
    page.locator("#switchingPreset").select_option("adaptive")
    assert harness.requests == []
    assert page.locator("#saveAutoChecker").evaluate("element => element.classList.contains('dirty')")
    page.locator("#autoSwitchPreferredCountry").select_option("DE")
    page.locator("#autoSwitchPreferredProtocol").select_option("TROJAN")
    page.locator("#autoSwitchExcluded").fill("ru; CN; RU")
    page.locator("#saveAutoChecker").click()

    wait_for_requests(page, harness, 2)
    settings, preferences = harness.requests
    assert settings["path"] == "/api/settings"
    assert settings["body"]["changes"]["auto_check_failures"] == 5
    assert settings["body"]["changes"]["switching_preset"] == "adaptive"
    assert settings["body"]["changes"]["auto_switch_excluded"] == "RU, CN"
    assert "auto_switch_preferred_country" not in settings["body"]["changes"]
    assert preferences == {
        "method": "POST", "path": "/api/preferences",
        "body": {"country": "DE", "protocol": "TROJAN"},
    }
    expect(page.locator("#toast")).to_contain_text("Предпочтения сохранены")


def test_subscription_save_shows_restart_decision_when_backend_requires_it(page: Page, web_app_html: str) -> None:
    harness = open_app(page, web_app_html)
    harness.responses["/api/settings"] = {
        "restart_required": ["subscription_url"], "supervisor_synced": True,
    }

    page.locator("#subscriptionUrl").fill("https://new.example/subscription")
    page.locator("#saveSubscription").click()

    expect(page.locator("#restartModal")).not_to_have_class("hidden")
    assert harness.requests[-1]["body"]["changes"]["subscription_url"] == "https://new.example/subscription"
    page.locator("#saveOnlyButton").click()
    assert "hidden" in (page.locator("#restartModal").get_attribute("class") or "").split()


def test_focused_selects_defer_status_refresh_and_option_rebuild(page: Page, web_app_html: str) -> None:
    harness = open_app(page, web_app_html)

    preset = page.locator("#switchingPreset")
    preset.focus()
    harness.payload["auto_checker"]["enabled"] = False
    page.wait_for_timeout(3200)
    expect(page.locator("#autoCheckerState")).to_have_text("Включён")
    preset.blur()
    expect(page.locator("#autoCheckerState")).to_have_text("Выключен")

    protocol = page.locator("#protocolFilter")
    protocol.focus()
    before = protocol.evaluate("element => element.innerHTML")
    harness.payload["protocols"].append("SHADOWSOCKS")
    page.wait_for_timeout(3200)
    assert protocol.evaluate("element => element.innerHTML") == before
    protocol.blur()
    expect(protocol.locator('option[value="SHADOWSOCKS"]')).to_have_count(1)


def test_logs_modal_loads_searches_and_closes(page: Page, web_app_html: str) -> None:
    open_app(page, web_app_html)

    page.locator("#logsButton").click()
    expect(page.locator("#logsModal")).not_to_have_class("hidden")
    expect(page.locator("#logsContent")).to_contain_text("proxy connected")
    page.locator("#logsSearchInput").fill("proxy")
    expect(page.locator("#logsSearchCount")).to_have_text("1 / 1")
    page.locator("#closeLogsButton").click()
    assert "hidden" in (page.locator("#logsModal").get_attribute("class") or "").split()


def test_api_error_is_visible_to_user(page: Page, web_app_html: str) -> None:
    harness = open_app(page, web_app_html)
    harness.responses["/api/test"] = lambda _body: {"error": "probe failed"}

    def failing_handler(route: Route) -> None:
        request = route.request
        if urlparse(request.url).path == "/api/test":
            route.fulfill(status=503, json={"error": "probe failed"}, headers=harness.cors_headers)
        else:
            harness.handler(route)

    page.unroute("**/api/**", harness.handler)
    page.route("**/api/**", failing_handler)
    page.locator("#testAllButton").click()
    expect(page.locator("#toast")).to_contain_text("Ошибка: probe failed")
