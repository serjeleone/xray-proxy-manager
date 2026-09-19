from __future__ import annotations

import copy
import json
from collections.abc import Callable
from pathlib import Path
from urllib.parse import urlparse

import pytest
from playwright.sync_api import Page, Route, expect

pytestmark = pytest.mark.ui
VERSION = (Path(__file__).parents[2] / "xray-proxy-manager" / "VERSION").read_text().strip()


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
        "version": VERSION,
        "xray_version": "Xray test core",
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
                    "candidate_id": "drain-id", "display_candidate_id": "drain-id",
                    "draining": True, "drain_connections": 14,
                },
                "xray-b": {
                    "tag": "xray-b", "socks_tcp": 10809, "running": True,
                    "candidate_id": "active-id", "display_candidate_id": "active-id",
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
        "release_notes": {"version": VERSION, "items": ["Тестовая версия"]},
    }


class ApiHarness:
    def __init__(self, payload: dict):
        self.payload = payload
        self.requests: list[dict] = []
        self.status_requests = 0
        self.logs = ["first line", "proxy connected", "last line"]
        self.throughput = {
            "available": True, "slot": "xray-b",
            "bytes_per_second": 15_400_000.0, "megabytes_per_second": 15.4,
            "updated_at": 1_700_000_000, "error": "",
        }
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
        if request.method == "GET" and path == "/api/throughput":
            route.fulfill(json=self.throughput, headers=self.cors_headers)
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
    expect(page.locator("#versionBadge")).to_have_text(f"v{VERSION}")
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
    payload["candidates"][0]["excluded"] = True  # Explicit manual selection remains active.
    payload["candidates"][1]["excluded"] = True
    open_app(page, web_app_html, payload)

    assert card_names(page) == ["Active Finland", "Draining Germany", "Regular VMESS"]
    expect(page.locator("#candidateCount")).to_contain_text("Показано 3 из 4")


def test_running_slots_override_stale_selection_with_visible_excluded_candidate(page: Page, web_app_html: str) -> None:
    payload = base_payload()
    payload["ui_settings"]["hide_excluded"] = False
    payload["auto_checker"]["excluded"] = "Blocked"
    excluded = candidate(
        "excluded-id", "Blocked fastest", "VLESS", excluded=True,
        latency={"status": "ok", "latency_ms": 1},
        active=True, slot_tags=["xray-b"],
    )
    # A stale row must never override the actual running-slot identity.
    payload["candidates"].insert(0, excluded)
    payload["candidates"][1].update(active=False, slot_tags=[], suspect=True)
    harness = open_app(page, web_app_html, payload)

    def assert_selected(name: str, candidate_id: str) -> None:
        expect(page.locator("#activeName")).to_have_text(name)
        expect(page.locator(".outbound-card.active .outbound-title")).to_have_text(name)
        expect(page.locator(".active-chip")).to_have_count(1)
        expect(page.locator("#outboundList .outbound-title").first).to_have_text(name)
        expect(page.locator(f'[data-select="{candidate_id}"]')).to_be_disabled()
        expect(page.locator('[data-select="excluded-id"]')).to_be_enabled()
        expect(page.locator(".outbound-card.active .ping.suspect")).to_have_count(0)

    assert_selected("Active Finland", "active-id")
    for sort in ("ping-desc", "name-asc", "protocol-desc", "ping-asc"):
        page.locator("#sortSelect").select_option(sort)
        assert_selected("Active Finland", "active-id")

    # Automatic switching changes the runtime slots, while stale row flags and
    # the faster excluded row remain unchanged.
    harness.payload["blue_green"]["active_slot"] = "xray-a"
    harness.payload["blue_green"]["slots"]["xray-a"].update(
        candidate_id="vless-id", display_candidate_id="vless-id", draining=False,
    )
    harness.payload["blue_green"]["slots"]["xray-b"]["draining"] = True
    harness.payload["active"] = next(item for item in harness.payload["candidates"] if item["id"] == "vless-id")
    page.evaluate("fetchStatus(true)")
    assert_selected("Regular VLESS", "vless-id")
    expect(page.locator(".outbound-card.draining .outbound-title")).to_have_text("Active Finland")

    page.locator("#hideExcluded").check()
    expect(page.locator('[data-select="excluded-id"]')).to_have_count(0)
    page.locator("#hideExcluded").uncheck()
    assert_selected("Regular VLESS", "vless-id")

    for slot in harness.payload["blue_green"]["slots"].values():
        slot["running"] = False
    harness.payload["xray_running"] = False
    page.evaluate("fetchStatus(true)")
    expect(page.locator(".outbound-card.active")).to_have_count(0)
    expect(page.locator(".slot-badge")).to_have_count(0)


def test_changed_profile_keeps_runtime_snapshot_active_in_ui(page: Page, web_app_html: str) -> None:
    payload = base_payload()
    payload["ui_settings"]["hide_excluded"] = False
    running = payload["candidates"][0]
    running.update(id="slot:xray-b", active=True)
    payload["blue_green"]["slots"]["xray-b"]["display_candidate_id"] = running["id"]
    changed = candidate(
        "active-id", "Blocked replacement", "VLESS", excluded=True,
        latency={"status": "ok", "latency_ms": 1},
    )
    changed["config_changed"] = True
    payload["candidates"].insert(0, changed)
    open_app(page, web_app_html, payload)

    expect(page.locator(".outbound-card.active .outbound-title")).to_have_text("Active Finland")
    expect(page.locator('[data-select="slot:xray-b"]')).to_be_disabled()
    replacement = page.locator('[data-select="active-id"]')
    expect(replacement).to_have_text("Применить")
    expect(replacement).to_be_enabled()
    expect(page.locator(".active-chip")).to_have_count(1)


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


def test_traffic_control_and_repeated_mode_changes_follow_server_state(page: Page, web_app_html: str) -> None:
    harness = open_app(page, web_app_html)
    page.locator('#trafficButton').click()
    wait_for_requests(page, harness, 1)
    assert harness.requests == [
        {'method': 'POST', 'path': '/api/traffic', 'body': {'enabled': False}},
    ]
    def mode(body):
        enabled = body['dual_slot_enabled']
        harness.payload['blue_green'].update(dual_slot_enabled=enabled, mode='dual' if enabled else 'single')
        return {'ok': True, 'dual_slot_enabled': enabled}
    harness.responses['/api/mode'] = mode
    page.on('dialog', lambda dialog: dialog.accept())
    for index, enabled in enumerate((False, True, False, True), 2):
        page.locator('#slotModeButton').click()
        expect(page.locator('#xrayState')).to_contain_text('Двухслотовый' if enabled else 'Однослотовый')
        wait_for_requests(page, harness, index)
        assert harness.requests[-1] == {
            'method': 'POST', 'path': '/api/mode', 'body': {'dual_slot_enabled': enabled},
        }


def test_manual_selection_during_full_scan_refreshes_rejected_candidate(page: Page, web_app_html: str) -> None:
    payload = base_payload()
    payload['jobs']['latency'].update(running=True, progress=1, total=4)
    harness = open_app(page, web_app_html, payload)
    def reject(route):
        harness.payload['candidates'][2]['latency'] = {
            'status': 'error', 'latency_ms': None, 'error': 'Превышен тайм-аут проверки',
        }
        route.fulfill(status=400, json={'error': 'Превышен тайм-аут проверки'}, headers=harness.cors_headers)
    page.route('**/api/select', reject)
    expect(page.locator('[data-select="vless-id"]')).to_be_enabled()
    page.locator('[data-select="vless-id"]').click()
    card = page.locator('.outbound-card').filter(has_text='Regular VLESS')
    expect(card.locator('.ping')).to_have_text('недоступен')
    expect(page.locator('#toast')).to_have_text('Ошибка: Превышен тайм-аут проверки')
    assert harness.payload['jobs']['latency']['running'] is True


@pytest.mark.parametrize('job', ['refresh', 'latency'])
def test_background_jobs_keep_manual_selection_available(page: Page, web_app_html: str, job: str):
    payload = base_payload()
    payload['jobs'][job].update(running=True, progress=1, total=4, message='Фоновая операция')
    for item in payload['candidates']:
        item['checking'] = job == 'latency'
    harness = open_app(page, web_app_html, payload)
    expect(page.locator('#testAllButton')).to_be_disabled()
    expect(page.locator('#refreshButton')).to_be_disabled()
    expect(page.locator('[data-select="vless-id"]')).to_be_enabled()

    def select(body):
        assert body == {'id': 'vless-id'}
        harness.payload['blue_green']['active_slot'] = 'xray-a'
        harness.payload['blue_green']['slots']['xray-a'].update(
            candidate_id='vless-id', display_candidate_id='vless-id', draining=False,
        )
        harness.payload['blue_green']['slots']['xray-b']['draining'] = True
        harness.payload['active'] = harness.payload['candidates'][2]
        return {'ok': True}

    harness.responses['/api/select'] = select
    page.locator('[data-select="vless-id"]').click()
    expect(page.locator('#activeName')).to_have_text('Regular VLESS')
    expect(page.locator('.outbound-card.active .outbound-title')).to_have_text('Regular VLESS')
    expect(page.locator('[data-select="active-id"]')).to_be_enabled()
    assert harness.payload['jobs'][job]['running'] is True

    harness.payload['jobs']['switch'].update(running=True, message='Переключение')
    page.evaluate('fetchStatus(true)')
    expect(page.locator('[data-select="active-id"]')).to_be_disabled()


@pytest.mark.parametrize("finish", ["drained", "stop"])
def test_suspect_draining_slot_stays_pinned_until_finished(page: Page, web_app_html: str, finish: str):
    payload = base_payload()
    payload['candidates'] = [payload['candidates'][0], payload['candidates'][2]]
    payload['candidates'][0]['suspect'] = True  # Old persisted status after an upgrade.
    for name, protocol, ping in [('Yellow Z', 'TROJAN', 1), ('Yellow A', 'VLESS', 50)]:
        item = candidate(name, name, protocol, latency={'status': 'ok', 'latency_ms': ping})
        item['suspect'] = True
        if name == 'Yellow Z':
            item.update(slot_tags=['xray-a'], draining_slots=['xray-a'])
            payload['blue_green']['slots']['xray-a'].update(candidate_id=name, display_candidate_id=name)
        payload['candidates'].append(item)
    harness = open_app(page, web_app_html, payload)
    active = page.locator('.outbound-card').filter(has_text='Active Finland')
    expect(active.locator('.ping.ok')).to_have_text('82 мс')
    expect(active.locator('.ping.suspect')).to_have_count(0)
    for sort in ('ping-asc', 'ping-desc', 'name-asc', 'name-desc', 'protocol-asc', 'protocol-desc'):
        page.locator('#sortSelect').select_option(sort)
        expect(page.locator('#outboundList .outbound-title')).to_have_text([
            'Active Finland', 'Yellow Z', 'Regular VLESS', 'Yellow A',
        ])
        expect(page.locator('.outbound-card.draining .ping.suspect')).to_have_text('1 мс')

    # Server state after natural completion and the Stop action must both unpin
    # the old slot, without clearing its yellow ping or changing the active one.
    def stop(_body):
        harness.payload['blue_green']['slots']['xray-a'].update(running=False, draining=False)
        return {'ok': True}
    if finish == 'stop':
        harness.responses['/api/drain/stop'] = stop
        page.locator('#outboundList [data-stop-slot="xray-a"]').click()
    else:
        stop({})
        page.evaluate('fetchStatus(true)')
    expect(page.locator('.outbound-card.draining')).to_have_count(0)
    for sort, suspect_names in [
        ('ping-asc', ['Yellow Z', 'Yellow A']), ('ping-desc', ['Yellow A', 'Yellow Z']),
        ('name-asc', ['Yellow A', 'Yellow Z']), ('name-desc', ['Yellow Z', 'Yellow A']),
        ('protocol-asc', ['Yellow Z', 'Yellow A']), ('protocol-desc', ['Yellow A', 'Yellow Z']),
    ]:
        page.locator('#sortSelect').select_option(sort)
        expect(page.locator('#outboundList .outbound-title')).to_have_text([
            'Active Finland', 'Regular VLESS', *suspect_names,
        ])
        expect(page.locator('.ping.suspect')).to_have_count(2)


def test_throughput_poll_recovers_from_a_stalled_request(page: Page, web_app_html: str):
    # Simulate a request left pending after the HA Ingress connection drops.
    script = """<script>
      const originalFetch = window.fetch.bind(window);
      let stallThroughput = true;
      window.fetch = (url, options = {}) => {
        if (String(url).endsWith('/api/throughput') && stallThroughput) {
          stallThroughput = false;
          return new Promise((resolve, reject) => {
            options.signal?.addEventListener('abort', () => reject(new DOMException('timeout', 'AbortError')));
          });
        }
        return originalFetch(url, options);
      };
    </script>"""
    harness = open_app(page, web_app_html.replace('<head>', '<head>' + script))
    badge = page.locator('#throughputValue')
    expect(badge).to_have_text('15.4 МБ/с', timeout=10000)
    harness.throughput.update(available=False, error='Статистика Xray временно недоступна')
    expect(badge).to_have_text('— МБ/с')
    expect(page.locator('#throughputBadge')).to_have_attribute('title', 'Статистика Xray временно недоступна')
    harness.throughput.update(available=True, megabytes_per_second=4.5, error='')
    expect(badge).to_have_text('4.5 МБ/с')


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
