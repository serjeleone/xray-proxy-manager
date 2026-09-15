"""Browser -> manager HTTP API -> real Xray -> local download server."""
from __future__ import annotations

import re
import threading
from pathlib import Path

import pytest
from playwright.sync_api import Page, expect

from test_xray_integration import live_manager, transfer  # noqa: F401: pytest fixture
from streaming import streaming_download  # noqa: F401: pytest fixture

pytestmark = pytest.mark.ui


def test_visible_faster_excluded_outbound_never_steals_live_selection(page: Page, m, live_manager, monkeypatch):
    instance = live_manager
    first, second, excluded = instance.candidates
    instance.ui_hide_excluded = False
    instance.auto_switch_excluded = excluded.name
    pings = {first.id: 350, second.id: 50, excluded.id: 1}
    monkeypatch.setattr(instance, 'test_candidate_for_full_scan', lambda item: {
        'status': 'ok', 'latency_ms': pings[item.id], 'checked_at': 1,
    })
    instance.latencies = {cid: {'status': 'ok', 'latency_ms': ping} for cid, ping in pings.items()}
    monkeypatch.setattr(m.common, 'WEB_ROOT', Path(__file__).parents[2] / 'xray-proxy-manager' / 'web')
    handler = lambda *args, **kwargs: m.web.WebHandler(instance, *args, **kwargs)
    server = m.web.ThreadingHTTPServer(('127.0.0.1', 0), handler)
    serving = threading.Thread(target=server.serve_forever, daemon=True)
    serving.start()
    try:
        page.goto(f'http://127.0.0.1:{server.server_port}/ingress/test/')
        expect(page.locator('#activeName')).to_have_text(first.name)
        expect(page.locator('.outbound-card.active .outbound-title')).to_have_text(first.name)
        expect(page.locator(f'[data-select="{excluded.id}"]')).to_be_visible()

        # Deterministic scan measurements; startup, pre-switch validation and
        # the slot processes themselves use the real Xray release binary.
        instance.latency_job(switch_to_best=True, source='auto-best')
        assert instance.active_candidate_id == second.id
        assert instance.active_slot_tag == 'xray-b'
        expect(page.locator('#activeName')).to_have_text(second.name)
        expect(page.locator('.outbound-card.active .outbound-title')).to_have_text(second.name)
        expect(page.locator('#outboundList .outbound-title').first).to_have_text(second.name)
        expect(page.locator('.active-chip')).to_have_count(1)
        expect(page.locator(f'[data-select="{excluded.id}"]')).to_be_enabled()
    finally:
        server.shutdown()
        server.server_close()
        serving.join(2)


def test_live_download_updates_badge_and_reselection_turns_green(
    page: Page, m, live_manager, monkeypatch,
):
    instance = live_manager
    instance.selector_control_enabled = False
    first, second, _ = instance.candidates
    monkeypatch.setattr(m.common, 'WEB_ROOT', Path(__file__).parents[2] / 'xray-proxy-manager' / 'web')
    monkeypatch.delenv('SUPERVISOR_TOKEN', raising=False)
    handler = lambda *args, **kwargs: m.web.WebHandler(instance, *args, **kwargs)
    server = m.web.ThreadingHTTPServer(('127.0.0.1', 0), handler)
    serving = threading.Thread(target=server.serve_forever, daemon=True)
    sampling = threading.Thread(target=instance.active_throughput_loop, daemon=True)
    stop_download = threading.Event()
    errors = []
    def download():
        while not stop_download.is_set():
            result = transfer(instance, '/download')
            if result.returncode:
                errors.append(result.stderr.decode())
                return
            stop_download.wait(0.05)
    downloading = threading.Thread(target=download, daemon=True)
    serving.start()
    sampling.start()
    try:
        # Use an Ingress-style nested URL to test the actual relative API URLs.
        page.goto(f'http://127.0.0.1:{server.server_port}/ingress/test/')
        badge = page.locator('#throughputValue')
        expect(badge).not_to_have_text('— МБ/с')
        downloading.start()
        expect(badge).to_have_text(re.compile(r'^(?:[1-9]\d*\.[0-9]|0\.[1-9]) МБ/с$'), timeout=10000)
        stop_download.set()
        downloading.join(8)
        assert not errors
        # Health probes are idle here, so the real counter settles back to zero.
        expect(badge).to_have_text('0.0 МБ/с', timeout=8000)
        instance.selector_control_enabled = True
        page.locator(f'[data-select="{second.id}"]').click()
        first_card = page.locator('.outbound-card').filter(has_text='First')
        expect(first_card.locator('.ping.suspect')).to_have_count(1)
        page.locator(f'[data-select="{first.id}"]').click()
        expect(first_card.locator('.ping.ok')).to_have_count(1)
        expect(first_card.locator('.ping.suspect')).to_have_count(0)
        assert instance.active_candidate_id == first.id
    finally:
        stop_download.set()
        if downloading.ident is not None:
            downloading.join(8)
        instance.stop_event.set()
        sampling.join(5)
        server.shutdown()
        server.server_close()
        serving.join(2)


def test_open_stream_badge_reacts_to_rate_pause_and_resume(page: Page, m, streaming_download, monkeypatch):
    stream = streaming_download
    instance = stream.instance
    monkeypatch.setattr(m.common, 'WEB_ROOT', Path(__file__).parents[2] / 'xray-proxy-manager' / 'web')
    monkeypatch.delenv('SUPERVISOR_TOKEN', raising=False)
    handler = lambda *args, **kwargs: m.web.WebHandler(instance, *args, **kwargs)
    server = m.web.ThreadingHTTPServer(('127.0.0.1', 0), handler)
    serving = threading.Thread(target=server.serve_forever, daemon=True)
    sampling = threading.Thread(target=instance.active_throughput_loop, daemon=True)
    serving.start()
    sampling.start()
    try:
        page.goto(f'http://127.0.0.1:{server.server_port}/ingress/test/')
        value = page.locator('#throughputValue')
        expect(value).to_have_text(re.compile(r'^[2-5]\.\d МБ/с$'), timeout=10000)
        assert instance.throughput_payload()['source'] == 'selector'
        assert stream.receiving.is_alive()
        stream.rate['chunk'] = 16384
        expect(value).to_have_text(re.compile(r'^(?:0\.[7-9]|1\.[0-5]) МБ/с$'), timeout=8000)
        stream.paused.set()
        expect(value).to_have_text('0.0 МБ/с', timeout=8000)
        assert stream.receiving.is_alive()  # Same TCP connection remains open.
        stream.rate['chunk'] = 65536
        stream.paused.clear()
        expect(value).to_have_text(re.compile(r'^[2-5]\.\d МБ/с$'), timeout=8000)
        assert stream.receiving.is_alive()
    finally:
        instance.stop_event.set()
        sampling.join(5)
        server.shutdown()
        server.server_close()
        serving.join(2)
