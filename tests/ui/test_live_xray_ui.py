"""Browser -> manager HTTP API -> real Xray -> local download server."""
from __future__ import annotations

import re
import threading
from pathlib import Path

import pytest
from playwright.sync_api import Page, expect

from test_xray_integration import live_manager, transfer  # noqa: F401: pytest fixture
from test_streaming_stats import streaming_download  # noqa: F401: pytest fixture

pytestmark = pytest.mark.ui


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
        badge = page.locator('#throughputBadge')
        expect(value).to_have_text(re.compile(r'^[2-5]\.\d МБ/с$'), timeout=10000)
        assert badge.bounding_box()['width'] == 70
        assert badge.bounding_box()['height'] == 26
        stream.rate['chunk'] = 16384
        expect(value).to_have_text(re.compile(r'^(?:0\.[7-9]|1\.[0-5]) МБ/с$'), timeout=8000)
        stream.paused.set()
        expect(value).to_have_text('0.0 МБ/с', timeout=8000)
        assert stream.receiving.is_alive()  # Same TCP connection remains open.
        stream.rate['chunk'] = 65536
        stream.paused.clear()
        expect(value).to_have_text(re.compile(r'^[2-5]\.\d МБ/с$'), timeout=8000)
        assert badge.bounding_box()['width'] == 70
        assert badge.bounding_box()['height'] == 26
    finally:
        instance.stop_event.set()
        sampling.join(5)
        server.shutdown()
        server.server_close()
        serving.join(2)
