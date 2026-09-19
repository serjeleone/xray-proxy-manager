"""Regression scenarios against the actual release binary, using only local traffic."""
from __future__ import annotations

import copy
import http.server
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError

import pytest


@pytest.mark.parametrize('phase, outcome', [
    ('download', 'updated'), ('apply', 'updated'),
    ('apply', 'invalid'), ('apply', 'removed'),
])
def test_manual_selection_during_subscription_refresh(live_manager, monkeypatch, phase, outcome):
    instance = live_manager
    first, second, _ = instance.candidates
    configs = copy.deepcopy(instance.subscription)
    configs[1]['remarks'] = 'Updated second'
    if outcome == 'invalid':
        configs = []
    elif outcome == 'removed':
        configs = configs[:1]
    entered = threading.Event()
    release = threading.Event()
    apply = instance.apply_subscription

    def pause():
        entered.set()
        assert release.wait(10), 'refresh was not released'

    def download():
        if phase == 'download':
            pause()
        return configs

    def apply_download(*args, **kwargs):
        if phase == 'apply':
            pause()
        return apply(*args, **kwargs)

    monkeypatch.setattr(instance, 'download_subscription', download)
    monkeypatch.setattr(instance, 'apply_subscription', apply_download)
    instance.state['jobs']['refresh']['running'] = True
    with ThreadPoolExecutor(max_workers=2) as pool:
        refreshing = pool.submit(instance.refresh_subscription_job)
        try:
            assert entered.wait(5)
            selection = pool.submit(instance.select_candidate, second.id)
            if phase == 'download':
                selection.result(timeout=5)
                assert instance.active_candidate_id == second.id
                assert instance.state['jobs']['refresh']['running']
            else:
                # Applying the list must delay the click, not reject it as a
                # competing switch or resolve it against the old list.
                with pytest.raises(TimeoutError):
                    selection.result(timeout=0.1)
        finally:
            release.set()
        refreshing.result(timeout=5)
        if outcome == 'removed':
            with pytest.raises(ValueError, match='Outbound не найден'):
                selection.result(timeout=5)
            assert instance.active_candidate_id == first.id
        else:
            selection.result(timeout=5)
            assert instance.active_candidate_id == second.id
            assert instance.slots['xray-a'].draining
            assert instance.slots['xray-b'].running()
            expected_name = second.name if outcome == 'invalid' else 'Updated second'
            assert instance.slots['xray-b'].candidate_name == expected_name
        assert bool(instance.state['subscription_error']) == (outcome == 'invalid')


def test_manual_selection_survives_inflight_full_scan(live_manager, monkeypatch):
    instance = live_manager
    first, second, _ = instance.candidates
    entered = threading.Event()
    release = threading.Event()

    def probe(candidate):
        entered.set()
        assert release.wait(10), 'scan was not released'
        return {'status': 'ok' if candidate.id == first.id else 'error',
                'latency_ms': 1 if candidate.id == first.id else None,
                'checked_at': 1, 'error': ''}

    monkeypatch.setattr(instance, 'test_candidate_for_full_scan', probe)
    instance.auto_checker_enabled = instance.auto_switch_best_enabled = True
    with ThreadPoolExecutor(max_workers=1) as pool:
        checking = pool.submit(instance.latency_job, switch_to_best=True, source='auto-best')
        try:
            assert entered.wait(5)
            instance.select_candidate(second.id)
            assert instance.state['jobs']['latency']['running']
            assert instance.active_candidate_id == second.id
        finally:
            release.set()
        checking.result(timeout=5)
    assert instance.active_candidate_id == second.id
    assert instance.latencies[second.id]['status'] == 'ok'
    assert instance.latencies[second.id]['checked_at'] > 1


@pytest.fixture
def live_manager(m, manager_factory, isolated_paths, monkeypatch, tmp_path):
    binary = os.environ.get('XRAY_TEST_BINARY') or shutil.which('xray')
    if not binary:
        pytest.skip('XRAY_TEST_BINARY is required for real-core integration tests')
    monkeypatch.setattr(m.common, 'XRAY_BIN', str(Path(binary).resolve()))
    monkeypatch.setattr(m.common, 'CURL_BIN', shutil.which('curl'))

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_GET(self):
            body = b'x' * 262144 if self.path == '/download' else b''
            self.send_response(200 if body else 204)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            self.rfile.read(int(self.headers['Content-Length']))
            self.send_response(204)
            self.send_header('Content-Length', '0')
            self.end_headers()

    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    instance = manager_factory()
    ports = [instance.find_free_port() for _ in range(5)]
    upstream_path = tmp_path / 'upstream.json'
    upstream_path.write_text(json.dumps({
        'log': {'loglevel': 'none'},
        'inbounds': [
            {'listen': '127.0.0.1', 'port': port, 'protocol': 'socks', 'settings': {'auth': 'noauth'}}
            for port in ports[:2]
        ],
        'outbounds': [{'protocol': 'freedom'}],
    }))
    upstream = subprocess.Popen([binary, 'run', '-config', str(upstream_path)], stdout=subprocess.DEVNULL)
    assert instance.wait_for_port(ports[0], upstream)
    instance.socks_tcp_a, instance.socks_tcp_b = ports[2:4]
    instance.slots['xray-a'].socks_tcp = ports[2]
    instance.slots['xray-b'].socks_tcp = ports[3]
    instance.socks_listen_address = '0.0.0.0'
    instance.socks_allowed_cidrs = ['0.0.0.0/0']
    instance.primary_test_url = f'http://127.0.0.1:{server.server_port}/check'
    instance.secondary_test_url = f'http://127.0.0.1:{server.server_port}/check2'
    instance.subscription = [{
        'remarks': name,
        'outbounds': [{
            'tag': 'node', 'protocol': 'socks',
            'settings': {'servers': [{'address': '127.0.0.1', 'port': port}]},
        }],
    } for name, port in zip(('First', 'Second', 'Unavailable'), [*ports[:2], ports[4]])]
    instance.candidates = instance.extract_candidates(instance.subscription)
    selector = {'current': 'xray-a'}
    instance.selector_status = lambda: selector['current']
    instance.switch_selector = lambda tag: selector.update(current=tag)
    instance.selector_connections = lambda **_kwargs: []
    instance.post_switch_watch = lambda *_args: None
    instance.start_initial_candidate(instance.candidates[0], 'integration test')
    try:
        yield instance
    finally:
        instance.stop_event.set()
        instance.stop_xray()
        upstream.terminate()
        upstream.wait(timeout=5)
        server.shutdown()
        server.server_close()


def test_repeated_slot_modes_and_return_to_draining_outbound(live_manager):
    instance = live_manager
    first, second, _ = instance.candidates
    instance.latencies[second.id] = {'status': 'ok', 'latency_ms': 9999, 'checked_at': 1}
    instance.select_candidate(second.id)
    assert instance.active_slot_tag == 'xray-b'
    assert 0 <= instance.latencies[second.id]['latency_ms'] < 500
    assert instance.latencies[second.id]['checked_at'] > 1
    # Returning to the previous outbound reuses its running process.
    original = instance.slots['xray-a'].process
    instance.latencies[first.id] = {'status': 'ok', 'latency_ms': 9999, 'checked_at': 1}
    instance.select_candidate(first.id)
    assert instance.slots['xray-a'].process is original
    assert 0 <= instance.latencies[first.id]['latency_ms'] < 500
    assert instance.latencies[first.id]['checked_at'] > 1
    assert first.id not in instance.state['suspect_candidate_ids']
    assert second.id in instance.state['suspect_candidate_ids']
    active = next(item for item in instance.status_payload()['candidates'] if item['active'])
    assert active['suspect'] is False
    for dual in (False, True, False, True, False):
        generation = instance.switch_generation
        instance.set_slot_mode(dual)
        assert instance.dual_slot_enabled is dual
        assert instance.switch_generation > generation
        assert instance.slots['xray-a'].running()
        assert not instance.slots['xray-b'].running()
        assert instance.probe_slot_health('xray-a')[0]
    instance.latencies[second.id] = {'status': 'ok', 'latency_ms': 9999, 'checked_at': 1}
    instance.select_candidate(second.id)
    assert instance.active_slot_tag == 'xray-a'
    assert 0 <= instance.latencies[second.id]['latency_ms'] < 500
    assert instance.latencies[second.id]['checked_at'] > 1


def transfer(instance, path, *, upload=None, interface=None):
    command = [
        shutil.which('curl'), '--silent', '--show-error', '--fail', '--max-time', '5',
        '--noproxy', '', '--socks5-hostname',
        f'127.0.0.1:{instance.slots[instance.active_slot_tag].socks_tcp}',
        '-o', '/dev/null',
    ]
    if interface:
        command += ['--interface', interface]
    if upload is not None:
        command += ['--data-binary', '@-']
    command.append(instance.primary_test_url.rsplit('/', 1)[0] + path)
    return subprocess.run(command, input=upload, capture_output=True, timeout=8)


def test_download_stats_without_selector_include_closed_connections(live_manager):
    instance = live_manager
    instance.selector_control_enabled = False
    instance.refresh_active_throughput()
    before = instance._throughput_download_bytes
    assert transfer(instance, '/download').returncode == 0
    instance.refresh_active_throughput()
    downloaded = instance._throughput_download_bytes - before
    assert 262144 <= downloaded < 264144
    assert instance.throughput_payload()['bytes_per_second'] > 0
    before_upload = instance._throughput_download_bytes
    assert transfer(instance, '/upload', upload=b'x' * 2_000_000).returncode == 0
    instance.refresh_active_throughput()
    assert instance._throughput_download_bytes - before_upload < 2000
    instance.set_slot_mode(False)
    instance.refresh_active_throughput()
    assert instance.throughput_payload()['bytes_per_second'] == 0


@pytest.mark.parametrize('strategy, observer', [
    ('leastPing', 'observatory'), ('leastLoad', 'burstObservatory'),
])
def test_subscription_with_observer_balancer_starts_and_transfers(live_manager, strategy, observer):
    instance = live_manager
    configs = copy.deepcopy(instance.subscription[:1])
    configs[0][observer] = {'subjectSelector': ['node']}
    configs[0]['routing'] = {
        'balancers': [{'tag': 'auto', 'selector': ['node'], 'strategy': {'type': strategy}}],
        'rules': [{'type': 'field', 'network': 'tcp,udp', 'balancerTag': 'auto'}],
    }
    instance.stop_xray()
    instance.download_subscription = lambda: configs
    instance.refresh_subscription_sync(initial=True)
    assert instance.state['subscription_error'] == ''
    assert instance.slots[instance.active_slot_tag].running()
    assert transfer(instance, '/download').returncode == 0
    instance.refresh_active_throughput()
    assert instance.throughput_payload()['available'] is True
    candidate = instance.candidates[0]
    probe = instance.build_config(candidate, test_port=instance.find_free_port())
    path = instance.slots[instance.active_slot_tag].config_path.with_name('probe.json')
    path.write_text(json.dumps(probe))
    assert instance.xray_test(path)[0]
    # Source subscription data must remain intact for export and future updates.
    assert configs[0]['routing']['balancers'][0]['strategy']['type'] == strategy
    assert observer in configs[0]


def test_socks_source_cidr_rejects_then_allows_client(live_manager):
    instance = live_manager
    instance.socks_allowed_cidrs = []
    instance.set_slot_mode(False)
    assert transfer(instance, '/download', interface='127.0.0.2').returncode != 0
    assert instance.probe_slot_health('xray-a')[0]  # Local manager remains allowed.
    instance.socks_allowed_cidrs = ['127.0.0.2/32']
    instance.set_slot_mode(True)
    assert transfer(instance, '/download', interface='127.0.0.2').returncode == 0


def test_manual_switch_during_scan_does_not_restore_rejected_latency(live_manager):
    instance = live_manager
    first, second, broken = instance.candidates
    instance.latency_test_parallelism = -1
    entered = threading.Event()
    release = threading.Event()
    def old_probe(candidate):
        if candidate.id == broken.id:
            entered.set()
            assert release.wait(15)
        return {'status': 'ok', 'latency_ms': 1, 'checked_at': int(time.time()), 'error': ''}
    instance.test_candidate_for_full_scan = old_probe
    scan = threading.Thread(target=instance.latency_job, args=(None, True, 'auto-best'))
    scan.start()
    try:
        assert entered.wait(5)
        instance.select_candidate(second.id)
        assert instance.active_candidate_id == second.id
        with pytest.raises(RuntimeError) as failure:
            instance.select_candidate(broken.id)
        assert len(str(failure.value)) < 100
        assert instance.latencies[broken.id]['status'] == 'error'
    finally:
        release.set()
        scan.join(10)
    assert not scan.is_alive()
    assert instance.active_candidate_id == second.id
    assert instance.latencies[broken.id]['latency_ms'] is None
    assert first.id in instance.state['suspect_candidate_ids']


def test_subscription_identity_survives_rename_reorder_and_config_revision(manager_factory):
    instance = manager_factory()
    config = {'remarks': 'Before', 'outbounds': [{
        'tag': 'old-label', 'protocol': 'vless',
        'settings': {'vnext': [{'address': 'example.test', 'port': 443, 'users': [{'id': 'test-user'}]}]},
        'streamSettings': {'network': 'tcp', 'security': 'tls', 'tlsSettings': {'serverName': 'a.test'}},
    }, {'tag': 'direct', 'protocol': 'freedom'}]}
    original = instance.extract_candidates([config])[0]
    instance.latencies[original.id] = {'status': 'ok', 'latency_ms': 123, 'config_revision': original.config_revision}
    renamed = copy.deepcopy(config)
    renamed['remarks'] = 'After'
    renamed['outbounds'][0]['tag'] = 'new-label'
    renamed['outbounds'].reverse()
    current = instance.extract_candidates([renamed])[0]
    assert (current.id, current.config_revision) == (original.id, original.config_revision)
    assert instance.latencies[current.id]['latency_ms'] == 123
    renamed['outbounds'][1]['streamSettings']['tlsSettings']['serverName'] = 'b.test'
    changed = instance.extract_candidates([renamed])[0]
    assert changed.id == original.id
    assert changed.config_revision != original.config_revision
    assert changed.id not in instance.latencies


def test_disabling_auto_switch_cancels_running_scan_and_failover(manager_factory, candidate_factory):
    first, second = candidate_factory('one'), candidate_factory('two')
    instance = manager_factory([first, second])
    instance.active_candidate_id = first.id
    entered, release = threading.Event(), threading.Event()
    def probe(candidate):
        entered.set()
        assert release.wait(5)
        return {'status': 'ok', 'latency_ms': 10 if candidate is second else 300, 'checked_at': 1, 'error': ''}
    instance.test_candidate_for_full_scan = probe
    switched = []
    instance.restart_xray_for = lambda *args, **kwargs: switched.append(args)
    scan = threading.Thread(target=instance.latency_job, args=(None, True, 'auto-best'))
    scan.start()
    assert entered.wait(5)
    instance.auto_switch_best_enabled = False
    release.set()
    scan.join(5)
    assert not scan.is_alive()
    assert instance.emergency_failover(3) is None
    assert not switched


def test_identity_preserves_chained_outbounds_when_tags_change(manager_factory):
    instance = manager_factory()
    original = {
        'remarks': 'Old profile',
        'outbounds': [
            {'tag': 'proxy-a', 'protocol': 'socks', 'settings': {'servers': [{'address': 'a.example', 'port': 1080}]}, 'proxySettings': {'tag': 'proxy-b'}},
            {'tag': 'proxy-b', 'protocol': 'socks', 'settings': {'servers': [{'address': 'b.example', 'port': 1080}]}},
        ],
        'routing': {'balancers': [{'tag': 'balancer', 'selector': ['proxy-']}]},
    }
    before = {item.server: (item.id, item.config_revision) for item in instance.extract_candidates([original])}
    renamed = copy.deepcopy(original)
    renamed['remarks'] = 'New profile'
    renamed['outbounds'][0]['tag'] = 'new-a'
    renamed['outbounds'][0]['proxySettings']['tag'] = 'new-b'
    renamed['outbounds'][1]['tag'] = 'new-b'
    renamed['outbounds'].reverse()
    renamed['routing']['balancers'][0]['selector'] = ['new-']
    after = {item.server: (item.id, item.config_revision) for item in instance.extract_candidates([renamed])}
    assert after == before
