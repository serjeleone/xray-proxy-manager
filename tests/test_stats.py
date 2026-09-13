from __future__ import annotations

import json
import subprocess
from types import SimpleNamespace

import pytest


def test_stats_failure_is_logged_once_and_recovers(m, manager_factory, isolated_paths, monkeypatch):
    instance = manager_factory()
    instance.selector_control_enabled = False
    instance.slots['xray-a'].process = SimpleNamespace(poll=lambda: None)
    responses = [
        subprocess.CompletedProcess([], 1, '', 'deadline exceeded'),
        subprocess.CompletedProcess([], 1, '', 'deadline exceeded'),
        subprocess.CompletedProcess([], 0, json.dumps({'stat': [{
            'name': 'inbound>>>socks>>>traffic>>>downlink', 'value': '1024',
        }]}), ''),
    ]
    monkeypatch.setattr(m.subprocess, 'run', lambda *a, **k: responses.pop(0))
    instance.refresh_active_throughput()
    instance.refresh_active_throughput()
    assert not instance.throughput_payload()['available']
    lines, _ = m.common.ui_log_snapshot(100)
    assert sum('throughput stats unavailable' in line for line in lines) == 1
    assert any('deadline exceeded' in line for line in lines)
    instance.refresh_active_throughput()
    assert instance.throughput_payload()['available']
    assert instance.throughput_payload()['bytes_per_second'] == 0  # Fresh baseline.
    assert instance._throughput_download_bytes == 1024
    lines, _ = m.common.ui_log_snapshot(100)
    assert sum('throughput stats recovered' in line for line in lines) == 1
    # A successful RPC with no downlink counter is also unavailable, not idle.
    responses.append(subprocess.CompletedProcess([], 0, '{}', ''))
    instance.refresh_active_throughput()
    assert not instance.throughput_payload()['available']
    lines, _ = m.common.ui_log_snapshot(100)
    assert any('downlink counter is missing' in line for line in lines)


def test_old_stats_response_does_not_reset_new_active_slot(m, manager_factory, monkeypatch):
    instance = manager_factory()
    instance.selector_control_enabled = False
    instance.slots['xray-a'].process = SimpleNamespace(poll=lambda: None)
    instance.slots['xray-b'].process = SimpleNamespace(poll=lambda: None)
    def run(*args, **kwargs):
        instance.active_slot_tag = 'xray-b'
        instance.update_active_throughput('xray-b', 100, sampled_at=1)
        instance.update_active_throughput('xray-b', 1100, sampled_at=2)
        raise subprocess.TimeoutExpired(args[0], 4)
    monkeypatch.setattr(m.subprocess, 'run', run)
    instance.refresh_active_throughput()
    result = instance.throughput_payload()
    assert result['available'] and result['slot'] == 'xray-b'
    assert result['bytes_per_second'] == 1000


def test_selector_counts_only_download_on_selected_slot(manager_factory):
    instance = manager_factory()
    def sample(a, b, *, upload=0, second=True, new=0):
        rows = [
            {'id': 'active', 'chains': ['selector', 'xray-a'], 'download': a, 'upload': upload},
            {'id': 'draining', 'chains': ['xray-b'], 'download': b, 'upload': upload},
            {'id': 'direct', 'chains': ['DIRECT'], 'download': b},
        ]
        if second:
            rows.append({'id': 'second-active', 'chains': ['xray-a'], 'download': 1_000_000})
        if new:
            rows.append({'id': 'new-active', 'chains': ['xray-a'], 'download': new})
        return rows
    baseline = instance.update_selector_throughput('xray-a', sample(5_000_000, 9_000_000), 10)
    assert baseline['bytes_per_second'] == 0
    # Other-slot traffic and 200 MB uploaded must not count as a download.
    result = instance.update_selector_throughput('xray-a', sample(8_000_000, 70_000_000, upload=200_000_000), 11)
    assert result['megabytes_per_second'] == 3
    # A completed connection disappearing must not reset the active flow.
    result = instance.update_selector_throughput('xray-a', sample(10_000_000, 90_000_000, second=False, new=500_000), 12)
    assert result['megabytes_per_second'] == 2.5
    result = instance.update_selector_throughput('xray-b', sample(15_000_000, 120_000_000), 13)
    assert result['bytes_per_second'] == 0
    result = instance.update_selector_throughput('xray-b', sample(99_000_000, 124_000_000), 14)
    assert result['megabytes_per_second'] == 4


def test_stats_sources_and_process_restarts_start_a_new_baseline(manager_factory):
    instance = manager_factory()
    connections = [{'id': 'one', 'chains': ['xray-a'], 'download': 90_000_000}]
    instance.update_active_throughput('xray-a', 1_000_000, 1)
    assert instance.update_selector_throughput('xray-a', connections, 2)['bytes_per_second'] == 0
    assert instance.update_active_throughput('xray-a', 200_000_000, 3)['bytes_per_second'] == 0
    instance.slots['xray-a'].process = SimpleNamespace(poll=lambda: None)
    assert instance.update_active_throughput('xray-a', 900_000_000, 4)['bytes_per_second'] == 0
    instance.switch_generation += 2  # A -> B -> A between samples.
    assert instance.update_active_throughput('xray-a', 999_000_000, 5)['bytes_per_second'] == 0


def test_selector_error_does_not_substitute_frozen_xray_stats(manager_factory, monkeypatch, m, isolated_paths):
    instance = manager_factory()
    instance.slots['xray-a'].process = SimpleNamespace(poll=lambda: None)
    def failed(**kwargs):
        assert kwargs['timeout'] == 2
        raise TimeoutError('selector timeout')
    instance.selector_connections = failed
    monkeypatch.setattr(m.subprocess, 'run', lambda *a, **k: pytest.fail('No silent switch to delayed splice counters'))
    instance.refresh_active_throughput()
    instance.refresh_active_throughput()
    assert not instance.throughput_payload()['available']
    assert 'selector' in instance.throughput_payload()['error']
    instance.selector_connections = lambda **_kwargs: []
    instance.refresh_active_throughput()
    assert instance.throughput_payload()['available']
    assert instance.throughput_payload()['source'] == 'selector'
    lines, _ = m.common.ui_log_snapshot(100)
    assert sum('throughput stats unavailable' in line for line in lines) == 1
    assert sum('throughput stats recovered' in line for line in lines) == 1


@pytest.mark.parametrize('change', ['generation', 'process', 'source'])
def test_stale_selector_response_is_ignored(manager_factory, change):
    instance = manager_factory()
    instance.slots['xray-a'].process = SimpleNamespace(poll=lambda: None)
    def connections(**_kwargs):
        if change == 'generation':
            instance.switch_generation += 2
        elif change == 'process':
            instance.slots['xray-a'].process = SimpleNamespace(poll=lambda: None)
        else:
            instance.selector_control_enabled = False
        return [{'id': 'old', 'chains': ['xray-a'], 'download': 999_000_000}]
    instance.selector_connections = connections
    instance.refresh_active_throughput()
    assert not instance.throughput_payload()['available']
