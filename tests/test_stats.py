from __future__ import annotations

import json
import subprocess
from types import SimpleNamespace


def test_stats_failure_is_logged_once_and_recovers(m, manager_factory, isolated_paths, monkeypatch):
    instance = manager_factory()
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


def test_old_stats_response_does_not_reset_new_active_slot(m, manager_factory, monkeypatch):
    instance = manager_factory()
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
