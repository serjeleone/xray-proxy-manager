from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from conftest import DummyProcess


@pytest.fixture
def subscription_manager(manager_factory, candidate_factory, isolated_paths):
    current = candidate_factory('current')
    added = candidate_factory('added')
    instance = manager_factory([current])
    instance.subscription = [{'revision': 1}]
    instance.active_candidate_id = current.id
    slot = instance.slots['xray-a']
    slot.process = DummyProcess()
    slot.candidate = current
    slot.candidate_id = current.id
    instance.download_subscription = lambda: [{'revision': 2}]
    instance.extract_candidates = lambda _configs: [current, added]
    instance.runtime_config_differs = lambda *_args: False
    instance.test_candidate_for_full_scan = lambda item: {
        'status': 'ok', 'latency_ms': 250 if item is current else 10,
        'checked_at': 1000, 'error': '',
    }
    return instance


@pytest.mark.parametrize('periodic, checker, switch', [
    (False, True, True), (True, True, True),
    (False, True, False), (False, False, True),
])
def test_successful_refresh_runs_full_check_and_resets_shared_schedule(
    m, subscription_manager, monkeypatch, periodic, checker, switch,
):
    instance = subscription_manager
    instance.auto_checker_enabled = checker
    instance.auto_switch_best_enabled = switch
    instance.state['auto_best_check_last_at'] = 100
    monkeypatch.setattr(m.common, 'now_ts', lambda: 1000)
    finished = threading.Event()
    job = instance.latency_job
    switches = []
    instance.restart_xray_for = lambda candidate, *_args, **_kwargs: switches.append(candidate.id)

    def check(*args, **kwargs):
        assert not instance.subscription_apply_lock.locked()
        assert not instance.switch_lock.locked()
        try:
            job(*args, **kwargs)
        finally:
            finished.set()

    instance.latency_job = check
    if periodic:
        # Exercise the scheduled update through the same loop used at runtime.
        from test_runtime_lifecycle import WaitSequence
        instance.next_update_at = 1
        instance.stop_event = WaitSequence(False, True)
        instance.periodic_update_loop()
    else:
        instance.refresh_subscription_job()
    assert finished.wait(5)
    assert set(instance.latencies) == {'current', 'added'}
    assert switches == (['added'] if checker and switch else [])
    assert instance.state['jobs']['latency']['scope'] == 'all'
    assert instance.state['auto_best_check_last_at'] == 1000
    assert not instance.auto_best_check_due(1599)
    assert instance.auto_best_check_due(1600)
    assert instance.settings_event.is_set()


@pytest.mark.parametrize('failure', ['download', 'invalid'])
def test_failed_refresh_does_not_start_check_or_reset_schedule(subscription_manager, failure):
    instance = subscription_manager
    instance.state['auto_best_check_last_at'] = 100
    scans = []
    instance.request_subscription_check = lambda: scans.append(True)
    if failure == 'download':
        instance.download_subscription = lambda: (_ for _ in ()).throw(RuntimeError('offline'))
        instance.load_cached_subscription = lambda: instance.subscription
    else:
        instance.extract_candidates = lambda _configs: []
    instance.refresh_subscription_job()
    assert instance.state['subscription_error']
    assert instance.state['auto_best_check_last_at'] == 100
    assert scans == []


@pytest.mark.parametrize('manual_selection', [False, True])
def test_refresh_during_scan_checks_latest_list_once_afterwards(
    subscription_manager, candidate_factory, manual_selection,
):
    instance = subscription_manager
    current = instance.candidates[0]
    intermediate = candidate_factory('intermediate')
    latest = candidate_factory('latest')
    entered = threading.Event()
    release = threading.Event()
    finished = threading.Event()
    job = instance.latency_job
    probed = []
    switches = []
    instance.restart_xray_for = lambda candidate, *_args, **_kwargs: switches.append(candidate.id)

    def probe(candidate):
        probed.append(candidate.id)
        if len(probed) == 1:
            entered.set()
            assert release.wait(5)
        return {'status': 'ok', 'latency_ms': 250 if candidate is current else 10,
                'checked_at': 1000, 'error': ''}

    def queued_check(*args, **kwargs):
        try:
            job(*args, **kwargs)
        finally:
            finished.set()

    instance.test_candidate_for_full_scan = probe
    instance.latency_job = queued_check
    with ThreadPoolExecutor(max_workers=1) as pool:
        scanning = pool.submit(job)
        try:
            assert entered.wait(5)
            for added in (intermediate, latest):
                instance.extract_candidates = lambda _configs, added=added: [current, added]
                instance.refresh_subscription_sync()
            # The active scan cannot cover new entries or overlap its successor.
            assert probed == ['current']
            if manual_selection:
                instance.select_candidate(current.id)
        finally:
            release.set()
        scanning.result(timeout=5)
        assert finished.wait(5)
    assert probed[0] == 'current'
    assert sorted(probed[1:]) == ['current', 'latest']
    assert instance.latencies['latest']['status'] == 'ok'
    assert switches == ([] if manual_selection else ['latest'])
    assert not instance.state['jobs']['latency']['running']
    assert instance.pending_subscription_check_generation is None
