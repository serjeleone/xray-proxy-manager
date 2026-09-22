from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

import pytest


def test_exact_window_partial_buckets_restart_and_log_rotation(m, tmp_path, monkeypatch):
    now = 1_800_000_123
    monkeypatch.setattr(m.common, 'now_ts', lambda: now)
    path = tmp_path / 'switch-history.json'
    history = m.switch_history.SwitchHistory(path)
    for ts in [now - 43201, now - 43200, now - 43199, now - 1, now, now]:
        history.record(ts)
    # Rotating the 2500-line UI log cannot change the persisted counters.
    for i in range(2600):
        m.common.append_ui_log(f'line {i}')
    payload = m.switch_history.SwitchHistory(path).payload()
    assert payload['total'] == 4
    assert len(payload['buckets']) == 145
    assert payload['buckets'][0] == {'start': now - 43200, 'end': now // 300 * 300 - 42900, 'count': 1}
    assert payload['buckets'][-1] == {'start': now // 300 * 300, 'end': now, 'count': 3}
    assert sum(bucket['count'] for bucket in payload['buckets']) == 4
    assert history.payload(now + 43201)['total'] == 0


def test_new_switch_visible_at_exact_five_minute_boundary(m, tmp_path):
    history = m.switch_history.SwitchHistory(tmp_path / 'history.json')
    now = 1_800_000_000
    history.record(now - 1)
    history.record(now)
    payload = history.payload(now)
    assert payload['buckets'][-2]['count'] == 1
    assert payload['buckets'][-1] == {'start': now, 'end': now, 'count': 1}
    assert payload['total'] == 2


@pytest.mark.parametrize('contents', ['not json', '[]', '{"version": 99}',
    '{"version": 1, "events": null}',
    '{"version": 1, "events": [[true, 1], [1, -2], ["x", 4], null, [3]]}'])
def test_malformed_history_does_not_prevent_startup(m, tmp_path, contents):
    path = tmp_path / 'history.json'
    path.write_text(contents)
    history = m.switch_history.SwitchHistory(path)
    assert history.payload()['total'] == 0
    history.record()
    assert json.loads(path.read_text())['version'] == 1


def test_failed_write_keeps_statistics_and_recovers(m, tmp_path, monkeypatch):
    history = m.switch_history.SwitchHistory(tmp_path / 'history.json')
    write = m.persistence.atomic_write_json
    def fail(*_args):
        raise OSError('disk full')
    monkeypatch.setattr(m.persistence, 'atomic_write_json', fail)
    history.record()
    assert history.payload()['total'] == 1
    assert history.payload()['persisted'] is False
    monkeypatch.setattr(m.persistence, 'atomic_write_json', write)
    history.record()
    assert history.payload()['persisted'] is True
    assert m.switch_history.SwitchHistory(history.path).payload()['total'] == 2


def test_concurrent_changes_are_not_lost(m, tmp_path):
    history = m.switch_history.SwitchHistory(tmp_path / 'history.json')
    with ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(lambda _: history.record(), range(32)))
    assert m.switch_history.SwitchHistory(history.path).payload()['total'] == 32


def test_activation_ignores_first_start_and_same_outbound_reload(manager_factory, candidate_factory):
    first, second = candidate_factory('first'), candidate_factory('second')
    instance = manager_factory([first, second])
    instance.record_outbound_change(None, first)
    instance.record_outbound_change(first, replace(first, config_revision='new'))
    assert instance.switch_history.payload()['total'] == 0
    instance.record_outbound_change(first, second)
    instance.record_outbound_change(second, first)
    assert instance.status_payload()['switch_history']['total'] == 2
