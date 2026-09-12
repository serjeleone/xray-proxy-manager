from __future__ import annotations

import json
import os
import re
import threading
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import urlparse
from . import common as xpm_common, models as xpm_models, persistence as xpm_persistence


class SettingsMixin:
    def _apply_runtime_values(self, source: dict[str, Any]) -> None:
        self.subscription_url = str(source.get('subscription_url') or '').strip()
        self.dual_slot_enabled = xpm_common.to_bool(source.get('dual_slot_enabled', True))
        self.auto_checker_enabled = xpm_common.to_bool(source.get('auto_checker_enabled', True))
        self.auto_switch_best_enabled = xpm_common.to_bool(source.get('auto_switch_best_enabled', True))
        self.switching_preset = xpm_common.normalize_switching_preset(source.get('switching_preset', 'smooth'))
        self.auto_switch_preferred_country = xpm_common.normalize_preferred_country(
            source.get('auto_switch_preferred_country', '')
        )
        self.auto_switch_preferred_protocol = xpm_common.normalize_preferred_protocol(
            source.get('auto_switch_preferred_protocol', '')
        )
        self.auto_switch_excluded = xpm_common.normalize_auto_switch_exclusions(
            source.get('auto_switch_excluded', 'RU')
        )
        self.auto_switch_min_ping_delta_ms = xpm_common.bounded_int(
            source.get('auto_switch_min_ping_delta_ms', 100), 0, 10000, 'auto_switch_min_ping_delta_ms'
        )
        self.auto_check_interval_seconds = xpm_common.bounded_int(
            source.get('auto_check_interval_seconds', 60), 10, 86400, 'auto_check_interval_seconds'
        )
        self.auto_check_failures = xpm_common.bounded_int(
            source.get('auto_check_failures', 3), 1, 100, 'auto_check_failures'
        )
        self.auto_check_max_latency_ms = xpm_common.bounded_int(
            source.get('auto_check_max_latency_ms', 500), 0, 10000, 'auto_check_max_latency_ms'
        )
        self.auto_best_check_interval_seconds = xpm_common.bounded_int(
            source.get('auto_best_check_interval_seconds', 600), 60, 86400,
            'auto_best_check_interval_seconds',
        )
        self.update_interval_hours = xpm_common.bounded_float(
            source.get('update_interval_hours', 1), 0, 720, 'update_interval_hours'
        )
        sort_value = str(source.get('ui_sort') or 'ping-asc')
        self.ui_sort = sort_value if sort_value in xpm_common.SORT_VALUES else 'ping-asc'
        protocol = str(source.get('ui_protocol_filter') or 'all').strip().upper()
        self.ui_protocol_filter = protocol if protocol else 'ALL'
        if self.ui_protocol_filter == 'ALL':
            self.ui_protocol_filter = 'all'
        self.ui_max_ping_ms = xpm_common.bounded_int(source.get('ui_max_ping_ms', 1000), 0, 10000, 'ui_max_ping_ms')
        self.ui_hide_unavailable = xpm_common.to_bool(source.get('ui_hide_unavailable', False))
        self.ui_hide_excluded = xpm_common.to_bool(source.get('ui_hide_excluded', True))

    def validate_runtime_changes(self, changes: dict[str, Any]) -> dict[str, Any]:
        normalized: dict[str, Any] = {}
        for key, value in changes.items():
            if key not in xpm_common.RUNTIME_SETTING_KEYS:
                raise ValueError(f'Настройка {key} недоступна для изменения из UI')
            if key == 'subscription_url':
                text = str(value or '').strip()
                parsed = urlparse(text)
                if not text or parsed.scheme not in {'http', 'https'} or not parsed.netloc or len(text) > 4096:
                    raise ValueError('Ссылка на подписку должна быть корректным HTTP(S)-адресом')
                normalized[key] = text
            elif key in {
                'dual_slot_enabled', 'auto_checker_enabled', 'auto_switch_best_enabled',
                'ui_hide_unavailable', 'ui_hide_excluded',
            }:
                normalized[key] = xpm_common.to_bool(value)
            elif key == 'switching_preset':
                normalized[key] = xpm_common.normalize_switching_preset(value)
            elif key == 'auto_switch_preferred_country':
                normalized[key] = xpm_common.normalize_preferred_country(value)
            elif key == 'auto_switch_preferred_protocol':
                normalized[key] = xpm_common.normalize_preferred_protocol(value)
            elif key == 'auto_switch_excluded':
                normalized[key] = xpm_common.normalize_auto_switch_exclusions(value)
            elif key == 'auto_switch_min_ping_delta_ms':
                normalized[key] = xpm_common.bounded_int(value, 0, 10000, key)
            elif key == 'auto_check_interval_seconds':
                normalized[key] = xpm_common.bounded_int(value, 10, 86400, key)
            elif key == 'auto_check_failures':
                normalized[key] = xpm_common.bounded_int(value, 1, 100, key)
            elif key == 'auto_check_max_latency_ms':
                normalized[key] = xpm_common.bounded_int(value, 0, 10000, key)
            elif key == 'auto_best_check_interval_seconds':
                normalized[key] = xpm_common.bounded_int(value, 60, 86400, key)
            elif key == 'update_interval_hours':
                normalized[key] = xpm_common.bounded_float(value, 0, 720, key)
            elif key == 'ui_max_ping_ms':
                normalized[key] = xpm_common.bounded_int(value, 0, 10000, key)
            elif key == 'ui_sort':
                text = str(value)
                if text not in xpm_common.SORT_VALUES:
                    raise ValueError('Неизвестный режим сортировки')
                normalized[key] = text
            elif key == 'ui_protocol_filter':
                text = str(value or 'all').strip().upper()
                if len(text) > 32 or not re.fullmatch(r'[A-Z0-9_-]+|ALL', text):
                    raise ValueError('Некорректный фильтр протокола')
                normalized[key] = 'all' if text == 'ALL' else text
        return normalized

    def update_runtime_settings(self, changes: dict[str, Any]) -> dict[str, Any]:
        normalized = self.validate_runtime_changes(changes)
        if 'dual_slot_enabled' in normalized:
            raise ValueError('Режим слотов изменяется отдельной кнопкой в верхнем блоке')
        with self.lock:
            self.options.update(normalized)
            self.options.pop(xpm_common.LEGACY_AUTO_SWITCH_EXCLUDED_KEY, None)
            runtime_options = xpm_persistence.load_json(xpm_common.RUNTIME_OPTIONS_PATH, {})
            if not isinstance(runtime_options, dict):
                runtime_options = {}
            base_options = xpm_persistence.load_json(xpm_common.OPTIONS_PATH, {})
            snapshot = runtime_options.setdefault('_base_options', {})
            for key in normalized:
                snapshot.setdefault(key, base_options.get(key, self.options.get(key)))
            runtime_options.update(normalized)
            runtime_options.pop(xpm_common.LEGACY_AUTO_SWITCH_EXCLUDED_KEY, None)
            xpm_persistence.atomic_write_json(xpm_common.RUNTIME_OPTIONS_PATH, runtime_options)
            self._apply_runtime_values(self.options)
            if normalized.get('auto_switch_best_enabled') is False or normalized.get('auto_checker_enabled') is False:
                self.preference_scan_generation += 1
                self.manual_generation = getattr(self, 'manual_generation', 0) + 1
            self.next_update_at = (
                xpm_common.now_ts() + self.update_interval_hours * 3600
                if self.update_interval_hours > 0 else None
            )
            self.settings_event.set()
        supervisor_synced, supervisor_error = self.sync_supervisor_options()
        return {
            'ok': True,
            'restart_required': [],
            'supervisor_synced': supervisor_synced,
            'supervisor_error': supervisor_error,
        }

    def candidate_preference_score(self, candidate: xpm_models.Candidate | None) -> tuple[int, int, int]:
        if candidate is None:
            return (0, 0, 0)
        preferred_country = getattr(self, 'auto_switch_preferred_country', '')
        preferred_protocol = getattr(self, 'auto_switch_preferred_protocol', '')
        country_match = int(bool(preferred_country and candidate.country_code == preferred_country))
        protocol_match = int(bool(
            preferred_protocol and candidate.protocol.casefold() == preferred_protocol.casefold()
        ))
        # Country is the primary preference. A candidate from the preferred
        # country always outranks a protocol-only match, while the protocol is
        # used to choose between candidates with the same country priority.
        weighted_score = country_match * 2 + protocol_match
        return (weighted_score, country_match, protocol_match)

    def candidate_preference_sort_key(self, candidate: xpm_models.Candidate) -> tuple[int, int, int]:
        score, country_match, protocol_match = self.candidate_preference_score(candidate)
        return (-score, -country_match, -protocol_match)

    def _deferred_preference_scan(
        self,
        country: str,
        protocol: str,
        generation: int,
        source: str,
    ) -> None:
        while not self.stop_event.wait(0.5):
            with self.lock:
                if (
                    generation != self.preference_scan_generation
                    or self.auto_switch_preferred_country != country
                    or self.auto_switch_preferred_protocol != protocol
                ):
                    return
                running = bool(self.state['jobs']['latency'].get('running'))
            if running:
                continue
            if self.request_latency_test(None, switch_to_best=True, source=source):
                return

    def _deferred_preferred_country_scan(self, country: str, generation: int) -> None:
        # Compatibility wrapper retained for existing callers and tests.
        self._deferred_preference_scan(
            country,
            getattr(self, 'auto_switch_preferred_protocol', ''),
            generation,
            'preferred-country',
        )

    def set_selection_preferences(
        self,
        country_value: Any,
        protocol_value: Any,
        *,
        source: str = 'preferred-selection',
    ) -> dict[str, Any]:
        country = xpm_common.normalize_preferred_country(country_value)
        protocol = xpm_common.normalize_preferred_protocol(protocol_value)
        settings_result = self.update_runtime_settings({
            'auto_switch_preferred_country': country,
            'auto_switch_preferred_protocol': protocol,
        })
        if not (self.auto_checker_enabled and self.auto_switch_best_enabled):
            return {
                **settings_result, 'country': country, 'protocol': protocol,
                'switch_started': False, 'matching_candidates': 0,
                'message': 'Приоритет сохранён; автопереключение отключено',
            }
        with self.lock:
            self.preference_scan_generation += 1
            generation = self.preference_scan_generation
            eligible = [
                candidate for candidate in self.candidates
                if not self.candidate_is_excluded(candidate)
            ]
            matching = [
                candidate for candidate in eligible
                if self.candidate_preference_score(candidate)[0] > 0
            ]
            cached_healthy: list[tuple[int, str, xpm_models.Candidate]] = []
            cached_latencies = getattr(self, 'latencies', {})
            max_latency_ms = int(getattr(self, 'auto_check_max_latency_ms', 0) or 0)
            for candidate in matching:
                latency = cached_latencies.get(candidate.id) or {}
                latency_ms = latency.get('latency_ms')
                if latency.get('status') != 'ok' or not isinstance(latency_ms, int):
                    continue
                if max_latency_ms > 0 and latency_ms > max_latency_ms:
                    continue
                cached_healthy.append((latency_ms, candidate.name.casefold(), candidate))
            cached_healthy.sort(key=lambda item: (
                *self.candidate_preference_sort_key(item[2]), item[0], item[1]
            ))
            immediate_candidate = cached_healthy[0][2] if cached_healthy else None
            current = self.candidate_by_id(getattr(self, 'active_candidate_id', ''))
            if hasattr(self, 'slots') and hasattr(self, 'active_slot_tag'):
                active_slot = self.slots.get(self.active_slot_tag)
                if active_slot is not None and active_slot.candidate is not None:
                    current = active_slot.candidate

        if not country and not protocol:
            return {
                **settings_result,
                'country': '',
                'protocol': '',
                'switch_started': False,
                'matching_candidates': 0,
                'message': 'Приоритет страны и протокола отключён',
            }

        immediate_switched = False
        immediate_error = ''
        should_switch_immediately = bool(
            immediate_candidate is not None
            and not self.same_outbound(current, immediate_candidate)
        )
        if should_switch_immediately and immediate_candidate is not None:
            try:
                preference_label = ', '.join(filter(None, (
                    f'country {country}' if country else '',
                    f'protocol {protocol}' if protocol else '',
                )))
                self.restart_xray_for(
                    immediate_candidate,
                    f'preferred {preference_label} selected from UI',
                    source='preference_ui',
                    preempt_draining=True,
                )
                immediate_switched = True
            except Exception as exc:
                immediate_error = str(exc)
                xpm_common.log(
                    f'immediate preferred-selection switch to {immediate_candidate.name} '
                    f'failed; continuing with full scan: {exc}',
                    error=True,
                )

        switch_started = self.request_latency_test(None, switch_to_best=True, source=source)
        queued = False
        active_full_switch_scan = False
        if not switch_started:
            with self.lock:
                job = dict(self.state['jobs']['latency'])
                active_full_switch_scan = bool(
                    job.get('running')
                    and job.get('scope') == 'all'
                    and job.get('switch_to_best')
                )
            if not active_full_switch_scan:
                queued = True
                threading.Thread(
                    target=self._deferred_preference_scan,
                    args=(country, protocol, generation, source),
                    daemon=True,
                    name='preferred-selection-scan',
                ).start()

        labels = []
        if country:
            labels.append(f'страны {country}')
        if protocol:
            labels.append(f'протокола {protocol}')
        preference_text = ' и '.join(labels)
        if immediate_switched and immediate_candidate is not None:
            message = (
                f'Активирован {immediate_candidate.name}; запущена полная проверка '
                f'с приоритетом {preference_text}'
            )
        elif switch_started:
            message = f'Запущена проверка outbound с приоритетом {preference_text}'
        elif active_full_switch_scan:
            message = f'Текущая полная проверка продолжена с приоритетом {preference_text}'
        else:
            message = f'Проверка с приоритетом {preference_text} поставлена в очередь'
        if immediate_error:
            message += f'; немедленное переключение не выполнено: {immediate_error}'
        if not matching:
            message += '; подходящие outbound не найдены, будет использован общий список'

        return {
            **settings_result,
            'country': country,
            'protocol': protocol,
            'switch_started': switch_started or active_full_switch_scan or immediate_switched,
            'immediate_switched': immediate_switched,
            'queued': queued,
            'matching_candidates': len(matching),
            'message': message,
        }

    def set_preferred_country(self, value: Any) -> dict[str, Any]:
        return self.set_selection_preferences(
            value,
            getattr(self, 'auto_switch_preferred_protocol', ''),
            source='preferred-country',
        )

    def set_preferred_protocol(self, value: Any) -> dict[str, Any]:
        return self.set_selection_preferences(
            getattr(self, 'auto_switch_preferred_country', ''),
            value,
            source='preferred-protocol',
        )

    def sync_supervisor_options(self) -> tuple[bool, str]:
        with self.options_sync_lock:
            return self._sync_supervisor_options()

    def _sync_supervisor_options(self) -> tuple[bool, str]:
        token = os.environ.get('SUPERVISOR_TOKEN', '').strip()
        if not token:
            return False, 'SUPERVISOR_TOKEN недоступен; настройки сохранены локально'
        with self.lock:
            sent_options = dict(self.options)
        request_body = json.dumps({'options': sent_options}, ensure_ascii=False).encode('utf-8')
        request = urllib.request.Request(
            'http://supervisor/addons/self/options',
            data=request_body,
            method='POST',
            headers={
                'Authorization': f'Bearer {token}',
                'Content-Type': 'application/json',
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                payload = json.loads(response.read().decode('utf-8') or '{}')
            if payload.get('result') != 'ok':
                return False, str(payload.get('message') or 'Supervisor отклонил настройки')
            with self.lock:
                runtime_options = xpm_persistence.load_json(xpm_common.RUNTIME_OPTIONS_PATH, {})
                runtime_options['_base_options'] = {
                    key: sent_options[key] for key in xpm_common.RUNTIME_SETTING_KEYS if key in sent_options
                }
                xpm_persistence.atomic_write_json(xpm_common.RUNTIME_OPTIONS_PATH, runtime_options)
            return True, ''
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
            xpm_common.log(f'could not sync UI settings to Supervisor: {exc}', error=True)
            return False, f'{exc}; настройки сохранены локально'

    def debug_log(self, message: str) -> None:
        if getattr(self, 'log_level', '') == 'debug':
            xpm_common.log(f'DEBUG: {message}')
