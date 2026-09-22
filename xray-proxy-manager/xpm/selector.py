from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import quote
from . import common as xpm_common


class SelectorMixin:
    def selector_api_request(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        *,
        timeout: int = 12,
    ) -> Any:
        if not self.selector_control_enabled:
            raise RuntimeError('Управление внешним selector отключено в настройках')
        method = method.upper()
        if method not in {'GET', 'PUT', 'DELETE'}:
            raise ValueError('Unsupported selector API method')
        if not path.startswith('/'):
            path = f'/{path}'
        url = f'{self.selector_api_url}{path}'
        headers = {'Accept': 'application/json'}
        data: bytes | None = None
        if self.selector_api_secret:
            headers['Authorization'] = f'Bearer {self.selector_api_secret}'
        if payload is not None:
            headers['Content-Type'] = 'application/json'
            data = json.dumps(payload, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
        request = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                raw = response.read().decode('utf-8')
        except urllib.error.HTTPError as exc:
            body = exc.read().decode('utf-8', errors='replace')[:500]
            raise RuntimeError(f'Selector API HTTP {exc.code}: {body or exc.reason}') from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise RuntimeError(f'Selector API недоступен: {exc}') from exc
        if not raw:
            return {}
        try:
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f'Selector API returned invalid JSON: {raw[:300]}') from exc

    def selector_status(self) -> str:
        payload = self.selector_api_request(
            'GET',
            f'/proxies/{quote(self.selector_tag, safe="")}',
        )
        current = str(payload.get('now') or '') if isinstance(payload, dict) else ''
        if current not in xpm_common.SLOT_TAGS:
            raise RuntimeError(
                f'Selector {self.selector_tag} returned unsupported slot: {current or "empty"}'
            )
        return current

    def switch_selector(self, slot_tag: str) -> None:
        if slot_tag not in xpm_common.SLOT_TAGS:
            raise ValueError('Unknown Xray slot')
        self.selector_api_request(
            'PUT',
            f'/proxies/{quote(self.selector_tag, safe="")}',
            {'name': slot_tag},
        )
        current = self.selector_status()
        if current != slot_tag:
            raise RuntimeError(
                f'Selector {self.selector_tag} remained on {current} instead of {slot_tag}'
            )
        if hasattr(self, 'selector_state') and hasattr(self, 'lock'):
            with self.lock:
                self.selector_state.update({
                    'configured': True,
                    'available': True,
                    'current': slot_tag,
                    'error': '',
                    'last_checked_at': xpm_common.now_ts(),
                })
        with self.lock:
            self.selector_state.update({
                'available': True,
                'current': current,
                'error': '',
                'last_checked_at': xpm_common.now_ts(),
            })

    def close_selector_connection(self, connection_id: str) -> None:
        connection_id = str(connection_id or '').strip()
        if not connection_id:
            raise ValueError('Connection id is empty')
        self.selector_api_request(
            'DELETE',
            f'/connections/{quote(connection_id, safe="")}',
            timeout=10,
        )

    def close_slot_selector_connections(
        self,
        slot_tag: str,
        connection_ids: set[str] | None = None,
        *,
        reason: str,
    ) -> tuple[int, int]:
        if slot_tag not in xpm_common.SLOT_TAGS:
            raise ValueError('Unknown Xray slot')
        if connection_ids is None:
            connections = self.connections_for_slot(self.selector_connections(), slot_tag)
            connection_ids = {
                self.connection_id(item) for item in connections if self.connection_id(item)
            }
        closed = 0
        failed = 0
        for connection_id in sorted(connection_ids):
            try:
                self.close_selector_connection(connection_id)
                closed += 1
            except RuntimeError as exc:
                # The connection may disappear between GET /connections and DELETE.
                # A 404 therefore means the desired final state is already reached.
                if 'HTTP 404' in str(exc):
                    closed += 1
                    continue
                failed += 1
                xpm_common.log(
                    f'could not close {slot_tag} selector connection {connection_id} '
                    f'({reason}): {exc}',
                    error=True,
                )
        if connection_ids:
            xpm_common.log(
                f'{slot_tag} {reason}: closed {closed}/{len(connection_ids)} selector '
                f'connection(s)' + (f'; failures={failed}' if failed else '')
            )
        return closed, failed

    def apply_switching_preset_to_draining_slot(self, slot_tag: str) -> None:
        if self.switching_preset != 'forced':
            return
        with self.lock:
            slot = self.slots[slot_tag]
            if not slot.draining:
                return
            connection_ids = set(slot.drain_known_connection_ids)
        try:
            self.close_slot_selector_connections(
                slot_tag,
                connection_ids,
                reason='forced switching preset',
            )
        except Exception as exc:
            xpm_common.log(
                f'{slot_tag} forced switching preset could not close old selector '
                f'connections: {exc}',
                error=True,
            )

    def selector_connections(self, timeout: float = 15) -> list[dict[str, Any]]:
        payload = self.selector_api_request('GET', '/connections', timeout=timeout)
        connections = payload.get('connections') if isinstance(payload, dict) else None
        if not isinstance(connections, list):
            raise RuntimeError('Selector API /connections response has no connection list')
        return [item for item in connections if isinstance(item, dict)]

    @staticmethod
    def connection_slot_stats(
        connections: list[dict[str, Any]],
        slot_tag: str,
    ) -> tuple[int, int, int, int]:
        count = 0
        tcp_count = 0
        udp_count = 0
        total_bytes = 0
        for item in connections:
            chains = item.get('chains')
            if not isinstance(chains, list) or slot_tag not in chains:
                continue
            count += 1
            metadata = item.get('metadata') if isinstance(item.get('metadata'), dict) else {}
            network = str(metadata.get('network') or item.get('network') or '').lower()
            if network == 'udp':
                udp_count += 1
            else:
                tcp_count += 1
            for key in ('upload', 'download'):
                try:
                    total_bytes += max(0, int(item.get(key) or 0))
                except (TypeError, ValueError):
                    pass
        return count, tcp_count, udp_count, total_bytes

    @staticmethod
    def connection_id(item: dict[str, Any]) -> str:
        return str(item.get('id') or item.get('uuid') or '')

    @staticmethod
    def connection_total_bytes(item: dict[str, Any]) -> int:
        total = 0
        for key in ('upload', 'download'):
            try:
                total += max(0, int(item.get(key) or 0))
            except (TypeError, ValueError):
                pass
        return total

    @staticmethod
    def connection_download_bytes(item: dict[str, Any]) -> int:
        try:
            return max(0, int(item.get('download') or 0))
        except (TypeError, ValueError):
            return 0

    def connections_for_slot(
        self,
        connections: list[dict[str, Any]],
        slot_tag: str,
    ) -> list[dict[str, Any]]:
        return [
            item for item in connections
            if isinstance(item.get('chains'), list) and slot_tag in item['chains']
        ]

    def connection_summary(self, item: dict[str, Any]) -> str:
        metadata = item.get('metadata') if isinstance(item.get('metadata'), dict) else {}
        source_ip = str(metadata.get('sourceIP') or metadata.get('source_ip') or '?')
        source_port = str(metadata.get('sourcePort') or metadata.get('source_port') or '?')
        destination = (
            str(metadata.get('host') or metadata.get('destinationIP') or metadata.get('destination_ip') or '?')
        )
        destination_port = str(
            metadata.get('destinationPort') or metadata.get('destination_port') or '?'
        )
        network = str(metadata.get('network') or item.get('network') or '?').lower()
        chains = ','.join(str(value) for value in item.get('chains') or [])
        return (
            f'id={self.connection_id(item) or "?"} source={source_ip}:{source_port} '
            f'network={network} destination={destination}:{destination_port} '
            f'chains={chains or "?"} bytes={self.connection_total_bytes(item)}'
        )

    def capture_drain_connection_baseline(self, slot_tag: str) -> None:
        """Capture existing selector flows so later arrivals can be detected."""
        slot = self.slots[slot_tag]
        try:
            connections = self.connections_for_slot(self.selector_connections(), slot_tag)
        except Exception as exc:
            with self.lock:
                slot.drain_known_connection_ids.clear()
                slot.drain_connection_bytes.clear()
                slot.drain_idle_polls.clear()
                slot.drain_last_error = str(exc)
            xpm_common.log(f'could not capture {slot_tag} drain baseline: {exc}', error=True)
            return
        known_ids = {
            self.connection_id(item) for item in connections if self.connection_id(item)
        }
        byte_map = {
            self.connection_id(item): self.connection_total_bytes(item)
            for item in connections if self.connection_id(item)
        }
        with self.lock:
            slot.drain_known_connection_ids = known_ids
            slot.drain_connection_bytes = byte_map
            slot.drain_idle_polls = {connection_id: 0 for connection_id in known_ids}
            slot.drain_new_connections = 0
            slot.drain_stalled_connections = 0
        xpm_common.log(f'{slot_tag} drain baseline captured: {len(known_ids)} selector connections')
        if self.log_level == 'debug':
            for item in connections[:10]:
                self.debug_log(f'{slot_tag} drain baseline: {self.connection_summary(item)}')

    def reconcile_startup_selector(self, current: str) -> None:
        """Resolve an unknown startup selector without surrendering manager state.

        The remembered manager slot is authoritative whenever its Xray process is
        running. The live selector is adopted only when that expected process is
        actually stopped and the reported slot is alive.
        """
        if not self.selector_reconciliation_pending or self.switch_lock.locked():
            return
        with self.lock:
            expected = self.active_slot_tag
            expected_running = self.slots[expected].running()
            current_running = self.slots[current].running()

        if expected_running:
            if current != expected:
                self.switch_selector(expected)
                xpm_common.log(
                    f'startup selector reported {current}; restored manager-expected {expected}',
                    error=True,
                )
            with self.lock:
                self.selector_reconciliation_pending = False
                self.save_state()
            xpm_common.log(f'startup selector confirmed on manager-expected {expected}')
            return

        if not current_running:
            return

        with self.lock:
            previous_slot_tag = self.active_slot_tag
            current_slot = self.slots[current]
            self.record_outbound_change(self.slots[previous_slot_tag].candidate, current_slot.candidate)
            self.active_slot_tag = current
            self.active_candidate_id = current_slot.candidate_id
            current_slot.draining = False
            current_slot.drain_started_at = None
            current_slot.drain_zero_since = None
            current_slot.drain_protect_until = None
            current_slot.drain_degraded_checks = 0
            current_slot.drain_last_latency_ms = None
            current_slot.drain_last_checked_at = None
            current_slot.drain_new_connections = 0
            current_slot.drain_stalled_connections = 0
            current_slot.drain_known_connection_ids.clear()
            current_slot.drain_connection_bytes.clear()
            current_slot.drain_idle_polls.clear()
            self.selector_reconciliation_pending = False
            self.switch_generation += 1
            self.save_state()
        candidate = self.candidate_by_id(current_slot.candidate_id)
        if candidate:
            try:
                self.save_active_config(current, candidate)
            except Exception as exc:
                xpm_common.log(f'could not save adopted selector config: {exc}', error=True)
        xpm_common.log(
            f'adopted live selector slot {current} only because manager-expected '
            f'{previous_slot_tag} was not running',
            error=True,
        )

    def restore_selector_alignment(self, reported_current: str, *, force_confirmation: bool = False) -> None:
        with self.lock:
            expected = self.active_slot_tag
            expected_running = self.slots[expected].running()
        if (reported_current == expected and not force_confirmation) or self.switch_lock.locked():
            return
        if not self.switch_lock.acquire(blocking=False):
            return
        try:
            current = self.selector_status()
            with self.lock:
                expected = self.active_slot_tag
                expected_running = self.slots[expected].running()
                current_running = self.slots[current].running()
            if current == expected:
                if force_confirmation and expected_running:
                    self.switch_selector(expected)
                return
            if expected_running:
                self.switch_selector(expected)
                xpm_common.log(f'Selector unexpectedly reported {current}; restored {expected}', error=True)
                return
            if current_running:
                with self.lock:
                    current_slot = self.slots[current]
                    self.record_outbound_change(self.slots[expected].candidate, current_slot.candidate)
                    self.active_slot_tag = current
                    self.active_candidate_id = current_slot.candidate_id
                    current_slot.draining = False
                    current_slot.drain_started_at = None
                    current_slot.drain_zero_since = None
                    current_slot.drain_protect_until = None
                    current_slot.drain_degraded_checks = 0
                    current_slot.drain_last_latency_ms = None
                    current_slot.drain_last_checked_at = None
                    current_slot.drain_new_connections = 0
                    current_slot.drain_stalled_connections = 0
                    current_slot.drain_known_connection_ids.clear()
                    current_slot.drain_connection_bytes.clear()
                    current_slot.drain_idle_polls.clear()
                    self.switch_generation += 1
                    self.save_state()
                candidate = self.candidate_by_id(self.active_candidate_id)
                if candidate:
                    try:
                        self.save_active_config(current, candidate)
                    except Exception as exc:
                        xpm_common.log(f'could not save adopted selector config: {exc}', error=True)
                xpm_common.log(f'adopted live selector slot {current} because {expected} was not running', error=True)
        except Exception as exc:
            xpm_common.log(f'could not reconcile selector state: {exc}', error=True)
        finally:
            self.switch_lock.release()

    def refresh_selector_status(self) -> None:
        if not self.selector_control_enabled:
            with self.lock:
                self.selector_state.update({
                    'configured': False,
                    'available': False,
                    'current': '',
                    'error': 'Управление selector отключено',
                    'connections_supported': False,
                    'last_checked_at': xpm_common.now_ts(),
                })
            return
        with self.lock:
            was_available = bool(self.selector_state.get('available'))
            first_check = self.selector_state.get('last_checked_at') is None
        try:
            current = self.selector_status()
        except Exception as exc:
            with self.lock:
                self.selector_state.update({
                    'configured': True,
                    'available': False,
                    'error': str(exc),
                    'connections_supported': False,
                    'last_checked_at': xpm_common.now_ts(),
                })
            if was_available or first_check:
                xpm_common.log(
                    f'Selector API unavailable; retry interval reduced to 1 second: {exc}',
                    error=True,
                )
            else:
                self.debug_log(f'Selector API still unavailable: {exc}')
            return

        with self.lock:
            need_connections_check = (
                not bool(self.selector_state.get('connections_supported'))
                or any(slot.draining for slot in self.slots.values())
            )
            self.selector_state.update({
                'configured': True,
                'available': True,
                'current': current,
                'error': '',
                'last_checked_at': xpm_common.now_ts(),
            })
        if not was_available:
            xpm_common.log(f'Selector API connection restored; reported active slot is {current}')
        self.reconcile_startup_selector(current)
        switch_in_progress = self.switch_lock.locked()
        if not self.selector_reconciliation_pending and not switch_in_progress:
            self.restore_selector_alignment(current, force_confirmation=not was_available)
        elif switch_in_progress:
            self.debug_log(
                'Selector reconciliation deferred because an outbound switch is in progress'
            )
        if not was_available and not switch_in_progress:
            with self.lock:
                expected = self.active_slot_tag
                draining = next(
                    (tag for tag in xpm_common.SLOT_TAGS if self.slots[tag].draining),
                    None,
                )
        if not need_connections_check:
            return

        try:
            self.selector_connections()
            with self.lock:
                self.selector_state['connections_supported'] = True
        except Exception as exc:
            with self.lock:
                self.selector_state.update({
                    'connections_supported': False,
                    'error': f'Selector API connection tracking unavailable: {exc}',
                })

    def selector_status_wait_seconds(self) -> int:
        with self.lock:
            urgent = self.selector_control_enabled and (
                any(slot.draining for slot in self.slots.values())
                or not bool(self.selector_state.get('available'))
            )
        return 1 if urgent else self.selector_status_interval_seconds

    def selector_status_loop(self) -> None:
        while not self.stop_event.is_set():
            self.refresh_selector_status()
            if self.stop_event.wait(self.selector_status_wait_seconds()):
                break
