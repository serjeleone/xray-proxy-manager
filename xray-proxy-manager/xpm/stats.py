from __future__ import annotations

import copy
import json
import subprocess
import time
from typing import Any
from . import common as xpm_common


class StatsMixin:
    def update_active_throughput(
        self,
        slot_tag: str,
        download_bytes: int,
        sampled_at: float | None = None,
        *,
        source: str = 'xray',
    ) -> dict[str, Any]:
        sample_time = time.monotonic() if sampled_at is None else float(sampled_at)
        current_bytes = max(0, int(download_bytes))
        with self.lock:
            process = self.slots[slot_tag].process
            same_slot = (
                self._throughput_last_slot == slot_tag
                and getattr(self, '_throughput_last_process', None) is process
                and self.throughput_state.get('source') == source
                and self._throughput_last_generation == self.switch_generation
            )
            previous_at = self._throughput_last_sample_at
            previous_bytes = getattr(self, '_throughput_download_bytes', 0)
            bytes_per_second = 0.0
            if same_slot and previous_at is not None and sample_time > previous_at and current_bytes >= previous_bytes:
                bytes_per_second = (current_bytes - previous_bytes) / (sample_time - previous_at)

            self._throughput_last_slot = slot_tag
            self._throughput_last_process = process
            self._throughput_last_sample_at = sample_time
            self._throughput_download_bytes = current_bytes
            self._throughput_last_generation = self.switch_generation
            if self.throughput_state.get('error'):
                xpm_common.log(f'throughput stats recovered for {slot_tag} ({source})')
            self.throughput_state.update({
                'available': True,
                'slot': slot_tag,
                'source': source,
                'bytes_per_second': bytes_per_second,
                'megabytes_per_second': bytes_per_second / 1_000_000,
                'updated_at': xpm_common.now_ts(),
                'error': '',
            })
            return copy.deepcopy(self.throughput_state)

    def reset_active_throughput(self, slot_tag: str = '', error: str = '') -> None:
        with self.lock:
            self._throughput_last_slot = slot_tag
            self._throughput_last_sample_at = None
            self._throughput_download_bytes = 0
            self._throughput_last_process = None
            self._throughput_last_generation = None
            self._throughput_connection_download_bytes = {}
            self.throughput_state.update({
                'available': False,
                'slot': slot_tag,
                'source': '',
                'bytes_per_second': 0.0,
                'megabytes_per_second': 0.0,
                'updated_at': xpm_common.now_ts(),
                'error': error,
            })

    def update_selector_throughput(
        self,
        slot_tag: str,
        connections: list[dict[str, Any]],
        sampled_at: float | None = None,
    ) -> dict[str, Any]:
        current = {
            connection_id: self.connection_download_bytes(item)
            for item in self.connections_for_slot(connections, slot_tag)
            if (connection_id := self.connection_id(item))
        }
        with self.lock:
            same_source = (
                self.throughput_state.get('source') == 'selector'
                and self._throughput_last_slot == slot_tag
                and self._throughput_last_process is self.slots[slot_tag].process
                and self._throughput_last_generation == self.switch_generation
            )
            previous = self._throughput_connection_download_bytes if same_source else {}
            # Keep a cumulative sample when completed connections disappear.
            # Only each connection's download delta counts; uploads and the
            # other (possibly draining) slot must not affect the badge.
            transferred = sum(
                value - previous[key] if key in previous and value >= previous[key] else value
                for key, value in current.items()
            )
            total = self._throughput_download_bytes + transferred if same_source else sum(current.values())
            self._throughput_connection_download_bytes = current
            return self.update_active_throughput(slot_tag, total, sampled_at, source='selector')

    def refresh_active_throughput(self) -> None:
        with self.lock:
            slot_tag = self.active_slot_tag
            slot = self.slots[slot_tag]
            process = slot.process
            slot_running = slot.running()
            generation = self.switch_generation
            use_selector = self.selector_control_enabled
            if not slot_running:
                self.reset_active_throughput(slot_tag, 'Активный Xray-слот не работает')
                return

        try:
            if use_selector:
                # Xray 26.9.9 adds splice bytes to inbound, outbound AND user
                # StatsService counters only after TCP ReadFrom returns. A
                # long Vision/video flow therefore looks idle until it closes.
                # The selector counts bytes as it forwards them, as in v0.9.3.
                connections = self.selector_connections(timeout=2)
                with self.lock:
                    if (self.active_slot_tag == slot_tag and slot.process is process
                            and self.switch_generation == generation
                            and self.selector_control_enabled == use_selector):
                        self.update_selector_throughput(slot_tag, connections)
                return

            # The bundled CLI uses the core's local gRPC StatsService. Inbound
            # counters count the selected slot once, including closed flows,
            # without double-counting chained outbounds. Do not reset them.
            result = subprocess.run([
                xpm_common.XRAY_BIN, 'api', 'statsquery', f'--server=127.0.0.1:{slot.stats_port}',
                '-timeout', '3', '-pattern', 'inbound>>>socks>>>traffic>>>downlink', '-reset=false',
            ], capture_output=True, text=True, timeout=4)
            if result.returncode != 0:
                detail = (result.stderr or result.stdout).strip().splitlines()
                raise RuntimeError(detail[-1][:300] if detail else f'Xray stats exit code {result.returncode}')
            payload = json.loads(result.stdout)
            counters = [
                max(0, int(item.get('value', 0))) for item in (payload.get('stat') or [])
                if item.get('name') == 'inbound>>>socks>>>traffic>>>downlink'
            ]
            if not counters:
                raise RuntimeError('Xray SOCKS downlink counter is missing')
            download_bytes = sum(counters)
            with self.lock:
                if (self.active_slot_tag == slot_tag and slot.process is process
                        and self.switch_generation == generation
                        and self.selector_control_enabled == use_selector):
                    self.update_active_throughput(slot_tag, download_bytes)
        except Exception as exc:
            with self.lock:
                if (self.active_slot_tag == slot_tag and slot.process is process
                        and self.switch_generation == generation
                        and self.selector_control_enabled == use_selector):
                    source_name = 'selector' if use_selector else 'Xray'
                    if not self.throughput_state.get('error'):
                        xpm_common.log(f'throughput stats unavailable for {slot_tag} ({source_name}): {exc}', error=True)
                    self.reset_active_throughput(slot_tag, f'Статистика {source_name} временно недоступна')

    def active_throughput_loop(self) -> None:
        while not self.stop_event.is_set():
            started = time.monotonic()
            self.refresh_active_throughput()
            elapsed = time.monotonic() - started
            if self.stop_event.wait(max(0.0, 1.0 - elapsed)):
                break

    def throughput_payload(self) -> dict[str, Any]:
        with self.lock:
            return copy.deepcopy(self.throughput_state)
