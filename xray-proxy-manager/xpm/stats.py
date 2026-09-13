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
    ) -> dict[str, Any]:
        sample_time = time.monotonic() if sampled_at is None else float(sampled_at)
        current_bytes = max(0, int(download_bytes))
        with self.lock:
            process = self.slots[slot_tag].process
            same_slot = (
                self._throughput_last_slot == slot_tag
                and getattr(self, '_throughput_last_process', None) is process
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
            self.throughput_state.update({
                'available': True,
                'slot': slot_tag,
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
            self.throughput_state.update({
                'available': False,
                'slot': slot_tag,
                'bytes_per_second': 0.0,
                'megabytes_per_second': 0.0,
                'updated_at': xpm_common.now_ts(),
                'error': error,
            })

    def refresh_active_throughput(self) -> None:
        with self.lock:
            slot_tag = self.active_slot_tag
            slot = self.slots[slot_tag]
            process = slot.process
            slot_running = slot.running()
        if not slot_running:
            self.reset_active_throughput(slot_tag, 'Активный Xray-слот не работает')
            return

        try:
            # The bundled CLI uses the core's local gRPC StatsService. Inbound
            # counters count each SOCKS payload once, including closed flows.
            result = subprocess.run([
                xpm_common.XRAY_BIN, 'api', 'statsquery', f'--server=127.0.0.1:{slot.stats_port}',
                '-timeout', '3', '-pattern', 'inbound>>>socks>>>traffic>>>downlink',
            ], capture_output=True, text=True, timeout=4)
            if result.returncode != 0:
                detail = (result.stderr or result.stdout).strip().splitlines()
                raise RuntimeError(detail[-1][:300] if detail else f'Xray stats exit code {result.returncode}')
            payload = json.loads(result.stdout)
            download_bytes = sum(
                max(0, int(item.get('value', 0))) for item in (payload.get('stat') or [])
                if item.get('name') == 'inbound>>>socks>>>traffic>>>downlink'
            )
            with self.lock:
                if self.active_slot_tag == slot_tag and slot.process is process:
                    if self.throughput_state.get('error'):
                        xpm_common.log(f'Xray throughput stats recovered for {slot_tag}')
                    self.update_active_throughput(slot_tag, download_bytes)
        except Exception as exc:
            with self.lock:
                if self.active_slot_tag == slot_tag and slot.process is process:
                    if not self.throughput_state.get('error'):
                        xpm_common.log(f'Xray throughput stats unavailable for {slot_tag}: {exc}', error=True)
                    self.reset_active_throughput(slot_tag, 'Статистика Xray временно недоступна')

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
