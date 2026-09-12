from __future__ import annotations

from pathlib import Path
from typing import Any
from . import common as xpm_common


class DrainMixin:
    def force_stop_draining_slot(self, slot_tag: str = '') -> str:
        if not self.switch_lock.acquire(blocking=False):
            raise RuntimeError('Переключение outbound уже выполняется')
        try:
            with self.lock:
                targets = [slot_tag] if slot_tag else [
                    tag for tag in xpm_common.SLOT_TAGS if self.slots[tag].draining
                ]
                if len(targets) != 1 or targets[0] not in xpm_common.SLOT_TAGS:
                    raise ValueError('Дренируемый слот не найден')
                target = targets[0]
                slot = self.slots[target]
                if target == self.active_slot_tag:
                    raise RuntimeError('Активный слот нельзя завершить принудительно')
                if not slot.draining:
                    raise RuntimeError(f'{target} не находится в состоянии дренирования')
                connections = slot.drain_connections
            xpm_common.log(f'force-stopping drained slot {target} with {connections} tracked connections', error=True)
            self.stop_slot(target)
            return target
        finally:
            self.switch_lock.release()

    def local_tcp_connection_count(self, port: int) -> int:
        target = f'{port:04X}'
        count = 0
        for path in (Path('/proc/net/tcp'), Path('/proc/net/tcp6')):
            try:
                lines = path.read_text(encoding='utf-8').splitlines()[1:]
            except OSError:
                continue
            for line in lines:
                fields = line.split()
                if len(fields) < 4:
                    continue
                local = fields[1]
                state = fields[3]
                if ':' not in local or local.rsplit(':', 1)[1].upper() != target:
                    continue
                # TIME_WAIT and CLOSED no longer belong to a live Xray flow and
                # must not keep a drained process running. Other states still
                # represent a connection being established, served, or closed.
                if state not in {'06', '07', '0A'}:
                    count += 1
        return count

    def drain_monitor_loop(self) -> None:
        while not self.stop_event.wait(self.drain_poll_interval_seconds):
            with self.lock:
                draining_tags = [tag for tag in xpm_common.SLOT_TAGS if self.slots[tag].draining]
            if not draining_tags:
                continue
            try:
                connections = self.selector_connections()
                with self.lock:
                    self.selector_state.update({
                        'connections_supported': True,
                        'error': '',
                    })
            except Exception as exc:
                with self.lock:
                    self.selector_state.update({
                        'connections_supported': False,
                        'error': str(exc),
                    })
                    for tag in draining_tags:
                        self.slots[tag].drain_last_error = str(exc)
                continue

            for slot_tag in draining_tags:
                if not self.switch_lock.acquire(blocking=False):
                    continue
                try:
                    slot = self.slots[slot_tag]
                    if slot.draining and slot_tag != self.active_slot_tag:
                        self.update_draining_slot(slot_tag, connections)
                finally:
                    self.switch_lock.release()

    def update_draining_slot(self, slot_tag: str, connections: list[dict[str, Any]]) -> None:
        slot = self.slots[slot_tag]
        slot_connections = self.connections_for_slot(connections, slot_tag)
        selector_count, _tcp_count, udp_count, selector_bytes = self.connection_slot_stats(
            connections, slot_tag
        )
        direct_tcp_count = self.local_tcp_connection_count(slot.socks_tcp)
        # /proc/net/tcp already contains every TCP connection accepted
        # by this SOCKS slot, including connections created by the
        # selector. Add only logical UDP sessions from the selector API
        # to avoid counting selector TCP connections twice.
        total_connections = direct_tcp_count + udp_count
        total_bytes = selector_bytes
        current_ids = {
            self.connection_id(item) for item in slot_connections
            if self.connection_id(item)
        }
        current_byte_map = {
            self.connection_id(item): self.connection_total_bytes(item)
            for item in slot_connections if self.connection_id(item)
        }
        with self.lock:
            known_ids = set(slot.drain_known_connection_ids)
            previous_byte_map = dict(slot.drain_connection_bytes)
            previous_idle = dict(slot.drain_idle_polls)
        new_ids = current_ids - known_ids
        if new_ids:
            new_items = [
                item for item in slot_connections
                if self.connection_id(item) in new_ids
            ]
            with self.lock:
                slot.drain_new_connections += len(new_ids)
                slot.drain_known_connection_ids.update(new_ids)
            xpm_common.log(
                f'WARNING: {slot_tag} accepted {len(new_ids)} new selector connection(s) '
                f'while draining; expected active slot is {self.active_slot_tag}',
                error=True,
            )
            for item in new_items[:10]:
                xpm_common.log(
                    f'{slot_tag} new connection while draining: '
                    f'{self.connection_summary(item)}',
                    error=True,
                )

        idle_polls: dict[str, int] = {}
        for connection_id in current_ids:
            current_bytes = current_byte_map.get(connection_id, 0)
            if previous_byte_map.get(connection_id) == current_bytes:
                idle_polls[connection_id] = previous_idle.get(connection_id, 0) + 1
            else:
                idle_polls[connection_id] = 0
        stalled_ids = {
            connection_id for connection_id, polls in idle_polls.items()
            if polls * self.drain_poll_interval_seconds >= 10
        }

        current_time = xpm_common.now_ts()
        drain_started_at = int(slot.drain_started_at or current_time)
        drain_elapsed = max(0, current_time - drain_started_at)
        preset_close_ids: set[str] = set()
        preset_close_reason = ''
        if self.switching_preset == 'forced':
            # The first close attempt happens immediately after the selector
            # switch. Repeating it here handles races and temporary API errors.
            preset_close_ids = set(current_ids)
            preset_close_reason = 'forced switching preset'
        elif (
            self.switching_preset == 'adaptive'
            and drain_elapsed >= xpm_common.ADAPTIVE_DRAIN_GRACE_SECONDS
        ):
            preset_close_ids = {
                connection_id for connection_id, polls in idle_polls.items()
                if polls >= xpm_common.ADAPTIVE_DRAIN_IDLE_POLLS
            }
            preset_close_reason = 'adaptive switching preset'
        if preset_close_ids:
            self.close_slot_selector_connections(
                slot_tag,
                preset_close_ids,
                reason=preset_close_reason,
            )

        stop_now = False
        info_due = False
        with self.lock:
            previous_bytes = slot.drain_bytes
            slot.drain_connections = total_connections
            slot.drain_tcp_connections = direct_tcp_count
            slot.drain_udp_connections = udp_count
            slot.drain_bytes = total_bytes
            slot.drain_last_error = ''
            slot.drain_connection_bytes = current_byte_map
            slot.drain_idle_polls = idle_polls
            slot.drain_stalled_connections = len(stalled_ids)
            slot.drain_known_connection_ids.update(current_ids)
            configured_timeout_reached = bool(
                self.drain_timeout_minutes > 0
                and slot.drain_started_at
                and current_time - slot.drain_started_at >= self.drain_timeout_minutes * 60
            )
            adaptive_timeout_reached = bool(
                self.switching_preset == 'adaptive'
                and slot.drain_started_at
                and current_time - slot.drain_started_at
                >= xpm_common.ADAPTIVE_DRAIN_HARD_TIMEOUT_SECONDS
            )
            if configured_timeout_reached or adaptive_timeout_reached:
                stop_now = True
            elif total_connections == 0 and total_bytes == previous_bytes:
                if slot.drain_zero_since is None:
                    slot.drain_zero_since = current_time
                elif (
                    current_time - slot.drain_zero_since >= self.drain_quiet_seconds
                    and current_time >= int(slot.drain_protect_until or 0)
                ):
                    stop_now = True
            else:
                slot.drain_zero_since = None
            info_due = (
                slot.drain_last_info_at is None
                or current_time - slot.drain_last_info_at >= 30
                or slot.drain_last_info_connections != total_connections
                or total_connections == 0
            )
            if info_due:
                slot.drain_last_info_at = current_time
                slot.drain_last_info_connections = total_connections

        if info_due:
            xpm_common.log(
                f'{slot_tag} draining: tracked={total_connections} '
                f'(tcp={direct_tcp_count}, udp={udp_count}, selector={selector_count}), '
                f'bytes={total_bytes}, stalled>=10s={len(stalled_ids)}, '
                f'new-after-switch={slot.drain_new_connections}'
            )
        if self.log_level == 'debug':
            for item in slot_connections[:10]:
                marker = ' stalled' if self.connection_id(item) in stalled_ids else ''
                self.debug_log(
                    f'{slot_tag} draining connection{marker}: {self.connection_summary(item)}'
                )

        if stop_now:
            adaptive_deadline = bool(
                self.switching_preset == 'adaptive'
                and slot.drain_started_at
                and xpm_common.now_ts() - slot.drain_started_at
                >= xpm_common.ADAPTIVE_DRAIN_HARD_TIMEOUT_SECONDS
            )
            configured_deadline = bool(
                self.drain_timeout_minutes > 0
                and slot.drain_started_at
                and xpm_common.now_ts() - slot.drain_started_at >= self.drain_timeout_minutes * 60
            )
            if adaptive_deadline:
                xpm_common.log(
                    f'{slot_tag} adaptive drain deadline of '
                    f'{xpm_common.ADAPTIVE_DRAIN_HARD_TIMEOUT_SECONDS}s reached; forcing slot stop '
                    f'with {slot.drain_connections} tracked connections',
                    error=True,
                )
            elif configured_deadline:
                xpm_common.log(
                    f'{slot_tag} drain timeout of {self.drain_timeout_minutes} min reached; '
                    f'forcing slot stop with {slot.drain_connections} tracked connections',
                    error=True,
                )
            else:
                xpm_common.log(
                    f'{slot_tag} has no tracked connections or traffic for '
                    f'{self.drain_quiet_seconds}s; stopping drained slot'
                )
            self.stop_slot(slot_tag)

    def handle_draining_full_scan_results(
        self,
        fresh_results: dict[str, dict[str, Any]],
    ) -> None:
        """Stop a draining slot after repeated unavailable checks.

        The same ``auto_check_failures`` threshold is used by the active-slot
        checker and by draining slots. Every completed latency test counts,
        including a test of one outbound. A successful result resets the
        counter. Once the threshold is reached, the draining process is stopped
        regardless of how many old connections it still reports, because the
        slot itself is no longer reachable.
        """
        to_stop: list[tuple[str, int, int, str]] = []
        with self.lock:
            for slot_tag in xpm_common.SLOT_TAGS:
                slot = self.slots[slot_tag]
                if not slot.running() or not slot.draining:
                    slot.drain_degraded_checks = 0
                    slot.drain_last_latency_ms = None
                    slot.drain_last_checked_at = None
                    continue

                current_candidate = next(
                    (
                        candidate for candidate in self.candidates
                        if self.same_outbound(candidate, slot.candidate)
                    ),
                    None,
                )
                result_id = (
                    current_candidate.id if current_candidate is not None
                    else self.slot_candidate_id(slot_tag)
                )
                if not result_id:
                    continue

                result = fresh_results.get(result_id)
                if not isinstance(result, dict):
                    continue

                checked_at = int(result.get('checked_at') or xpm_common.now_ts())
                latency_value = result.get('latency_ms')
                latency_ms = latency_value if isinstance(latency_value, int) else None
                unavailable = result.get('status') != 'ok'
                slot.drain_last_latency_ms = latency_ms
                slot.drain_last_checked_at = checked_at
                if unavailable:
                    slot.drain_degraded_checks += 1
                else:
                    slot.drain_degraded_checks = 0

                if slot.drain_degraded_checks < self.auto_check_failures:
                    continue

                reason = str(result.get('error') or 'outbound is unavailable')
                to_stop.append((
                    slot_tag,
                    slot.drain_degraded_checks,
                    slot.drain_connections,
                    reason,
                ))

        for slot_tag, failures, connections, reason in to_stop:
            with self.lock:
                slot = self.slots[slot_tag]
                can_stop = (
                    slot.running()
                    and slot.draining
                    and slot.drain_degraded_checks >= self.auto_check_failures
                )
            if not can_stop:
                continue
            xpm_common.log(
                f'{slot_tag} remained unavailable for {failures} consecutive checks '
                f'with {connections} tracked connection(s) ({reason}); '
                'force-stopping drained slot',
                error=True,
            )
            try:
                self.force_stop_draining_slot(slot_tag)
            except Exception as exc:
                xpm_common.log(f'could not stop unavailable drained slot {slot_tag}: {exc}', error=True)

    def check_draining_slots_health(self) -> None:
        """Probe every draining slot independently of subscription contents."""
        with self.lock:
            if self.state['jobs']['latency'].get('running'):
                return
            targets = []
            for slot_tag in xpm_common.SLOT_TAGS:
                slot = self.slots[slot_tag]
                target_id = slot.candidate_id or (
                    slot.candidate.id if slot.candidate is not None else ''
                )
                if slot.running() and slot.draining and target_id:
                    targets.append((slot_tag, target_id))
                    self.latency_checking_ids.add(target_id)

        for slot_tag, target_id in targets:
            try:
                result = self.test_running_slot_for_full_scan(slot_tag)
            except Exception as exc:
                result = {
                    'status': 'error',
                    'latency_ms': None,
                    'checked_at': xpm_common.now_ts(),
                    'error': str(exc)[-500:],
                }
            with self.lock:
                self.latencies[target_id] = result
                self.latency_checking_ids.discard(target_id)
                self.save_latencies()
            self.handle_draining_full_scan_results({target_id: result})
