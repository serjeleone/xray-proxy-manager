from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Any
from . import common as xpm_common, errors as xpm_errors, models as xpm_models, persistence as xpm_persistence


class SwitchingMixin:
    def set_slot_mode(self, dual_slot_enabled: bool) -> dict[str, Any]:
        desired_mode = bool(dual_slot_enabled)
        with self.lock:
            if desired_mode == self.dual_slot_enabled:
                return {'ok': True, 'dual_slot_enabled': desired_mode, 'changed': False}
            current_slot_tag = self.active_slot_tag
            previous_candidate = (
                self.slots[current_slot_tag].candidate
                or self.candidate_by_id(self.active_candidate_id)
            )
            current_candidate = self.candidate_by_id(self.active_candidate_id) or previous_candidate
            if current_candidate is None:
                current_candidate = self.choose_initial_candidate()
            previous_mode = self.dual_slot_enabled
            previous_slot_tag = self.active_slot_tag

        if not self.switch_lock.acquire(blocking=False):
            raise RuntimeError('Переключение режима уже выполняется')
        try:
            with self.lock:
                # Invalidate watchers and in-flight health checks before any
                # process is stopped. Repeated 2 -> 1 -> 2 transitions must not
                # inherit a watcher from the previous two-slot session.
                self.switch_generation += 1
                self.manual_generation = getattr(self, 'manual_generation', 0) + 1
                self.options['dual_slot_enabled'] = desired_mode
                self.state['jobs']['switch'].update({
                    'running': True,
                    'message': 'Перезапуск Xray для смены режима...',
                })
                self.save_state()
            self.stop_xray()
            with self.lock:
                self.dual_slot_enabled = desired_mode
                self.active_slot_tag = 'xray-a'
                self.active_candidate_id = current_candidate.id
            self.log_switch_request(
                current_candidate,
                'slot_mode_ui',
                'slot mode changed from UI',
            )
            self.start_initial_candidate(
                current_candidate,
                'slot mode changed from UI',
                source='slot_mode_ui',
            )

            with self.lock:
                self.options['dual_slot_enabled'] = desired_mode
                runtime_options = xpm_persistence.load_json(xpm_common.RUNTIME_OPTIONS_PATH, {})
                if not isinstance(runtime_options, dict):
                    runtime_options = {}
                base_options = xpm_persistence.load_json(xpm_common.OPTIONS_PATH, {})
                runtime_options.setdefault('_base_options', {}).setdefault(
                    'dual_slot_enabled', base_options.get('dual_slot_enabled', previous_mode),
                )
                runtime_options['dual_slot_enabled'] = desired_mode
                xpm_persistence.atomic_write_json(xpm_common.RUNTIME_OPTIONS_PATH, runtime_options)
                self.save_state()
            supervisor_synced, supervisor_error = self.sync_supervisor_options({'dual_slot_enabled': desired_mode})
            xpm_common.log(
                'Xray slot mode changed to '
                f'{"dual-slot" if desired_mode else "single-slot"}; processes restarted'
            )
            return {
                'ok': True,
                'dual_slot_enabled': desired_mode,
                'changed': True,
                'supervisor_synced': supervisor_synced,
                'supervisor_error': supervisor_error,
            }
        except Exception:
            try:
                self.stop_xray()
                with self.lock:
                    self.dual_slot_enabled = previous_mode
                    self.options['dual_slot_enabled'] = previous_mode
                    self.active_slot_tag = (
                        previous_slot_tag
                        if previous_mode and previous_slot_tag in xpm_common.SLOT_TAGS
                        else 'xray-a'
                    )
                    self.active_candidate_id = current_candidate.id
                self.log_switch_request(
                    current_candidate,
                    'slot_mode_rollback',
                    'rollback after failed slot mode change',
                )
                self.start_initial_candidate(
                    previous_candidate or current_candidate,
                    'rollback after failed slot mode change',
                    source='slot_mode_rollback',
                )
            except Exception as rollback_exc:
                xpm_common.log(f'could not restore previous slot mode: {rollback_exc}', error=True)
            raise
        finally:
            try:
                with self.lock:
                    self.state['jobs']['switch'].update({'running': False, 'message': ''})
                    self.save_state()
            finally:
                self.switch_lock.release()

    def ensure_switch_allowed(self, source: str, expected_manual_generation: int | None = None) -> None:
        if source in {'auto_check_failover', 'auto_best_check', 'startup_scan', 'manual_scan', 'preference_ui'} and not (
            self.auto_checker_enabled and self.auto_switch_best_enabled
        ):
            raise xpm_errors.SwitchCancelled('Автопереключение отключено')
        if (expected_manual_generation is not None
                and expected_manual_generation != getattr(self, 'manual_generation', 0)):
            raise xpm_errors.SwitchCancelled('Выбор изменён вручную')

    @staticmethod
    def switch_source_for_latency_job(source: str) -> str:
        return {
            'manual': 'manual_scan',
            'auto-best': 'auto_best_check',
            'startup': 'startup_scan',
            'preferred-selection': 'preference_ui',
            'preferred-country': 'preference_ui',
            'preferred-protocol': 'preference_ui',
        }.get(source, source or 'internal')

    def log_switch_request(
        self,
        candidate: xpm_models.Candidate,
        source: str,
        reason: str,
    ) -> None:
        mode = 'dual' if self.dual_slot_enabled else 'single'
        xpm_common.log(
            f'switch requested: source={source}; mode={mode}; '
            f'target={candidate.name} [{candidate.outbound_tag}]; reason={reason}'
        )

    def start_initial_candidate(
        self,
        candidate: xpm_models.Candidate,
        reason: str,
        *,
        source: str = 'internal',
        expected_manual_generation: int | None = None,
    ) -> None:
        expected_slot = self.active_slot_tag if self.dual_slot_enabled else 'xray-a'
        if expected_slot not in xpm_common.SLOT_TAGS:
            expected_slot = 'xray-a'
        self.active_slot_tag = expected_slot
        started_slots: list[str] = []
        try:
            self.start_slot(expected_slot, candidate)
            started_slots.append(expected_slot)
            initial_latency, initial_checks = self.validate_slot(
                expected_slot,
                enforce_latency_limit=False,
            )
            xpm_common.log(
                f'initial {expected_slot} validation: '
                + self.format_probe_results(initial_checks)
                + f'; fastest={initial_latency:.0f}ms'
            )
            if (
                self.auto_check_max_latency_ms > 0
                and initial_latency > self.auto_check_max_latency_ms
            ):
                xpm_common.log(
                    f'initial active slot latency {initial_latency:.0f}ms exceeds '
                    f'{self.auto_check_max_latency_ms}ms; automatic failover will be attempted',
                    error=True,
                )

            self.ensure_switch_allowed(source, expected_manual_generation)
            if self.selector_control_enabled:
                try:
                    reported = self.selector_status()
                    if reported != expected_slot:
                        self.switch_selector(expected_slot)
                        xpm_common.log(
                            f'startup restored selector from {reported} to manager-expected '
                            f'{expected_slot}',
                            error=True,
                        )
                    self.selector_reconciliation_pending = False
                    with self.lock:
                        self.selector_state.update({
                            'available': True,
                            'current': expected_slot,
                            'error': '',
                        })
                except Exception as exc:
                    self.selector_reconciliation_pending = True
                    xpm_common.log(
                        f'Selector is unavailable during startup; manager keeps '
                        f'{expected_slot} as the expected slot: {exc}',
                        error=True,
                    )
                    with self.lock:
                        self.selector_state.update({
                            'available': False,
                            'error': str(exc),
                        })

            self.active_candidate_id = candidate.id
            self.state['last_switch_at'] = xpm_common.now_ts()
            self.state['last_switch_reason'] = reason
            self.state['last_switch_source'] = source
            self.state['auto_check_failures'] = 0
            self.state['auto_check_last_error'] = ''
            self.latencies[candidate.id] = {
                'status': 'ok',
                'latency_ms': int(round(initial_latency)),
                'checked_at': xpm_common.now_ts(),
                'error': '',
            }
            try:
                self.save_latencies()
                self.save_state()
            except Exception as exc:
                xpm_common.log(f'could not persist initial active state: {exc}', error=True)
            try:
                self.save_active_config(expected_slot, candidate)
            except Exception as exc:
                xpm_common.log(f'could not save last-good active config: {exc}', error=True)
            xpm_common.log(
                f'active outbound: {candidate.name} [{candidate.outbound_tag}] via {expected_slot}; '
                f'source={source}'
            )
        except Exception:
            for slot_tag in reversed(started_slots):
                self.stop_slot(slot_tag)
            raise

    def switch_candidate_blue_green(
        self,
        candidate: xpm_models.Candidate,
        reason: str,
        *,
        source: str = 'internal',
        force_reload: bool = False,
        preempt_draining: bool = False,
        emergency_failover: bool = False,
        expected_manual_generation: int | None = None,
    ) -> None:
        if not self.dual_slot_enabled:
            raise RuntimeError('Blue-green switching is disabled in single-slot mode')
        if not self.selector_control_enabled:
            raise RuntimeError('Blue-green переключение требует доступного внешнего selector')
        try:
            reported_selector = self.selector_status()
        except Exception as exc:
            raise RuntimeError(
                f'Selector API недоступен; переключение не начато: {exc}'
            ) from exc
        if self.selector_reconciliation_pending:
            self.reconcile_startup_selector(reported_selector)
        if not self.switch_lock.acquire(blocking=False):
            raise RuntimeError('Переключение outbound уже выполняется')
        standby_tag = ''
        old_slot_tag = ''
        selector_switched = False
        state_committed = False
        try:
            current_selector = self.selector_status()
            with self.lock:
                expected_selector = self.active_slot_tag
                expected_running = self.slots[expected_selector].running()
            if current_selector != expected_selector:
                if not expected_running:
                    raise RuntimeError(
                        f'Активный слот {expected_selector} не запущен, а selector указывает '
                        f'на {current_selector}'
                    )
                self.switch_selector(expected_selector)
                xpm_common.log(
                    f'Selector был на {current_selector}; перед переключением '
                    f'восстановлен {expected_selector}',
                    error=True,
                )
            with self.lock:
                self.state['jobs']['switch'].update({
                    'running': True,
                    'message': f'Подготовка {candidate.name}...',
                })
                self.save_state()
                active_slot = self.slots[self.active_slot_tag]
                active_candidate = active_slot.candidate or self.candidate_by_id(self.active_candidate_id)
                if active_slot.running() and self.same_outbound(candidate, active_candidate) and not force_reload:
                    return
                old_slot_tag = self.active_slot_tag
                standby_tag = self.other_slot_tag(old_slot_tag)
                standby = self.slots[standby_tag]
                stop_standby = False
                standby_needs_rebuild = (
                    standby.running()
                    and (
                        not self.same_outbound(candidate, standby.candidate)
                        or force_reload
                    )
                )
                if standby_needs_rebuild:
                    if standby.draining and not preempt_draining:
                        raise RuntimeError(
                            f'{standby_tag} ещё обслуживает старые соединения '
                            f'({standby.drain_connections}); автоматическое переключение отложено'
                        )
                    stop_standby = True

            if stop_standby:
                self.stop_slot(standby_tag)
            standby = self.slots[standby_tag]
            if not standby.running():
                self.start_slot(standby_tag, candidate)
            elif not self.same_outbound(candidate, standby.candidate):
                raise RuntimeError(f'{standby_tag} занят другим outbound')

            with self.lock:
                self.state['jobs']['switch']['message'] = f'Проверка {candidate.name}...'
                self.save_state()
            measured_latency, checks = self.validate_slot(standby_tag)
            self.ensure_switch_allowed(source, expected_manual_generation)
            xpm_common.log(
                f'{standby_tag} passed pre-switch validation: ' +
                self.format_probe_results(checks)
                + f'; fastest={measured_latency:.0f}ms'
            )

            with self.lock:
                self.state['jobs']['switch']['message'] = 'Защита дренируемого слота...'
                self.save_state()
                old_slot_running = self.slots[old_slot_tag].running()
            with self.lock:
                self.state['jobs']['switch']['message'] = 'Переключение selector...'
                self.save_state()
            self.switch_selector(standby_tag)
            selector_switched = True

            switched_at = xpm_common.now_ts()
            rollback_candidate: xpm_models.Candidate | None = None
            generation = 0
            with self.lock:
                old_slot = self.slots[old_slot_tag]
                rollback_candidate = old_slot.candidate or self.candidate_by_id(old_slot.candidate_id)
                self.active_slot_tag = standby_tag
                self.active_candidate_id = candidate.id
                # From this point the in-memory routing state agrees with the
                # already switched selector, so exception cleanup must never stop
                # the new active process.
                state_committed = True
                self.switch_generation += 1
                generation = self.switch_generation
                standby.draining = False
                standby.drain_started_at = None
                standby.drain_zero_since = None
                standby.drain_protect_until = None
                standby.drain_degraded_checks = 0
                standby.drain_last_latency_ms = None
                standby.drain_last_checked_at = None
                standby.drain_new_connections = 0
                standby.drain_stalled_connections = 0
                standby.drain_known_connection_ids.clear()
                standby.drain_connection_bytes.clear()
                standby.drain_idle_polls.clear()
                old_slot.draining = old_slot.running()
                old_slot.drain_started_at = switched_at if old_slot.draining else None
                old_slot.drain_zero_since = None
                old_slot.drain_protect_until = (
                    switched_at + xpm_common.POST_SWITCH_WATCH_SECONDS if old_slot.draining else None
                )
                old_slot.drain_connections = 0
                old_slot.drain_bytes = 0
                old_slot.drain_last_error = ''
                old_slot.drain_degraded_checks = 0
                old_slot.drain_last_latency_ms = None
                old_slot.drain_last_checked_at = None
                old_slot.drain_new_connections = 0
                old_slot.drain_stalled_connections = 0
                old_slot.drain_known_connection_ids.clear()
                old_slot.drain_connection_bytes.clear()
                old_slot.drain_idle_polls.clear()
                old_slot.drain_last_info_at = None
                old_slot.drain_last_info_connections = None
                self.state['last_switch_at'] = switched_at
                self.state['last_switch_reason'] = reason
                self.state['last_switch_source'] = source
                self.state['auto_check_failures'] = 0
                self.state['auto_check_last_error'] = ''
                self.latencies[candidate.id] = {
                    'status': 'ok',
                    'latency_ms': int(round(measured_latency)),
                    'checked_at': switched_at,
                    'error': '',
                }
                self.save_latencies()
                self.save_state()
            try:
                self.save_active_config(standby_tag, candidate)
            except Exception as exc:
                xpm_common.log(f'could not save last-good active config: {exc}', error=True)
            xpm_common.log(
                f'active outbound: {candidate.name} [{candidate.outbound_tag}] via {standby_tag}; '
                f'{old_slot_tag} is draining; source={source}'
            )
            if self.slots[old_slot_tag].draining:
                self.capture_drain_connection_baseline(old_slot_tag)
                self.apply_switching_preset_to_draining_slot(old_slot_tag)
            if rollback_candidate is not None:
                threading.Thread(
                    target=self.post_switch_watch,
                    args=(
                        generation,
                        standby_tag,
                        old_slot_tag,
                        rollback_candidate,
                        emergency_failover,
                    ),
                    daemon=True,
                ).start()
        except Exception as exc:
            if state_committed:
                xpm_common.log(
                    f'blue-green switch completed, but post-switch bookkeeping failed: {exc}',
                    error=True,
                )
                return
            safe_to_stop_standby = not selector_switched
            if selector_switched and not state_committed and old_slot_tag:
                try:
                    self.switch_selector(old_slot_tag)
                    safe_to_stop_standby = True
                    xpm_common.log(
                        f'switch transaction failed after selector update; '
                        f'selector restored to {old_slot_tag}',
                        error=True,
                    )
                except Exception as rollback_exc:
                    # Do not terminate the process that may already receive new
                    # connections. Reflect the safest known state and leave both
                    # slots running for manual recovery.
                    safe_to_stop_standby = False
                    with self.lock:
                        self.active_slot_tag = standby_tag
                        self.active_candidate_id = candidate.id
                        self.switch_generation += 1
                        old_slot = self.slots[old_slot_tag]
                        old_slot.draining = old_slot.running()
                        old_slot.drain_started_at = xpm_common.now_ts() if old_slot.draining else None
                        old_slot.drain_protect_until = (
                            xpm_common.now_ts() + xpm_common.POST_SWITCH_WATCH_SECONDS if old_slot.draining else None
                        )
                        old_slot.drain_degraded_checks = 0
                        old_slot.drain_last_latency_ms = None
                        old_slot.drain_last_checked_at = None
                        self.save_state()
                    xpm_common.log(
                        f'selector rollback to {old_slot_tag} failed after partial switch: '
                        f'{rollback_exc}; keeping {standby_tag} active and both slots running',
                        error=True,
                    )
            if safe_to_stop_standby and standby_tag and standby_tag != self.active_slot_tag:
                standby = self.slots[standby_tag]
                if standby.running() and not standby.draining:
                    self.stop_slot(standby_tag)
            raise
        finally:
            try:
                with self.lock:
                    self.state['jobs']['switch'].update({'running': False, 'message': ''})
                    self.save_state()
            except Exception as exc:
                xpm_common.log(f'could not persist switch job state: {exc}', error=True)
            self.switch_lock.release()

    def rollback_to_running_slot(
        self,
        generation: int,
        failed_slot_tag: str,
        rollback_slot_tag: str,
        rollback_candidate: xpm_models.Candidate,
        reason: str,
        *,
        source: str = 'post_switch_rollback',
    ) -> bool:
        if failed_slot_tag == rollback_slot_tag:
            raise ValueError('Rollback slot must differ from the failed active slot')
        self.log_switch_request(rollback_candidate, source, reason)
        if not self.switch_lock.acquire(blocking=False):
            raise RuntimeError('Another outbound switch is already running')
        selector_switched = False
        state_committed = False
        try:
            with self.lock:
                if (
                    generation != self.switch_generation
                    or self.active_slot_tag != failed_slot_tag
                ):
                    return False
                rollback_slot = self.slots[rollback_slot_tag]
                if not rollback_slot.running():
                    raise RuntimeError(f'Rollback slot {rollback_slot_tag} is no longer running')

            with self.lock:
                failed_running_before_commit = self.slots[failed_slot_tag].running()
            self.switch_selector(rollback_slot_tag)
            selector_switched = True
            switched_at = xpm_common.now_ts()
            with self.lock:
                failed_slot = self.slots[failed_slot_tag]
                rollback_slot = self.slots[rollback_slot_tag]
                if not rollback_slot.running():
                    raise RuntimeError(
                        f'Rollback slot {rollback_slot_tag} stopped during selector update'
                    )
                self.active_slot_tag = rollback_slot_tag
                self.active_candidate_id = rollback_candidate.id
                rollback_slot.candidate_id = rollback_candidate.id
                rollback_slot.candidate_name = rollback_candidate.name
                rollback_slot.candidate = rollback_candidate
                rollback_slot.draining = False
                rollback_slot.drain_started_at = None
                rollback_slot.drain_zero_since = None
                rollback_slot.drain_protect_until = None
                rollback_slot.drain_last_error = ''
                rollback_slot.drain_degraded_checks = 0
                rollback_slot.drain_last_latency_ms = None
                rollback_slot.drain_last_checked_at = None
                rollback_slot.drain_new_connections = 0
                rollback_slot.drain_stalled_connections = 0
                rollback_slot.drain_known_connection_ids.clear()
                rollback_slot.drain_connection_bytes.clear()
                rollback_slot.drain_idle_polls.clear()

                failed_slot.draining = failed_slot.running()
                failed_slot.drain_started_at = switched_at if failed_slot.draining else None
                failed_slot.drain_zero_since = None
                failed_slot.drain_protect_until = (
                    switched_at + xpm_common.POST_SWITCH_WATCH_SECONDS if failed_slot.draining else None
                )
                failed_slot.drain_connections = 0
                failed_slot.drain_tcp_connections = 0
                failed_slot.drain_udp_connections = 0
                failed_slot.drain_bytes = 0
                failed_slot.drain_last_error = ''
                failed_slot.drain_degraded_checks = 0
                failed_slot.drain_last_latency_ms = None
                failed_slot.drain_last_checked_at = None
                failed_slot.drain_new_connections = 0
                failed_slot.drain_stalled_connections = 0
                failed_slot.drain_known_connection_ids.clear()
                failed_slot.drain_connection_bytes.clear()
                failed_slot.drain_idle_polls.clear()
                failed_slot.drain_last_info_at = None
                failed_slot.drain_last_info_connections = None

                self.switch_generation += 1
                self.state['last_switch_at'] = switched_at
                self.state['last_switch_reason'] = reason
                self.state['last_switch_source'] = source
                self.state['auto_check_failures'] = 0
                self.state['auto_check_last_error'] = ''
                state_committed = True
                self.save_state()
            try:
                self.save_active_config(rollback_slot_tag, rollback_candidate)
            except Exception as exc:
                xpm_common.log(f'could not save last-good rollback config: {exc}', error=True)
            xpm_common.log(
                f'rolled back selector to {rollback_slot_tag} ({rollback_candidate.name}); '
                f'{failed_slot_tag} is draining; source={source}',
                error=True,
            )
            if self.slots[failed_slot_tag].draining:
                self.capture_drain_connection_baseline(failed_slot_tag)
                self.apply_switching_preset_to_draining_slot(failed_slot_tag)
            return True
        except Exception as exc:
            if state_committed:
                xpm_common.log(f'rollback completed, but bookkeeping failed: {exc}', error=True)
                return True
            if selector_switched:
                try:
                    with self.lock:
                        failed_running = self.slots[failed_slot_tag].running()
                    if failed_running:
                        self.switch_selector(failed_slot_tag)
                except Exception as restore_exc:
                    xpm_common.log(
                        f'could not restore selector to {failed_slot_tag} after rollback failure: '
                        f'{restore_exc}',
                        error=True,
                    )
            raise
        finally:
            self.switch_lock.release()

    def post_switch_watch(
        self,
        generation: int,
        active_slot_tag: str,
        rollback_slot_tag: str,
        rollback_candidate: xpm_models.Candidate,
        force_disconnect_rollback: bool = False,
    ) -> None:
        failures = 0
        successes = 0
        deadline = time.monotonic() + xpm_common.POST_SWITCH_WATCH_SECONDS
        while time.monotonic() < deadline and not self.stop_event.wait(5):
            with self.lock:
                if generation != self.switch_generation or self.active_slot_tag != active_slot_tag:
                    return
                slot = self.slots[active_slot_tag]
                if not slot.running():
                    failures += 1
                    error = 'active Xray slot stopped'
                else:
                    error = ''
            if not error:
                success, _latency_ms, _checks, error = self.probe_slot_health(active_slot_tag)
                if success:
                    failures = 0
                    successes += 1
                else:
                    failures += 1
                    successes = 0
            else:
                successes = 0

            if force_disconnect_rollback and successes >= 2:
                with self.lock:
                    still_current = (
                        generation == self.switch_generation
                        and self.active_slot_tag == active_slot_tag
                    )
                    rollback_slot = self.slots[rollback_slot_tag]
                    can_stop = (
                        still_current
                        and rollback_slot.running()
                        and rollback_slot.draining
                    )
                    connections = rollback_slot.drain_connections
                if can_stop:
                    xpm_common.log(
                        f'emergency failover confirmed on {active_slot_tag}; force-stopping '
                        f'degraded {rollback_slot_tag} with {connections} tracked connections',
                        error=True,
                    )
                    try:
                        self.force_stop_draining_slot(rollback_slot_tag)
                    except Exception as exc:
                        xpm_common.log(f'could not force-stop degraded slot {rollback_slot_tag}: {exc}', error=True)
                return

            if failures < 2:
                continue
            xpm_common.log(
                f'post-switch validation failed twice ({error}); rolling back to '
                f'{rollback_candidate.name}',
                error=True,
            )
            try:
                self.rollback_to_running_slot(
                    generation,
                    active_slot_tag,
                    rollback_slot_tag,
                    rollback_candidate,
                    'automatic rollback after post-switch validation errors',
                    source='post_switch_rollback',
                )
            except Exception as exc:
                xpm_common.log(f'automatic rollback failed: {exc}', error=True)
            return

    def switch_candidate_single_slot(
        self,
        candidate: xpm_models.Candidate,
        reason: str,
        *,
        source: str = 'internal',
        force_reload: bool = False,
        expected_manual_generation: int | None = None,
    ) -> None:
        """Restart xray-a in place and intentionally drop all existing flows."""
        if not self.switch_lock.acquire(blocking=False):
            raise RuntimeError('Переключение outbound уже выполняется')
        slot_tag = 'xray-a'
        old_candidate: xpm_models.Candidate | None = None
        old_candidate_id = ''
        old_config: bytes | None = None
        prepared_config: Path | None = None
        interrupted = False
        state_committed = False
        try:
            with self.lock:
                self.state['jobs']['switch'].update({
                    'running': True,
                    'message': f'Однослотовое переключение на {candidate.name}...',
                })
                self.save_state()
                slot = self.slots[slot_tag]
                old_candidate = slot.candidate or self.candidate_by_id(self.active_candidate_id)
                old_candidate_id = self.active_candidate_id
                if (
                    slot.running()
                    and self.same_outbound(candidate, old_candidate)
                    and not force_reload
                ):
                    return
                if slot.config_path.exists():
                    old_config = slot.config_path.read_bytes()

            # Validate the replacement while the current Xray is still
            # serving traffic. The unavoidable outage then contains only the
            # process stop/start and port readiness, not config generation or
            # `xray -test`.
            prepared_config, _changed = self.prepare_slot_config(slot_tag, candidate)
            self.ensure_switch_allowed(source, expected_manual_generation)

            if self.selector_control_enabled:
                try:
                    reported = self.selector_status()
                    if reported != slot_tag:
                        self.switch_selector(slot_tag)
                        xpm_common.log(
                            f'single-slot mode restored selector from {reported} to {slot_tag}',
                            error=True,
                        )
                except Exception as exc:
                    raise RuntimeError(
                        f'Selector API недоступен; однослотовое переключение не начато: {exc}'
                    ) from exc

            xpm_common.log(
                f'single-slot switch is stopping {slot_tag}; all existing TCP/UDP '
                f'connections will be dropped before activating {candidate.name}'
            )
            self.stop_slot(slot_tag)
            interrupted = True
            self.install_prepared_slot_config(slot_tag, candidate, prepared_config)
            prepared_config = None
            self.start_slot(slot_tag)
            measured_latency, checks = self.validate_slot(slot_tag)
            self.ensure_switch_allowed(source, expected_manual_generation)
            if self.selector_control_enabled:
                self.switch_selector(slot_tag)
            switched_at = xpm_common.now_ts()
            with self.lock:
                self.active_slot_tag = slot_tag
                self.active_candidate_id = candidate.id
                state_committed = True
                self.switch_generation += 1
                slot = self.slots[slot_tag]
                slot.draining = False
                self.state['last_switch_at'] = switched_at
                self.state['last_switch_reason'] = reason
                self.state['last_switch_source'] = source
                self.state['auto_check_failures'] = 0
                self.state['auto_check_last_error'] = ''
                self.latencies[candidate.id] = {
                    'status': 'ok',
                    'latency_ms': int(round(measured_latency)),
                    'checked_at': switched_at,
                    'error': '',
                }
                self.save_latencies()
                self.save_state()
            self.save_active_config(slot_tag, candidate)
            xpm_common.log(
                f'active outbound: {candidate.name} [{candidate.outbound_tag}] via {slot_tag}; '
                f'single-slot validation: '
                + self.format_probe_results(checks)
                + f'; fastest={measured_latency:.0f}ms; source={source}'
            )
        except Exception:
            if prepared_config is not None:
                prepared_config.unlink(missing_ok=True)
            if state_committed:
                xpm_common.log('single-slot switch completed; could not persist bookkeeping', error=True)
                return
            if not interrupted:
                raise
            try:
                self.stop_slot(slot_tag)
                if old_candidate is not None:
                    if old_config is not None:
                        self.slots[slot_tag].config_path.write_bytes(old_config)
                        self.slots[slot_tag].candidate = old_candidate
                        self.slots[slot_tag].candidate_id = old_candidate.id
                        self.slots[slot_tag].candidate_name = old_candidate.name
                        self.start_slot(slot_tag)
                    else:
                        self.start_slot(slot_tag, old_candidate)
                    self.validate_slot(slot_tag, enforce_latency_limit=False)
                    if self.selector_control_enabled:
                        self.switch_selector(slot_tag)
                    with self.lock:
                        self.active_slot_tag = slot_tag
                        self.active_candidate_id = old_candidate_id or old_candidate.id
                        self.save_state()
                    xpm_common.log(
                        f'single-slot switch failed; restored {old_candidate.name} on {slot_tag}',
                        error=True,
                    )
            except Exception as rollback_exc:
                xpm_common.log(f'single-slot rollback failed: {rollback_exc}', error=True)
            raise
        finally:
            try:
                with self.lock:
                    self.state['jobs']['switch'].update({'running': False, 'message': ''})
                    self.save_state()
            except Exception as exc:
                xpm_common.log(f'could not persist switch job state: {exc}', error=True)
            self.switch_lock.release()

    def restart_xray_for(
        self,
        candidate: xpm_models.Candidate,
        reason: str,
        *,
        source: str = 'internal',
        force_reload: bool = False,
        preempt_draining: bool = False,
        emergency_failover: bool = False,
        expected_manual_generation: int | None = None,
    ) -> None:
        self.ensure_switch_allowed(source, expected_manual_generation)
        self.log_switch_request(candidate, source, reason)
        with self.lock:
            active_running = self.slots[self.active_slot_tag].running()
        if not active_running:
            if not self.switch_lock.acquire(blocking=False):
                raise RuntimeError('Переключение outbound уже выполняется')
            try:
                self.start_initial_candidate(candidate, reason, source=source, expected_manual_generation=expected_manual_generation)
            finally:
                self.switch_lock.release()
            return
        if not self.dual_slot_enabled:
            self.switch_candidate_single_slot(
                candidate,
                reason,
                source=source,
                force_reload=force_reload,
                expected_manual_generation=expected_manual_generation,
            )
            return
        self.switch_candidate_blue_green(
            candidate,
            reason,
            source=source,
            force_reload=force_reload,
                expected_manual_generation=expected_manual_generation,
            preempt_draining=preempt_draining,
            emergency_failover=emergency_failover,
        )

    def rollback_after_active_exit(self, failed_slot_tag: str) -> bool:
        if not self.dual_slot_enabled:
            return False
        rollback_slot_tag = self.other_slot_tag(failed_slot_tag)
        rollback_slot = self.slots[rollback_slot_tag]
        if not rollback_slot.running():
            return False
        if not self.switch_lock.acquire(blocking=False):
            return False
        try:
            rollback_candidate = (
                rollback_slot.candidate
                or self.candidate_by_id(rollback_slot.candidate_id)
            )
            if rollback_candidate is not None:
                self.log_switch_request(
                    rollback_candidate,
                    'active_process_exit',
                    'automatic rollback after active Xray process exit',
                )
            self.switch_selector(rollback_slot_tag)
            with self.lock:
                failed_slot = self.slots[failed_slot_tag]
                failed_slot.process = None
                failed_slot.draining = False
                rollback_slot.draining = False
                rollback_slot.drain_started_at = None
                rollback_slot.drain_zero_since = None
                rollback_slot.drain_protect_until = None
                self.active_slot_tag = rollback_slot_tag
                self.active_candidate_id = rollback_slot.candidate_id
                self.switch_generation += 1
                self.state['last_switch_at'] = xpm_common.now_ts()
                self.state['last_switch_reason'] = 'automatic rollback after active Xray process exit'
                self.state['last_switch_source'] = 'active_process_exit'
                self.state['auto_check_failures'] = 0
                self.state['auto_check_last_error'] = ''
                self.save_state()
            if rollback_candidate:
                try:
                    self.save_active_config(rollback_slot_tag, rollback_candidate)
                except Exception as exc:
                    xpm_common.log(f'could not save last-good rollback config: {exc}', error=True)
            xpm_common.log(
                f'active slot {failed_slot_tag} exited; selector rolled back to '
                f'{rollback_slot_tag} ({rollback_slot.candidate_name}); source=active_process_exit',
                error=True,
            )
            return True
        except Exception as exc:
            xpm_common.log(f'rollback after active Xray exit failed: {exc}', error=True)
            return False
        finally:
            self.switch_lock.release()

    def select_candidate(self, candidate_id: str) -> None:
        with self.lock:
            candidate = self.candidate_by_id(candidate_id)
            slot = None if candidate is not None else self.running_slot_by_candidate_id(candidate_id)
            if candidate is None and slot is not None:
                candidate = slot.candidate
            if candidate is None:
                raise ValueError('Outbound не найден')
            already_active = (
                (
                    slot is not None
                    and slot is self.slots[self.active_slot_tag]
                )
                or (
                    self.same_outbound(candidate, self.slots[self.active_slot_tag].candidate or self.candidate_by_id(self.active_candidate_id))
                    and self.slots[self.active_slot_tag].running()
                )
            )
            previous = self.slots[self.active_slot_tag].candidate
            self.manual_generation = getattr(self, 'manual_generation', 0) + 1
            self.invalidate_candidate_probe(candidate.id)
        if already_active:
            with self.lock:
                suspects = set(self.state.get('suspect_candidate_ids', []))
                if candidate.id in suspects:
                    suspects.discard(candidate.id)
                    self.state['suspect_candidate_ids'] = sorted(suspects)
                    self.save_state()
            return
        try:
            self.restart_xray_for(
                candidate, 'manual selection from UI', source='manual_ui', preempt_draining=True,
            )
        except xpm_errors.ProbeFailure as exc:
            with self.lock:
                self.invalidate_candidate_probe(candidate.id)
                self.latencies[candidate.id] = {
                    'status': 'error', 'latency_ms': None, 'checked_at': xpm_common.now_ts(),
                    'error': xpm_errors.human_probe_error(exc), 'config_revision': candidate.config_revision,
                }
                self.save_latencies()
            raise xpm_errors.ProbeFailure(xpm_errors.human_probe_error(exc)) from exc
        with self.lock:
            self.invalidate_candidate_probe(candidate.id)
            suspects = set(self.state.get('suspect_candidate_ids', []))
            suspects.discard(candidate.id)
            if previous is not None and previous.id != candidate.id:
                suspects.add(previous.id)
            self.state['suspect_candidate_ids'] = sorted(suspects)
            self.save_state()
