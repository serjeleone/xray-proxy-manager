from __future__ import annotations

from concurrent.futures import Future, ThreadPoolExecutor, as_completed
import os
import socket
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Iterable
from . import common as xpm_common, errors as xpm_errors, models as xpm_models, persistence as xpm_persistence


class ProbingMixin:
    def validation_urls(self) -> list[str]:
        return [self.primary_test_url, self.secondary_test_url]

    def test_url_label(self, url: str) -> str:
        if url == getattr(self, 'primary_test_url', xpm_common.DEFAULT_PRIMARY_TEST_URL):
            return 'primary_test_url'
        if url == getattr(self, 'secondary_test_url', xpm_common.DEFAULT_SECONDARY_TEST_URL):
            return 'secondary_test_url'
        return 'test_url'

    def format_probe_results(self, results: Iterable[tuple[str, float]]) -> str:
        return ', '.join(
            f'{self.test_url_label(url)}={latency:.0f}ms'
            for url, latency in results
        )

    def probe_proxy_urls(
        self,
        host: str,
        port: int,
        timeout_seconds: int,
        *,
        auth: bool,
    ) -> tuple[bool, float | None, list[tuple[str, float]], str]:
        """Probe both configured endpoints in parallel and use the fastest success."""
        urls = self.validation_urls()
        successful: list[tuple[str, float]] = []
        errors: list[tuple[str, str]] = []
        futures: dict[Future[tuple[bool, float | None, str]], str] = {}
        with ThreadPoolExecutor(
            max_workers=len(urls),
            thread_name_prefix='xray-endpoint-probe',
        ) as executor:
            for url in urls:
                futures[executor.submit(
                    self.proxy_curl,
                    host,
                    port,
                    url,
                    timeout_seconds,
                    auth=auth,
                )] = url
            for future in as_completed(futures):
                url = futures[future]
                try:
                    success, latency_ms, error = future.result()
                except Exception as exc:
                    success, latency_ms, error = False, None, str(exc)
                if success and latency_ms is not None:
                    successful.append((url, latency_ms))
                else:
                    errors.append((url, error or 'request failed'))

        order = {url: index for index, url in enumerate(urls)}
        successful.sort(key=lambda item: order.get(item[0], len(order)))
        errors.sort(key=lambda item: order.get(item[0], len(order)))
        if not successful:
            self.debug_log('; '.join(f'{url}: {error}' for url, error in errors))
            details = '; '.join(
                dict.fromkeys(xpm_errors.human_probe_error(error) for _url, error in errors)
            )
            return False, None, [], details or 'both test endpoints failed'
        minimum = min(latency for _url, latency in successful)
        return True, minimum, successful, ''

    def probe_slot_health(
        self,
        slot_tag: str,
        *,
        enforce_latency_limit: bool = True,
    ) -> tuple[bool, float | None, list[tuple[str, float]], str]:
        slot = self.slots[slot_tag]
        with self.lock:
            if not slot.running():
                return False, None, [], f'{slot_tag} Xray process is not running'
            port = slot.socks_tcp

        success, minimum, results, error = self.probe_proxy_urls(
            self.socks_probe_host(),
            port,
            self.auto_check_timeout_seconds,
            auth=True,
        )
        if not success or minimum is None:
            return False, None, results, error
        if (
            enforce_latency_limit
            and self.auto_check_max_latency_ms > 0
            and minimum > self.auto_check_max_latency_ms
        ):
            checks = self.format_probe_results(results)
            return (
                False,
                minimum,
                results,
                f'latency threshold exceeded ({checks}; fastest {minimum:.0f}ms; '
                f'limit {self.auto_check_max_latency_ms}ms)',
            )
        return True, minimum, results, ''

    def validate_slot(
        self,
        slot_tag: str,
        *,
        enforce_latency_limit: bool = True,
    ) -> tuple[float, list[tuple[str, float]]]:
        slot = self.slots[slot_tag]
        if not self.wait_for_port(slot.socks_tcp, slot.process, timeout=6.0):
            raise xpm_errors.ProbeFailure(f'{slot_tag} did not open SOCKS port {slot.socks_tcp}')
        success, minimum, results, error = self.probe_slot_health(
            slot_tag,
            enforce_latency_limit=enforce_latency_limit,
        )
        if not success or minimum is None:
            raise xpm_errors.ProbeFailure(error)
        return minimum, results

    def find_free_port(self) -> int:
        # Temporary Xray instances are started concurrently. Keep selected
        # ephemeral ports reserved in-process until each test has finished so
        # two workers cannot receive the same port between bind() and Xray start.
        with xpm_common.TEST_PORT_LOCK:
            for _attempt in range(100):
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.bind(('127.0.0.1', 0))
                    port = int(sock.getsockname()[1])
                if port not in xpm_common.RESERVED_TEST_PORTS:
                    xpm_common.RESERVED_TEST_PORTS.add(port)
                    return port
        raise RuntimeError('Unable to reserve a temporary SOCKS port')

    def release_test_port(self, port: int) -> None:
        with xpm_common.TEST_PORT_LOCK:
            xpm_common.RESERVED_TEST_PORTS.discard(port)

    def effective_latency_test_parallelism(self, candidate_count: int) -> int:
        if candidate_count <= 1:
            return max(1, candidate_count)
        configured = int(self.latency_test_parallelism)
        if configured == -1:
            return candidate_count
        if configured > 0:
            return max(1, min(configured, candidate_count))
        cpu_count = max(1, int(os.cpu_count() or 1))
        automatic = min(8, max(2, cpu_count * 2))
        return max(1, min(automatic, candidate_count))

    def wait_for_port(self, port: int, process: subprocess.Popen[str], timeout: float = 4.0) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if process.poll() is not None:
                return False
            try:
                host = self.socks_probe_host() if port in {self.socks_tcp_a, self.socks_tcp_b} else '127.0.0.1'
                with socket.create_connection((host, port), timeout=0.25):
                    return True
            except OSError:
                time.sleep(0.1)
        return False

    def proxy_curl(
        self,
        host: str,
        port: int,
        url: str,
        timeout_seconds: int,
        *,
        auth: bool,
    ) -> tuple[bool, float | None, str]:
        command = [
            xpm_common.CURL_BIN, '-sS', '--fail', '--noproxy', '', '-o', '/dev/null', '-w', '%{time_total}',
            '--socks5-hostname', f'[{host}]:{port}' if ':' in host else f'{host}:{port}',
            '--connect-timeout', str(min(5, timeout_seconds)),
            '--max-time', str(timeout_seconds),
        ]
        if auth and self.proxy_username and self.proxy_password:
            command.extend(['--proxy-user', f'{self.proxy_username}:{self.proxy_password}'])
        command.append(url)
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=timeout_seconds + 3)
        except subprocess.TimeoutExpired:
            return False, None, 'timeout'
        if result.returncode != 0:
            return False, None, (result.stderr or f'curl exit {result.returncode}').strip()
        try:
            seconds = float(result.stdout.strip())
        except ValueError:
            return False, None, 'invalid curl timing response'
        return True, seconds * 1000.0, ''

    def test_candidate(self, candidate: xpm_models.Candidate) -> dict[str, Any]:
        port = self.find_free_port()
        try:
            with tempfile.TemporaryDirectory(prefix='xray-latency.') as temp_dir:
                config_path = Path(temp_dir) / 'config.json'
                log_path = Path(temp_dir) / 'xray.log'
                try:
                    config = self.build_config(candidate, test_port=port)
                    xpm_persistence.atomic_write_json(config_path, config)
                    ok, output = self.xray_test(config_path)
                    if not ok:
                        return {'status': 'error', 'latency_ms': None, 'checked_at': xpm_common.now_ts(), 'error': output[-500:]}

                    with log_path.open('w+', encoding='utf-8') as log_file:
                        process = subprocess.Popen(
                            [xpm_common.XRAY_BIN, '-config', str(config_path)],
                            stdout=log_file,
                            stderr=subprocess.STDOUT,
                            text=True,
                        )
                        try:
                            if not self.wait_for_port(port, process):
                                log_file.flush()
                                log_file.seek(0)
                                error_text = log_file.read()[-500:] or 'temporary xray did not open SOCKS port'
                                return {
                                    'status': 'error',
                                    'latency_ms': None,
                                    'checked_at': xpm_common.now_ts(),
                                    'error': error_text,
                                }
                            success, latency_ms, _checks, error_text = self.probe_proxy_urls(
                                '127.0.0.1',
                                port,
                                self.latency_test_timeout_seconds,
                                auth=False,
                            )
                            if success and latency_ms is not None:
                                return {
                                    'status': 'ok',
                                    'latency_ms': int(round(latency_ms)),
                                    'checked_at': xpm_common.now_ts(),
                                    'error': '',
                                }
                            return {
                                'status': 'error',
                                'latency_ms': None,
                                'checked_at': xpm_common.now_ts(),
                                'error': error_text[-500:],
                            }
                        finally:
                            process.terminate()
                            try:
                                process.wait(timeout=3)
                            except subprocess.TimeoutExpired:
                                process.kill()
                                process.wait(timeout=2)
                except Exception as exc:
                    return {
                        'status': 'error',
                        'latency_ms': None,
                        'checked_at': xpm_common.now_ts(),
                        'error': str(exc)[-500:],
                    }
        finally:
            self.release_test_port(port)

    def test_candidate_for_full_scan(self, candidate: xpm_models.Candidate) -> dict[str, Any]:
        """Measure an already running candidate through its real slot.

        Other candidates still use isolated temporary Xray processes. This keeps
        the full-scan list comparable while ensuring active and draining slot
        values describe the paths that are actually running.
        """
        with self.lock:
            slot = next(
                (
                    item for item in self.slots.values()
                    if item.running() and self.same_outbound(candidate, item.candidate)
                ),
                None,
            )
            port = slot.socks_tcp if slot is not None else None
            process = slot.process if slot is not None else None
        if port is None:
            return self.test_candidate(candidate)

        success, latency_ms, _checks, error_text = self.probe_proxy_urls(
            self.socks_probe_host(),
            port,
            self.latency_test_timeout_seconds,
            auth=True,
        )
        with self.lock:
            changed = slot.process is not process or not self.same_outbound(candidate, slot.candidate)
        if changed:
            return self.test_candidate(candidate)
        if success and latency_ms is not None:
            return {
                'status': 'ok',
                'latency_ms': int(round(latency_ms)),
                'checked_at': xpm_common.now_ts(),
                'error': '',
            }
        return {
            'status': 'error',
            'latency_ms': None,
            'checked_at': xpm_common.now_ts(),
            'error': error_text[-500:],
        }

    def test_running_slot_for_full_scan(self, slot_tag: str) -> dict[str, Any]:
        """Measure a running slot even when its outbound left the subscription."""
        success, latency_ms, _checks, error_text = self.probe_slot_health(
            slot_tag,
            enforce_latency_limit=False,
        )
        if success and latency_ms is not None:
            return {
                'status': 'ok',
                'latency_ms': int(round(latency_ms)),
                'checked_at': xpm_common.now_ts(),
                'error': '',
            }
        return {
            'status': 'error',
            'latency_ms': None,
            'checked_at': xpm_common.now_ts(),
            'error': error_text[-500:],
        }

    def latency_job(
        self,
        candidate_ids: list[str] | None = None,
        switch_to_best: bool = False,
        source: str = 'manual',
        manual_generation: int | None = None,
    ) -> None:
        with self.lock:
            if manual_generation is None:
                manual_generation = getattr(self, 'manual_generation', 0)
            probe_versions = dict(getattr(self, 'latency_versions', {}))
            candidates = [
                item for item in self.candidates
                if candidate_ids is None or item.id in candidate_ids
            ]
            runtime_slot_targets: list[tuple[str, str, str, Any]] = []
            requested_ids = set(candidate_ids or [])
            for slot_tag, slot in getattr(self, 'slots', {}).items():
                if not slot.running():
                    continue
                represented = any(
                    self.same_outbound(candidate, slot.candidate)
                    for candidate in candidates
                )
                target_id = self.slot_candidate_id(slot_tag)
                requested = candidate_ids is None or target_id in requested_ids
                if represented or not requested:
                    continue
                target_name = slot.candidate_name or (
                    slot.candidate.name if slot.candidate is not None else slot_tag
                )
                runtime_slot_targets.append((slot_tag, target_id, target_name, slot.process))
            job = self.state['jobs']['latency']
            total_targets = len(candidates) + len(runtime_slot_targets)
            workers = self.effective_latency_test_parallelism(total_targets)
            checking_target_ids = {
                candidate.id for candidate in candidates
            } | {target_id for _tag, target_id, _name, _process in runtime_slot_targets}
            if not hasattr(self, 'latency_checking_ids'):
                self.latency_checking_ids = set()
            self.latency_checking_ids.update(checking_target_ids)
            job.update({
                'running': True,
                'progress': 0,
                'total': total_targets,
                'message': f'Проверка доступности · параллельно: {workers}',
            })
            self.save_state()

        fresh_results: dict[str, dict[str, Any]] = {}
        final_message = 'Проверка завершена'
        try:
            completed = 0
            futures: dict[Future[dict[str, Any]], tuple[str, str, Any, Any]] = {}
            with ThreadPoolExecutor(
                max_workers=workers,
                thread_name_prefix='xray-latency',
            ) as executor:
                for candidate in candidates:
                    if self.stop_event.is_set():
                        break
                    future = executor.submit(self.test_candidate_for_full_scan, candidate)
                    futures[future] = (candidate.id, candidate.name, candidate, None)
                for slot_tag, target_id, target_name, process in runtime_slot_targets:
                    if self.stop_event.is_set():
                        break
                    future = executor.submit(self.test_running_slot_for_full_scan, slot_tag)
                    futures[future] = (target_id, target_name, slot_tag, process)

                for future in as_completed(futures):
                    target_id, target_name, target, process = futures[future]
                    if self.stop_event.is_set():
                        for pending in futures:
                            pending.cancel()
                        break
                    try:
                        result = future.result()
                    except Exception as exc:
                        result = {
                            'status': 'error', 'latency_ms': None,
                            'checked_at': xpm_common.now_ts(),
                            'error': xpm_errors.human_probe_error(exc),
                        }
                    completed += 1
                    with self.lock:
                        if isinstance(target, xpm_models.Candidate):
                            current = self.candidate_by_id(target_id)
                            unchanged = current is not None and self.same_outbound(current, target)
                            result['config_revision'] = target.config_revision
                        else:
                            slot = self.slots[target]
                            unchanged = slot.process is process and self.slot_candidate_id(target) == target_id
                        unchanged = unchanged and (
                            getattr(self, 'latency_versions', {}).get(target_id, 0)
                            == probe_versions.get(target_id, 0)
                        )
                        if unchanged:
                            fresh_results[target_id] = result
                            self.latencies[target_id] = result
                        self.latency_checking_ids.discard(target_id)
                        self.save_latencies()
                        job = self.state['jobs']['latency']
                        job.update({
                            'progress': completed,
                            'message': f'{target_name}: ' + (
                                f'{result["latency_ms"]} мс'
                                if result['status'] == 'ok' else 'недоступен'
                            ),
                        })
                        self.save_state()

            if fresh_results and not self.stop_event.is_set():
                self.handle_draining_full_scan_results(fresh_results)

            if (switch_to_best and fresh_results and not self.stop_event.is_set()
                    and self.auto_checker_enabled and self.auto_switch_best_enabled
                    and manual_generation == getattr(self, 'manual_generation', 0)):
                healthy: list[tuple[int, str, xpm_models.Candidate]] = []
                for candidate in candidates:
                    result = fresh_results.get(candidate.id) or {}
                    latency_ms = result.get('latency_ms')
                    if result.get('status') != 'ok' or not isinstance(latency_ms, int):
                        continue
                    if self.auto_check_max_latency_ms > 0 and latency_ms > self.auto_check_max_latency_ms:
                        continue
                    if self.candidate_is_excluded(candidate):
                        continue
                    healthy.append((latency_ms, candidate.name.casefold(), candidate))
                healthy.sort(key=lambda item: (
                    *self.candidate_preference_sort_key(item[2]),
                    item[0],
                    item[1],
                ))

                if healthy:
                    best_latency, _best_name, best_candidate = healthy[0]
                    with self.lock:
                        effective, selected, _mismatch = self.effective_active_candidate()
                        current = selected or effective
                        current_result = fresh_results.get(current.id) if current else None
                        current_latency = (
                            current_result.get('latency_ms')
                            if isinstance(current_result, dict) and current_result.get('status') == 'ok'
                            else self.candidate_latency_ms(current)
                        )

                    ping_difference = (
                        current_latency - best_latency
                        if isinstance(current_latency, int) else None
                    )
                    preferred_switch = bool(
                        current is not None
                        and self.candidate_preference_score(best_candidate)
                        > self.candidate_preference_score(current)
                    )
                    should_switch = (
                        current is None
                        or (
                            not self.same_outbound(current, best_candidate)
                            and (
                                preferred_switch
                                or
                                not isinstance(current_latency, int)
                                or ping_difference >= self.auto_switch_min_ping_delta_ms
                            )
                        )
                    )
                    if should_switch:
                        self.restart_xray_for(
                            best_candidate,
                            f'automatic best latency after {source} check: {best_latency} ms',
                            source=self.switch_source_for_latency_job(source),
                            expected_manual_generation=manual_generation,
                        )
                        final_message = f'Проверка завершена · выбран {best_candidate.name} ({best_latency} мс)'
                        xpm_common.log(
                            f'{source} latency check switched to {best_candidate.name} '
                            f'({best_latency} ms, difference {ping_difference} ms, '
                            f'preferred_country={getattr(self, "auto_switch_preferred_country", "") or "none"}, '
                            f'preferred_protocol={getattr(self, "auto_switch_preferred_protocol", "") or "none"})'
                        )
                    elif current is not None and self.same_outbound(current, best_candidate):
                        final_message = f'Проверка завершена · текущий outbound оптимален ({current_latency} мс)'
                    elif current is not None and isinstance(ping_difference, int):
                        if ping_difference < 0:
                            final_message = (
                                f'Проверка завершена · текущий outbound быстрее подходящих кандидатов '
                                f'на {-ping_difference} мс'
                            )
                        else:
                            final_message = (
                                f'Проверка завершена · разница {ping_difference} мс меньше порога '
                                f'{self.auto_switch_min_ping_delta_ms} мс'
                            )
                else:
                    excluded_text = self.auto_switch_excluded or 'нет'
                    final_message = (
                        'Проверка завершена · подходящие outbound не найдены '
                        f'(исключения выбора: {excluded_text})'
                    )
        except Exception as exc:
            final_message = f'Ошибка проверки: {exc}'
            xpm_common.log(f'latency job error: {exc}', error=True)
        finally:
            with self.lock:
                self.latency_checking_ids.difference_update(checking_target_ids)
                self.state['jobs']['latency'].update({'running': False, 'message': final_message})
                if candidate_ids is None and source in {'manual', 'auto-best', 'startup', 'subscription'}:
                    self.state['auto_best_check_last_at'] = xpm_common.now_ts()
                    self.settings_event.set()
                self.save_state()
                self.start_pending_subscription_check()

    def request_subscription_check(self) -> None:
        with self.lock:
            # Coalesce updates while a scan is running: its snapshot may not
            # contain the new subscription, so scan the latest list afterwards.
            self.pending_subscription_check_generation = getattr(self, 'manual_generation', 0)
            self.start_pending_subscription_check()

    def start_pending_subscription_check(self) -> None:
        with self.lock:
            generation = self.pending_subscription_check_generation
            if (generation is None or self.state['jobs']['latency'].get('running')
                    or self.stop_event.is_set()):
                return
            self.pending_subscription_check_generation = None
            self.request_latency_test(
                None,
                switch_to_best=(
                    self.auto_switch_best_enabled
                    and generation == getattr(self, 'manual_generation', 0)
                ),
                source='subscription',
            )

    def request_latency_test(
        self,
        candidate_ids: list[str] | None = None,
        switch_to_best: bool = False,
        source: str = 'manual',
    ) -> bool:
        with self.lock:
            if self.state['jobs']['latency'].get('running'):
                return False
            targets = [
                item for item in self.candidates
                if candidate_ids is None or item.id in candidate_ids
            ]
            checking_ids = {item.id for item in targets}
            runtime_target_count = 0
            requested_ids = set(candidate_ids or [])
            for slot_tag, slot in self.slots.items():
                if not slot.running():
                    continue
                represented = any(
                    self.same_outbound(candidate, slot.candidate)
                    for candidate in targets
                )
                target_id = self.slot_candidate_id(slot_tag)
                requested = candidate_ids is None or target_id in requested_ids
                if represented or not requested:
                    continue
                checking_ids.add(target_id)
                runtime_target_count += 1
            total = len(targets) + runtime_target_count
            if not hasattr(self, 'latency_checking_ids'):
                self.latency_checking_ids = set()
            self.latency_checking_ids.update(checking_ids)
            self.state['jobs']['latency'].update({
                'running': True,
                'progress': 0,
                'total': total,
                'message': 'Проверка доступности...',
                'source': source,
                'scope': 'all' if candidate_ids is None else 'selected',
                'switch_to_best': bool(switch_to_best),
            })
            self.save_state()
            threading.Thread(
                target=self.latency_job,
                args=(candidate_ids, switch_to_best, source, getattr(self, 'manual_generation', 0)),
                daemon=True,
            ).start()
            return True

    def check_active_tunnel(
        self,
    ) -> tuple[bool, float | None, list[tuple[str, float]], str]:
        return self.probe_slot_health(self.active_slot_tag)

    def auto_best_check_due(self, current_time: int | None = None) -> bool:
        interval = max(60, int(self.auto_best_check_interval_seconds))
        try:
            last_check = int(self.state.get('auto_best_check_last_at') or 0)
        except (TypeError, ValueError):
            last_check = 0
        if last_check <= 0:
            return True
        now_value = xpm_common.now_ts() if current_time is None else int(current_time)
        return now_value - last_check >= interval

    @staticmethod
    def failover_error_is_global(error: Exception) -> bool:
        if isinstance(error, xpm_errors.SwitchCancelled):
            return True
        """Return True when trying another outbound cannot fix the failure."""
        text = str(error).casefold()
        markers = (
            'selector api недоступен',
            'переключение outbound уже выполняется',
            'another outbound switch is already running',
            'активный слот',
            'blue-green switching is disabled',
            'blue-green переключение требует',
        )
        return any(marker in text for marker in markers)

    def emergency_failover(self, failures: int) -> xpm_models.Candidate | None:
        """Try each eligible outbound once until one passes real validation."""
        if not (self.auto_checker_enabled and self.auto_switch_best_enabled):
            return None
        generation = getattr(self, 'manual_generation', 0)
        candidates = self.failover_candidates()
        if not candidates:
            excluded_text = self.auto_switch_excluded or 'нет'
            xpm_common.log(
                'auto-check could not find a failover outbound outside configured '
                f'exclusions: {excluded_text}',
                error=True,
            )
            return None

        attempted: list[xpm_models.Candidate] = []
        total = len(candidates)
        for candidate in candidates:
            if (generation != getattr(self, 'manual_generation', 0)
                    or not self.auto_checker_enabled or not self.auto_switch_best_enabled):
                return None
            if any(self.same_outbound(candidate, seen) for seen in attempted):
                continue
            attempted.append(candidate)
            attempt = len(attempted)
            xpm_common.log(
                f'auto-check failover attempt {attempt}/{total}: '
                f'{candidate.name} [{candidate.outbound_tag}]'
            )
            try:
                self.restart_xray_for(
                    candidate,
                    f'emergency failover after {failures} consecutive degraded checks',
                    source='auto_check_failover',
                    preempt_draining=True,
                    emergency_failover=True,
                    expected_manual_generation=generation,
                )
            except Exception as exc:
                if self.failover_error_is_global(exc):
                    raise
                checked_at = xpm_common.now_ts()
                with self.lock:
                    self.latencies[candidate.id] = {
                        'status': 'error',
                        'latency_ms': None,
                        'checked_at': checked_at,
                        'error': xpm_errors.human_probe_error(exc),
                        'config_revision': candidate.config_revision,
                    }
                    self.save_latencies()
                xpm_common.log(
                    f'auto-check rejected failover outbound {candidate.name} '
                    f'[{candidate.outbound_tag}]: {exc}; trying next candidate',
                    error=True,
                )
                continue

            xpm_common.log(
                f'auto-check switched to {candidate.name}; old degraded slot will be '
                'force-stopped after two successful checks',
                error=True,
            )
            return candidate

        xpm_common.log(
            f'auto-check exhausted {len(attempted)} failover candidate(s); '
            'no outbound passed validation',
            error=True,
        )
        return None

    def auto_check_wait_seconds(self, current_time: int | None = None) -> float:
        if not self.auto_checker_enabled:
            return 5.0
        interval = max(10, int(self.auto_check_interval_seconds))
        try:
            last_check = int(self.state.get('auto_check_last_at') or 0)
        except (TypeError, ValueError):
            last_check = 0
        if last_check <= 0:
            return float(interval)
        now_value = xpm_common.now_ts() if current_time is None else int(current_time)
        elapsed = max(0, now_value - last_check)
        return float(max(0, interval - elapsed))

    def auto_checker_loop(self) -> None:
        while not self.stop_event.is_set():
            timeout = self.auto_check_wait_seconds()
            woke_for_settings = self.settings_event.wait(timeout)
            if self.stop_event.is_set():
                break
            if woke_for_settings:
                self.settings_event.clear()
                continue
            if not self.auto_checker_enabled:
                continue
            active_check_id = ''
            try:
                self.check_draining_slots_health()
                with self.lock:
                    if self.switch_lock.locked():
                        continue
                    active_slot = self.slots[self.active_slot_tag]
                    checked_slot_tag = self.active_slot_tag
                    checked_process = active_slot.process
                    checked_generation = self.switch_generation
                    active_check_id = self.active_candidate_id or active_slot.candidate_id or (
                        active_slot.candidate.id if active_slot.candidate is not None else ''
                    )
                    if active_check_id:
                        self.latency_checking_ids.add(active_check_id)
                success, latency_ms, checks, error = self.check_active_tunnel()
                checked_at = xpm_common.now_ts()
                check_details = self.format_probe_results(checks) or 'both endpoints failed'
                with self.lock:
                    if active_check_id:
                        self.latency_checking_ids.discard(active_check_id)
                    if (checked_slot_tag != self.active_slot_tag
                            or checked_process is not active_slot.process
                            or checked_generation != self.switch_generation
                            or self.switch_lock.locked()):
                        continue
                    self.state['auto_check_last_at'] = checked_at
                    if success:
                        self.state['auto_check_failures'] = 0
                        self.state['auto_check_last_error'] = ''
                        if self.active_candidate_id and latency_ms is not None:
                            self.latencies[self.active_candidate_id] = {
                                'status': 'ok',
                                'latency_ms': int(round(latency_ms)),
                                'checked_at': checked_at,
                                'error': '',
                            }
                            self.save_latencies()
                        self.save_state()
                    else:
                        failures = int(self.state.get('auto_check_failures') or 0) + 1
                        self.state['auto_check_failures'] = failures
                        self.state['auto_check_last_error'] = error
                        if active_check_id:
                            self.latencies[active_check_id] = {
                                'status': 'error',
                                'latency_ms': None,
                                'checked_at': checked_at,
                                'error': error,
                            }
                            self.save_latencies()
                        self.save_state()

                if success:
                    xpm_common.log(
                        f'active slot check {self.active_slot_tag}: {check_details}; '
                        f'fastest={latency_ms:.0f}ms; result=ok'
                    )
                    if self.auto_best_check_due(checked_at):
                        accepted = self.request_latency_test(
                            None,
                            switch_to_best=self.auto_switch_best_enabled,
                            source='auto-best',
                        )
                        if not accepted:
                            xpm_common.log('scheduled full outbound check postponed because another latency test is running')
                    continue

                failures = int(self.state.get('auto_check_failures') or 0)
                xpm_common.log(
                    f'active slot check {self.active_slot_tag}: {check_details}; result=failed; '
                    f'auto-check failures={failures}/{self.auto_check_failures}; {error}',
                    error=True,
                )
                if failures < self.auto_check_failures:
                    continue

                self.emergency_failover(failures)
            except Exception as exc:
                xpm_common.log(f'auto-check error: {exc}', error=True)
            finally:
                if active_check_id:
                    with self.lock:
                        self.latency_checking_ids.discard(active_check_id)
