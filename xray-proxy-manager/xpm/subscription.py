from __future__ import annotations

import copy
import hashlib
import json
import os
import subprocess
import tempfile
import threading
from dataclasses import replace
from pathlib import Path
from typing import Any, Callable
from . import common as xpm_common, config as xpm_config, conversion as xpm_conversion, identity as xpm_identity, models as xpm_models, persistence as xpm_persistence


class SubscriptionMixin:
    def download_subscription_once(self, proxy_slot: str | None = None) -> list[dict[str, Any]]:
        with tempfile.NamedTemporaryFile(prefix='subscription.', suffix='.json', delete=False) as temp_file:
            temp_path = Path(temp_file.name)
        try:
            command = [
                xpm_common.CURL_BIN, '-fSL', '--connect-timeout', '20', '--max-time', '90',
                '--retry', '2', '--retry-delay', '2', '--retry-all-errors',
                '-A', self.user_agent,
            ]
            environment = os.environ.copy()
            for key in (
                'http_proxy', 'https_proxy', 'all_proxy', 'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY',
            ):
                environment.pop(key, None)
            if proxy_slot is None:
                command.extend(['--noproxy', '*'])
                environment['NO_PROXY'] = '*'
                environment['no_proxy'] = '*'
            else:
                slot = self.slots[proxy_slot]
                host = self.socks_probe_host()
                proxy = f'[{host}]:{slot.socks_tcp}' if ':' in host else f'{host}:{slot.socks_tcp}'
                command.extend(['--socks5-hostname', proxy, '--noproxy', ''])
                if self.proxy_username and self.proxy_password:
                    command.extend(['--proxy-user', f'{self.proxy_username}:{self.proxy_password}'])
            command.extend([self.subscription_url, '-o', str(temp_path)])
            result = subprocess.run(
                command, capture_output=True, text=True, timeout=110, env=environment
            )
            if result.returncode != 0:
                raise RuntimeError((result.stderr or result.stdout or 'curl failed').strip())
            with temp_path.open('r', encoding='utf-8-sig') as file_handle:
                payload = json.load(file_handle)
            if isinstance(payload, dict):
                configs = [payload]
            elif isinstance(payload, list):
                configs = payload
            else:
                raise ValueError('subscription must be a JSON object or array')
            normalized = [item for item in configs if isinstance(item, dict)]
            if not normalized:
                raise ValueError('subscription contains no JSON configuration objects')
            return normalized
        finally:
            temp_path.unlink(missing_ok=True)

    def download_subscription(self) -> list[dict[str, Any]]:
        """Download directly first, then fall back to already running Xray slots."""
        try:
            configs = self.download_subscription_once()
            self.debug_log('subscription downloaded directly without a slot proxy')
            return configs
        except Exception as direct_exc:
            errors = [f'direct: {direct_exc}']
            with self.lock:
                ordered_slots = [self.active_slot_tag] + [
                    tag for tag in xpm_common.SLOT_TAGS if tag != self.active_slot_tag
                ]
                running_slots = [tag for tag in ordered_slots if self.slots[tag].running()]
            if not running_slots:
                raise RuntimeError(str(direct_exc)) from direct_exc
            xpm_common.log(
                'direct subscription download failed; retrying through already running '
                f'Xray slot(s): {", ".join(running_slots)}',
                error=True,
            )
            for slot_tag in running_slots:
                try:
                    configs = self.download_subscription_once(slot_tag)
                    xpm_common.log(f'subscription download succeeded through running Xray slot {slot_tag}')
                    return configs
                except Exception as proxy_exc:
                    errors.append(f'{slot_tag}: {proxy_exc}')
            raise RuntimeError('; '.join(errors)) from direct_exc

    def load_cached_subscription(self) -> list[dict[str, Any]]:
        payload = xpm_persistence.load_json(xpm_common.SUBSCRIPTION_PATH, None)
        if isinstance(payload, dict):
            return [payload]
        if isinstance(payload, list):
            return [item for item in payload if isinstance(item, dict)]
        return []

    def sing_box_subscription(self) -> tuple[dict[str, Any], dict[str, Any]]:
        with self.lock:
            source = copy.deepcopy(self.subscription)
        if not source:
            source = self.load_cached_subscription()
        if not source:
            raise RuntimeError('Текущая подписка пуста')

        config, metadata = xpm_conversion.convert_xray_subscription_to_sing_box(
            source,
            test_url=self.primary_test_url,
        )
        skipped = metadata.get('skipped') or []
        xpm_common.log(
            'sing-box subscription converted: '
            f'{metadata.get("converted_count", 0)} outbound(s), {len(skipped)} skipped'
        )
        for item in skipped:
            xpm_common.log(
                'sing-box conversion skipped '
                f'{item.get("name", "unknown")} [{item.get("protocol", "unknown")}]: '
                f'{item.get("reason", "unknown reason")}'
            )
        return config, metadata

    def extract_candidates(self, configs: list[dict[str, Any]]) -> list[xpm_models.Candidate]:
        entries: list[tuple[str, str, xpm_models.Candidate]] = []
        seen_ids: set[str] = set()
        for source_index, raw_config in enumerate(configs):
            config = xpm_config.ensure_outbound_tags(raw_config)
            profile_name = xpm_config.config_display_name(config, source_index)
            proxy_entries: list[tuple[int, dict[str, Any]]] = []
            for outbound_index, outbound in enumerate(config.get('outbounds') or []):
                if not isinstance(outbound, dict):
                    continue
                protocol = str(outbound.get('protocol') or '').lower()
                tag = str(outbound.get('tag') or '')
                if not protocol or protocol in xpm_common.DIRECT_PROTOCOLS or tag.lower() in xpm_common.DIRECT_TAGS:
                    continue
                proxy_entries.append((outbound_index, outbound))

            if not proxy_entries:
                continue

            multiple = len(proxy_entries) > 1
            for outbound_index, outbound in proxy_entries:
                tag = str(outbound.get('tag') or f'ui-outbound-{outbound_index + 1}')
                protocol = str(outbound.get('protocol') or 'unknown')
                server, port = xpm_config.extract_endpoint(outbound)
                outbound_name = xpm_common.first_text(outbound.get('remarks'), outbound.get('name'), tag)
                name = f'{profile_name} — {outbound_name}' if multiple else profile_name
                if name == f'Профиль {source_index + 1}' and outbound_name:
                    name = outbound_name

                fingerprint_payload = {
                    'profile_name': profile_name,
                    'protocol': protocol,
                    'server': server,
                    'port': port,
                    'outbound': {key: value for key, value in outbound.items() if key != 'tag'},
                }
                fingerprint = hashlib.sha256(
                    json.dumps(
                        fingerprint_payload,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(',', ':'),
                    ).encode('utf-8')
                ).hexdigest()[:20]
                candidate_id = fingerprint
                serial = 2
                while candidate_id in seen_ids:
                    candidate_id = f'{fingerprint}-{serial}'
                    serial += 1
                seen_ids.add(candidate_id)
                entries.append((xpm_identity.candidate_identity_key(outbound), candidate_id, xpm_models.Candidate(
                    id=candidate_id,
                    source_index=source_index,
                    outbound_index=outbound_index,
                    outbound_tag=tag,
                    name=name,
                    protocol=protocol.upper(),
                    server=server,
                    port=port,
                    country_code=xpm_common.infer_country_code(name, tag, server),
                    fingerprint=xpm_identity.config_hash(xpm_identity.technical_outbound(outbound))[:20],
                    config_revision=xpm_identity.candidate_config_revision(config, tag),
                    config=config,
                )))

        registry = self.state.setdefault('candidate_identities', {})
        aliases = getattr(self, 'candidate_aliases', {}).copy()
        candidates: list[xpm_models.Candidate] = []
        groups: dict[str, dict[str, list[tuple[str, xpm_models.Candidate]]]] = {}
        for key, legacy_id, candidate in entries:
            groups.setdefault(key, {}).setdefault(candidate.config_revision, []).append((legacy_id, candidate))
        for key, revisions in sorted(groups.items()):
            previous = {cid: data for cid, data in registry.items() if data.get('key') == key}
            assigned = {}
            for revision in sorted(revisions):
                match = next((cid for cid, data in previous.items() if data.get('revision') == revision), None)
                if match:
                    assigned[revision] = match
            unmatched = sorted(set(revisions) - set(assigned))
            remaining = sorted(set(previous) - set(assigned.values()))
            # A unique changed variant keeps its identity. Ambiguous variants
            # are never matched by position or human-readable name.
            if len(unmatched) == len(remaining) == 1:
                assigned[unmatched[0]] = remaining[0]
            for revision, duplicates in sorted(revisions.items()):
                cid = assigned.get(revision)
                if not cid:
                    cid = key[:24] if not previous and len(revisions) == 1 else xpm_identity.config_hash([key, revision])[:24]
                candidate = min((item for _legacy, item in duplicates), key=lambda item: (item.name, item.outbound_tag))
                candidate = replace(candidate, id=cid)
                candidates.append(candidate)
                for legacy_id, _item in duplicates:
                    aliases[legacy_id] = cid
                    legacy = self.latencies.get(legacy_id)
                    if legacy and cid not in self.latencies:
                        self.latencies[cid] = {**legacy, 'config_revision': revision}
                cached = self.latencies.get(cid)
                if cached and cached.get('config_revision', revision) != revision:
                    self.latencies.pop(cid, None)
                registry[cid] = {'key': key, 'revision': revision}
        self.candidate_aliases = aliases
        remembered = str(self.state.get('active_candidate_id') or '')
        if remembered in aliases:
            self.state['active_candidate_id'] = aliases[remembered]
            if self.active_candidate_id == remembered:
                self.active_candidate_id = aliases[remembered]
        # Presentation retains subscription order; identity never uses it.
        candidates.sort(key=lambda item: (item.source_index, item.outbound_index))
        return candidates

    def candidate_by_id(self, candidate_id: str) -> xpm_models.Candidate | None:
        candidate_id = getattr(self, 'candidate_aliases', {}).get(candidate_id, candidate_id)
        return next((item for item in self.candidates if item.id == candidate_id), None)

    @staticmethod
    def slot_candidate_id(slot_tag: str) -> str:
        return f'slot:{slot_tag}'

    def running_slot_by_candidate_id(self, candidate_id: str) -> xpm_models.XraySlot | None:
        if candidate_id.startswith('slot:'):
            slot = self.slots.get(candidate_id.removeprefix('slot:'))
            return slot if slot is not None and slot.running() else None
        return next(
            (
                slot for slot in self.slots.values()
                if slot.running()
                and candidate_id
                and candidate_id in {
                    slot.candidate_id,
                    slot.candidate.id if slot.candidate is not None else '',
                }
            ),
            None,
        )

    @staticmethod
    def same_outbound(left: xpm_models.Candidate | None, right: xpm_models.Candidate | None) -> bool:
        if left is None or right is None:
            return False
        if left.config_revision and right.config_revision:
            return left.id == right.id and left.config_revision == right.config_revision
        if left.id and left.id == right.id:
            return True
        if left.fingerprint and left.fingerprint == right.fingerprint:
            return True
        if left.id or right.id or left.fingerprint or right.fingerprint:
            return False
        return (
            left.protocol.casefold(),
            left.server.casefold(),
            left.port,
            left.outbound_tag,
        ) == (
            right.protocol.casefold(),
            right.server.casefold(),
            right.port,
            right.outbound_tag,
        )

    @staticmethod
    def same_candidate_identity(left: xpm_models.Candidate | None, right: xpm_models.Candidate | None) -> bool:
        """Compare concrete subscription entries without merging duplicates.

        Fingerprints intentionally survive subscription refreshes, so two
        duplicate entries can share one fingerprint while having distinct IDs.
        Runtime slot and active-card assignment must prefer the concrete ID.
        """
        if left is None or right is None:
            return False
        if left.id and right.id:
            return left.id == right.id
        return SubscriptionMixin.same_outbound(left, right)

    def candidate_by_tag(self, outbound_tag: str, preferred_source: int | None = None) -> xpm_models.Candidate | None:
        matches = [item for item in self.candidates if item.outbound_tag == outbound_tag]
        if preferred_source is not None:
            preferred = next((item for item in matches if item.source_index == preferred_source), None)
            if preferred:
                return preferred
        return matches[0] if matches else None

    def candidate_latency_ms(self, candidate: xpm_models.Candidate | None) -> int | None:
        if candidate is None:
            return None
        data = self.latencies.get(candidate.id) or {}
        latency_ms = data.get('latency_ms')
        if data.get('status') != 'ok' or not isinstance(latency_ms, int):
            return None
        return latency_ms

    def choose_initial_candidate(self, preferred: xpm_models.Candidate | None = None) -> xpm_models.Candidate:
        selected = preferred
        if selected is None:
            remembered = str(self.state.get('active_candidate_id') or '')
            if remembered:
                selected = self.candidate_by_id(remembered)
        if selected is None:
            matching_index = [
                item for item in self.candidates if item.source_index == self.config_index
            ]
            selected = matching_index[0] if matching_index else None
        if selected is None:
            if not self.candidates:
                raise RuntimeError('No proxy outbounds were found in the subscription.')
            selected = self.candidates[0]

        if not self.auto_switch_best_enabled:
            return selected

        allowed = [item for item in self.candidates if not self.candidate_is_excluded(item)]
        if not allowed:
            raise RuntimeError(
                'No proxy outbounds remain after applying configured selection exclusions.'
            )

        healthy = self.sorted_healthy_candidates(exclude_configured_countries=True)
        if self.candidate_is_excluded(selected):
            allowed_for_index = [
                item for item in allowed if item.source_index == self.config_index
            ]
            replacement = healthy[0] if healthy else (
                allowed_for_index[0] if allowed_for_index else allowed[0]
            )
            xpm_common.log(
                f'startup skipped excluded outbound {selected.name} '
                f'[{selected.outbound_tag}]; selected {replacement.name} '
                f'[{replacement.outbound_tag}] instead'
            )
            selected = replacement

        if not healthy:
            return selected
        best = healthy[0]
        if self.same_outbound(selected, best):
            return selected

        selected_latency = self.candidate_latency_ms(selected)
        best_latency = self.candidate_latency_ms(best)
        if best_latency is None:
            return selected

        improvement = (
            selected_latency - best_latency
            if isinstance(selected_latency, int) else None
        )
        preferred_switch = (
            self.candidate_preference_score(best)
            > self.candidate_preference_score(selected)
        )
        if preferred_switch or selected_latency is None or (
            isinstance(improvement, int)
            and improvement >= self.auto_switch_min_ping_delta_ms
        ):
            previous_latency = f'{selected_latency} ms' if selected_latency is not None else 'unknown'
            if preferred_switch:
                xpm_common.log(
                    f'startup selected preferred outbound {best.name} '
                    f'({best_latency} ms) instead of '
                    f'{selected.name} ({previous_latency})'
                )
            else:
                xpm_common.log(
                    f'startup selected cached best outbound {best.name} ({best_latency} ms) '
                    f'instead of {selected.name} ({previous_latency})'
                )
            return best
        return selected

    def refresh_subscription_sync(self, *, initial: bool = False) -> None:
        attempt_at = xpm_common.now_ts()
        with self.lock:
            self.state['subscription_last_attempt_at'] = attempt_at
            self.save_state()

        downloaded = False
        try:
            configs = self.download_subscription()
            downloaded = True
            download_error = ''
            with self.lock:
                self.state['subscription_consecutive_failures'] = 0
        except Exception as exc:
            download_error = str(exc)
            with self.lock:
                self.state['subscription_consecutive_failures'] = int(
                    self.state.get('subscription_consecutive_failures') or 0
                ) + 1
                self.save_state()
            configs = self.load_cached_subscription()
            if not configs:
                with self.lock:
                    self.state['subscription_error'] = download_error
                    self.state['subscription_last_error_at'] = xpm_common.now_ts()
                    self.save_state()
                raise
            xpm_common.log(
                f'subscription update failed; using cached subscription: {download_error}',
                error=True,
            )

        # Downloads remain concurrent with manual selection. Only committing
        # the new list waits for a selection (and vice versa).
        with self.subscription_apply_lock, self.switch_lock:
            self.apply_subscription(configs, downloaded, download_error, initial=initial)

    def apply_subscription(
        self, configs: list[dict[str, Any]], downloaded: bool, download_error: str,
        *, initial: bool = False,
    ) -> None:
        with self.lock:
            old_subscription = self.subscription
            old_candidates = self.candidates
            old_active_id = self.active_candidate_id
            old_active_slot_tag = self.active_slot_tag
            old_identities = copy.deepcopy(self.state.get('candidate_identities', {}))
            old_aliases = dict(getattr(self, 'candidate_aliases', {}))
            old_latencies = copy.deepcopy(self.latencies)
            old_active_candidate = (
                self.slots[old_active_slot_tag].candidate
                or self.candidate_by_id(old_active_id)
            )


        try:
            with self.lock:
                candidates = self.extract_candidates(configs)
            if not candidates:
                raise RuntimeError('No usable proxy outbounds were found in the subscription.')

            with self.lock:
                self.subscription = configs
                self.candidates = candidates
                active_slot = self.slots[self.active_slot_tag]
                active_running = active_slot.running()

                selected: xpm_models.Candidate | None = None
                if old_active_candidate is not None:
                    selected = next(
                        (item for item in candidates if item.id == old_active_candidate.id),
                        None,
                    )
                    if selected is None:
                        selected = next(
                            (
                                item for item in candidates
                                if item.fingerprint == old_active_candidate.fingerprint
                            ),
                            None,
                        )
                if initial:
                    selected = self.choose_initial_candidate(selected)
                elif selected is None and not active_running:
                    selected = self.choose_initial_candidate()

            if initial or not active_running:
                if selected is None:
                    raise RuntimeError('Не удалось выбрать outbound для запуска Xray.')
                self.start_initial_candidate(
                    selected,
                    'initial start' if initial else 'start after subscription refresh',
                    source='startup_subscription' if initial else 'subscription_refresh',
                )
            else:
                with self.lock:
                    active_slot = self.slots[self.active_slot_tag]
                    if selected is not None and self.same_outbound(selected, active_slot.candidate):
                        active_slot.candidate = selected
                        active_slot.candidate_id = selected.id
                        active_slot.candidate_name = selected.name
                        self.active_candidate_id = selected.id
                    else:
                        # Keep the currently running configuration intact even if
                        # it disappeared from the refreshed subscription.
                        self.active_candidate_id = old_active_id
                    self.rebind_slot_candidates()
                    self.save_state()
                if selected is not None and self.runtime_config_differs(
                    self.active_slot_tag, selected
                ):
                    xpm_common.log(
                        'subscription changed the active outbound configuration; '
                        'the running Xray processes were preserved and the new '
                        'configuration will be applied on the next explicit selection'
                    )

        except Exception:
            with self.lock:
                self.subscription = old_subscription
                self.candidates = old_candidates
                self.active_candidate_id = old_active_id
                self.active_slot_tag = old_active_slot_tag
                self.state['active_candidate_id'] = old_active_id
                self.state['active_slot_tag'] = old_active_slot_tag
                self.state['candidate_identities'] = old_identities
                self.candidate_aliases = old_aliases
                self.latencies = old_latencies
                self.state['subscription_error'] = (
                    'Загруженную подписку не удалось применить; предыдущая рабочая '
                    'подписка сохранена.'
                )
                self.state['subscription_last_error_at'] = xpm_common.now_ts()
                self.save_state()
            raise

        with self.lock:
            if downloaded:
                xpm_persistence.atomic_write_json(xpm_common.SUBSCRIPTION_PATH, configs)
                success_at = xpm_common.now_ts()
                self.state['subscription_updated_at'] = success_at
                self.state['subscription_last_success_at'] = success_at
                self.state['subscription_error'] = ''
                self.state['subscription_consecutive_failures'] = 0
                self.state['suspect_candidate_ids'] = []
            else:
                self.state['subscription_error'] = download_error
                self.state['subscription_last_error_at'] = xpm_common.now_ts()
            self.save_latencies()
            self.save_state()
            self.next_update_at = (
                xpm_common.now_ts() + self.update_interval_hours * 3600
                if self.update_interval_hours > 0 else None
            )

    def refresh_subscription_job(self) -> None:
        xpm_common.log('manual subscription refresh started')
        try:
            self.refresh_subscription_sync(initial=False)
            with self.lock:
                error = self.state.get('subscription_error', '')
                count = len(self.candidates)
            if error:
                message = f'Подписка не обновлена: {error}'
                xpm_common.log(f'manual subscription refresh failed; cached subscription retained: {error}', error=True)
            else:
                message = 'Подписка обновлена'
                xpm_common.log(f'manual subscription refresh completed: {count} outbounds')
        except Exception as exc:
            xpm_common.log(f'manual subscription refresh failed: {exc}', error=True)
            message = f'Ошибка: {exc}'
        finally:
            with self.lock:
                # A manual refresh starts a new subscription-update interval even
                # when the current attempt fails, so the periodic loop does not
                # immediately repeat the same request.
                self.next_update_at = (
                    xpm_common.now_ts() + self.update_interval_hours * 3600
                    if self.update_interval_hours > 0 else None
                )
                self.state['jobs']['refresh'].update({'running': False, 'message': message})
                self.save_state()

    def request_refresh(self) -> bool:
        with self.lock:
            if self.state['jobs']['refresh'].get('running'):
                return False
            self.state['jobs']['refresh'].update({'running': True, 'message': 'Обновление подписки...'})
            self.save_state()
            threading.Thread(target=self.refresh_subscription_job, daemon=True).start()
            return True

    def excluded_country_codes(self) -> set[str]:
        country_codes, _fragments = xpm_common.parse_auto_switch_exclusions(
            self.auto_switch_excluded
        )
        return country_codes

    def excluded_outbound_fragments(self) -> list[str]:
        _country_codes, fragments = xpm_common.parse_auto_switch_exclusions(
            self.auto_switch_excluded
        )
        return fragments

    def candidate_is_excluded(self, candidate: xpm_models.Candidate) -> bool:
        country_codes, fragments = xpm_common.parse_auto_switch_exclusions(
            self.auto_switch_excluded
        )
        if candidate.country_code and candidate.country_code in country_codes:
            return True
        haystack = ' '.join((
            candidate.name,
            candidate.outbound_tag,
            candidate.protocol,
            candidate.server,
            candidate.id,
        )).casefold()
        return any(fragment in haystack for fragment in fragments)

    def candidate_country_is_excluded(self, candidate: xpm_models.Candidate) -> bool:
        # Compatibility alias: exclusions now also include text fragments.
        return self.candidate_is_excluded(candidate)

    def sorted_healthy_candidates(self, exclude_configured_countries: bool = False) -> list[xpm_models.Candidate]:
        healthy: list[tuple[int, xpm_models.Candidate]] = []
        for candidate in self.candidates:
            if exclude_configured_countries and self.candidate_is_excluded(candidate):
                continue
            data = self.latencies.get(candidate.id) or {}
            latency_ms = data.get('latency_ms')
            if data.get('status') == 'ok' and isinstance(latency_ms, int):
                if self.auto_check_max_latency_ms > 0 and latency_ms > self.auto_check_max_latency_ms:
                    continue
                healthy.append((latency_ms, candidate))
        healthy.sort(key=lambda item: (
            *self.candidate_preference_sort_key(item[1]),
            item[0],
            item[1].name.casefold(),
        ))
        return [item[1] for item in healthy]

    def failover_candidates(self) -> list[xpm_models.Candidate]:
        """Return unique failover candidates in the order they should be tried.

        Previously healthy candidates are preferred because they are the most likely
        to restore traffic immediately. Candidates without a currently healthy
        latency result follow in the normal country/protocol preference order. The
        actual standby-slot validation is the authoritative check, so a separate
        pre-scan is intentionally avoided here.
        """
        active = (
            self.slots[self.active_slot_tag].candidate
            or self.candidate_by_id(self.active_candidate_id)
        )
        healthy = [
            candidate
            for candidate in self.sorted_healthy_candidates(
                exclude_configured_countries=True
            )
            if not self.same_outbound(candidate, active)
        ]

        ordered: list[xpm_models.Candidate] = []
        for candidate in healthy:
            if not any(self.same_outbound(candidate, seen) for seen in ordered):
                ordered.append(candidate)

        remaining = [
            candidate
            for candidate in self.candidates
            if not self.same_outbound(candidate, active)
            and not self.candidate_is_excluded(candidate)
            and not any(self.same_outbound(candidate, seen) for seen in ordered)
        ]
        remaining.sort(key=lambda candidate: (
            *self.candidate_preference_sort_key(candidate),
            candidate.name.casefold(),
        ))
        ordered.extend(remaining)
        return ordered

    def choose_failover_candidate(self) -> xpm_models.Candidate | None:
        candidates = self.failover_candidates()
        return candidates[0] if candidates else None

    def periodic_update_loop(self) -> None:
        while not self.stop_event.wait(5):
            if self.update_interval_hours <= 0 or self.next_update_at is None:
                continue
            if xpm_common.now_ts() < self.next_update_at:
                continue
            try:
                self.refresh_subscription_sync(initial=False)
            except Exception as exc:
                xpm_common.log(f'periodic subscription update failed: {exc}', error=True)
                self.next_update_at = xpm_common.now_ts() + self.update_interval_hours * 3600

    def unique_candidate_match(self, predicate: Callable[[xpm_models.Candidate], bool]) -> xpm_models.Candidate | None:
        matches = [item for item in self.candidates if predicate(item)]
        return matches[0] if len(matches) == 1 else None

    def rebind_slot_candidates(self) -> bool:
        """Rebind running slots without guessing by display name.

        A subscription refresh may rebuild candidate IDs, but a running Xray
        process still uses the exact configuration that was written into its
        slot. Rebinding therefore uses only an exact candidate ID or a unique full-profile fingerprint.
        If the outbound disappeared from the refreshed subscription, the stale
        slot candidate is intentionally retained and displayed as a normal
        outbound until that running slot is stopped.
        """
        changed = False
        for tag, slot in self.slots.items():
            if not slot.running():
                continue
            stale = slot.candidate
            match: xpm_models.Candidate | None = None
            if tag == self.active_slot_tag and self.active_candidate_id:
                match = self.candidate_by_id(self.active_candidate_id)
            if match is None and slot.candidate_id:
                match = self.candidate_by_id(slot.candidate_id)
            if match is None and stale is not None and stale.fingerprint:
                match = self.unique_candidate_match(
                    lambda item: item.fingerprint == stale.fingerprint
                )
            if match is None and stale is None and slot.observed_outbound_tag:
                match = self.unique_candidate_match(
                    lambda item: item.outbound_tag == slot.observed_outbound_tag
                )
            if match is None:
                continue
            if stale is not None and stale.config_revision and match.config_revision != stale.config_revision:
                # Keep the snapshot of the process that is actually running.
                continue
            if slot.candidate_id != match.id or slot.candidate is not match:
                changed = True
            slot.candidate = match
            slot.candidate_id = match.id
            slot.candidate_name = match.name
            if tag == self.active_slot_tag and self.active_candidate_id != match.id:
                self.active_candidate_id = match.id
                self.state['active_candidate_id'] = match.id
                changed = True
        return changed

    def effective_active_candidate(self) -> tuple[xpm_models.Candidate | None, xpm_models.Candidate | None, bool]:
        active_slot = self.slots[self.active_slot_tag]
        selected = self.candidate_by_id(self.active_candidate_id) or active_slot.candidate
        observed = None
        if active_slot.observed_outbound_tag:
            preferred_source = selected.source_index if selected else None
            observed = self.candidate_by_tag(active_slot.observed_outbound_tag, preferred_source)

        # The generated runtime rule explicitly selects active_candidate_id.
        # Runtime log observations remain diagnostic only: they can include
        # auxiliary traffic and must not clear the UI selection or re-enable
        # the Select button for the already configured outbound.
        effective = active_slot.candidate or selected or observed
        mismatch = bool(observed and selected and observed.id != selected.id)
        return effective, selected, mismatch
