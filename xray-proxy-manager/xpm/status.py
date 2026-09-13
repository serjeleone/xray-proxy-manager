from __future__ import annotations

import copy
from typing import Any
from . import common as xpm_common


class StatusMixin:
    def status_payload(self) -> dict[str, Any]:
        with self.lock:
            if self.rebind_slot_candidates():
                self.save_state()
            active_slot = self.slots[self.active_slot_tag]
            process_running = active_slot.running()
            active, selected, mismatch = self.effective_active_candidate()
            runtime_active_candidate = active_slot.candidate or selected or active
            effective_id = runtime_active_candidate.id if runtime_active_candidate else ''
            represented_slots: set[str] = set()
            candidates = []
            for item in self.candidates:
                assigned_slots = [
                    tag for tag, slot in self.slots.items()
                    if slot.running() and self.same_candidate_identity(item, slot.candidate)
                ]
                represented_slots.update(assigned_slots)
                draining_slots = [
                    tag for tag in assigned_slots if self.slots[tag].draining
                ]
                is_active = bool(
                    process_running and self.active_slot_tag in assigned_slots
                )
                payload = item.public(self.latencies.get(item.id), is_active)
                payload['slot_tags'] = assigned_slots
                payload['draining_slots'] = draining_slots
                payload['draining'] = bool(draining_slots)
                payload['excluded'] = self.candidate_is_excluded(item)
                payload['checking'] = item.id in getattr(self, 'latency_checking_ids', set())
                payload['suspect'] = not is_active and item.id in self.state.get('suspect_candidate_ids', [])
                payload['config_changed'] = bool(is_active and not self.same_outbound(item, active_slot.candidate))
                candidates.append(payload)

            # A running slot may still use an outbound removed by a subscription
            # refresh. Keep it visible as a normal card until the slot finishes,
            # without attaching it to a similarly named replacement.
            for tag, slot in self.slots.items():
                if not slot.running() or tag in represented_slots:
                    continue
                stale = slot.candidate
                stale_id = slot.candidate_id or (stale.id if stale else '')
                display_id = self.slot_candidate_id(tag)
                latency = self.latencies.get(display_id)
                if latency is None and stale_id:
                    latency = self.latencies.get(stale_id)
                payload = {
                    'id': display_id,
                    'source_index': stale.source_index if stale else -1,
                    'outbound_index': stale.outbound_index if stale else -1,
                    'outbound_tag': (
                        stale.outbound_tag if stale else slot.observed_outbound_tag
                    ),
                    'name': slot.candidate_name or (stale.name if stale else '') or f'Слот {tag}',
                    'protocol': stale.protocol if stale else '',
                    'server': stale.server if stale else '',
                    'port': stale.port if stale else None,
                    'country_code': stale.country_code if stale else '',
                    'fingerprint': stale.fingerprint if stale else '',
                    'latency': latency,
                    'active': bool(process_running and tag == self.active_slot_tag),
                    'slot_tags': [tag],
                    'draining_slots': [tag] if slot.draining else [],
                    'draining': bool(slot.draining),
                    'excluded': False,
                    'checking': display_id in getattr(self, 'latency_checking_ids', set()),
                    'suspect': tag != self.active_slot_tag and stale_id in self.state.get('suspect_candidate_ids', []),
                }
                candidates.append(payload)
            protocols = sorted({item.protocol for item in self.candidates})
            countries = sorted({
                item.country_code for item in self.candidates
                if item.country_code
            })
            available_count = sum(
                1 for item in candidates
                if (item.get('latency') or {}).get('status') == 'ok'
            )
            unavailable_count = sum(
                1 for item in candidates
                if (item.get('latency') or {}).get('status') == 'error'
            )
            slots_payload = {}
            for tag, slot in self.slots.items():
                slots_payload[tag] = {
                    'tag': tag,
                    'running': slot.running(),
                    'active': tag == self.active_slot_tag,
                    'draining': slot.draining,
                    'candidate_id': slot.candidate_id,
                    'candidate_name': slot.candidate_name,
                    'candidate_fingerprint': slot.candidate.fingerprint if slot.candidate else '',
                    'candidate_outbound_tag': slot.candidate.outbound_tag if slot.candidate else '',
                    'candidate_protocol': slot.candidate.protocol if slot.candidate else '',
                    'candidate_server': slot.candidate.server if slot.candidate else '',
                    'candidate_port': slot.candidate.port if slot.candidate else None,
                    'socks_tcp': slot.socks_tcp,
                    'socks_udp': slot.socks_udp,
                    'started_at': slot.started_at,
                    'drain_started_at': slot.drain_started_at,
                    'drain_zero_since': slot.drain_zero_since,
                    'drain_protect_until': slot.drain_protect_until,
                    'drain_connections': slot.drain_connections,
                    'drain_tcp_connections': slot.drain_tcp_connections,
                    'drain_udp_connections': slot.drain_udp_connections,
                    'drain_bytes': slot.drain_bytes,
                    'drain_last_error': slot.drain_last_error,
                    'drain_degraded_checks': slot.drain_degraded_checks,
                    'drain_last_latency_ms': slot.drain_last_latency_ms,
                    'drain_last_checked_at': slot.drain_last_checked_at,
                    'drain_new_connections': slot.drain_new_connections,
                    'drain_stalled_connections': slot.drain_stalled_connections,
                    'observed_outbound_tag': slot.observed_outbound_tag,
                    'observed_outbound_at': slot.observed_outbound_at,
                }
            return {
                'version': xpm_common.ADDON_VERSION,
                'home_assistant_host': getattr(self, 'home_assistant_host', 'host'),
                'release_notes': xpm_common.release_notes_payload(),
                'xray_version': self.xray_version(),
                'started_at': self.started_at,
                'xray_running': process_running,
                'active': runtime_active_candidate.public(self.latencies.get(runtime_active_candidate.id), True) if runtime_active_candidate else None,
                'selected_active': selected.public(self.latencies.get(selected.id), selected.id == effective_id) if selected else None,
                'observed_outbound_tag': active_slot.observed_outbound_tag,
                'observed_outbound_at': active_slot.observed_outbound_at,
                'route_mismatch': mismatch,
                'candidates': candidates,
                'protocols': protocols,
                'countries': countries,
                'availability': {
                    'available': available_count,
                    'unavailable': unavailable_count,
                    'untested': max(0, len(candidates) - available_count - unavailable_count),
                    'total': len(candidates),
                },
                'subscription': {
                    'updated_at': self.state.get('subscription_updated_at'),
                    'last_attempt_at': self.state.get('subscription_last_attempt_at'),
                    'last_success_at': self.state.get('subscription_last_success_at') or self.state.get('subscription_updated_at'),
                    'last_error_at': self.state.get('subscription_last_error_at'),
                    'error': self.state.get('subscription_error') or '',
                    'consecutive_failures': int(
                        self.state.get('subscription_consecutive_failures') or 0
                    ),
                    'next_update_at': self.next_update_at,
                    'url': self.subscription_url,
                    'update_interval_hours': self.update_interval_hours,
                },
                'jobs': copy.deepcopy(self.state.get('jobs') or {}),
                'auto_checker': {
                    'enabled': self.auto_checker_enabled,
                    'switch_to_best': self.auto_switch_best_enabled,
                    'switching_preset': self.switching_preset,
                    'preferred_country': getattr(self, 'auto_switch_preferred_country', ''),
                    'preferred_protocol': getattr(self, 'auto_switch_preferred_protocol', ''),
                    'excluded': self.auto_switch_excluded,
                    'min_ping_delta_ms': self.auto_switch_min_ping_delta_ms,
                    'interval_seconds': self.auto_check_interval_seconds,
                    'failure_threshold': self.auto_check_failures,
                    'max_latency_ms': self.auto_check_max_latency_ms,
                    'best_check_interval_seconds': self.auto_best_check_interval_seconds,
                    'current_failures': int(self.state.get('auto_check_failures') or 0),
                    'last_check_at': self.state.get('auto_check_last_at'),
                    'last_best_check_at': self.state.get('auto_best_check_last_at'),
                    'last_error': self.state.get('auto_check_last_error') or '',
                    'last_switch_at': self.state.get('last_switch_at'),
                    'last_switch_reason': self.state.get('last_switch_reason') or '',
                    'last_switch_source': self.state.get('last_switch_source') or '',
                },
                'ui_settings': {
                    'port': getattr(self, 'ui_port', xpm_common.DEFAULT_UI_PORT),
                    'sort': self.ui_sort,
                    'protocol_filter': self.ui_protocol_filter,
                    'max_ping_ms': self.ui_max_ping_ms,
                    'hide_unavailable': self.ui_hide_unavailable,
                    'hide_excluded': self.ui_hide_excluded,
                },
                'selector': copy.deepcopy(self.selector_state),
                'router': copy.deepcopy(self.router_state),
                'blue_green': {
                    'mode': 'dual' if self.dual_slot_enabled else 'single',
                    'dual_slot_enabled': self.dual_slot_enabled,
                    'active_slot': self.active_slot_tag,
                    'selector_tag': self.selector_tag,
                    'drain_quiet_seconds': self.drain_quiet_seconds,
                    'drain_timeout_minutes': self.drain_timeout_minutes,
                    'switching_preset': self.switching_preset,
                    'slots': slots_payload,
                },
                'primary_test_url': self.primary_test_url,
                'secondary_test_url': self.secondary_test_url,
            }
