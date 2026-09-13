from __future__ import annotations

import copy
import ipaddress
import json
import os
import re
import shutil
import subprocess
import threading
from pathlib import Path
from typing import Any
from . import common as xpm_common, config as xpm_config, errors as xpm_errors, models as xpm_models, persistence as xpm_persistence


class RuntimeMixin:
    def patch_inbounds(
        self,
        config: dict[str, Any],
        *,
        test_port: int | None = None,
        slot_tag: str | None = None,
    ) -> dict[str, Any]:
        result = copy.deepcopy(config)
        if test_port is not None:
            listen = '127.0.0.1'
            socks_tcp = test_port
            socks_udp = False
        else:
            if slot_tag not in xpm_common.SLOT_TAGS:
                raise ValueError('slot_tag is required for a runtime Xray configuration')
            slot = self.slots[slot_tag]
            listen = getattr(self, 'socks_listen_address', '0.0.0.0')
            socks_tcp = slot.socks_tcp
            socks_udp = slot.socks_udp

        result.setdefault('log', {})['loglevel'] = 'none' if test_port is not None else self.log_level
        for key in ('api', 'metrics', 'stats', 'observatory', 'burstObservatory'):
            result.pop(key, None)
        # The manager performs the health checks and pins SOCKS traffic to the
        # selected outbound. Subscription balancers must not require the
        # observatories removed above, even when their rules are shadowed by
        # our SOCKS rule: Xray resolves every balancer's dependencies at startup.
        routing = result.get('routing') if isinstance(result.get('routing'), dict) else {}
        for balancer in routing.get('balancers') or []:
            if (balancer.get('strategy') or {}).get('type', '').lower() in {'leastping', 'leastload'}:
                balancer['strategy'] = {'type': 'random'}
        if test_port is None:
            if not slot.stats_port:
                slot.stats_port = self.find_free_port()
            result['api'] = {
                'tag': 'xpm-stats', 'listen': f'127.0.0.1:{slot.stats_port}',
                'services': ['StatsService'],
            }
            result['stats'] = {}
            result.setdefault('policy', {}).setdefault('system', {}).update({
                'statsInboundDownlink': True,
                'statsInboundUplink': True,
            })
        socks_settings: dict[str, Any] = {
            'auth': 'noauth',
            'udp': socks_udp,
            'userLevel': 8,
        }
        if test_port is None and self.proxy_username and self.proxy_password:
            socks_settings['auth'] = 'password'
            socks_settings['accounts'] = [{'user': self.proxy_username, 'pass': self.proxy_password}]

        socks_inbound = {
            'tag': 'socks',
            'listen': listen,
            'port': socks_tcp,
            'protocol': 'socks',
            'settings': socks_settings,
            'sniffing': {
                'enabled': True,
                'destOverride': ['http', 'tls'],
                'routeOnly': False,
            },
        }
        if test_port is not None:
            result['inbounds'] = [socks_inbound]
            return result

        if self.override_inbounds:
            result['inbounds'] = [socks_inbound]
            return result

        patched: list[Any] = []
        found_socks = False
        for inbound in result.get('inbounds') or []:
            if not isinstance(inbound, dict):
                patched.append(inbound)
                continue
            item = copy.deepcopy(inbound)
            if item.get('protocol') == 'socks':
                found_socks = True
                item.update(socks_inbound)
            patched.append(item)
        if not found_socks:
            patched.append(socks_inbound)
        result['inbounds'] = patched
        return result

    def build_config(
        self,
        candidate: xpm_models.Candidate,
        *,
        test_port: int | None = None,
        slot_tag: str | None = None,
    ) -> dict[str, Any]:
        source = candidate.config
        if source is None and candidate.source_index >= len(self.subscription):
            raise ValueError('candidate source config is no longer available')
        config = xpm_config.ensure_outbound_tags(source if source is not None else self.subscription[candidate.source_index])
        outbounds = config.get('outbounds') or []
        if candidate.outbound_index >= len(outbounds) or not isinstance(outbounds[candidate.outbound_index], dict):
            raise ValueError('candidate outbound is no longer available')

        selected_tag = str(outbounds[candidate.outbound_index].get('tag') or candidate.outbound_tag)
        config = self.patch_inbounds(config, test_port=test_port, slot_tag=slot_tag)
        config = xpm_config.fix_routing_tags(config, self.auto_fix_tags)
        config = xpm_config.add_proxy_direct(config, self.auto_add_proxy_direct)

        routing = config.setdefault('routing', {})
        if not isinstance(routing, dict):
            routing = {}
            config['routing'] = routing
        rules = routing.setdefault('rules', [])
        if not isinstance(rules, list):
            rules = []
            routing['rules'] = rules
        inbound_tags = ['socks']
        rules.insert(0, {
            'type': 'field',
            'inboundTag': inbound_tags,
            'outboundTag': selected_tag,
        })
        xpm_config.validate_routing_tags(config, self.validate_tags)
        if test_port is None:
            self.apply_socks_access_rules(config)
        return config

    def resolve_socks_allowed_cidrs(self, values: Any) -> list[str]:
        if isinstance(values, str):
            values = [item.strip() for item in values.split(',') if item.strip()]
        if not isinstance(values, list):
            raise ValueError('socks_allowed_cidrs: требуется список CIDR')
        networks = []
        for value in values:
            if str(value).strip().lower() == 'router':
                payload = json.loads(self.run_router_command('ubus call network.interface.lan status'))
                addresses = payload.get('ipv4-address', []) + payload.get('ipv6-address', [])
                router_networks = [
                    str(ipaddress.ip_network(f'{item["address"]}/{item["mask"]}', strict=False))
                    for item in addresses if 'address' in item and 'mask' in item
                ]
                if not router_networks:
                    raise ValueError('Не удалось определить LAN-сеть OpenWrt; укажите CIDR вручную')
                networks.extend(router_networks)
            else:
                networks.append(str(ipaddress.ip_network(str(value).strip(), strict=False)))
        return sorted(set(networks))

    def socks_probe_host(self) -> str:
        listen = getattr(self, 'socks_listen_address', '0.0.0.0')
        return {'0.0.0.0': '127.0.0.1', '::': '::1'}.get(listen, listen)

    def apply_socks_access_rules(self, config: dict[str, Any]) -> None:
        rules = config.setdefault('routing', {}).setdefault('rules', [])
        # Used for newly built, cloned and last-good configs alike.
        rules[:] = [rule for rule in rules if rule.get('ruleTag') != 'xpm-socks-access']
        allowed = list(getattr(self, 'socks_allowed_cidrs', ['0.0.0.0/0']))
        allowed.extend(['127.0.0.1/32', '::1/128'])
        probe_host = ipaddress.ip_address(self.socks_probe_host())
        allowed.append(f'{probe_host}/{probe_host.max_prefixlen}')
        outbounds = config.setdefault('outbounds', [])
        block_tag = 'xpm-socks-denied'
        while any(item.get('tag') == block_tag and item.get('protocol') != 'blackhole' for item in outbounds):
            block_tag += '-'
        if not any(item.get('tag') == block_tag for item in outbounds):
            outbounds.append({'tag': block_tag, 'protocol': 'blackhole'})
        for index, rule in enumerate(rules):
            if rule.get('inboundTag') == ['socks']:
                rule['source'] = sorted(set(allowed))
                rules.insert(index + 1, {
                    'type': 'field', 'ruleTag': 'xpm-socks-access',
                    'inboundTag': ['socks'], 'outboundTag': block_tag,
                })
                break

    def xray_test(self, config_path: Path) -> tuple[bool, str]:
        result = subprocess.run(
            [xpm_common.XRAY_BIN, '-test', '-config', str(config_path)],
            capture_output=True,
            text=True,
            timeout=30,
        )
        output = '\n'.join(
            xpm_common.normalize_xray_log_line(line)
            for part in (result.stdout, result.stderr) if part.strip()
            for line in part.strip().splitlines()
        )
        bad_markers = (
            'Failed to start',
            'not all dependencies are resolved',
            'failed to decode config',
            'Failed to get format',
            'EOF',
        )
        ok = result.returncode == 0 and not any(marker in output for marker in bad_markers)
        return ok, output

    def prepare_slot_config(self, slot_tag: str, candidate: xpm_models.Candidate) -> tuple[Path, bool]:
        """Build and validate a slot config without interrupting the running Xray."""
        slot = self.slots[slot_tag]
        config = self.build_config(candidate, slot_tag=slot_tag)
        temp_path = slot.config_path.with_name(f'{slot.config_path.stem}.new.json')
        xpm_persistence.atomic_write_json(temp_path, config)
        ok, output = self.xray_test(temp_path)
        if not ok:
            temp_path.unlink(missing_ok=True)
            raise xpm_errors.ProbeFailure(output or 'xray config validation failed')
        old_bytes = slot.config_path.read_bytes() if slot.config_path.exists() else None
        new_bytes = temp_path.read_bytes()
        changed = old_bytes != new_bytes
        return temp_path, changed

    def install_prepared_slot_config(
        self,
        slot_tag: str,
        candidate: xpm_models.Candidate,
        temp_path: Path,
    ) -> None:
        slot = self.slots[slot_tag]
        os.replace(temp_path, slot.config_path)
        slot.candidate_id = candidate.id
        slot.candidate_name = candidate.name
        slot.candidate = candidate

    def write_slot_config(self, slot_tag: str, candidate: xpm_models.Candidate) -> bool:
        temp_path, changed = self.prepare_slot_config(slot_tag, candidate)
        self.install_prepared_slot_config(slot_tag, candidate, temp_path)
        return changed

    def runtime_config_differs(self, slot_tag: str, candidate: xpm_models.Candidate) -> bool:
        slot = self.slots[slot_tag]
        current = xpm_persistence.load_json(slot.config_path, {})
        if not isinstance(current, dict) or not current:
            return True
        expected = self.build_config(candidate, slot_tag=slot_tag)
        return current != expected

    def save_active_config(self, slot_tag: str, candidate: xpm_models.Candidate) -> None:
        slot = self.slots[slot_tag]
        if not slot.config_path.exists():
            raise RuntimeError(f'Active configuration for {slot_tag} is missing')
        # config.json and last_good must represent only a successfully activated
        # path, never a merely prepared standby candidate.
        shutil.copy2(slot.config_path, xpm_common.CONFIG_PATH)
        shutil.copy2(slot.config_path, xpm_common.LAST_GOOD_CONFIG_PATH)
        xpm_persistence.atomic_write_json(xpm_common.LAST_GOOD_META_PATH, {
            'candidate_id': candidate.id,
            'fingerprint': candidate.fingerprint,
            'source_index': candidate.source_index,
            'outbound_tag': candidate.outbound_tag,
            'name': candidate.name,
            'slot_tag': slot_tag,
            'saved_at': xpm_common.now_ts(),
        })

    def clone_slot_config(self, source_tag: str, target_tag: str) -> None:
        source = self.slots[source_tag]
        target = self.slots[target_tag]
        config = xpm_persistence.load_json(source.config_path, {})
        if not isinstance(config, dict) or not config:
            raise RuntimeError(f'Cannot clone missing configuration from {source_tag}')
        config = self.patch_inbounds(config, slot_tag=target_tag)
        self.apply_socks_access_rules(config)
        temp_path = target.config_path.with_name(f'{target.config_path.stem}.new.json')
        xpm_persistence.atomic_write_json(temp_path, config)
        ok, output = self.xray_test(temp_path)
        if not ok:
            temp_path.unlink(missing_ok=True)
            raise RuntimeError(output or f'Cloned configuration for {target_tag} is invalid')
        os.replace(temp_path, target.config_path)
        target.candidate_id = source.candidate_id
        target.candidate_name = source.candidate_name
        target.candidate = source.candidate

    def write_runtime_config(self, candidate: xpm_models.Candidate) -> bool:
        return self.write_slot_config(self.active_slot_tag, candidate)

    def log_xray_output(self, slot_tag: str, process: subprocess.Popen[str]) -> None:
        assert process.stdout is not None
        for line in process.stdout:
            text = xpm_common.normalize_xray_log_line(line.rstrip('\n'))
            match = xpm_common.OUTBOUND_LOG_RE.search(text)
            if match:
                observed_tag = match.group(1)
                with self.lock:
                    slot = self.slots[slot_tag]
                    slot.observed_outbound_tag = observed_tag
                    slot.observed_outbound_at = xpm_common.now_ts()
            if self.disable_observatory and 'app/observatory/burst: error ping ' in text:
                continue
            xpm_common.log(text, prefix=f'[{slot_tag}]')

    def start_slot(self, slot_tag: str, candidate: xpm_models.Candidate | None = None) -> None:
        slot = self.slots[slot_tag]
        with self.lock:
            if slot.running():
                if candidate is not None and slot.candidate_id != candidate.id:
                    raise RuntimeError(
                        f'{slot_tag} is already running {slot.candidate_name or slot.candidate_id}'
                    )
                return
        if candidate is not None:
            self.write_slot_config(slot_tag, candidate)
        with self.lock:
            if slot.running():
                if candidate is not None and slot.candidate_id != candidate.id:
                    raise RuntimeError(f'{slot_tag} was started concurrently with another outbound')
                return
            if not slot.config_path.exists():
                raise RuntimeError(f'Configuration for {slot_tag} is missing')
            xpm_common.log(f'starting xray-core slot {slot_tag} on SOCKS {slot.socks_tcp}...')
            slot.intentional_stop = False
            slot.observed_outbound_tag = ''
            slot.observed_outbound_at = None
            process = subprocess.Popen(
                [xpm_common.XRAY_BIN, '-config', str(slot.config_path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            slot.process = process
            slot.started_at = xpm_common.now_ts()
            slot.log_thread = threading.Thread(
                target=self.log_xray_output,
                args=(slot_tag, process),
                daemon=True,
            )
            slot.log_thread.start()
            xpm_common.log(f'xray-core slot {slot_tag} pid: {process.pid}')

    def stop_slot(self, slot_tag: str) -> None:
        slot = self.slots[slot_tag]
        with self.lock:
            process = slot.process
            if not process or process.poll() is not None:
                slot.process = None
                slot.draining = False
                slot.drain_zero_since = None
                slot.drain_protect_until = None
                slot.drain_degraded_checks = 0
                slot.drain_last_latency_ms = None
                slot.drain_last_checked_at = None
                slot.drain_new_connections = 0
                slot.drain_stalled_connections = 0
                slot.drain_known_connection_ids.clear()
                slot.drain_connection_bytes.clear()
                slot.drain_idle_polls.clear()
                slot.drain_last_info_at = None
                slot.drain_last_info_connections = None
                return
            slot.intentional_stop = True
            xpm_common.log(f'stopping xray-core slot {slot_tag}...')
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        with self.lock:
            slot.process = None
            slot.draining = False
            slot.drain_started_at = None
            slot.drain_zero_since = None
            slot.drain_protect_until = None
            slot.drain_connections = 0
            slot.drain_tcp_connections = 0
            slot.drain_udp_connections = 0
            slot.drain_bytes = 0
            slot.drain_last_error = ''
            slot.drain_degraded_checks = 0
            slot.drain_last_latency_ms = None
            slot.drain_last_checked_at = None
            slot.drain_new_connections = 0
            slot.drain_stalled_connections = 0
            slot.drain_known_connection_ids.clear()
            slot.drain_connection_bytes.clear()
            slot.drain_idle_polls.clear()
            slot.drain_last_info_at = None
            slot.drain_last_info_connections = None

    def start_xray(self) -> None:
        candidate = self.candidate_by_id(self.active_candidate_id)
        if candidate is not None:
            self.log_switch_request(candidate, 'service_start', 'Xray start')
            self.start_initial_candidate(candidate, 'Xray start', source='service_start')
            return

        expected_slot = self.active_slot_tag if self.dual_slot_enabled else 'xray-a'
        if expected_slot not in xpm_common.SLOT_TAGS:
            expected_slot = 'xray-a'
        self.active_slot_tag = expected_slot
        self.start_slot(expected_slot)
        if not self.wait_for_port(
            self.slots[expected_slot].socks_tcp,
            self.slots[expected_slot].process,
            timeout=6.0,
        ):
            self.stop_slot(expected_slot)
            raise RuntimeError(
                f'{expected_slot} did not open SOCKS port {self.slots[expected_slot].socks_tcp}'
            )

        if self.selector_control_enabled:
            try:
                reported = self.selector_status()
                if reported != expected_slot:
                    self.switch_selector(expected_slot)
                    xpm_common.log(
                        f'last-good startup restored selector from {reported} to '
                        f'manager-expected {expected_slot}',
                        error=True,
                    )
                self.selector_reconciliation_pending = False
            except Exception as exc:
                self.selector_reconciliation_pending = True
                xpm_common.log(
                    f'Selector is unavailable during last-good start; manager keeps '
                    f'{expected_slot} as the expected slot: {exc}',
                    error=True,
                )
        self.save_state()

    def stop_xray(self) -> None:
        for slot_tag in xpm_common.SLOT_TAGS:
            self.stop_slot(slot_tag)

    def other_slot_tag(self, slot_tag: str) -> str:
        return 'xray-b' if slot_tag == 'xray-a' else 'xray-a'

    def xray_monitor_loop(self) -> None:
        while not self.stop_event.wait(1):
            for slot_tag in xpm_common.SLOT_TAGS:
                with self.lock:
                    slot = self.slots[slot_tag]
                    process = slot.process
                    intentional = slot.intentional_stop
                    is_active = slot_tag == self.active_slot_tag
                if process is None or process.poll() is None or intentional:
                    continue
                code = process.returncode
                xpm_common.log(f'xray-core slot {slot_tag} exited unexpectedly with code {code}', error=True)
                if is_active and self.rollback_after_active_exit(slot_tag):
                    continue
                if not self.switch_lock.acquire(blocking=False):
                    continue
                try:
                    with self.lock:
                        if slot.process is not process or slot.intentional_stop:
                            continue
                        slot.process = None
                        slot.draining = False
                        is_active = slot_tag == self.active_slot_tag
                    if is_active and self.restart_on_runtime_error:
                        os._exit(1)
                finally:
                    self.switch_lock.release()

    def xray_version(self) -> str:
        if self._xray_version_cache:
            return self._xray_version_cache
        try:
            result = subprocess.run([xpm_common.XRAY_BIN, 'version'], capture_output=True, text=True, timeout=5)
            lines = (result.stdout or result.stderr).splitlines()
            banner = lines[0].strip() if lines else 'unknown'
            self._xray_version_cache = re.sub(r'\s+\(Xray,[^)]*\)', '', banner)
        except Exception:
            self._xray_version_cache = 'unknown'
        return self._xray_version_cache
