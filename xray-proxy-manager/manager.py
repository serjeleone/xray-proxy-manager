from __future__ import annotations

import copy
from collections import deque
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
import hashlib
import http.server
import ipaddress
import json
import math
import os
import re
import shlex
import shutil
import signal
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from typing import Any, Callable, Iterable
from urllib.parse import parse_qs, quote, urlparse
from xpm import common, config, conversion, drain, errors, identity, models, openwrt, persistence, probing, runtime, selector, settings, stats, status, subscription, switching, web


class XrayManager(
    drain.DrainMixin,
    openwrt.OpenwrtMixin,
    persistence.PersistenceMixin,
    probing.ProbingMixin,
    runtime.RuntimeMixin,
    selector.SelectorMixin,
    settings.SettingsMixin,
    stats.StatsMixin,
    status.StatusMixin,
    subscription.SubscriptionMixin,
    switching.SwitchingMixin,
    web.WebMixin,
):
    def __init__(self) -> None:
        persistence.migrate_legacy_workdir()
        common.WORKDIR.mkdir(parents=True, exist_ok=True)
        # Remove the invalidly named temporary file left by 0.3.0, if present.
        common.CONFIG_PATH.with_suffix('.json.new').unlink(missing_ok=True)

        base_options = persistence.load_json(common.OPTIONS_PATH, {})
        runtime_options = persistence.load_json(common.RUNTIME_OPTIONS_PATH, {})
        if not isinstance(base_options, dict):
            base_options = {}
        if not isinstance(runtime_options, dict):
            runtime_options = {}

        base_changed = common.migrate_auto_switch_excluded_option(base_options)
        base_changed = common.migrate_test_url_options(base_options) or base_changed
        runtime_changed = common.migrate_auto_switch_excluded_option(runtime_options)
        runtime_changed = common.migrate_test_url_options(runtime_options) or runtime_changed
        for retired_key in common.RETIRED_OPTION_KEYS:
            if retired_key in base_options:
                base_options.pop(retired_key, None)
                base_changed = True
            if retired_key in runtime_options:
                runtime_options.pop(retired_key, None)
                runtime_changed = True
        if runtime_changed:
            persistence.atomic_write_json(common.RUNTIME_OPTIONS_PATH, runtime_options)

        self.options: dict[str, Any] = copy.deepcopy(base_options)
        base_snapshot = runtime_options.get('_base_options', {})
        if not isinstance(base_snapshot, dict):
            base_snapshot = {}
        for key in common.RUNTIME_SETTING_KEYS:
            if key in runtime_options:
                if (key in base_options
                        and (key not in base_snapshot or base_options[key] != base_snapshot[key])
                        and base_options[key] != runtime_options[key]):
                    # A later edit in Home Assistant takes precedence over a
                    # saved UI override from an earlier application session.
                    # Legacy overrides have no baseline; do not let them
                    # silently replace values explicitly saved in HA.
                    runtime_options.pop(key)
                    runtime_changed = True
                else:
                    self.options[key] = runtime_options[key]
        if runtime_changed:
            persistence.atomic_write_json(common.RUNTIME_OPTIONS_PATH, runtime_options)

        self.subscription_url = str(self.options.get('subscription_url') or '').strip()
        self.config_index = int(self.options.get('config_index', 0) or 0)
        self.socks_tcp_a = int(self.options.get('socks_tcp_a', 10808))
        self.socks_tcp_b = int(
            self.options.get('socks_tcp_b', common.DEFAULT_SOCKS_TCP_B)
        )
        self.ui_port = common.bounded_int(
            self.options.get('ui_port', common.DEFAULT_UI_PORT), 1, 65535, 'ui_port'
        )
        # SOCKS5 UDP relay always uses the same port number as TCP.
        self.socks_udp_a = True
        self.socks_udp_b = True
        self.dual_slot_enabled = common.to_bool(self.options.get('dual_slot_enabled', True))
        self.override_inbounds = True
        self.proxy_username = str(self.options.get('proxy_username') or '')
        self.proxy_password = str(self.options.get('proxy_password') or '')
        self.disable_observatory = True
        self.log_level = str(self.options.get('log_level') or 'warning')
        self.user_agent = str(self.options.get('user_agent') or 'Xray Proxy Manager Home Assistant App')
        self.validate_tags = True
        self.auto_fix_tags = True
        self.auto_add_proxy_direct = True
        self.restart_on_runtime_error = True
        self.latency_test_timeout_seconds = max(3, int(self.options.get('latency_test_timeout_seconds', 12) or 12))
        self.latency_test_parallelism = common.bounded_int(
            self.options.get('latency_test_parallelism', 0), -1, 32, 'latency_test_parallelism'
        )
        self.primary_test_url, self.secondary_test_url = common.resolve_test_urls(self.options)
        if (
            str(base_options.get('primary_test_url') or '').strip() != self.primary_test_url
            or str(base_options.get('secondary_test_url') or '').strip()
            != self.secondary_test_url
        ):
            base_options['primary_test_url'] = self.primary_test_url
            base_options['secondary_test_url'] = self.secondary_test_url
            base_changed = True
        self.options['primary_test_url'] = self.primary_test_url
        self.options['secondary_test_url'] = self.secondary_test_url
        for legacy_key in common.LEGACY_SECONDARY_TEST_KEYS:
            self.options.pop(legacy_key, None)

        self.selector_control_enabled = common.to_bool(self.options.get('selector_control_enabled', False))
        self.selector_api_url = str(
            self.options.get('selector_api_url') or 'http://192.168.0.1:9090'
        ).rstrip('/')
        self.selector_api_secret = str(self.options.get('selector_api_secret') or '')
        self.selector_tag = str(self.options.get('selector_tag') or 'xray-active').strip()
        self.selector_status_interval_seconds = max(
            5, int(self.options.get('selector_status_interval_seconds', 10) or 10)
        )
        self.drain_quiet_seconds = max(5, int(self.options.get('drain_quiet_seconds', 30) or 30))
        self.drain_poll_interval_seconds = max(1, int(
            self.options.get('drain_poll_interval_seconds', 2) or 2
        ))
        self.drain_timeout_minutes = max(
            0, int(self.options.get('drain_timeout_minutes', 0) or 0)
        )

        self.router_control_enabled = common.to_bool(self.options.get('router_control_enabled', True))
        self.router_host = str(self.options.get('router_host') or '192.168.0.1').strip()
        self.router_ssh_port = int(self.options.get('router_ssh_port', 22) or 22)
        self.router_ssh_user = str(self.options.get('router_ssh_user') or 'root').strip()
        self.router_ssh_password = str(self.options.get('router_ssh_password') or '')
        configured_auth_method = str(self.options.get('router_auth_method') or '').strip().lower()
        if not configured_auth_method:
            configured_auth_method = 'password' if self.router_ssh_password else 'existing_key'
        if configured_auth_method not in common.ROUTER_AUTH_METHODS:
            raise RuntimeError('router_auth_method must be existing_key, password or generate_key.')
        self.router_auth_method = configured_auth_method
        self.router_ssh_key_name = self.normalize_router_key_name(
            self.options.get('router_ssh_key_name') or 'id_ed25519'
        )
        self.router_ssh_key_path_override = str(self.options.get('router_ssh_key_path') or '').strip()
        self.router_ssh_key_path: Path | None = None
        self.router_firewall_rule = str(self.options.get('router_firewall_rule') or 'mark_domains').strip()
        self.router_status_interval_seconds = max(
            5, int(self.options.get('router_status_interval_seconds', 10) or 10)
        )

        self.auto_checker_enabled = True
        self.auto_switch_best_enabled = True
        self.switching_preset = 'smooth'
        self.auto_switch_preferred_country = ''
        self.auto_switch_preferred_protocol = ''
        self.auto_switch_excluded = 'RU'
        self.auto_switch_min_ping_delta_ms = 100
        self.auto_check_interval_seconds = 60
        self.auto_check_failures = 3
        self.auto_check_max_latency_ms = 500
        self.auto_best_check_interval_seconds = 600
        self.auto_check_timeout_seconds = max(3, int(self.options.get('auto_check_timeout_seconds', 12) or 12))
        self.update_interval_hours = 1
        self.ui_sort = 'ping-asc'
        self.ui_protocol_filter = 'all'
        self.ui_max_ping_ms = 1000
        self.ui_hide_unavailable = False
        self.ui_hide_excluded = True
        self._apply_runtime_values(self.options)

        if not self.subscription_url:
            raise RuntimeError('subscription_url is empty. Set it in app configuration.')
        if bool(self.proxy_username) != bool(self.proxy_password):
            raise RuntimeError('proxy_username and proxy_password must be set together, or both left empty.')
        if not common.SAFE_RULE_RE.fullmatch(self.selector_tag):
            raise RuntimeError('selector_tag contains unsupported characters.')
        if not common.SAFE_RULE_RE.fullmatch(self.router_firewall_rule):
            raise RuntimeError('router_firewall_rule contains unsupported characters.')
        if self.socks_tcp_b == self.socks_tcp_a:
            raise RuntimeError('socks_tcp_b must differ from socks_tcp_a.')
        if self.ui_port in {self.socks_tcp_a, self.socks_tcp_b}:
            raise RuntimeError('ui_port must differ from both SOCKS slot ports.')
        if self.ui_port == common.WATCHDOG_PORT:
            raise RuntimeError(f'ui_port must differ from the reserved watchdog port {common.WATCHDOG_PORT}.')

        self.lock = threading.RLock()
        self.switch_lock = threading.Lock()
        self.router_lock = threading.Lock()
        self.options_sync_lock = threading.Lock()
        self.stop_event = threading.Event()
        self.settings_event = threading.Event()
        self.preference_scan_generation = 0
        self.subscription: list[dict[str, Any]] = []
        self.candidates: list[models.Candidate] = []
        self.active_candidate_id = ''
        self.active_slot_tag = 'xray-a'
        self.switch_generation = 0
        self.manual_generation = 0
        self.latency_versions: dict[str, int] = {}
        self.selector_reconciliation_pending = False
        self.slots: dict[str, models.XraySlot] = {
            'xray-a': models.XraySlot(
                tag='xray-a',
                socks_tcp=self.socks_tcp_a,
                socks_udp=self.socks_udp_a,
                config_path=common.SLOT_CONFIG_PATHS['xray-a'],
            ),
            'xray-b': models.XraySlot(
                tag='xray-b',
                socks_tcp=self.socks_tcp_b,
                socks_udp=self.socks_udp_b,
                config_path=common.SLOT_CONFIG_PATHS['xray-b'],
            ),
        }
        self.state = persistence.load_json(common.STATE_PATH, {
            'active_candidate_id': '',
            'active_slot_tag': 'xray-a',
            'subscription_updated_at': None,
            'subscription_last_attempt_at': None,
            'subscription_last_success_at': None,
            'subscription_last_error_at': None,
            'subscription_error': '',
            'subscription_consecutive_failures': 0,
            'last_switch_at': None,
            'last_switch_reason': '',
            'last_switch_source': '',
            'auto_check_failures': 0,
            'auto_check_last_at': None,
            'auto_best_check_last_at': None,
            'auto_check_last_error': '',
            'jobs': {},
        })
        if not isinstance(self.state, dict):
            self.state = {}
        self.state.setdefault('jobs', {})
        self.state['jobs']['latency'] = {'running': False, 'progress': 0, 'total': 0, 'message': ''}
        self.state['jobs']['refresh'] = {'running': False, 'message': ''}
        self.state['jobs']['switch'] = {'running': False, 'message': ''}
        self.latencies = persistence.load_json(common.LATENCY_PATH, {})
        if not isinstance(self.latencies, dict):
            self.latencies = {}
        self.latency_checking_ids: set[str] = set()
        self.active_candidate_id = str(self.state.get('active_candidate_id') or '')
        remembered_slot = str(self.state.get('active_slot_tag') or 'xray-a')
        self.active_slot_tag = (
            remembered_slot if self.dual_slot_enabled and remembered_slot in common.SLOT_TAGS else 'xray-a'
        )
        self.started_at = common.now_ts()
        self.home_assistant_host = self.detect_home_assistant_host()
        self.next_update_at = (
            common.now_ts() + self.update_interval_hours * 3600
            if self.update_interval_hours > 0 else None
        )
        self.servers: list[socketserver.BaseServer] = []
        self._xray_version_cache = ''
        self.selector_state: dict[str, Any] = {
            'configured': self.selector_control_enabled,
            'available': False,
            'current': '',
            'error': '',
            'connections_supported': False,
            'last_checked_at': None,
        }
        self.throughput_state: dict[str, Any] = {
            'available': False,
            'slot': self.active_slot_tag,
            'bytes_per_second': 0.0,
            'megabytes_per_second': 0.0,
            'updated_at': None,
            'error': '',
        }
        self._throughput_last_slot = ''
        self._throughput_last_sample_at: float | None = None
        self._throughput_connection_download_bytes: dict[str, int] = {}
        self.router_state: dict[str, Any] = {
            'configured': self.router_control_enabled,
            'available': False,
            'rule_enabled': None,
            'rule_name': self.router_firewall_rule,
            'rule_section': '',
            'busy': False,
            'desired_rule_enabled': (
                self.state.get('router_rule_desired_enabled')
                if isinstance(self.state.get('router_rule_desired_enabled'), bool)
                else None
            ),
            'last_checked_at': None,
            'error': '',
            'auth_method': self.router_auth_method,
            'key_name': self.router_ssh_key_name if self.router_auth_method != 'password' else '',
            'public_key': '',
        }
        self.prepare_router_auth()
        self.socks_listen_address = str(ipaddress.ip_address(
            str(self.options.get('socks_listen_address') or '0.0.0.0')
        ))
        self.socks_allowed_cidrs = self.resolve_socks_allowed_cidrs(
            self.options.get('socks_allowed_cidrs', ['0.0.0.0/0'])
        )
        self.options_migration_pending = bool(base_changed or runtime_changed)
        if self.options_migration_pending:
            migrated, migration_error = self.sync_supervisor_options()
            if migrated:
                common.log('migrated renamed and retired options in Home Assistant configuration')
                self.options_migration_pending = False
            else:
                common.log(f'could not persist migrated options to Supervisor: {migration_error}', error=True)

    def initialize(self) -> None:
        cached = self.load_cached_subscription()
        if cached:
            self.subscription = cached
            self.candidates = self.extract_candidates(cached)
        try:
            self.refresh_subscription_sync(initial=True)
        except Exception as exc:
            common.log(f'initial subscription update failed: {exc}', error=True)
            if cached and self.candidates:
                candidate = self.choose_initial_candidate()
                try:
                    self.restart_xray_for(
                        candidate,
                        'cached subscription fallback',
                        source='cached_subscription_fallback',
                    )
                except Exception as cached_error:
                    common.log(f'cached subscription could not be applied: {cached_error}', error=True)
                    restored, restored_candidate = self.restore_last_good()
                    if not restored:
                        raise
                    if restored_candidate:
                        self.log_switch_request(
                            restored_candidate,
                            'last_good_recovery',
                            'last-good recovery',
                        )
                        self.start_initial_candidate(
                            restored_candidate,
                            'last-good recovery',
                            source='last_good_recovery',
                        )
                    else:
                        self.active_candidate_id = ''
                        self.save_state()
                        self.start_xray()
            else:
                restored, restored_candidate = self.restore_last_good()
                if not restored:
                    raise
                if restored_candidate:
                    self.log_switch_request(
                        restored_candidate,
                        'last_good_recovery',
                        'last-good recovery',
                    )
                    self.start_initial_candidate(
                        restored_candidate,
                        'last-good recovery',
                        source='last_good_recovery',
                    )
                else:
                    self.active_candidate_id = ''
                    self.save_state()
                    self.start_xray()

    def run(self) -> None:
        self.initialize()
        if self.auto_checker_enabled:
            accepted = self.request_latency_test(
                None,
                switch_to_best=self.auto_switch_best_enabled,
                source='startup',
            )
            if accepted:
                common.log(
                    'startup latency check started in background '
                    f'(parallelism {self.effective_latency_test_parallelism(len(self.candidates))})'
                )
        threading.Thread(target=self.auto_checker_loop, daemon=True).start()
        threading.Thread(target=self.periodic_update_loop, daemon=True).start()
        threading.Thread(target=self.xray_monitor_loop, daemon=True).start()
        threading.Thread(target=self.drain_monitor_loop, daemon=True).start()
        threading.Thread(target=self.selector_status_loop, daemon=True).start()
        threading.Thread(target=self.active_throughput_loop, daemon=True).start()
        threading.Thread(target=self.router_status_loop, daemon=True).start()

        handler_factory = lambda *args, **kwargs: web.WebHandler(self, *args, **kwargs)
        ingress_port = self.detect_ingress_port()
        if ingress_port == common.WATCHDOG_PORT:
            raise RuntimeError(
                f'Home Assistant assigned the reserved watchdog port {common.WATCHDOG_PORT} to Ingress; '
                'restart the app so Supervisor assigns another port.'
            )

        if ingress_port == self.ui_port:
            ui_server = web.ThreadingHTTPServer(('0.0.0.0', self.ui_port), handler_factory)
            self.servers.append(ui_server)
            threading.Thread(target=ui_server.serve_forever, daemon=True).start()
            common.log(
                f'web UI is listening on 0.0.0.0:{self.ui_port}; '
                'Home Assistant Ingress uses the same port'
            )
        else:
            ui_server = web.ThreadingHTTPServer(('127.0.0.1', self.ui_port), handler_factory)
            self.servers.append(ui_server)
            threading.Thread(target=ui_server.serve_forever, daemon=True).start()

            ingress_server = web.ThreadingTCPProxyServer(
                ('0.0.0.0', ingress_port),
                target_host='127.0.0.1',
                target_port=self.ui_port,
            )
            self.servers.append(ingress_server)
            threading.Thread(target=ingress_server.serve_forever, daemon=True).start()
            common.log(
                f'web UI is listening on 127.0.0.1:{self.ui_port}; '
                f'Home Assistant Ingress proxy is listening on 0.0.0.0:{ingress_port}'
            )

        watchdog_server = web.ThreadingHTTPServer(('0.0.0.0', common.WATCHDOG_PORT), handler_factory)
        self.servers.append(watchdog_server)
        threading.Thread(target=watchdog_server.serve_forever, daemon=True).start()
        common.log(f'watchdog health endpoint is listening on 0.0.0.0:{common.WATCHDOG_PORT}')

        while not self.stop_event.wait(1):
            pass

    def shutdown(self) -> None:
        self.stop_event.set()
        self.settings_event.set()
        for server in list(self.servers):
            try:
                server.shutdown()
                server.server_close()
            except Exception:
                pass
        self.servers.clear()
        self.stop_xray()


def main() -> int:
    manager: XrayManager | None = None
    try:
        manager = XrayManager()

        def handle_signal(_signum: int, _frame: Any) -> None:
            if manager:
                manager.shutdown()

        signal.signal(signal.SIGTERM, handle_signal)
        signal.signal(signal.SIGINT, handle_signal)
        manager.run()
        return 0
    except Exception as exc:
        common.log(f'fatal error: {exc}', error=True)
        traceback.print_exc()
        return 1
    finally:
        if manager:
            manager.shutdown()


if __name__ == '__main__':
    raise SystemExit(main())
