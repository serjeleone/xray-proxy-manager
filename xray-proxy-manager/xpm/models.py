from __future__ import annotations

import subprocess
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class Candidate:
    id: str
    source_index: int
    outbound_index: int
    outbound_tag: str
    name: str
    protocol: str
    server: str
    port: int | None
    country_code: str
    fingerprint: str
    config_revision: str = ''
    config: dict[str, Any] | None = field(default=None, repr=False, compare=False)

    def public(self, latency: dict[str, Any] | None, active: bool) -> dict[str, Any]:
        payload = {key: value for key, value in self.__dict__.items() if key != 'config'}
        payload['candidate_id'] = self.id
        payload['display_name'] = self.name
        payload['latency'] = latency
        payload['active'] = active
        return payload


@dataclass
class XraySlot:
    tag: str
    socks_tcp: int
    socks_udp: bool
    config_path: Path
    stats_port: int = 0
    process: subprocess.Popen[str] | None = None
    log_thread: threading.Thread | None = None
    candidate_id: str = ''
    candidate_name: str = ''
    candidate: Candidate | None = None
    started_at: int | None = None
    intentional_stop: bool = False
    draining: bool = False
    drain_started_at: int | None = None
    drain_zero_since: int | None = None
    drain_protect_until: int | None = None
    drain_connections: int = 0
    drain_tcp_connections: int = 0
    drain_udp_connections: int = 0
    drain_bytes: int = 0
    drain_last_error: str = ''
    drain_degraded_checks: int = 0
    drain_last_latency_ms: int | None = None
    drain_last_checked_at: int | None = None
    drain_new_connections: int = 0
    drain_stalled_connections: int = 0
    drain_known_connection_ids: set[str] = field(default_factory=set, repr=False)
    drain_connection_bytes: dict[str, int] = field(default_factory=dict, repr=False)
    drain_idle_polls: dict[str, int] = field(default_factory=dict, repr=False)
    drain_last_info_at: int | None = None
    drain_last_info_connections: int | None = None
    observed_outbound_tag: str = ''
    observed_outbound_at: int | None = None

    def running(self) -> bool:
        return bool(self.process and self.process.poll() is None)
