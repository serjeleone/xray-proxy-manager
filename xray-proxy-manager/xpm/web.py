from __future__ import annotations

import http.server
import json
import os
import socket
import socketserver
import threading
import time
import traceback
import urllib.error
import urllib.request
from typing import Any, TYPE_CHECKING
from urllib.parse import parse_qs, urlparse
from . import common as xpm_common, conversion as xpm_conversion

if TYPE_CHECKING:
    from manager import XrayManager


class ServerLoggingMixin:
    def handle_error(self, request: Any, client_address: Any) -> None:
        xpm_common.log(f'request failed for {client_address}:\n{traceback.format_exc()}', error=True)


class ThreadingHTTPServer(ServerLoggingMixin, socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class IngressTCPProxyHandler(socketserver.BaseRequestHandler):
    @staticmethod
    def forward_stream(source: socket.socket, target: socket.socket) -> None:
        try:
            while True:
                data = source.recv(65536)
                if not data:
                    break
                target.sendall(data)
        except (ConnectionError, OSError):
            pass
        finally:
            try:
                target.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    def handle(self) -> None:
        server = self.server
        target_host = getattr(server, 'target_host', '127.0.0.1')
        target_port = int(getattr(server, 'target_port', 0) or 0)
        try:
            upstream = socket.create_connection((target_host, target_port), timeout=5)
        except OSError:
            return

        client = self.request
        client.settimeout(None)
        upstream.settimeout(None)
        request_thread = threading.Thread(
            target=self.forward_stream,
            args=(client, upstream),
            daemon=True,
        )
        request_thread.start()
        try:
            self.forward_stream(upstream, client)
        finally:
            try:
                upstream.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            upstream.close()
            request_thread.join(timeout=1)


class ThreadingTCPProxyServer(ServerLoggingMixin, socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        server_address: tuple[str, int],
        *,
        target_host: str,
        target_port: int,
    ) -> None:
        self.target_host = target_host
        self.target_port = target_port
        super().__init__(server_address, IngressTCPProxyHandler)


class WebHandler(http.server.BaseHTTPRequestHandler):
    server_version = f'XrayProxyManager/{xpm_common.ADDON_VERSION}'

    def __init__(self, manager: XrayManager, *args: Any, **kwargs: Any) -> None:
        self.manager = manager
        super().__init__(*args, **kwargs)

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def ingress_client_allowed(self) -> bool:
        address = str(self.client_address[0] or '')
        if address.startswith('::ffff:'):
            address = address[7:]
        return address in {'172.30.32.2', '127.0.0.1', '::1'}

    def reject_non_ingress_client(self) -> bool:
        if self.ingress_client_allowed():
            return False
        self.send_error(403, 'Web UI is available only through Home Assistant Ingress')
        return True

    def send_json(self, payload: Any, status: int = 200) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_download(
        self,
        body: bytes,
        filename: str,
        *,
        content_type: str = 'application/octet-stream',
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        self.send_response(200)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Disposition', f'attachment; filename="{filename}"')
        self.send_header('Cache-Control', 'no-store')
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def read_json(self) -> dict[str, Any]:
        length = int(self.headers.get('Content-Length') or 0)
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        payload = json.loads(raw.decode('utf-8'))
        return payload if isinstance(payload, dict) else {}

    def send_static(self, relative: str, content_type: str) -> None:
        path = (xpm_common.WEB_ROOT / relative).resolve()
        if xpm_common.WEB_ROOT.resolve() not in path.parents and path != xpm_common.WEB_ROOT.resolve():
            self.send_error(404)
            return
        try:
            body = path.read_bytes()
        except FileNotFoundError:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header('Content-Type', content_type)
        self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0')
        self.send_header('Pragma', 'no-cache')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path.rstrip('/') or '/'
        if path.endswith('/api/health'):
            status = self.manager.status_payload()
            xray_running = bool(status.get('xray_running'))
            healthy = xray_running
            self.send_json({
                'ok': healthy,
                'xray_running': xray_running,
            }, 200 if healthy else 503)
            return
        if self.reject_non_ingress_client():
            return
        if path.endswith('/api/status'):
            self.send_json(self.manager.status_payload())
            return
        if path.endswith('/api/throughput'):
            self.send_json(self.manager.throughput_payload())
            return
        if path.endswith('/api/subscription/convert'):
            try:
                config, metadata = self.manager.sing_box_subscription()
                body = (json.dumps(config, ensure_ascii=False, indent=2) + '\n').encode('utf-8')
                self.send_download(
                    body,
                    xpm_conversion.SING_BOX_DOWNLOAD_FILENAME,
                    content_type='application/json; charset=utf-8',
                    extra_headers={
                        'Profile-Title': xpm_conversion.SING_BOX_PROFILE_NAME,
                        'X-XPM-Converted-Count': str(metadata.get('converted_count') or 0),
                        'X-XPM-Skipped-Count': str(len(metadata.get('skipped') or [])),
                    },
                )
            except Exception as exc:
                xpm_common.log(f'sing-box conversion failed: {exc}', error=True)
                self.send_json({'ok': False, 'error': str(exc)}, 400)
            return
        if path.endswith('/api/logs'):
            query = parse_qs(parsed.query)
            try:
                limit = int((query.get('limit') or ['1000'])[0])
            except (TypeError, ValueError):
                limit = 1000
            lines, total = xpm_common.ui_log_snapshot(limit)
            self.send_json({
                'lines': lines,
                'count': len(lines),
                'total': total,
                'limit': max(1, min(limit, xpm_common.LOG_BUFFER_MAX_LINES)),
                'generated_at': xpm_common.now_ts(),
            })
            return
        if path.endswith('/app.js'):
            self.send_static('app.js', 'application/javascript; charset=utf-8')
            return
        if path.endswith('/style.css'):
            self.send_static('style.css', 'text/css; charset=utf-8')
            return
        if path.endswith('/favicon.svg'):
            self.send_static('favicon.svg', 'image/svg+xml')
            return
        self.send_static('index.html', 'text/html; charset=utf-8')

    def do_POST(self) -> None:
        if self.reject_non_ingress_client():
            return
        path = urlparse(self.path).path.rstrip('/')
        try:
            payload = self.read_json()
            if path.endswith('/api/select'):
                self.manager.select_candidate(str(payload.get('id') or ''))
                self.send_json({'ok': True})
                return
            if path.endswith('/api/test'):
                candidate_id = str(payload.get('id') or '')
                accepted = self.manager.request_latency_test([candidate_id] if candidate_id else None)
                self.send_json({'ok': accepted}, 202 if accepted else 409)
                return
            if path.endswith('/api/refresh'):
                accepted = self.manager.request_refresh()
                self.send_json({'ok': accepted}, 202 if accepted else 409)
                return
            if path.endswith('/api/mode'):
                desired = payload.get('dual_slot_enabled')
                if not isinstance(desired, bool):
                    raise ValueError('Не указан режим слотов')
                self.send_json(self.manager.set_slot_mode(desired))
                return
            if path.endswith('/api/preferred-country'):
                self.send_json(self.manager.set_preferred_country(payload.get('country')))
                return
            if path.endswith('/api/preferences'):
                self.send_json(self.manager.set_selection_preferences(
                    payload.get('country'),
                    payload.get('protocol'),
                ))
                return
            if path.endswith('/api/settings'):
                changes = payload.get('changes') if isinstance(payload.get('changes'), dict) else payload
                self.send_json(self.manager.update_runtime_settings(changes))
                return
            if path.endswith('/api/traffic'):
                desired = payload.get('enabled')
                if not isinstance(desired, bool):
                    current = self.manager.router_state.get('rule_enabled')
                    if not isinstance(current, bool):
                        raise ValueError('Состояние правила OpenWrt неизвестно')
                    desired = not current
                self.manager.set_router_rule(desired)
                self.send_json({'ok': True, 'enabled': desired})
                return
            if path.endswith('/api/drain/stop'):
                stopped = self.manager.force_stop_draining_slot(str(payload.get('slot') or ''))
                self.send_json({'ok': True, 'slot': stopped})
                return
            self.send_json({'ok': False, 'error': 'not found'}, 404)
        except Exception as exc:
            xpm_common.log(f'web API error: {exc}', error=True)
            self.send_json({'ok': False, 'error': str(exc)}, 400)


class WebMixin:
    def detect_ingress_port(self) -> int:
        """Read the dynamically assigned Home Assistant Ingress port."""
        token = os.environ.get('SUPERVISOR_TOKEN', '').strip()
        if not token:
            raise RuntimeError('SUPERVISOR_TOKEN is unavailable; cannot determine the Ingress port.')

        last_error = 'unknown error'
        for attempt in range(1, 11):
            request = urllib.request.Request(
                'http://supervisor/addons/self/info',
                headers={'Authorization': f'Bearer {token}'},
            )
            try:
                with urllib.request.urlopen(request, timeout=5) as response:
                    payload = json.loads(response.read().decode('utf-8') or '{}')
                data = payload.get('data') if isinstance(payload, dict) else None
                port = data.get('ingress_port') if isinstance(data, dict) else None
                port = int(port)
                if 1 <= port <= 65535:
                    return port
                last_error = f'invalid port returned by Supervisor: {port}'
            except (TypeError, ValueError, urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
                last_error = str(exc)
            if attempt < 10:
                time.sleep(0.5)

        raise RuntimeError(f'could not determine the Home Assistant Ingress port: {last_error}')

    def detect_home_assistant_host(self) -> str:
        """Return the Home Assistant host address visible to LAN clients."""
        token = os.environ.get('SUPERVISOR_TOKEN', '').strip()
        candidates: list[str] = []
        if token:
            request = urllib.request.Request(
                'http://supervisor/network/info',
                headers={'Authorization': f'Bearer {token}'},
            )
            try:
                with urllib.request.urlopen(request, timeout=5) as response:
                    payload = json.loads(response.read().decode('utf-8') or '{}')
                data = payload.get('data') if isinstance(payload, dict) else None
                interfaces = data.get('interfaces') if isinstance(data, dict) else None
                if isinstance(interfaces, list):
                    ordered = sorted(
                        (item for item in interfaces if isinstance(item, dict)),
                        key=lambda item: not bool(item.get('primary')),
                    )
                    for interface in ordered:
                        ipv4 = interface.get('ipv4')
                        addresses = ipv4.get('address') if isinstance(ipv4, dict) else None
                        if isinstance(addresses, list):
                            candidates.extend(str(item).split('/', 1)[0] for item in addresses)
            except Exception as exc:
                self.debug_log(f'could not read Home Assistant host address from Supervisor: {exc}')

        for address in candidates:
            try:
                parsed = socket.inet_pton(socket.AF_INET, address)
            except OSError:
                continue
            if parsed and not address.startswith('127.') and address != '0.0.0.0':
                return address
        return 'host'
