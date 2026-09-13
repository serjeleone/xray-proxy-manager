"""Keep downloads open: completed short transfers cannot detect splice stalls."""
from __future__ import annotations

from dataclasses import replace
import http.server
import json
import socket
import ssl
import struct
import subprocess
import threading
from types import SimpleNamespace

import pytest

from test_xray_integration import live_manager  # noqa: F401: pytest fixture


def recv_exact(connection, length):
    data = b''
    while len(data) < length:
        part = connection.recv(length - len(data))
        assert part, 'SOCKS connection closed during handshake'
        data += part
    return data


@pytest.fixture(params=['freedom', 'vision'])
def streaming_download(live_manager, m, tmp_path, request):
    instance = live_manager
    stop, paused = threading.Event(), threading.Event()
    counters = {'download': 0, 'upload': 0}
    rate = {'chunk': 65536}
    lock = threading.Lock()

    class DownloadHandler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_GET(self):
            self.send_response(200)
            self.send_header('Content-Length', str(1_000_000_000))
            self.end_headers()
            try:
                while not stop.is_set():
                    if not paused.is_set():
                        self.wfile.write(b'x' * rate['chunk'])
                    stop.wait(0.015625)  # Roughly 4 MB/s, like a video download.
            except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
                pass

    class SelectorHandler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_GET(self):
            assert self.path == '/connections'
            with lock:
                # The meter receives real bytes from the slot's SOCKS socket.
                # Expose the same per-connection HTTP contract as a selector.
                data = json.dumps({'connections': [
                    {'id': 'stream', 'chains': ['xray-active', 'xray-a'], **counters},
                ]}).encode()
            self.send_response(200)
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    download_server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), DownloadHandler)
    selector_server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), SelectorHandler)
    upstream = client = receiving = None
    servers = [download_server, selector_server]
    serving = []
    try:
        instance.stop_xray()
        candidate = instance.candidates[0]
        outbound = {'tag': candidate.outbound_tag, 'protocol': 'freedom'}
        if request.param == 'vision':
            cert_path, key_path = tmp_path / 'test.crt', tmp_path / 'test.key'
            subprocess.run([
                'openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1',
                '-nodes', '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1',
                '-keyout', str(key_path), '-out', str(cert_path),
            ], check=True, capture_output=True, timeout=5)
            certificate = {'certificate': cert_path.read_text().splitlines(), 'key': key_path.read_text().splitlines()}
            server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_context.minimum_version = ssl.TLSVersion.TLSv1_3
            server_context.load_cert_chain(cert_path, key_path)
            download_server.socket = server_context.wrap_socket(download_server.socket, server_side=True)
            port = instance.find_free_port()
            user_id = 'f37c1b19-25c1-4800-8700-e1eb7a530ae7'
            upstream_path = tmp_path / 'vision.json'
            upstream_path.write_text(json.dumps({
                'log': {'loglevel': 'none'},
                'inbounds': [{
                    'listen': '127.0.0.1', 'port': port, 'protocol': 'vless',
                    'settings': {'decryption': 'none', 'clients': [
                        {'id': user_id, 'flow': 'xtls-rprx-vision'},
                    ]},
                    'streamSettings': {'network': 'raw', 'security': 'tls', 'tlsSettings': {
                        'certificates': [certificate],
                    }},
                }],
                'outbounds': [{'protocol': 'freedom', 'settings': {'finalRules': [
                    {'action': 'allow', 'ip': ['127.0.0.1/32']},
                ]}}],
            }))
            upstream = subprocess.Popen([m.common.XRAY_BIN, 'run', '-config', str(upstream_path)], stdout=subprocess.DEVNULL)
            assert instance.wait_for_port(port, upstream)
            outbound = {
                'tag': candidate.outbound_tag, 'protocol': 'vless',
                'settings': {'vnext': [{'address': '127.0.0.1', 'port': port, 'users': [
                    {'id': user_id, 'encryption': 'none', 'flow': 'xtls-rprx-vision'},
                ]}]},
                'streamSettings': {'network': 'raw', 'security': 'tls', 'tlsSettings': {
                    'serverName': 'localhost',
                    'certificates': [{'certificate': certificate['certificate'], 'usage': 'verify'}],
                }},
            }
        for server in servers:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            serving.append(thread)
        candidate = replace(candidate, config={
            'outbounds': [outbound],
            'policy': {'system': {'statsOutboundDownlink': True}},
        })
        instance.start_initial_candidate(candidate, 'streaming test')
        client = socket.create_connection(('127.0.0.1', instance.slots['xray-a'].socks_tcp), timeout=5)
        client.sendall(b'\x05\x01\x00')
        assert recv_exact(client, 2) == b'\x05\x00'
        client.sendall(b'\x05\x01\x00\x01' + socket.inet_aton('127.0.0.1') + struct.pack('!H', download_server.server_port))
        assert recv_exact(client, 10)[:2] == b'\x05\x00'
        if request.param == 'vision':
            client_context = ssl.create_default_context(cafile=str(cert_path))
            client = client_context.wrap_socket(client, server_hostname='127.0.0.1')
        client.settimeout(15)
        http_request = b'GET /stream HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n'
        client.sendall(http_request)
        counters['upload'] = len(http_request)

        def consume():
            try:
                while not stop.is_set():
                    data = client.recv(65536)
                    if not data:
                        return
                    with lock:
                        counters['download'] += len(data)
            except OSError:
                if not stop.is_set():
                    raise

        receiving = threading.Thread(target=consume, daemon=True)
        receiving.start()
        del instance.selector_connections  # Use the real manager HTTP client.
        instance.selector_api_url = f'http://127.0.0.1:{selector_server.server_port}'
        yield SimpleNamespace(instance=instance, counters=counters, receiving=receiving,
                              paused=paused, rate=rate)
    finally:
        stop.set()
        if client is not None:
            try:
                client.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            client.close()
        if receiving:
            receiving.join(5)
        if upstream:
            upstream.terminate()
            upstream.wait(timeout=5)
        for server, thread in zip(servers, serving):
            server.shutdown()
            thread.join(2)
        for server in servers:
            server.server_close()
