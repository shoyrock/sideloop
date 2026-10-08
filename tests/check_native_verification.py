"""Test the compiled auth-only entrypoint with fake local Apple rejection.

Run with --network none --add-host gsa.apple.com:127.0.0.1.
This checks the real binary's wiring and errors, not Apple's live MFA service.
"""
import datetime
import http.server
import json
import os
import plistlib
import ssl
import subprocess
import tempfile
import threading
from pathlib import Path

operations = []
class Anisette(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def do_GET(self):
        values = {
            'X-Apple-I-MD-M': 'ZmFrZQ==', 'X-Apple-I-MD': 'ZmFrZQ==',
            'X-Apple-I-MD-LU': 'ZmFrZQ==', 'X-Apple-I-MD-RINFO': '17106176',
            'X-Mme-Device-Id': '11111111-1111-1111-1111-111111111111',
            'X-Apple-I-SRL-NO': '0', 'X-MMe-Client-Info': '<MacBookPro> <macOS> <com.apple.akd>',
            'X-Apple-I-Client-Time': datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
            'X-Apple-Locale': 'en_US', 'X-Apple-I-TimeZone': 'UTC',
        }
        self.send_response(200); self.send_header('Content-Type','application/json'); self.end_headers()
        self.wfile.write(json.dumps(values).encode())
class Apple(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def do_POST(self):
        request = plistlib.loads(self.rfile.read(int(self.headers['Content-Length'])))
        operations.append(request['Request']['o'])
        response = plistlib.dumps({'Response': {'Status': {'ec': -22411, 'em': 'Synthetic rejection'}}})
        self.send_response(200); self.send_header('Content-Type','text/x-xml-plist')
        self.send_header('Content-Length', str(len(response))); self.end_headers()
        self.wfile.write(response)

with tempfile.TemporaryDirectory() as folder:
    root = Path(folder)
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                    '-subj', '/CN=gsa.apple.com', '-keyout', str(root/'key'), '-out', str(root/'cert')],
                   check=True, capture_output=True)
    anisette = http.server.ThreadingHTTPServer(('127.0.0.1', 6969), Anisette)
    apple = http.server.ThreadingHTTPServer(('127.0.0.1', 443), Apple)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(root/'cert', root/'key')
    apple.socket = context.wrap_socket(apple.socket, server_side=True)
    for server in (anisette, apple): threading.Thread(target=server.serve_forever, daemon=True).start()
    result = subprocess.run(['AltServer', '--verify-account'], cwd=root,
                            env={**os.environ, 'TZ': 'UTC', 'ALTSERVER_APPLE_ID': 'synthetic@example.test',
                                 'ALTSERVER_APPLE_PASSWORD': 'synthetic-password',
                                 'ALTSERVER_ANISETTE_SERVER': 'http://127.0.0.1:6969'},
                            capture_output=True, text=True, timeout=15)
    assert result.returncode == 1
    assert 'Authentication failed:' in result.stderr and '-22411' in result.stderr, (result.stdout, result.stderr, operations)
    assert 'Account authentication succeeded.' not in result.stdout
    assert operations == ['init'], operations
    assert not (root/'AltServerData').exists()
    print('PASS: compiled auth-only entrypoint reaches Apple authentication, rejects failure, and creates no signing data')
    for server in (anisette, apple): server.shutdown()
