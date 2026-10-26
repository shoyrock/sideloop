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
client_identities = []
advertised_identity = ''
http_status = 200
windows = '<PC> <Windows;6.2(0,0);9200> <com.apple.AuthKit/1 (com.apple.iTunes/12.12.4.1)>'
stock_mac = '<MacBookPro13,2> <macOS;13.1;22C65> <com.apple.AuthKit/1 (com.apple.dt.Xcode/3594.4.19)>'
modern_mac = '<Mac15,7> <macOS;27.0;26A5378j> <com.apple.AuthKit/1 (com.apple.akd/1.0)>'

class Anisette(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def do_GET(self):
        values = {
            'X-Apple-I-MD-M': 'ZmFrZQ==', 'X-Apple-I-MD': 'ZmFrZQ==',
            'X-Apple-I-MD-LU': 'ZmFrZQ==', 'X-Apple-I-MD-RINFO': '17106176',
            'X-Mme-Device-Id': '11111111-1111-1111-1111-111111111111',
            'X-Apple-I-SRL-NO': '0', 'X-MMe-Client-Info': advertised_identity,
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
        client_identities.append(self.headers.get('X-Mme-Client-Info', ''))
        response = plistlib.dumps({'Response': {'Status': {'ec': -22411, 'em': 'Synthetic rejection'}}})
        if http_status == 503:
            response = b'<html>Service unavailable; synthetic-private-response</html>'
        self.send_response(http_status); self.send_header('Content-Type','text/x-xml-plist')
        self.send_header('Content-Length', str(len(response))); self.end_headers()
        self.wfile.write(response)

with tempfile.TemporaryDirectory() as folder:
    root = Path(folder)
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                    '-subj', '/CN=gsa.apple.com', '-addext', 'subjectAltName=DNS:gsa.apple.com',
                    '-keyout', str(root/'key'), '-out', str(root/'cert')],
                   check=True, capture_output=True)
    # The statically linked signer uses its compiled-in system trust store,
    # rather than SSL_CERT_FILE. This runs only in a disposable test container.
    test_ca = Path('/usr/local/share/ca-certificates/sideloop-native-test.crt')
    test_ca.write_bytes((root/'cert').read_bytes())
    subprocess.run(['update-ca-certificates'], check=True, capture_output=True)
    anisette = http.server.ThreadingHTTPServer(('127.0.0.1', 6969), Anisette)
    apple = http.server.ThreadingHTTPServer(('127.0.0.1', 443), Apple)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(root/'cert', root/'key')
    apple.socket = context.wrap_socket(apple.socket, server_side=True)
    for server in (anisette, apple): threading.Thread(target=server.serve_forever, daemon=True).start()
    cases = [
        ('stock Mac fallback', stock_mac, windows, 200),
        ('second stock Mac fallback', '<MacBookPro15,1> <Mac OS X;10.15.2;19C57> <com.apple.akd>', windows, 200),
        ('Android fallback', '<Pixel 7> <Android;14;UQ1A.240205.002> <com.apple.akd>', windows, 200),
        ('empty fallback', '   ', windows, 200),
        ('Windows preserved', windows, windows, 200),
        ('modern Mac preserved', modern_mac, modern_mac, 200),
        ('Xcode sanitized', modern_mac.replace('com.apple.akd', 'com.apple.dt.Xcode'), modern_mac, 200),
        ('HTTP 503 before MFA', stock_mac, windows, 503),
    ]
    for label, advertised_identity, expected, http_status in cases:
        operations.clear(); client_identities.clear()
        result = subprocess.run(['AltServer', '--verify-account'], cwd=root,
                                env={**os.environ, 'TZ': 'UTC',
                                     'ALTSERVER_APPLE_ID': 'synthetic@example.test',
                                     'ALTSERVER_APPLE_PASSWORD': 'synthetic-password',
                                     'ALTSERVER_ANISETTE_SERVER': 'http://127.0.0.1:6969'},
                                capture_output=True, text=True, timeout=15)
        output = result.stdout + result.stderr
        assert result.returncode == 1, (label, output)
        assert 'Authentication failed:' in output, (label, output)
        assert ('(17)' if http_status == 503 else '-22411') in output, (label, output)
        assert 'Account authentication succeeded.' not in output
        assert 'Enter two factor code' not in output
        assert operations == ['init'], (label, operations)
        assert client_identities == [expected], (label, client_identities)
        if http_status == 503:
            assert 'Apple authentication HTTP status: 503' in output
            assert 'synthetic-private-response' not in output
        assert not (root/'AltServerData').exists()
        print('PASS: compiled auth-only entrypoint, verified TLS: ' + label)
    operations.clear(); client_identities.clear()
    request = root/'refresh.json'
    request.write_text(json.dumps({'team':'TEAM123456', 'certificate_serial':'01',
                                   'bundles':['test.app.TEAM123456'], 'output':str(root)}))
    result = subprocess.run(['AltServer','--refresh-profiles',str(request)], cwd=root,
                            env={**os.environ, 'TZ':'UTC',
                                 'ALTSERVER_APPLE_ID':'synthetic@example.test',
                                 'ALTSERVER_APPLE_PASSWORD':'synthetic-password',
                                 'ALTSERVER_ANISETTE_SERVER':'http://127.0.0.1:6969'},
                            capture_output=True,text=True,timeout=15)
    assert result.returncode == 1, result.stdout + result.stderr
    assert 'Apple account authentication failed.' in result.stderr
    assert 'Apple account authentication started.' in result.stdout
    assert 'Account authentication succeeded.' not in result.stdout
    assert operations == ['init'], operations
    assert not list(root.glob('*.mobileprovision'))
    assert not (root/'AltServerData').exists()
    print('PASS: compiled profile-only entrypoint authenticates and preserves data on rejection')
    for server in (anisette, apple): server.shutdown()
