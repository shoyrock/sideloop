"""Run the actual AltServer against loopback-only fake services; no Apple traffic."""
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

timestamp = "2026-10-08T12:00:00Z"
observed = []
class Anisette(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def do_GET(self):
        values = {
            "X-Apple-I-MD-M": "ZmFrZQ==", "X-Apple-I-MD": "ZmFrZQ==",
            "X-Apple-I-MD-LU": "ZmFrZQ==", "X-Apple-I-MD-RINFO": "17106176",
            "X-Mme-Device-Id": "11111111-1111-1111-1111-111111111111",
            "X-Apple-I-SRL-NO": "0", "X-MMe-Client-Info": "<MacBookPro> <macOS> <com.apple.akd>",
            "X-Apple-I-Client-Time": timestamp, "X-Apple-Locale": "en_US", "X-Apple-I-TimeZone": "UTC",
        }
        self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
        self.wfile.write(json.dumps(values).encode())
class Apple(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def do_POST(self):
        request = plistlib.loads(self.rfile.read(int(self.headers["Content-Length"])))
        observed.append(request["Request"]["cpd"]["X-Apple-I-Client-Time"])
        response = plistlib.dumps({"Response": {"Status": {"ec": -22411, "em": "Synthetic authentication failure"}}})
        self.send_response(200); self.send_header("Content-Type", "text/x-xml-plist"); self.end_headers()
        self.wfile.write(response)

with tempfile.TemporaryDirectory() as folder:
    root = Path(folder)
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                    "-subj", "/CN=gsa.apple.com", "-keyout", str(root/"key"), "-out", str(root/"cert")],
                   check=True, capture_output=True)
    anisette = http.server.ThreadingHTTPServer(("127.0.0.1", 6969), Anisette)
    apple = http.server.ThreadingHTTPServer(("127.0.0.1", 443), Apple)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(root/"cert", root/"key")
    apple.socket = context.wrap_socket(apple.socket, server_side=True)
    for service in (anisette, apple): threading.Thread(target=service.serve_forever, daemon=True).start()
    for zone in ("America/New_York", "UTC"):
        result = subprocess.run(["/usr/local/bin/AltServer", "-u", "1234567890abcdef1234567890abcdef12345678",
                                 "-a", "synthetic@example.test", "-p", "synthetic-password", "/tmp/fake.ipa"],
                                input="\n", capture_output=True, text=True, timeout=15,
                                env={**os.environ, "TZ": zone, "ALTSERVER_ANISETTE_SERVER": "http://127.0.0.1:6969"})
        assert observed, result.stdout + result.stderr
        sent = observed.pop()
        source = datetime.datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        delta = (datetime.datetime.fromisoformat(sent) - source).total_seconds()
        print(json.dumps({"timezone": zone, "source_time": timestamp, "sent_time": sent,
                          "clock_error_seconds": delta, "actual_binary_exit_code": result.returncode}))
    for service in (anisette, apple): service.shutdown()
