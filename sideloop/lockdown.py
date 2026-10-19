import os
import plistlib
import socket
import ssl
import struct
import tempfile

LOCKDOWN_PORT = 62078
WIFI_DOMAIN = "com.apple.mobile.wireless_lockdown"
WIFI_KEY = "EnableWiFiConnections"


def _mux_connect(addr):
    if ":" in addr:
        host, port = addr.rsplit(":", 1)
        return socket.create_connection((host, int(port)), timeout=15)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(15)
    s.connect(addr)
    return s


def _recv_exact(s, n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed")
        buf += chunk
    return buf


def _mux_request(s, msg, tag=1):
    body = plistlib.dumps(dict(msg, ClientVersionString="sideloop", ProgName="sideloop"))
    s.sendall(struct.pack("<IIII", 16 + len(body), 1, 8, tag) + body)
    length = struct.unpack("<I", _recv_exact(s, 4))[0]
    _recv_exact(s, 12)
    return plistlib.loads(_recv_exact(s, length - 16))


def _device_id(udid, mux):
    with _mux_connect(mux) as s:
        devices = _mux_request(s, {"MessageType": "ListDevices"}).get("DeviceList", [])
        # Prefer a connected cable when the muxer lists both Wi-Fi and USB.
        for d in sorted(devices, key=lambda d: d['Properties'].get('ConnectionType') != 'USB'):
            if d["Properties"].get("SerialNumber", "").lower() == udid.lower():
                return d["DeviceID"]
    raise LookupError(f"device {udid} not visible to the muxer")


def _pair_record(udid, mux):
    with _mux_connect(mux) as s:
        r = _mux_request(s, {"MessageType": "ReadPairRecord", "PairRecordID": udid})
    if "PairRecordData" not in r:
        raise LookupError("no pairing record: pair the device first")
    return plistlib.loads(r["PairRecordData"])


class Lockdown:
    def __init__(self, udid, mux):
        self.udid, self.mux = udid, mux
        self.pair = _pair_record(udid, mux)
        s = _mux_connect(mux)
        self.sock = s
        try:
            port = socket.htons(LOCKDOWN_PORT)
            r = _mux_request(s, {"MessageType": "Connect", "DeviceID": _device_id(udid, mux), "PortNumber": port})
            if r.get("Number", 1) != 0:
                raise ConnectionError(f"muxer refused the lockdown connection ({r.get('Number')})")
            r = self._call({"Request": "StartSession", "HostID": self.pair["HostID"],
                            "SystemBUID": self.pair["SystemBUID"]})
            if "Error" in r:
                raise PermissionError(f"lockdown StartSession: {r['Error']}")
            self.session = r["SessionID"]
            if r.get("EnableSessionSSL"):
                self._start_tls()
        except Exception:
            self.sock.close()
            raise

    def _start_tls(self):
        self.sock = _paired_tls(self.sock, self.pair)

    def service(self, name):
        reply = self._call({"Request": "StartService", "Service": name})
        if "Error" in reply or not reply.get("Port"):
            raise ConnectionError(f"device service unavailable: {name}")
        s = _mux_connect(self.mux)
        try:
            port = socket.htons(reply["Port"])
            r = _mux_request(s, {"MessageType": "Connect", "DeviceID": _device_id(self.udid, self.mux), "PortNumber": port})
            if r.get("Number", 1) != 0:
                raise ConnectionError("device service connection refused")
            if reply.get("EnableServiceSSL"):
                s = _paired_tls(s, self.pair)
            return PlistService(s)
        except Exception:
            s.close()
            raise

    def _call(self, req):
        body = plistlib.dumps(dict(req, Label="sideloop"))
        self.sock.sendall(struct.pack(">I", len(body)) + body)
        return _receive_plist(self.sock)

    def get(self, domain, key):
        r = self._call({"Request": "GetValue", "Domain": domain, "Key": key})
        if r.get("Error") == "MissingValue":
            return None
        if "Error" in r:
            raise RuntimeError(r["Error"])
        return r.get("Value")

    def set(self, domain, key, value):
        r = self._call({"Request": "SetValue", "Domain": domain, "Key": key, "Value": value})
        if "Error" in r:
            raise RuntimeError(r["Error"])

    def close(self):
        try:
            self._call({"Request": "StopSession", "SessionID": self.session})
        except Exception:
            pass
        self.sock.close()


def _paired_tls(sock, pair):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    with tempfile.TemporaryDirectory() as d:
        cert, key = os.path.join(d, "c"), os.path.join(d, "k")
        with open(cert, "wb") as f:
            f.write(pair["HostCertificate"])
        with open(key, "wb") as f:
            f.write(pair["HostPrivateKey"])
        ctx.load_cert_chain(cert, key)
    return ctx.wrap_socket(sock)


def _receive_plist(sock):
    size = struct.unpack(">I", _recv_exact(sock, 4))[0]
    if not 0 < size <= 64 * 1024 * 1024:
        raise ConnectionError("invalid device response length")
    return plistlib.loads(_recv_exact(sock, size))


class PlistService:
    def __init__(self, sock):
        self.sock = sock

    def send(self, req):
        body = plistlib.dumps(req)
        self.sock.sendall(struct.pack(">I", len(body)) + body)

    def receive(self):
        return _receive_plist(self.sock)

    def close(self):
        self.sock.close()


def enable_wifi(udid, mux):
    ld = Lockdown(udid, mux)
    try:
        ld.set(WIFI_DOMAIN, WIFI_KEY, True)
        return bool(ld.get(WIFI_DOMAIN, WIFI_KEY))
    finally:
        ld.close()
