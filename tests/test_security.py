"""Security regression tests. Synthetic data only; no Apple requests or devices."""
import base64
import hashlib
import http.client
import json
import plistlib
import re
import tempfile
import threading
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from sideloop import auth, config, ipa, server, store

DEVICE = "1234567890abcdef1234567890abcdef12345678"


def make_ipa(path, bundle="com.example.app", min_ios="16.0", extra=()):
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("Payload/App.app/Info.plist", plistlib.dumps(
            {"CFBundleIdentifier": bundle, "CFBundleExecutable": "App", "MinimumOSVersion": min_ios}))
        z.writestr("Payload/App.app/App", b"binary")
        for name in extra:
            z.writestr(name, b"x")
    return path


class TempData(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.old = {k: getattr(config, k) for k in ("DATA", "CONFIG", "APPS", "DEVICES")}
        config.DATA, config.CONFIG = self.root, self.root / "config.env"
        config.APPS = store.APPS = self.root / "apps"
        config.DEVICES = store.DEVICES = self.root / "devices"
        self.ui_file = patch.object(auth, "UI_FILE", self.root / "ui.json")
        self.ui_file.start()

    def tearDown(self):
        self.ui_file.stop()
        for k, value in self.old.items():
            setattr(config, k, value)
        store.APPS, store.DEVICES = config.APPS, config.DEVICES
        self.temp.cleanup()


class ArchiveTests(TempData):
    def test_members_outside_the_app_are_rejected(self):
        for name in ("../escape", "Payload/App.app/../../escape", "/etc/passwd", "\\evil", "C:/evil"):
            with self.subTest(name=name):
                info = ipa.inspect(make_ipa(self.root / "bad.ipa", extra=[name]))
                self.assertIn("unsafe archive", info.get("error", ""))

    def test_dot_bundle_identifiers_are_rejected(self):
        for bundle in ("..", ".", "../x", "a/b", ""):
            with self.subTest(bundle=bundle):
                self.assertIn("bundle identifier", ipa.inspect(make_ipa(self.root / "b.ipa", bundle))["error"])
        with self.assertRaises(ValueError):
            store.add_app(make_ipa(self.root / "c.ipa"), {"bundle_id": ".."}, "c.ipa")
        self.assertFalse((self.root / "app.ipa").exists())

    def test_oversized_archives_are_rejected(self):
        with patch.object(ipa, "MAX_ENTRIES", 2):
            self.assertIn("too many files", ipa.inspect(make_ipa(self.root / "m.ipa", extra=["Payload/App.app/x"]))["error"])

    def test_normal_ipa_is_accepted_and_bad_versions_dropped(self):
        info = ipa.inspect(make_ipa(self.root / "ok.ipa"))
        self.assertEqual((info["bundle_id"], info["min_ios"]), ("com.example.app", "16.0"))
        info = ipa.inspect(make_ipa(self.root / "v.ipa", min_ios="1/e touch /tmp/pwned #"))
        self.assertEqual((info["min_ios"], info["app_min_ios"]), ("", ""))


class SessionTests(TempData):
    def setUp(self):
        super().setUp()
        auth.set_password("correct horse battery")
        auth._failures.clear()

    def test_sign_out_revokes_the_session(self):
        token = auth.new_session()
        self.assertTrue(auth.valid_session(token))
        auth.revoke_session(token)
        self.assertFalse(auth.valid_session(token))
        self.assertTrue(auth.valid_session(auth.new_session()))

    def test_forged_and_legacy_tokens_are_rejected(self):
        exp, nonce, sig = auth.new_session().split(".")
        for token in (f"{exp}.{sig}", f"{int(exp) + 1}.{nonce}.{sig}", f"{exp}.{nonce}.{'0' * 64}", "", "a.b.c"):
            self.assertFalse(auth.valid_session(token), token)

    def test_repeated_wrong_passwords_lock_the_client_out(self):
        with patch.object(auth.time, "sleep"):
            for _ in range(auth.MAX_FAILURES):
                self.assertFalse(auth.check_password("wrong", "10.0.0.5"))
        self.assertGreater(auth.login_wait("10.0.0.5"), 0)
        self.assertEqual(auth.login_wait("10.0.0.6"), 0)
        self.assertTrue(auth.check_password("correct horse battery", "10.0.0.6"))


class FakeApp:
    jobs = None

    def routes(self):
        return {"/api/echo": lambda data: {"echo": data}}

    def logs(self):
        return {"lines": []}


class HttpTests(TempData):
    def setUp(self):
        super().setUp()
        auth._failures.clear()
        self.httpd = server.Server(("127.0.0.1", 0), server.handler(FakeApp()))
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.port = self.httpd.server_address[1]

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        super().tearDown()

    def request(self, method, path, body=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        base = {"X-Requested-With": "sideloop", "Content-Type": "application/json"}
        conn.request(method, path, body=json.dumps(body).encode() if isinstance(body, dict) else body,
                     headers={**base, **(headers or {})})
        r = conn.getresponse()
        data = r.read()
        conn.close()
        return r, data

    def setup_session(self):
        r, _ = self.request("POST", "/api/auth/setup", {"password": "correct horse battery"})
        return r.getheader("Set-Cookie").split(";", 1)[0]

    def test_page_has_hash_based_csp_and_security_headers(self):
        r, html = self.request("GET", "/")
        # Browsers hash the script with normalized line endings; the served page must already match.
        self.assertNotIn(b"\r", html)
        script = re.search(rb"<script>(.*?)</script>", html, re.S).group(1)
        digest = base64.b64encode(hashlib.sha256(script).digest()).decode()
        csp = r.getheader("Content-Security-Policy")
        self.assertIn(f"script-src 'sha256-{digest}'", csp)
        self.assertNotIn("unsafe-inline'; img", csp.split("script-src")[1].split(";")[0])
        self.assertIn("frame-ancestors 'none'", csp)
        self.assertEqual((r.getheader("X-Frame-Options"), r.getheader("X-Content-Type-Options")), ("DENY", "nosniff"))

    def test_cross_site_and_headerless_requests_are_refused(self):
        cookie = self.setup_session()
        r, _ = self.request("POST", "/api/echo", {}, {"Cookie": cookie, "Sec-Fetch-Site": "cross-site"})
        self.assertEqual(r.status, 403)
        r, _ = self.request("POST", "/api/echo", {}, {"Cookie": cookie, "X-Requested-With": ""})
        self.assertEqual(r.status, 403)
        r, data = self.request("POST", "/api/echo", {"a": 1}, {"Cookie": cookie, "Sec-Fetch-Site": "same-origin"})
        self.assertEqual((r.status, json.loads(data)), (200, {"echo": {"a": 1}}))

    def test_invalid_bodies_get_clean_errors(self):
        cookie = self.setup_session()
        r, _ = self.request("POST", "/api/echo", b"{}", {"Cookie": cookie, "Content-Length": "-1"})
        self.assertEqual(r.status, 400)
        r, _ = self.request("POST", "/api/echo", b"[1, 2]", {"Cookie": cookie})
        self.assertEqual(r.status, 400)
        r, _ = self.request("GET", "/api/job?since=abc", headers={"Cookie": cookie})
        self.assertEqual(r.status, 400)

    def test_logout_revokes_the_cookie_server_side(self):
        cookie = self.setup_session()
        r, _ = self.request("GET", "/api/logs", headers={"Cookie": cookie})
        self.assertNotEqual(r.status, 401)
        self.request("POST", "/api/auth/logout", {}, {"Cookie": cookie})
        r, _ = self.request("GET", "/api/logs", headers={"Cookie": cookie})
        self.assertEqual(r.status, 401)

    def test_login_is_throttled_after_repeated_failures(self):
        self.setup_session()
        with patch.object(auth.time, "sleep"):
            for _ in range(auth.MAX_FAILURES):
                r, _ = self.request("POST", "/api/auth/login", {"password": "wrong"})
                self.assertEqual(r.status, 401)
            r, data = self.request("POST", "/api/auth/login", {"password": "correct horse battery"})
        self.assertEqual(r.status, 429)
        self.assertIn("too many wrong passwords", json.loads(data)["error"])
        self.assertTrue(r.getheader("Retry-After"))

    def test_secure_cookie_behind_https_proxy(self):
        r, _ = self.request("POST", "/api/auth/setup", {"password": "correct horse battery"},
                            {"X-Forwarded-Proto": "https"})
        self.assertIn("; Secure", r.getheader("Set-Cookie"))


if __name__ == "__main__":
    unittest.main()
