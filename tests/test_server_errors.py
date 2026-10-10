"""Request handlers must answer with an error instead of dropping the connection."""
import io
import json
import threading
import unittest
from http.client import HTTPConnection
from unittest.mock import patch

from sideloop import server


class FakeJobs:
    current = None


class FakeHealth:
    def snapshot(self):
        raise PermissionError(13, "Permission denied", "/data/ui.json")


class HandlerErrorTests(unittest.TestCase):
    def setUp(self):
        app = server.App.__new__(server.App)
        app.jobs, app.health, app.muxers = FakeJobs(), FakeHealth(), None
        self.httpd = server.Server(("127.0.0.1", 0), server.handler(app))
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.port = self.httpd.server_address[1]

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()

    def request(self, method, path, body=None):
        c = HTTPConnection("127.0.0.1", self.port, timeout=5)
        c.request(method, path, body=json.dumps(body) if body is not None else None,
                  headers={"X-Requested-With": "sideloop", "Content-Type": "application/json"})
        r = c.getresponse()
        return r.status, json.loads(r.read())

    def test_get_exception_becomes_500_with_message_and_log(self):
        with patch("sideloop.server.auth.has_password", side_effect=PermissionError(13, "Permission denied", "/data/ui.json")), \
             patch("sys.stdout", new_callable=io.StringIO) as out:
            status, body = self.request("GET", "/api/auth")
        self.assertEqual(status, 500)
        self.assertEqual(body, {"error": "PermissionError: [Errno 13] Permission denied: '/data/ui.json'"})
        self.assertIn("GET /api/auth failed:", out.getvalue())
        self.assertIn("PermissionError", out.getvalue())

    def test_post_exception_becomes_500(self):
        with patch("sideloop.server.auth.has_password", side_effect=RuntimeError("boom")), \
             patch("sys.stdout", new_callable=io.StringIO):
            status, body = self.request("POST", "/api/auth/setup", {"password": "password123"})
        self.assertEqual(status, 500)
        self.assertEqual(body, {"error": "RuntimeError: boom"})

    def test_healthy_requests_unaffected(self):
        with patch("sideloop.server.auth.has_password", return_value=False):
            status, body = self.request("GET", "/api/auth")
        self.assertEqual((status, body), (200, {"has_password": False, "logged_in": False}))


if __name__ == "__main__":
    unittest.main()
