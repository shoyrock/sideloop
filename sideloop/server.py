import http.server
import json
import os
import time
import traceback
import urllib.parse
from pathlib import Path

from . import accounts, auth, config, ipa, pairing, store, verification
from .config import LIFETIME_DAYS, MUX, PENDING_IPA, STATE
from .jobs import redact, run_capture, run_pty
from .log import log
from .watcher import configured

INDEX = Path(__file__).with_name("index.html")
COOKIE = "sideloop_session"
CSP = "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:"
MAX_JSON = 1_000_000
MAX_IPA = 4 * 1024 ** 3


class App:
    def __init__(self, jobs, health, muxers):
        self.jobs, self.health, self.muxers = jobs, health, muxers
        accounts.clear_interrupted_verifications()

    def state(self):
        cfg = config.read()
        h = self.health.snapshot()
        live = {d["udid"].lower(): d for d in h["devices"]}
        auto = self.jobs.auto
        return {
            "mode": MUX,
            "now": int(time.time()),
            "configured": configured(cfg),
            "config": {"apple_id": cfg["APPLE_ID"], "has_password": bool(cfg["APPLE_PASSWORD"]),
                       "renew_before_days": config.renew_before_days(cfg), "lifetime_days": LIFETIME_DAYS,
                       "auto_check": cfg["AUTO_CHECK"] == "1"},
            "apps": [store.app_view(a) for a in store.app_ids()],
            "accounts": accounts.views(),
            "registered": [{"udid": u, "name": store.device_name(u), "live": live.get(u.lower()),
                            "account": accounts.device_account(u)}
                           for u in store.device_ids()],
            "devices": h["devices"],
            "scanning": h["scanning"],
            "services": {"anisette": h["anisette"], "muxer": h["muxer"]},
            "watcher": {"running": bool(auto and auto.running), "job": auto.view() if auto and auto.running else None},
            "job": self.jobs.current.view() if self.jobs.current else None,
        }

    def logs(self):
        try:
            lines = (STATE / "refresh.log").read_text(errors="replace").splitlines()[-5000:]
        except FileNotFoundError:
            lines = []
        return {"lines": redact(lines)[-300:]}

    def idle(self):
        if self.jobs.busy():
            raise RuntimeError("wait for the current run to finish")

    def device(self, data):
        if not data.get("device"):
            return None
        udid = store.resolve_device(data["device"])
        if not udid:
            raise ValueError("no such device")
        return udid

    def app(self, data):
        if not data.get("app"):
            return None
        if str(data["app"]) not in store.app_ids():
            raise ValueError("no such app")
        return store.app_view(str(data["app"]))

    def scan(self, data):
        self.health.scan()

    def add_device(self, data):
        d = self.health.visible(str(data["udid"]))
        if not d:
            raise ValueError("that device isn't visible right now")
        store.add_device(d["udid"], d["name"])
        self.health.scan()

    def remove_device(self, data):
        udid = self.device(data)
        if not udid:
            raise ValueError("which device?")
        self.idle()
        store.remove_device(udid)

    def set_app_devices(self, data):
        app = self.app(data)
        if not app:
            raise ValueError("which app?")
        self.idle()
        store.set_app_devices(app["id"], [u for u in map(store.resolve_device, data.get("devices", [])) if u])

    def use_ipa(self, data):
        if not PENDING_IPA.exists():
            raise ValueError("upload an IPA first")
        info = ipa.inspect(PENDING_IPA)
        if "error" in info:
            raise ValueError(info["error"])
        self.idle()
        return {"id": store.add_app(PENDING_IPA, info, str(data.get("filename", "")))}

    def remove_app(self, data):
        if str(data.get("id")) not in store.app_ids():
            raise ValueError("no such app")
        self.idle()
        store.remove_app(str(data["id"]))

    def apple_id(self, data):
        return self.save_account({**data, "account": "default"})

    def save_account(self, data):
        account_id = data.get("account", "new")
        candidate = accounts.prepare(account_id, data.get("apple_id", ""), data.get("password", ""))
        return {"job": self.jobs.start('verify', 'Sign In and Save Account',
                                      lambda j: verification.verify_and_save(j, account_id, candidate)).id}

    def assign_account(self, data):
        with self.jobs.lock:
            self.idle()
            udid, app = self.device(data), self.app(data)
            if not udid:
                raise ValueError("which device?")
            if app and not any(t["udid"] == udid for t in app["targets"]):
                raise ValueError("that app isn't assigned to this device")
            if not app:
                for app_id in store.app_ids():
                    if udid in store.app_devices(app_id):
                        accounts.pin(app_id, udid)
            accounts.assign(udid, str(data.get("account", "")), app["id"] if app else None)

    def verify_account(self, data):
        account_id = str(data.get('account', 'default'))
        if not accounts.ready(account_id):
            raise ValueError('save the Apple account email and password first')
        return {"job": self.jobs.start('verify', 'Verify Apple Account',
                                      lambda j: verification.verify(j, account_id)).id}

    def settings(self, data):
        values = {}
        if "auto_check" in data:
            values["AUTO_CHECK"] = "1" if data["auto_check"] else "0"
        if "renew_before_days" in data:
            days = int(data["renew_before_days"])
            if not 1 <= days <= 6:
                raise ValueError("pick between 1 and 6 days")
            values["RENEW_BEFORE_DAYS"] = days
        config.update(values)

    def _target(self, data):
        app, udid = self.app(data), self.device(data)
        args = (["--app", app["id"]] if app else []) + (["--device", udid] if udid else [])
        what = (app["name"] if app else "all apps") + (f" on {store.device_name(udid)}" if udid else "")
        return args, what

    def refresh(self, data):
        if not configured():
            raise ValueError("finish setup first")
        args, what = self._target(data)
        if data.get("force"):
            args, title = args + ["--force"], f"Signing {what}"
        else:
            title = "Checking if a refresh is due"
        return {"job": self.jobs.start("refresh", title, lambda j: run_pty(j, ["refresh.sh", *args])).id}

    def recheck(self, data):
        args, what = self._target(data)
        argv = ["refresh.sh", "--recheck", *args]
        return {"job": self.jobs.start("recheck", f"Checking {what}", lambda j: run_capture(j, argv)).id}

    def pair(self, data):
        if not self.muxers:
            raise ValueError("pairing from the browser only works on Linux; on a Mac use Finder")
        return {"job": self.jobs.start("pair", "Pairing a device", lambda j: pairing.pair(j, self.muxers)).id}

    def job_input(self, data):
        job = self.jobs.current
        if not job or not job.running:
            raise ValueError("nothing is waiting for input")
        job.send(str(data.get("text", "")))

    def job_cancel(self, data):
        job = self.jobs.current
        if job and job.running:
            job.cancel()

    def routes(self):
        return {
            "/api/devices/scan": self.scan,
            "/api/device/add": self.add_device,
            "/api/device/remove": self.remove_device,
            "/api/app/devices": self.set_app_devices,
            "/api/app/remove": self.remove_app,
            "/api/ipa/use": self.use_ipa,
            "/api/appleid": self.apple_id,
            "/api/account/save": self.save_account,
            "/api/account/assign": self.assign_account,
            "/api/account/verify": self.verify_account,
            "/api/settings": self.settings,
            "/api/refresh": self.refresh,
            "/api/recheck": self.recheck,
            "/api/pair": self.pair,
            "/api/job/input": self.job_input,
            "/api/job/cancel": self.job_cancel,
        }


def handler(app):
    routes = app.routes()

    class Handler(http.server.BaseHTTPRequestHandler):
        server_version = "sideloop"

        def log_message(self, *args):
            pass

        def send(self, code, body, content_type="application/json", headers=()):
            if not isinstance(body, bytes):
                body = json.dumps(body).encode()
            self.replied = True
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            for k, v in headers:
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def error(self, code, message):
            self.send(code, {"error": message})

        def json(self):
            n = int(self.headers.get("Content-Length") or 0)
            if n > MAX_JSON:
                raise ValueError("request too large")
            return json.loads(self.rfile.read(n) or b"{}")

        def authed(self):
            for part in (self.headers.get("Cookie") or "").split(";"):
                k, _, v = part.strip().partition("=")
                if k == COOKIE:
                    return auth.valid_session(v)
            return False

        def same_origin(self):
            return self.headers.get("X-Requested-With") == "sideloop"

        def login(self, token="", max_age=auth.SESSION_TTL):
            cookie = f"{COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}"
            self.send(200, {"ok": True}, headers=[("Set-Cookie", cookie)])

        def guarded(self, handle):
            # A handler that raises would otherwise drop the connection without a
            # response, which the browser reports only as "Failed to fetch".
            self.replied = False
            try:
                handle()
            except Exception as e:
                log(f"{self.command} {self.path.partition('?')[0]} failed:\n{traceback.format_exc().rstrip()}")
                if not self.replied:
                    self.error(500, f"{type(e).__name__}: {e}"[:400])

        def do_GET(self):
            self.guarded(self.get)

        def do_POST(self):
            self.guarded(self.post)

        def do_PUT(self):
            self.guarded(self.put)

        def get(self):
            path, _, query = self.path.partition("?")
            if path in ("/", "/index.html"):
                return self.send(200, INDEX.read_bytes(), "text/html; charset=utf-8", [("Content-Security-Policy", CSP)])
            if path == "/api/health":
                return self.send(200, {"ok": True})
            if path == "/api/auth":
                return self.send(200, {"has_password": auth.has_password(), "logged_in": self.authed()})
            if not self.authed():
                return self.error(401, "sign in first")
            if path == "/api/state":
                return self.send(200, app.state())
            if path == "/api/job":
                since = int(urllib.parse.parse_qs(query).get("since", ["0"])[0])
                job = app.jobs.current
                return self.send(200, {"job": job.view(since) if job else None})
            if path == "/api/logs":
                return self.send(200, app.logs())
            self.error(404, "not found")

        def post(self):
            path = self.path.partition("?")[0]
            if not self.same_origin():
                return self.error(403, "bad request origin")
            try:
                data = self.json()
            except ValueError as e:
                return self.error(400, str(e))
            if path == "/api/auth/setup":
                if auth.has_password():
                    return self.error(409, "a password is already set")
                if len(str(data.get("password", ""))) < 8:
                    return self.error(400, "use at least 8 characters")
                auth.set_password(str(data["password"]))
                return self.login(auth.new_session())
            if path == "/api/auth/login":
                if auth.check_password(str(data.get("password", ""))):
                    return self.login(auth.new_session())
                time.sleep(1)
                return self.error(401, "wrong password")
            if path == "/api/auth/logout":
                return self.login("", 0)
            if not self.authed():
                return self.error(401, "sign in first")
            if path not in routes:
                return self.error(404, "not found")
            try:
                self.send(200, routes[path](data) or {"ok": True})
            except RuntimeError as e:
                self.error(409, str(e))
            except (ValueError, KeyError) as e:
                self.error(400, str(e))

        def put(self):
            if self.path.partition("?")[0] != "/api/ipa":
                return self.error(404, "not found")
            if not self.same_origin():
                return self.error(403, "bad request origin")
            if not self.authed():
                return self.error(401, "sign in first")
            n = int(self.headers.get("Content-Length") or 0)
            if not 0 < n < MAX_IPA:
                return self.error(400, "empty or too large")
            PENDING_IPA.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(PENDING_IPA, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as f:
                while n and (chunk := self.rfile.read(min(n, 1 << 20))):
                    f.write(chunk)
                    n -= len(chunk)
            if n:
                PENDING_IPA.unlink(missing_ok=True)
                return self.error(400, "upload interrupted")
            info = ipa.inspect(PENDING_IPA)
            if "error" in info:
                PENDING_IPA.unlink(missing_ok=True)
                return self.error(400, info["error"])
            self.send(200, {"info": info})

    return Handler


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
