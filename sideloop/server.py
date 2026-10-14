import base64
import hashlib
import http.server
import json
import os
import re
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
# The page's one inline script is allowed by hash, so injected markup can't run scripts.
CSP = ("default-src 'self'; script-src 'sha256-{}'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
       "connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
SECURITY_HEADERS = [("X-Content-Type-Options", "nosniff"), ("X-Frame-Options", "DENY"),
                    ("Referrer-Policy", "no-referrer"), ("Cross-Origin-Opener-Policy", "same-origin")]
REQUEST_TIMEOUT = 60


def page():
    # Browsers hash the script after normalizing line endings, so serve and hash it with LF only
    # (a Windows checkout has CRLF).
    html = INDEX.read_bytes().replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    script = re.search(rb"<script>(.*?)</script>", html, re.S).group(1)
    return html, CSP.format(base64.b64encode(hashlib.sha256(script).digest()).decode())
MAX_JSON = 1_000_000
MAX_IPA = 4 * 1024 ** 3


class App:
    def __init__(self, jobs, health, muxers, watcher=None):
        self.jobs, self.health, self.muxers, self.watcher = jobs, health, muxers, watcher
        accounts.clear_interrupted_verifications()
        targets = {u: [a for a in store.app_ids() if u in store.app_devices(a)] for u in store.device_ids()}
        for app_id, udid, old, new in accounts.migrate(targets):
            note = (f"accounts: {app_id} on {store.device_name(udid)} now signs with the device's account "
                    f"({accounts.label(new)} instead of {accounts.label(old)})")
            log(note)
            STATE.mkdir(parents=True, exist_ok=True)
            with (STATE / "refresh.log").open("a") as f:
                f.write(time.strftime("%Y-%m-%d %H:%M:%S ") + note + "\n")

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
                            "account": accounts.device_account(u), "ios": store.device_ios(u)}
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

    def set_auto_resign(self, data):
        app, udid = self.app(data), self.device(data)
        if not app or not udid or not any(t["udid"] == udid for t in app["targets"]):
            raise ValueError("that app isn't on this device")
        store.set_auto_resign(app["id"], udid, bool(data.get("auto")))
        if data.get("auto") and self.watcher:
            self.watcher.soon()

    def set_app_extensions(self, data):
        app = self.app(data)
        if not app:
            raise ValueError("which app?")
        self.idle()
        store.set_keep_extensions(app["id"], bool(data.get("keep")))

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
            if data.get("app"):
                raise ValueError("signing accounts are chosen per device and apply to all of its apps")
            udid = self.device(data)
            if not udid:
                raise ValueError("which device?")
            installed = [a for a in store.app_ids() if udid in store.app_devices(a)
                         and store.read_state(accounts.state_folder(a, udid))["expiry"]]
            accounts.assign(udid, str(data.get("account", "")))
            # Apps installed with the previous account stay installed apps: mark them due under
            # the new one so automatic checks re-sign them, as the switch confirmation says.
            for app_id in installed:
                state = accounts.state_folder(app_id, udid)
                if not store.read_state(state)["expiry"]:
                    state.mkdir(parents=True, exist_ok=True)
                    (state / "expiry").write_text("1")
        # Apps that moved to the new account have no signature yet; re-sign them soon.
        if self.watcher:
            self.watcher.soon()

    def remove_account(self, data):
        with self.jobs.lock:
            self.idle()
            accounts.remove(str(data.get("account", "")))

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
            # Re-signing several apps never installs the ones that aren't installed yet.
            args = args + ["--force"] + ([] if data.get("app") else ["--resign-only"])
            title = f"Signing {what}"
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
            "/api/app/extensions": self.set_app_extensions,
            "/api/app/auto": self.set_auto_resign,
            "/api/app/remove": self.remove_app,
            "/api/ipa/use": self.use_ipa,
            "/api/appleid": self.apple_id,
            "/api/account/save": self.save_account,
            "/api/account/assign": self.assign_account,
            "/api/account/verify": self.verify_account,
            "/api/account/remove": self.remove_account,
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
        # Slow or stalled clients can't hold a request thread forever.
        timeout = REQUEST_TIMEOUT

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
            for k, v in [*SECURITY_HEADERS, *headers]:
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def error(self, code, message):
            self.send(code, {"error": message})

        def length(self):
            try:
                n = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                n = -1
            if n < 0:
                raise ValueError("invalid Content-Length")
            return n

        def json(self):
            n = self.length()
            if n > MAX_JSON:
                raise ValueError("request too large")
            data = json.loads(self.rfile.read(n) or b"{}")
            if not isinstance(data, dict):
                raise ValueError("expected a JSON object")
            return data

        def cookie(self):
            for part in (self.headers.get("Cookie") or "").split(";"):
                k, _, v = part.strip().partition("=")
                if k == COOKIE:
                    return v
            return ""

        def authed(self):
            return auth.valid_session(self.cookie())

        def same_origin(self):
            # The custom header can't be sent cross-site without CORS; also reject requests the
            # browser labels as coming from another site. (Origin isn't compared with Host:
            # reverse proxies commonly rewrite Host.)
            if self.headers.get("X-Requested-With") != "sideloop":
                return False
            return self.headers.get("Sec-Fetch-Site", "same-origin") in ("same-origin", "none")

        def login(self, token="", max_age=auth.SESSION_TTL):
            # Behind an HTTPS reverse proxy the cookie is also limited to HTTPS.
            secure = "; Secure" if self.headers.get("X-Forwarded-Proto", "").lower() == "https" else ""
            cookie = f"{COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}{secure}"
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
                    # The signed-in admin sees what failed; others get no internals. (The session
                    # check reads ui.json, which may be what failed, so it can't raise here.)
                    try:
                        signed_in = self.authed()
                    except Exception:
                        signed_in = False
                    detail = f"{type(e).__name__}: {e}"[:400] if signed_in else "see the container log"
                    self.error(500, f"something went wrong: {detail}")

        def do_GET(self):
            self.guarded(self.get)

        def do_POST(self):
            self.guarded(self.post)

        def do_PUT(self):
            self.guarded(self.put)

        def get(self):
            path, _, query = self.path.partition("?")
            if path in ("/", "/index.html"):
                html, csp = page()
                return self.send(200, html, "text/html; charset=utf-8", [("Content-Security-Policy", csp)])
            if path == "/api/health":
                return self.send(200, {"ok": True})
            if path == "/api/auth":
                return self.send(200, {"has_password": auth.has_password(), "logged_in": self.authed()})
            if not self.authed():
                return self.error(401, "sign in first")
            if path == "/api/state":
                return self.send(200, app.state())
            if path == "/api/job":
                try:
                    since = max(0, int(urllib.parse.parse_qs(query).get("since", ["0"])[0]))
                except ValueError:
                    return self.error(400, "invalid since")
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
                client = self.client_address[0]
                if wait := auth.login_wait(client):
                    minutes = (wait + 59) // 60
                    return self.send(429, {"error": f"too many wrong passwords; try again in {minutes} min"},
                                     headers=[("Retry-After", str(wait))])
                if auth.check_password(str(data.get("password", "")), client):
                    return self.login(auth.new_session())
                return self.error(401, "wrong password")
            if path == "/api/auth/logout":
                auth.revoke_session(self.cookie())
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
            try:
                n = self.length()
            except ValueError as e:
                return self.error(400, str(e))
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
            try:
                info = ipa.inspect(PENDING_IPA)
            except Exception as e:
                info = {"error": "the IPA can't be read"}
                log(f"IPA inspection failed: {type(e).__name__}: {e}")
            if "error" in info:
                PENDING_IPA.unlink(missing_ok=True)
                return self.error(400, info["error"])
            self.send(200, {"info": info})

    return Handler


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
