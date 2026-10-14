import hashlib
import hmac
import json
import os
import secrets
import threading
import time

from .config import UI_FILE

SESSION_TTL = 30 * 86400
# Login throttling: password checks run one at a time (so parallel requests can't multiply the
# guess rate), and an address is locked out after repeated failures.
MAX_FAILURES = 10
FAILURE_WINDOW = 15 * 60
_check_lock = threading.Lock()
_failures = {}
_failures_lock = threading.Lock()
_file_lock = threading.Lock()


def _load():
    try:
        return json.loads(UI_FILE.read_text())
    except (FileNotFoundError, ValueError):
        return {}


def _save(c):
    UI_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = UI_FILE.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(c, f)
    os.replace(tmp, UI_FILE)


def _hash(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 200_000).hex()


def _sign(secret, value):
    return hmac.new(secret.encode(), value.encode(), "sha256").hexdigest()


def has_password():
    return bool(_load())


def set_password(password):
    # A new secret also invalidates every existing session.
    salt = secrets.token_hex(16)
    with _file_lock:
        _save({"salt": salt, "hash": _hash(password, salt), "secret": secrets.token_hex(32)})


def login_wait(client):
    """Seconds until this client may try again, or 0."""
    now = time.time()
    with _failures_lock:
        recent = [t for t in _failures.get(client, []) if now - t < FAILURE_WINDOW]
        _failures[client] = recent
        return int(recent[0] + FAILURE_WINDOW - now) + 1 if len(recent) >= MAX_FAILURES else 0


def check_password(password, client=""):
    with _check_lock:
        c = _load()
        ok = bool(c) and hmac.compare_digest(_hash(password, c["salt"]), c["hash"])
        if not ok:
            time.sleep(1)
    with _failures_lock:
        if ok:
            _failures.pop(client, None)
        else:
            _failures.setdefault(client, []).append(time.time())
    return ok


def new_session():
    exp, nonce = str(int(time.time()) + SESSION_TTL), secrets.token_hex(16)
    return f"{exp}.{nonce}.{_sign(_load()['secret'], f'{exp}.{nonce}')}"


def _parse(token, c):
    parts = (token or "").split(".")
    if not c or len(parts) != 3 or not parts[0].isdigit():
        return None
    exp, nonce, sig = parts
    if not hmac.compare_digest(sig, _sign(c["secret"], f"{exp}.{nonce}")) or int(exp) <= time.time():
        return None
    return exp, nonce


def valid_session(token):
    c = _load()
    parsed = _parse(token, c)
    return bool(parsed) and parsed[1] not in c.get("revoked", {})


def revoke_session(token):
    """Sign-out invalidates the session itself, not just the browser's cookie."""
    with _file_lock:
        c = _load()
        parsed = _parse(token, c)
        if not parsed:
            return
        now = time.time()
        revoked = {n: e for n, e in c.get("revoked", {}).items() if int(e) > now}
        revoked[parsed[1]] = parsed[0]
        _save({**c, "revoked": revoked})
