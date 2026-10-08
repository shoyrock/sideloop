"""Signing accounts and assignments, kept separate from upstream app/device metadata.

The default account continues to use config.env and the original certificate cache.
Additional accounts each have their own credentials, HOME, working directory and
per-app/device signature state. Changing an account never deletes the old state.
"""

import json
import os
import re
import secrets
import shlex
import sys
import threading
import time
from pathlib import Path

from . import config

ACCOUNT_KEYS = ["APPLE_ID", "APPLE_PASSWORD"]
ID_RE = re.compile(r"^[a-f0-9]{24}$")
_lock = threading.RLock()


def _folder(account_id):
    if not ID_RE.fullmatch(str(account_id)):
        raise ValueError("invalid signing account")
    return config.DATA / "accounts" / account_id


def credentials(account_id):
    if account_id == "default":
        cfg = config.read()
        return {k: cfg[k] for k in ACCOUNT_KEYS}
    path = _folder(account_id) / "credentials.env"
    if not path.is_file():
        raise ValueError("no such signing account")
    return config.read_env(path, ACCOUNT_KEYS)


def ids():
    root = config.DATA / "accounts"
    extra = sorted(p.name for p in root.iterdir()
                   if ID_RE.fullmatch(p.name) and (p / "credentials.env").is_file()) if root.is_dir() else []
    return ["default", *extra]


def views():
    return [{"id": i, "email": c["APPLE_ID"], "has_password": bool(c["APPLE_PASSWORD"]),
             "verification": verification(i)}
            for i in ids() for c in [credentials(i)]]


def passwords():
    return [c["APPLE_PASSWORD"] for i in ids() for c in [credentials(i)] if c["APPLE_PASSWORD"]]


def ready(account_id):
    try:
        c = credentials(account_id)
        return bool(c["APPLE_ID"] and c["APPLE_PASSWORD"])
    except ValueError:
        return False


def prepare(account_id, email, password=""):
    """Validate candidate credentials without saving or adding an account."""
    email = str(email).strip()
    if "@" not in email or len(email) > 254:
        raise ValueError("enter the Apple ID's email address")
    with _lock:
        new = account_id in (None, "", "new")
        old = {k: "" for k in ACCOUNT_KEYS} if new else credentials(account_id)
        if old["APPLE_ID"] and old["APPLE_ID"].casefold() != email.casefold():
            raise ValueError("add a new account to change the email; this account has its own signing data")
        email = old["APPLE_ID"] or email
        for i in ids():
            if i != account_id and credentials(i)["APPLE_ID"].casefold() == email.casefold():
                raise ValueError("that Apple account is already saved")
        password = str(password or old["APPLE_PASSWORD"])
        if not password:
            raise ValueError("enter the password")
        return {"APPLE_ID": email, "APPLE_PASSWORD": password}


def save(account_id, email, password=""):
    with _lock:
        values = prepare(account_id, email, password)
        new = account_id in (None, "", "new")
        old = {k: "" for k in ACCOUNT_KEYS} if new else credentials(account_id)
        if account_id == "default":
            config.update(values)
        else:
            account_id = secrets.token_hex(12) if new else account_id
            folder = _folder(account_id)
            folder.mkdir(parents=True, exist_ok=True, mode=0o700)
            config.write_env(folder / "credentials.env", values)
            if not config.CONFIG.exists():
                config.update({})
        if new or values != old:
            set_verification(account_id, "unverified")
        return account_id


def verification(account_id):
    path = config.DATA / 'account-verification.json'
    try:
        return json.loads(path.read_text()).get(account_id, {"status": "unverified"})
    except FileNotFoundError:
        return {"status": "unverified"}


def set_verification(account_id, status):
    # Only status and time are persisted; codes and Apple session tokens aren't.
    with _lock:
        credentials(account_id)
        path = config.DATA / 'account-verification.json'
        data = json.loads(path.read_text()) if path.exists() else {}
        data[account_id] = {"status": status, "checked_at": int(time.time())}
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix('.tmp')
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'w') as f:
            json.dump(data, f)
        os.replace(tmp, path)


def clear_interrupted_verifications():
    for account_id in ids():
        if verification(account_id)['status'] == 'checking':
            set_verification(account_id, 'unverified')


def _assignments():
    path = config.DATA / "signing-accounts.json"
    if not path.exists():
        return {"devices": {}, "apps": {}}
    return json.loads(path.read_text())


def _write_assignments(data):
    config.DATA.mkdir(parents=True, exist_ok=True)
    path = config.DATA / "signing-accounts.json"
    tmp = path.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(data, f)
    os.replace(tmp, path)


def forget(app_id=None, udid=None):
    """Remove assignments when the corresponding app or device is removed."""
    with _lock:
        data = _assignments()
        if app_id is not None:
            data["apps"].pop(app_id, None)
        if udid is not None:
            data["devices"].pop(udid, None)
            for targets in data["apps"].values():
                targets.pop(udid, None)
        _write_assignments(data)


def device_account(udid):
    return _assignments()["devices"].get(udid, "default")


def app_override(app_id, udid):
    return _assignments()["apps"].get(app_id, {}).get(udid, "")


def resolve(app_id, udid):
    data = _assignments()
    return data["apps"].get(app_id, {}).get(udid) or data["devices"].get(udid, "default")


def state_folder(app_id, udid):
    base = config.APPS / app_id / "state" / udid
    account_id = resolve(app_id, udid)
    return base if account_id == "default" else base / "accounts" / _folder(account_id).name


def assign(udid, account_id, app_id=None):
    if account_id and not ready(account_id):
        raise ValueError("finish setting up that signing account first")
    with _lock:
        data = _assignments()
        target = data["devices"] if app_id is None else data["apps"].setdefault(app_id, {})
        if account_id:
            target[udid] = account_id
        else:
            target.pop(udid, None)
        _write_assignments(data)


def pin(app_id, udid):
    """Keep an existing target's signer when the device default is later changed."""
    if not app_override(app_id, udid) and ready(resolve(app_id, udid)):
        assign(udid, resolve(app_id, udid), app_id)


def shell_context(app_id, udid):
    account_id = resolve(app_id, udid)
    values = credentials(account_id)
    if not all(values.values()):
        raise ValueError("finish setting up the selected signing account first")
    pin(app_id, udid)
    if account_id == "default":
        work, home = config.DATA, config.DATA / ".altserver"
    else:
        work = _folder(account_id) / "runtime"
        home = work / ".altserver"
    home.mkdir(parents=True, exist_ok=True)
    values.update(SIGNING_ACCOUNT=account_id, SIGNING_WORKDIR=str(work), SIGNING_HOME=str(home),
                  SIGNING_STATE=str(state_folder(app_id, udid)),
                  SIGNING_ISOLATED="1" if len(ids()) > 1 else "0")
    return "\n".join(f"{k}={shlex.quote(str(v))}" for k, v in values.items())


if __name__ == "__main__":
    try:
        action, app_id, udid = sys.argv[1:]
        # Paths originate in validated app/device metadata, also used by refresh.sh.
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,120}", app_id) or app_id in (".", ".."):
            raise ValueError("invalid app")
        if not re.fullmatch(r"[0-9A-Fa-f-]{20,64}", udid):
            raise ValueError("invalid device")
        if action == "resolve":
            print(shell_context(app_id, udid))
        elif action == "state":
            print(state_folder(app_id, udid))
        else:
            raise ValueError("invalid account operation")
    except ValueError as e:
        print(str(e), file=sys.stderr)
        sys.exit(78)
