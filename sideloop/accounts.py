"""Signing accounts and assignments, kept separate from upstream app/device metadata.

The default account continues to use config.env and the original certificate cache.
Additional accounts each have their own credentials, HOME, working directory and
per-app/device signature state. Each device has one signing account for all of its
apps. Changing it never deletes the old state.
"""

import json
import os
import re
import secrets
import shlex
import shutil
import sys
import threading
import time
from pathlib import Path

from . import config, signing_auth

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
             "verification": verification(i), "authentication": signing_auth.read(runtime_folder(i))}
            for i in ids() for c in [credentials(i)]]


def label(account_id):
    try:
        return credentials(account_id)["APPLE_ID"] or account_id
    except ValueError:
        return account_id


def passwords():
    return [c["APPLE_PASSWORD"] for i in ids() for c in [credentials(i)] if c["APPLE_PASSWORD"]]


def ready(account_id):
    try:
        c = credentials(account_id)
        return bool(c["APPLE_ID"] and c["APPLE_PASSWORD"])
    except ValueError:
        return False


def runtime_folder(account_id):
    return config.DATA if account_id == 'default' else _folder(account_id) / 'runtime'


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
            signing_auth.clear(runtime_folder(account_id))
        return account_id


def verification(account_id):
    return _verification_data().get(account_id, {"status": "unverified"})


def _verification_data():
    with _lock:
        return _read_verification_data()


def _read_verification_data():
    path = config.DATA / 'account-verification.json'
    try:
        data = json.loads(path.read_text())
        if not isinstance(data, dict) or any(not isinstance(v, dict) or
                v.get('status') not in ('unverified', 'checking', 'verified', 'failed') or
                ('checked_at' in v and (type(v['checked_at']) is not int or v['checked_at'] < 0))
                for v in data.values()):
            raise ValueError('invalid verification status')
        return data
    except FileNotFoundError:
        return {}
    except (ValueError, UnicodeError):
        # Status is only a cache. Preserve the damaged copy for inspection; never
        # touch credentials or signing data when recovering from a damaged cache.
        with _lock:
            try:
                path.replace(path.with_name(path.name + '.invalid-' + secrets.token_hex(6)))
            except FileNotFoundError:
                pass
        return {}


def set_verification(account_id, status):
    # Only status and time are persisted; codes and Apple session tokens aren't.
    with _lock:
        credentials(account_id)
        path = config.DATA / 'account-verification.json'
        data = _verification_data()
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
    """Read assignments, tolerating a missing, partial or damaged file.

    A file without one of the sections (written by an earlier build) must not
    take down every state read and the automatic re-sign loop with a KeyError.
    """
    path = config.DATA / "signing-accounts.json"
    try:
        data = json.loads(path.read_text())
    except FileNotFoundError:
        return {"version": 2, "devices": {}, "apps": {}}
    except ValueError:
        data = {}
    if not isinstance(data, dict):
        data = {}
    devices, apps = data.get("devices"), data.get("apps")
    return {"version": data.get("version") if data.get("version") == 2 else None,
            "devices": {k: v for k, v in devices.items() if isinstance(v, str)} if isinstance(devices, dict) else {},
            "apps": {k: v for k, v in apps.items() if isinstance(v, dict)} if isinstance(apps, dict) else {}}


def _write_assignments(data):
    config.DATA.mkdir(parents=True, exist_ok=True)
    path = config.DATA / "signing-accounts.json"
    tmp = path.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(data, f)
    os.replace(tmp, path)


def migrate(targets):
    """Convert per-app signers to one signer per device; returns targets whose signer changed.

    targets maps each device to the apps assigned to it. An explicit device choice
    wins; otherwise the account most of the device's apps already use is kept.
    """
    with _lock:
        data = _assignments()
        if data.get("version") == 2:
            return []
        devices, apps = data.get("devices", {}), data.get("apps", {})
        changed = []
        for udid, app_ids in targets.items():
            used = {a: apps.get(a, {}).get(udid) or devices.get(udid, "default") for a in app_ids}
            if udid not in devices and used:
                counts = [(list(used.values()).count(u), u) for u in dict.fromkeys(used.values())]
                devices[udid] = max(counts, key=lambda c: c[0])[1]
            if devices.get(udid, "default") != "default" and not ready(devices[udid]):
                devices.pop(udid)
            chosen = devices.get(udid, "default")
            if chosen == "default":
                devices.pop(udid, None)
            changed += [(a, udid, old, chosen) for a, old in used.items() if old != chosen]
        # An empty "apps" section keeps the file readable by builds that predate per-device accounts.
        _write_assignments({"version": 2, "devices": devices, "apps": {}})
        return changed


def forget(udid):
    """Remove a device's assignment when the device is removed."""
    with _lock:
        data = _assignments()
        data["devices"].pop(udid, None)
        _write_assignments(data)


def device_account(udid):
    return _assignments()["devices"].get(udid, "default")


def resolve(app_id, udid):
    # Every app on a device is signed by that device's account.
    return device_account(udid)


def state_folder(app_id, udid):
    base = config.APPS / app_id / "state" / udid
    account_id = resolve(app_id, udid)
    return base if account_id == "default" else base / "accounts" / _folder(account_id).name


def assign(udid, account_id):
    if not ready(account_id):
        raise ValueError("finish setting up that signing account first")
    with _lock:
        data = _assignments()
        if account_id == "default":
            data["devices"].pop(udid, None)
        else:
            data["devices"][udid] = account_id
        _write_assignments(data)


def remove(account_id):
    """Delete an additional account and its certificate cache once no device uses it."""
    if account_id == "default":
        raise ValueError("the default account can't be removed")
    with _lock:
        folder = _folder(account_id)
        if not (folder / "credentials.env").is_file():
            raise ValueError("no such signing account")
        if account_id in _assignments()["devices"].values():
            raise ValueError("switch the devices that use this account to another account first")
        shutil.rmtree(folder)
        path = config.DATA / 'account-verification.json'
        if path.exists():
            data = json.loads(path.read_text())
            if data.pop(account_id, None) is not None:
                tmp = path.with_suffix('.tmp')
                fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(fd, 'w') as f:
                    json.dump(data, f)
                os.replace(tmp, path)


def shell_context(app_id, udid):
    account_id = resolve(app_id, udid)
    values = credentials(account_id)
    if not all(values.values()):
        raise ValueError("finish setting up the selected signing account first")
    work = runtime_folder(account_id)
    home = work / '.altserver'
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
