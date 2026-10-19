import os
import hashlib
import re
import shutil
import time

from . import accounts, ipa
from .config import APPS, DEVICES, read_env, write_env

APP_KEYS = ["BUNDLE_ID", "APP_NAME", "APP_VERSION", "IPA_SOURCE", "ADDED", "DEVICES", "KEEP_EXTENSIONS"]
DEVICE_KEYS = ["DEVICE_NAME", "ADDED", "IOS", "MANUAL_APPS"]
UDID_RE = re.compile(r"^[0-9A-Fa-f-]{20,64}$")


def read_state(folder):
    def rd(name):
        try:
            return (folder / name).read_text().strip()
        except OSError:
            return ""
    lr = rd("last_run").split("\t")
    last_run = None
    if len(lr) >= 2 and lr[0].isdigit():
        last_run = {"t": int(lr[0]), "result": lr[1], "message": lr[2] if len(lr) > 2 else ""}
    expiry = rd('expiry')
    return {"expiry": int(expiry) if expiry.isdigit() else None, "last_run": last_run}


def device_ids():
    return sorted(f.stem for f in DEVICES.glob("*.env")) if DEVICES.is_dir() else []


def resolve_device(udid):
    return {u.lower(): u for u in device_ids()}.get(str(udid).lower())


def device_name(udid):
    return read_env(DEVICES / f"{udid}.env", DEVICE_KEYS)["DEVICE_NAME"] or udid


def device_ios(udid):
    return read_env(DEVICES / f"{udid}.env", DEVICE_KEYS)["IOS"]


def set_device_ios(udid, ios):
    # Remembered so incompatible apps are flagged while the device is away.
    path = DEVICES / f"{udid}.env"
    old = read_env(path, DEVICE_KEYS)
    if path.exists() and ios and ios != "-" and old["IOS"] != ios:
        write_env(path, {**old, "IOS": ios})


def add_device(udid, name):
    if not UDID_RE.match(udid):
        raise ValueError("that doesn't look like a device ID")
    old = read_env(DEVICES / f"{udid}.env", DEVICE_KEYS)
    # A new device starts without apps; the user chooses which go on it.
    write_env(DEVICES / f"{udid}.env", {**old, "DEVICE_NAME": name or udid, "ADDED": old["ADDED"] or int(time.time())})


def auto_resign(app_id, udid):
    return app_id not in read_env(DEVICES / f"{udid}.env", DEVICE_KEYS)["MANUAL_APPS"].split()


def set_auto_resign(app_id, udid, on):
    path = DEVICES / f"{udid}.env"
    if not path.exists():
        raise ValueError("no such device")
    old = read_env(path, DEVICE_KEYS)
    manual = [a for a in old["MANUAL_APPS"].split() if a != app_id] + ([] if on else [app_id])
    write_env(path, {**old, "MANUAL_APPS": " ".join(manual)})


def remove_device(udid):
    (DEVICES / f"{udid}.env").unlink(missing_ok=True)
    for app_id in app_ids():
        set_app_devices(app_id, [u for u in app_meta(app_id)["DEVICES"].split() if u.lower() != udid.lower()])
        shutil.rmtree(APPS / app_id / "state" / udid, ignore_errors=True)
    accounts.forget(udid)


def app_ids():
    if not APPS.is_dir():
        return []
    return sorted(d.name for d in APPS.iterdir() if (d / "meta.env").exists() and (d / "app.ipa").exists())


def app_meta(app_id):
    return read_env(APPS / app_id / "meta.env", APP_KEYS)


def app_devices(app_id, meta=None):
    known = {u.lower(): u for u in device_ids()}
    return [known[u.lower()] for u in (meta or app_meta(app_id))["DEVICES"].split() if u.lower() in known]


def set_app_devices(app_id, udids):
    meta = app_meta(app_id)
    meta["DEVICES"] = " ".join(udids)
    write_env(APPS / app_id / "meta.env", meta)


def app_view(app_id):
    from .renewal import read_json
    d, meta = APPS / app_id, app_meta(app_id)
    info = ipa.cached(d)
    keep = meta["KEEP_EXTENSIONS"] == "1"
    min_ios = ipa.required_ios(info, keep)
    return {
        "id": app_id,
        "bundle_id": meta["BUNDLE_ID"],
        "name": meta["APP_NAME"] or app_id,
        "version": meta["APP_VERSION"],
        "info": info,
        "keep_extensions": keep,
        "min_ios": min_ios,
        "targets": [{"udid": u, "name": device_name(u), "account": accounts.resolve(app_id, u),
                     "signature": read_state(accounts.state_folder(app_id, u)),
                     "installed": read_json(accounts.state_folder(app_id, u) / 'installed.json'),
                     "auto": auto_resign(app_id, u),
                     "needs_ios": min_ios if ipa.requires_newer(min_ios, device_ios(u)) else ""}
                    for u in app_devices(app_id, meta)],
    }


def add_app(src, info, filename):
    bundle = info['bundle_id']
    # Reuse legacy directories only when their full ID matches. Never overwrite
    # another IPA just because two long IDs share the same first 120 characters.
    existing = next((a for a in app_ids() if app_meta(a)['BUNDLE_ID'] == bundle), None)
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", bundle)
    app_id = existing or (safe if len(safe) <= 120 else safe[:90] + '-' + hashlib.sha256(bundle.encode()).hexdigest()[:24])
    # The id is a folder name under APPS; "." or ".." would escape it.
    if app_id.startswith(".") or ".." in app_id:
        raise ValueError("the app's bundle identifier isn't valid")
    d = APPS / app_id
    if (d / 'meta.env').exists() and app_meta(app_id)['BUNDLE_ID'] != bundle:
        raise ValueError('another app already uses this storage identifier')
    (d / "state").mkdir(parents=True, exist_ok=True)
    os.replace(src, d / "app.ipa")
    old = app_meta(app_id)
    write_env(d / "meta.env", {
        "BUNDLE_ID": info["bundle_id"],
        "APP_NAME": info.get("name", ""),
        "APP_VERSION": info.get("version", ""),
        "IPA_SOURCE": filename[:200],
        "ADDED": old["ADDED"] or int(time.time()),
        "DEVICES": old["DEVICES"] if old["ADDED"] else " ".join(device_ids()),
        "KEEP_EXTENSIONS": old["KEEP_EXTENSIONS"],
    })
    (d / "info.json").unlink(missing_ok=True)
    (d / "app-noext.ipa").unlink(missing_ok=True)
    return app_id


def set_keep_extensions(app_id, keep):
    meta = app_meta(app_id)
    meta["KEEP_EXTENSIONS"] = "1" if keep else ""
    write_env(APPS / app_id / "meta.env", meta)
    if keep:
        (APPS / app_id / "app-noext.ipa").unlink(missing_ok=True)


def remove_app(app_id):
    shutil.rmtree(APPS / app_id)
    for udid in device_ids():
        if not auto_resign(app_id, udid):
            set_auto_resign(app_id, udid, True)
