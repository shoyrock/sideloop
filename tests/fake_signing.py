"""Test doubles for USB tools and signing. Never talks to Apple or a device."""

import datetime
import hashlib
import json
import os
import plistlib
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

root = Path(os.environ["DATA_DIR"])
profiles = root / "profiles"
profiles.mkdir(exist_ok=True)
command, *args = sys.argv[1:]
if command == "idevice_id":
    print(os.environ["TEST_DEVICE"])
elif command == "ideviceinfo":
    print("Test iPhone")
elif command == "ideviceprovision":
    if "copy" in args:
        for p in profiles.glob("*.mobileprovision"):
            shutil.copy(p, Path(args[-1]) / p.name)
    elif "remove" in args:
        (profiles / (args[-1] + ".mobileprovision")).unlink(missing_ok=True)
elif command == "AltServer":
    email = args[args.index("-a") + 1]
    cache = Path.cwd() / "AltServerData"
    cache.mkdir(exist_ok=True)
    identity = cache / "account.txt"
    if identity.exists() and identity.read_text() != email:
        raise RuntimeError("signing cache crossed accounts")
    identity.write_text(email)
    with (root / "signing-records.jsonl").open("a") as f:
        f.write(json.dumps({"email": email, "cwd": str(Path.cwd()), "home": os.environ["HOME"]}) + "\n")
    app = Path(args[-1]).parent.name
    team = hashlib.sha256(email.encode()).hexdigest()[:10].upper()
    now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    token = str(uuid.uuid4())
    payload = root / "payload.plist"
    payload.write_bytes(plistlib.dumps({
        "Entitlements": {"application-identifier": f"{team}.{app}.{team}"},
        "CreationDate": now, "ExpirationDate": now + datetime.timedelta(days=7),
        "UUID": token, "DeveloperCertificates": [email.encode()],
    }))
    subprocess.run(["openssl", "smime", "-sign", "-signer", str(root / "cert.pem"),
                    "-inkey", str(root / "key.pem"), "-in", str(payload), "-outform", "DER",
                    "-nodetach", "-out", str(profiles / (token + ".mobileprovision"))],
                   capture_output=True, check=True)
    print("Signing Progress: 1\nInstallation Progress: 1")
