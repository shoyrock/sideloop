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
    print(os.environ.get("TEST_IOS", "26.0") if "ProductVersion" in args else "Test iPhone")
elif command == "ideviceprovision":
    if "copy" in args:
        for p in profiles.glob("*.mobileprovision"):
            shutil.copy(p, Path(args[-1]) / p.name)
    elif "remove" in args:
        (profiles / (args[-1] + ".mobileprovision")).unlink(missing_ok=True)
elif command == "AltServer" and os.environ.get("TEST_IOS_REJECT"):
    # What AltServer prints when iOS answers DeviceOSVersionTooLow; it still exits 0.
    print("Alert: Could not install app.ipa to unknown.\n"
          "    Your device must be running iOS 12.2 or later to install AltStore.\n"
          "Error: com.rileytestut.AltServer (10).\nFinished!")
elif command == "AltServer" and os.environ.get("TEST_REFUSE"):
    # Apple refusing the sign-in itself, before anything is signed.
    with (root / "refused-attempts").open("a") as f:
        f.write(os.environ["ALTSERVER_APPLE_ID"] + "\n")
    if os.environ["TEST_REFUSE"] == "mfa":
        print("Enter two factor code\nError: authentication cancelled without a verification code")
    elif os.environ["TEST_REFUSE"] == "503":
        print("Apple authentication HTTP status: 503\nError: com.rileytestut.ALTAppleAPI (17).")
    elif os.environ["TEST_REFUSE"] == "17":
        print("Error: com.rileytestut.ALTAppleAPI (17).")
    elif os.environ["TEST_REFUSE"] == "80046":
        print("Error: com.rileytestut.AltServer.Localized (-80046).")
    else:
        print("Error: This action cannot be completed at this time. (-80045)")
    sys.exit(1)
elif command == "AltServer" and os.environ.get("TEST_APP_LIMIT"):
    # AltServer's output when iOS refuses a 4th app signed with a free developer profile.
    with (root / "limit-attempts").open("a") as f:
        f.write("1\n")
    print('Alert: Could not install app.ipa to unknown.\n'
          '    This device has reached the maximum number of installed apps using a free developer profile: {(\n'
          '    "FAF69A2244.com.recsynq.recsynq",\n    "FAF69A2244.com.lavaamp.player",\n'
          '    "PWFY567U42.test.app.PWFY567U42"\n)}\n\n'
          "Please deactivate a sideloaded app with AltStore in order to install another app. If you're running "
          "iOS 13.5 or later, make sure 'Offload Unused Apps' is disabled in Settings > iTunes & App Stores.\n"
          "Error: com.rileytestut.AltServer (9).\nFinished!")
elif command == "AltServer":
    # Credentials arrive in the environment; arguments are visible in the process list.
    assert "-a" not in args and "-p" not in args, args
    email = os.environ["ALTSERVER_APPLE_ID"]
    assert os.environ["ALTSERVER_APPLE_PASSWORD"]
    cache = Path.cwd() / "AltServerData"
    cache.mkdir(exist_ok=True)
    identity = cache / "account.txt"
    if identity.exists() and identity.read_text() != email:
        raise RuntimeError("signing cache crossed accounts")
    identity.write_text(email)
    with (root / "signing-records.jsonl").open("a") as f:
        f.write(json.dumps({"email": email, "cwd": str(Path.cwd()), "home": os.environ["HOME"], "ipa": args[-1]}) + "\n")
    app = Path(args[-1]).parent.name
    team = hashlib.sha256(email.encode()).hexdigest()[:10].upper()
    now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    # Plist dates have whole-second precision. Synthetic signing finishes far
    # faster than a real Apple request; keep issuance dates distinct so tests
    # don't accidentally select a tied profile from the other account.
    clock = root / 'profile-clock'
    if clock.exists():
        now = max(now, datetime.datetime.fromisoformat(clock.read_text()) + datetime.timedelta(seconds=1))
    clock.write_text(now.replace(microsecond=0).isoformat())
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
