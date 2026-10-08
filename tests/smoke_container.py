"""Exercise the combined image without an Apple account or an iOS device.

Usage: python tests/smoke_container.py [image]
Requires Docker and an unused loopback port 18080. Test data is disposable.
"""

import hashlib
import json
import pathlib
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid


ROOT = pathlib.Path(__file__).resolve().parents[1]
IMAGE = sys.argv[1] if len(sys.argv) > 1 else "sideloop:all-in-one"
NAME = f"sideloop-smoke-{uuid.uuid4().hex[:8]}"
VOLUME = f"{NAME}-data"
BASE = "http://127.0.0.1:18080"


def docker(*args):
    result = subprocess.run(
        ["docker", *args], capture_output=True, text=True, timeout=60
    )
    if result.returncode:
        raise RuntimeError(f"docker {' '.join(args)}: {result.stderr.strip()}")
    return result.stdout.strip()


def inside(*args):
    return docker("exec", NAME, *args)


def check(condition, message):
    if not condition:
        raise AssertionError(message)
    print(f"PASS: {message}", flush=True)


def wait_for(predicate, timeout=600):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(2)
    raise TimeoutError("container did not become ready")


def healthy():
    state = json.loads(docker("inspect", NAME))[0]["State"]
    if not state["Running"]:
        raise RuntimeError(f"container exited: {state['ExitCode']}")
    if state.get("Health", {}).get("Status") != "healthy":
        return False
    # Docker's last recorded status can precede a process restart. Probe the
    # actual services as well when checking recovery.
    return subprocess.run(
        ["docker", "exec", NAME, "python3", "/usr/local/bin/container-healthcheck.py"],
        capture_output=True, timeout=20,
    ).returncode == 0


def request(path, data=None, cookie=None):
    headers = {"X-Requested-With": "sideloop"}
    if cookie:
        headers["Cookie"] = cookie
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(
        BASE + path,
        json.dumps(data).encode() if data is not None else None,
        headers,
    )
    with urllib.request.urlopen(req, timeout=10) as response:
        return json.load(response), response.headers


def file_hash(path):
    code = "import hashlib,pathlib,sys; print(hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest())"
    return inside("python3", "-c", code, path)


def supervisor_pid(program):
    return inside("supervisorctl", "-c", "/etc/sideloop/supervisord.conf", "pid", program)


def main():
    created = False
    try:
        docker(
            "run", "-d", "--name", NAME, "--privileged", "--stop-timeout", "45",
            "-p", "127.0.0.1:18080:8080",
            "--mount", f"type=volume,source={VOLUME},target=/data", IMAGE,
        )
        created = True
        print("Waiting for first-start Anisette provisioning and container health...", flush=True)
        wait_for(healthy)
        check(True, "UI, Anisette, and builtin netmuxd pass the image health check")

        status = inside("supervisorctl", "-c", "/etc/sideloop/supervisord.conf", "status")
        check(status.count("RUNNING") == 2, "both supervised services run in one container")
        process_code = "from pathlib import Path; print('\\n'.join(p.read_bytes().replace(bytes([0]),b' ').decode(errors='replace') for p in Path('/proc').glob('[0-9]*/cmdline') if p.exists()))"
        processes = inside("python3", "-c", process_code)
        check("usbmuxd -f" in processes and "netmuxd --host" in processes, "USB and Wi-Fi service processes start")
        anisette_pid = supervisor_pid("anisette")
        owner = inside("python3", "-c", f"import os,pwd; print(pwd.getpwuid(os.stat('/proc/{anisette_pid}').st_uid).pw_name)")
        check(owner == "Alcoholic", "Anisette retains its upstream service account")

        # This upstream version prints usage but exits 1 for its advertised
        # help flag. Preserve it; this check only establishes binary startup.
        help_result = subprocess.run(
            ["docker", "exec", NAME, "AltServer", "-h"],
            capture_output=True, text=True, timeout=10,
        )
        check("Usage:  AltServer-Linux" in help_result.stdout, "the built AltServer binary launches")
        inside("bash", "-n", "/usr/local/bin/refresh.sh")
        inside("bash", "-n", "/usr/local/bin/probe.sh")
        inside("bash", "-n", "/usr/local/bin/container-entrypoint.sh")
        inside("bash", "-n", "/usr/local/bin/container-run-sideloop.sh")
        for source in (ROOT / "sideloop").iterdir():
            if source.is_file():
                expected = hashlib.sha256(source.read_bytes()).hexdigest()
                check(file_hash(f"/opt/sideloop/{source.name}") == expected, f"application file {source.name} matches checkout")
        for name in ("refresh.sh", "probe.sh"):
            expected = hashlib.sha256((ROOT / "scripts" / name).read_bytes().replace(b"\r\n", b"\n")).hexdigest()
            check(file_hash(f"/usr/local/bin/{name}") == expected, f"{name} matches checkout; Linux line endings")

        auth_state, _ = request("/api/auth")
        check(not auth_state["has_password"], "fresh persistent volume starts with normal setup flow")
        _, headers = request("/api/auth/setup", {"password": "smoke-test-password"})
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        wait_for(
            lambda: all(request("/api/state", cookie=cookie)[0]["services"].values()),
            timeout=90,
        )
        state, _ = request("/api/state", cookie=cookie)
        check(state["services"]["anisette"] and state["services"]["muxer"], "authenticated UI reports both internal helpers available")
        request("/api/settings", {"auto_check": False}, cookie)
        identity = file_hash("/data/anisette/device.json")
        ui_config = file_hash("/data/ui.json")

        inside("python3", "-c", f"import os,signal; os.kill({anisette_pid}, signal.SIGKILL)")
        wait_for(lambda: supervisor_pid("anisette") not in ("0", anisette_pid), timeout=30)
        wait_for(healthy, timeout=90)
        check(file_hash("/data/anisette/device.json") == identity, "Anisette recovers from process failure without replacing its identity")

        loop_pid = supervisor_pid("sideloop")
        main_pid_code = "from pathlib import Path; print(next(p.parent.name for p in Path('/proc').glob('[0-9]*/cmdline') if p.read_bytes().split(bytes([0]))[:3] == [b'python3', b'-m', b'sideloop']))"
        main_pid = inside("python3", "-c", main_pid_code)
        inside("python3", "-c", f"import os,signal; os.kill({main_pid}, signal.SIGKILL)")
        wait_for(lambda: supervisor_pid("sideloop") not in ("0", loop_pid), timeout=30)
        wait_for(healthy, timeout=90)
        mux_count_code = "from pathlib import Path; commands=[p.read_bytes().split(bytes([0]))[0] for p in Path('/proc').glob('[0-9]*/cmdline') if p.exists()]; print(commands.count(b'usbmuxd'), commands.count(b'netmuxd'))"
        check(inside("python3", "-c", mux_count_code) == "1 1", "Sideloop recovers after a crash without duplicate device helpers")

        stopped_at = time.monotonic()
        docker("stop", "--time", "45", NAME)
        stopped = json.loads(docker("inspect", NAME))[0]["State"]
        check(stopped["ExitCode"] == 0 and time.monotonic() - stopped_at < 45, "container stops gracefully without Docker's forced kill")

        docker("rm", NAME)
        created = False
        docker(
            "run", "-d", "--name", NAME, "--privileged", "--stop-timeout", "45",
            "-p", "127.0.0.1:18080:8080",
            "--mount", f"type=volume,source={VOLUME},target=/data", IMAGE,
        )
        created = True
        wait_for(healthy)
        check(file_hash("/data/anisette/device.json") == identity, "Anisette identity persists when container is recreated")
        check(file_hash("/data/ui.json") == ui_config, "UI credentials persist when container is recreated")
        state, _ = request("/api/state", cookie=cookie)
        check(not state["config"]["auto_check"], "application settings persist when container is recreated")
        print("All container smoke checks passed. Physical-device signing was not tested.", flush=True)
    except Exception:
        if created:
            print(docker("logs", "--tail", "70", NAME), flush=True)
        raise
    finally:
        if created:
            docker("rm", "-f", NAME)
        docker("volume", "rm", VOLUME)


if __name__ == "__main__":
    main()
