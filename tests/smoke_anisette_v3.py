"""Exercise the v3 supervisor mode offline, preserving only a disposable volume."""

import json
import subprocess
import sys
import time
import uuid


def main():
    image = sys.argv[1]
    name = 'sideloop-v3-smoke-' + uuid.uuid4().hex[:8]
    volume = name + '-data'

    def docker(*args):
        return subprocess.check_output(['docker', *args], text=True, timeout=60).strip()

    def ready():
        for _ in range(45):
            result = subprocess.run(
                ['docker', 'exec', name, 'python3', '/usr/local/bin/container-healthcheck.py'],
                capture_output=True,
                timeout=15,
            )
            if result.returncode == 0:
                return
            time.sleep(1)
        raise AssertionError('offline v3 mode did not become healthy')

    def start():
        docker(
            'run',
            '-d',
            '--name',
            name,
            '--network',
            'none',
            '-e',
            'MUX=usb',
            '-e',
            'ANISETTE_V3_SERVERS=https://offline.example',
            '--mount',
            f'type=volume,source={volume},target=/data',
            image,
        )
        ready()

    docker('volume', 'create', volume)
    try:
        start()
        dependency = docker(
            'exec', name, 'python3', '-c', 'import websocket; print(websocket.__version__)'
        )
        assert dependency
        docker(
            'exec',
            name,
            'python3',
            '-c',
            "from pathlib import Path; p=Path('/data/anisette-v3/identity.json'); "
            "assert not p.exists(), 'health probes must not provision'; p.write_text('synthetic-state')",
        )
        docker('restart', name)
        ready()
        docker('stop', '--time', '30', name)
        assert json.loads(docker('inspect', name))[0]['State']['ExitCode'] == 0
        docker('rm', name)
        start()
        docker(
            'exec',
            name,
            'python3',
            '-c',
            "from pathlib import Path; assert Path('/data/anisette-v3/identity.json').read_text() == 'synthetic-state'",
        )
        assert 'synthetic-state' not in docker('logs', name)
        print(
            'PASS: offline v3 startup, dependency, restart, recreation, state preservation and secret-free health checks'
        )
    finally:
        subprocess.run(['docker', 'rm', '-f', name], capture_output=True, timeout=30)
        docker('volume', 'rm', volume)


if __name__ == '__main__':
    main()
