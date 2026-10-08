"""Run refresh.sh with fake device/signing tools, including its interactive path."""
import os
import datetime
import pty
import select
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from zoneinfo import ZoneInfo

sys.path.insert(0, "/opt")
from sideloop import config
from sideloop.jobs import Job, run_pty

DEVICE = "1234567890abcdef1234567890abcdef12345678"

class SigningFixTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "apps/test.app/state").mkdir(parents=True)
        (self.root / "devices").mkdir()
        (self.root / "bin").mkdir()
        (self.root / "config.env").write_text("APPLE_ID=synthetic@example.test\nAPPLE_PASSWORD=synthetic-password\n")
        (self.root / "apps/test.app/meta.env").write_text("BUNDLE_ID=test.app\nAPP_NAME=Test\n")
        (self.root / "apps/test.app/app.ipa").write_bytes(b"synthetic IPA")
        (self.root / f"devices/{DEVICE}.env").write_text("DEVICE_NAME=Test\n")
        for command, body in {
            "idevice_id": f"print('{DEVICE}')",
            "ideviceinfo": "print('Test')",
            "ideviceprovision": "pass",
            "AltServer": """import os,sys
from pathlib import Path
root=Path(os.environ['DATA_DIR'])
(root/'signer-timezone').write_text(os.environ.get('TZ',''))
if os.environ.get('TEST_2FA'):
    print('Enter verification code:',flush=True)
    (root/'input-received').write_text(input())
if os.environ.get('TEST_ERROR_PAUSE'):
    print('Alert: Could not install app.ipa to unknown.',flush=True)
    print('    This action cannot be completed at this time (-22411)',flush=True)
    # A prompt split across reads must still be acknowledged exactly once.
    print('Press any key to cont',end='',flush=True)
    import time
    time.sleep(0.1)
    print('inue...',end='',flush=True)
    (root/'error-ack').write_text(input())
print('This action cannot be completed at this time (-22411)')
print('Error: com.rileytestut.AltServer.Localized (-22411).')
print('Finished!')
""",
        }.items():
            path = self.root / "bin" / command
            path.write_text("#!/usr/bin/env python3\n" + body + "\n")
            path.chmod(0o755)
        self.env = {**os.environ, "DATA_DIR": str(self.root), "TZ": "America/New_York",
                    "PATH": f"{self.root / 'bin'}:{os.environ['PATH']}",
                    "ALTSERVER_BIN": str(self.root / "bin/AltServer")}
        self.argv = ["bash", "/usr/local/bin/refresh.sh", "--app", "test.app", "--device", DEVICE, "--force"]

    def tearDown(self):
        self.temp.cleanup()

    def check_result(self, returncode, output):
        self.assertEqual(returncode, 1, output)
        self.assertEqual((self.root / "signer-timezone").read_text(), "UTC")
        self.assertIn("Apple rejected sign-in (-22411)", output)
        self.assertNotIn("did it lock or leave Wi-Fi", output)
        log = (self.root / "state/refresh.log").read_text()
        self.assertIn("Error: com.rileytestut.AltServer.Localized (-22411)", log)
        self.assertIn(datetime.datetime.now(ZoneInfo("America/New_York")).strftime("%Y-%m-%d %H"), log)
        state = (self.root / f"apps/test.app/state/{DEVICE}/last_run").read_text()
        self.assertIn("\tfail\t", state)
        self.assertIn("Apple rejected sign-in", state)

    def test_background_signing_uses_utc_and_reports_authentication_failure(self):
        result = subprocess.run(self.argv, env=self.env, capture_output=True, text=True, timeout=15)
        self.check_result(result.returncode, result.stdout + result.stderr)

    def test_interactive_signing_keeps_2fa_input_and_persists_real_error(self):
        pid, fd = pty.fork()
        if pid == 0:
            os.execvpe(self.argv[0], self.argv, {**self.env, "TEST_2FA": "1"})
        output = ""
        sent = False
        deadline = time.monotonic() + 15
        try:
            while time.monotonic() < deadline:
                if select.select([fd], [], [], 0.2)[0]:
                    try: chunk = os.read(fd, 4096)
                    except OSError: break
                    if not chunk: break
                    output += chunk.decode()
                    if not sent and "Enter verification code:" in output:
                        os.write(fd, b"123456\n")
                        sent = True
            else:
                os.kill(pid, 9)
                self.fail("interactive signing timed out")
        finally:
            os.close(fd)
            status = os.waitpid(pid, 0)[1]
        self.assertTrue(sent)
        self.assertEqual((self.root / "input-received").read_text(), "123456")
        self.check_result(os.waitstatus_to_exitcode(status), output)

    def test_web_job_waits_for_2fa_then_acknowledges_only_error_pause(self):
        original_config = config.CONFIG
        config.CONFIG = self.root / 'config.env'
        job = Job('refresh', 'Synthetic signing')
        config.CONFIG = original_config
        worker = threading.Thread(target=run_pty, args=(job, [
            'env', *[f'{key}={self.env[key]}' for key in ('DATA_DIR', 'TZ', 'PATH', 'ALTSERVER_BIN')],
            'TEST_2FA=1', 'TEST_ERROR_PAUSE=1', *self.argv,
        ]), daemon=True)
        worker.start()
        try:
            deadline = time.monotonic() + 10
            while worker.is_alive() and not job.view()['needs_input']:
                self.assertLess(time.monotonic(), deadline, job.view())
                time.sleep(0.02)
            self.assertTrue(job.view()['needs_input'], job.view())
            self.assertFalse((self.root / 'input-received').exists())
            job.send('123456')
            worker.join(10)
            self.assertFalse(worker.is_alive(), job.view())
            self.assertEqual((self.root / 'input-received').read_text(), '123456')
            self.assertEqual((self.root / 'error-ack').read_text(), '')
            self.check_result(job.rc, '\n'.join(job.view(0)['lines']))
        finally:
            if worker.is_alive():
                job.cancel()
                worker.join(5)

    def test_unrelated_keypress_prompt_is_not_acknowledged(self):
        job = Job('refresh', 'Synthetic signing')
        job.add('Press any key to continue...\n')
        self.assertFalse(job.take_error_ack())
        job.add('Alert: Could not install app.ipa to unknown.\nEnter verification code:')
        self.assertTrue(job.view()['needs_input'])
        self.assertFalse(job.take_error_ack())

if __name__ == "__main__":
    unittest.main()
