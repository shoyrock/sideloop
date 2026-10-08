"""Run refresh.sh with fake device/signing tools, including its interactive path."""
import os
import datetime
import pty
import select
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from zoneinfo import ZoneInfo

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

if __name__ == "__main__":
    unittest.main()
