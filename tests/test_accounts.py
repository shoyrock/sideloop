"""Linux regression tests: no Apple requests and no physical devices are used."""

import json
import os
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path

from sideloop import accounts, config, jobs, store
from sideloop.server import App
from sideloop.watcher import Watcher, configured

DEVICE = "1234567890abcdef1234567890abcdef12345678"
APP = "test.app"


class AccountTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.old = {k: getattr(config, k) for k in ("DATA", "CONFIG", "APPS", "DEVICES")}
        config.DATA = self.root
        config.CONFIG = self.root / "config.env"
        config.APPS = store.APPS = self.root / "apps"
        config.DEVICES = store.DEVICES = self.root / "devices"
        config.update({"APPLE_ID": "first@example.test", "APPLE_PASSWORD": "first-secret"})
        store.add_device(DEVICE, "Test iPhone")
        self.app_dir = config.APPS / APP
        self.app_dir.mkdir(parents=True)
        (self.app_dir / "app.ipa").write_bytes(b"fake IPA")
        config.write_env(self.app_dir / "meta.env", {
            "BUNDLE_ID": APP, "APP_NAME": "Test App", "APP_VERSION": "1",
            "DEVICES": DEVICE, "ADDED": "1", "IPA_SOURCE": "test.ipa"})
        (self.app_dir / "info.json").write_text(json.dumps({"bundle_id": APP, "name": "Test App"}))
        self.second = accounts.save("new", "second@example.test", "second-secret")

    def tearDown(self):
        for k, value in self.old.items():
            setattr(config, k, value)
        store.APPS, store.DEVICES = config.APPS, config.DEVICES
        self.temp.cleanup()

    def test_legacy_cache_and_signature_are_preserved(self):
        legacy = self.app_dir / "state" / DEVICE
        legacy.mkdir(parents=True)
        (legacy / "expiry").write_text("2000000000")
        (self.root / "AltServerData").mkdir()
        (self.root / "AltServerData" / "certificate").write_text("original")
        context = accounts.shell_context(APP, DEVICE)
        self.assertIn(f"SIGNING_WORKDIR={self.root}", context)
        self.assertEqual(accounts.state_folder(APP, DEVICE), legacy)
        self.assertEqual(store.app_view(APP)["targets"][0]["signature"]["expiry"], 2000000000)
        self.assertEqual((self.root / "AltServerData" / "certificate").read_text(), "original")

    def test_device_default_preserves_existing_signers(self):
        app = App(jobs.Jobs(lambda: None), None, None)
        app.assign_account({"device": DEVICE, "account": self.second})
        self.assertEqual(accounts.resolve(APP, DEVICE), "default")
        self.assertEqual(accounts.device_account(DEVICE), self.second)
        store.set_app_devices(APP, [DEVICE])
        self.assertEqual(accounts.resolve(APP, DEVICE), "default")
        # Newly assigned apps use the device's new default.
        other = config.APPS / "new.app"
        other.mkdir()
        config.write_env(other / "meta.env", {"DEVICES": ""})
        store.set_app_devices("new.app", [DEVICE])
        self.assertEqual(accounts.resolve("new.app", DEVICE), self.second)

    def test_target_switch_keeps_separate_signature_state(self):
        legacy = accounts.state_folder(APP, DEVICE)
        legacy.mkdir(parents=True)
        (legacy / "expiry").write_text("2000000000")
        accounts.assign(DEVICE, self.second, APP)
        second_state = accounts.state_folder(APP, DEVICE)
        self.assertNotEqual(second_state, legacy)
        self.assertIsNone(store.app_view(APP)["targets"][0]["signature"]["expiry"])
        self.assertTrue(Watcher(None, None).due())
        context = accounts.shell_context(APP, DEVICE)
        self.assertIn("APPLE_ID=second@example.test", context)
        self.assertIn(str(self.root / "accounts" / self.second / "runtime"), context)
        accounts.assign(DEVICE, "default", APP)
        self.assertEqual(accounts.state_folder(APP, DEVICE), legacy)
        self.assertFalse(Watcher(None, None).due())

    def test_removed_apps_and_devices_do_not_leave_stale_assignments(self):
        accounts.assign(DEVICE, self.second, APP)
        store.remove_app(APP)
        self.assertEqual(accounts.app_override(APP, DEVICE), "")
        accounts.assign(DEVICE, self.second)
        accounts.assign(DEVICE, self.second, APP)
        store.remove_device(DEVICE)
        self.assertEqual(accounts.device_account(DEVICE), "default")
        self.assertEqual(accounts.app_override(APP, DEVICE), "")
        self.assertTrue(accounts.ready(self.second))

    def test_invalid_and_duplicate_accounts_do_not_replace_credentials(self):
        for account_id, email, password in [
            ("../escape", "x@example.test", "secret"),
            ("new", "FIRST@example.test", "secret"),
            (self.second, "changed@example.test", "secret"),
            ("new", "third@example.test", ""),
        ]:
            with self.assertRaises(ValueError):
                accounts.save(account_id, email, password)
        with self.assertRaises(ValueError):
            accounts.assign(DEVICE, "../escape", APP)
        self.assertEqual(accounts.credentials(self.second)["APPLE_PASSWORD"], "second-secret")
        accounts.save(self.second, "SECOND@example.test", "")
        self.assertEqual(accounts.credentials(self.second)["APPLE_PASSWORD"], "second-secret")
        self.assertEqual((self.root / "accounts" / self.second / "credentials.env").stat().st_mode & 0o777, 0o600)

    def test_all_account_passwords_are_redacted_and_not_in_api_views(self):
        public = json.dumps(accounts.views())
        self.assertNotIn("first-secret", public)
        self.assertNotIn("second-secret", public)
        self.assertEqual(jobs.redact(["first-secret second-secret"]), [f"{jobs.MASK} {jobs.MASK}"])
        job = jobs.Job("refresh", "test")
        job.add("first-sec")
        job.add("ret second-secret\n")
        self.assertNotIn("first-secret", json.dumps(job.view(0)))
        self.assertNotIn("second-secret", json.dumps(job.view(0)))

    def test_mutations_are_blocked_during_signing(self):
        runner = jobs.Jobs(lambda: None)
        runner.current = jobs.Job("refresh", "test")
        app = App(runner, None, None)
        with self.assertRaises(RuntimeError):
            app.assign_account({"device": DEVICE, "app": APP, "account": self.second})
        with self.assertRaises(RuntimeError):
            app.save_account({"account": self.second, "apple_id": "second@example.test", "password": "new"})

    def test_additional_account_works_without_legacy_credentials(self):
        config.update({"APPLE_ID": "", "APPLE_PASSWORD": ""})
        accounts.assign(DEVICE, self.second, APP)
        self.assertTrue(configured())
        self.assertIn("APPLE_PASSWORD=second-secret", accounts.shell_context(APP, DEVICE))

    def test_legacy_setup_remains_configured_when_apps_are_unassigned(self):
        store.set_app_devices(APP, [])
        self.assertTrue(configured())

    def test_shell_escaping_and_subprocess_persistence(self):
        password = "spaces ' quotes $(not-a-command); $HOME"
        accounts.save(self.second, "second@example.test", password)
        accounts.assign(DEVICE, self.second, APP)
        context = accounts.shell_context(APP, DEVICE)
        result = subprocess.run(["bash", "-c", context + '\n printf "%s" "$APPLE_PASSWORD"'],
                                capture_output=True, text=True, check=True)
        self.assertEqual(result.stdout, password)
        env = {**os.environ, "DATA_DIR": str(self.root)}
        result = subprocess.run(["python3", "-m", "sideloop.accounts", "state", APP, DEVICE],
                                env=env, capture_output=True, text=True, check=True)
        self.assertEqual(result.stdout.strip(), str(accounts.state_folder(APP, DEVICE)))

    def test_refresh_script_signs_and_renews_with_isolated_accounts(self):
        fakebin = self.root / "bin"
        fakebin.mkdir()
        fixture = Path(__file__).with_name("fake_signing.py")
        for command in ("idevice_id", "ideviceinfo", "ideviceprovision", "AltServer"):
            target = fakebin / command
            target.write_text(f'#!/bin/sh\nexec python3 "{fixture}" "{command}" "$@"\n')
            target.chmod(0o755)
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                        "-subj", "/CN=Sideloop regression test", "-keyout", str(self.root / "key.pem"),
                        "-out", str(self.root / "cert.pem")], capture_output=True, check=True)
        env = {**os.environ, "DATA_DIR": str(self.root), "PATH": f"{fakebin}:{os.environ['PATH']}",
               "ALTSERVER_BIN": str(fakebin / "AltServer"), "TEST_DEVICE": DEVICE}
        script = Path("/usr/local/bin/refresh.sh")
        def run(*args):
            r = subprocess.run(["bash", str(script), "--app", APP, "--device", DEVICE, *args],
                               env=env, capture_output=True, text=True, timeout=30)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        run("--force")
        legacy = accounts.state_folder(APP, DEVICE)
        self.assertTrue((legacy / "expiry").is_file())
        accounts.assign(DEVICE, self.second, APP)
        run("--force")
        second_state = accounts.state_folder(APP, DEVICE)
        self.assertTrue((second_state / "expiry").is_file())
        run("--recheck")
        run("--force")
        accounts.assign(DEVICE, "default", APP)
        run("--force")
        records = [json.loads(line) for line in (self.root / "signing-records.jsonl").read_text().splitlines()]
        self.assertEqual([r["email"] for r in records], ["first@example.test", "second@example.test",
                                                        "second@example.test", "first@example.test"])
        self.assertEqual(records[0]["cwd"], records[-1]["cwd"])
        self.assertNotEqual(records[0]["cwd"], records[1]["cwd"])
        self.assertEqual(records[1]["home"], records[2]["home"])
        self.assertEqual(len(list((self.root / "profiles").glob("*.mobileprovision"))), 2)


if __name__ == "__main__":
    unittest.main()
