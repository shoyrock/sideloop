"""Linux regression tests: no Apple requests and no physical devices are used."""

import json
import os
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from sideloop import accounts, config, ipa, jobs, store, watcher
from sideloop.server import App
from sideloop.watcher import Watcher, configured

DEVICE = "1234567890abcdef1234567890abcdef12345678"
# The checkout's script when run from the repository; the installed copy inside the container.
REFRESH = Path(__file__).resolve().parents[1] / "scripts" / "refresh.sh"
if not REFRESH.is_file():
    REFRESH = Path("/usr/local/bin/refresh.sh")
APP = "test.app"


class AccountTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.refresh_script = self.root / 'refresh.sh'
        self.refresh_script.write_text(REFRESH.read_text().replace('python3 -m sideloop.renewal',
            'python3 "' + str(Path(__file__).with_name('fake_renewal.py')) + '"'))
        self.refresh_script.chmod(0o755)
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

    def test_device_account_signs_every_app_on_the_device(self):
        other = config.APPS / "new.app"
        other.mkdir()
        (other / "app.ipa").write_bytes(b"fake IPA")
        config.write_env(other / "meta.env", {"DEVICES": DEVICE})
        app = App(jobs.Jobs(lambda: None), None, None)
        app.assign_account({"device": DEVICE, "account": self.second})
        self.assertEqual(accounts.device_account(DEVICE), self.second)
        self.assertEqual([t["account"] for a in (APP, "new.app") for t in store.app_view(a)["targets"]],
                         [self.second, self.second])
        # Apps assigned later follow the device too, and switching back moves all of them.
        store.set_app_devices(APP, [DEVICE])
        self.assertEqual(accounts.resolve(APP, DEVICE), self.second)
        app.assign_account({"device": DEVICE, "account": "default"})
        self.assertEqual({accounts.resolve(a, DEVICE) for a in (APP, "new.app")}, {"default"})
        with self.assertRaises(ValueError):
            app.assign_account({"device": DEVICE, "app": APP, "account": self.second})

    def test_assignment_change_schedules_a_prompt_check(self):
        watcher = Watcher(None, None)
        watcher.next_run = 10 ** 12
        App(jobs.Jobs(lambda: None), None, None, watcher).assign_account({"device": DEVICE, "account": self.second})
        self.assertLess(watcher.next_run, 10 ** 12)

    def legacy_assignments(self, data):
        (self.root / "signing-accounts.json").write_text(json.dumps(data))

    def test_migration_keeps_explicit_device_choice(self):
        self.legacy_assignments({"devices": {DEVICE: self.second}, "apps": {APP: {DEVICE: "default"}}})
        changed = accounts.migrate({DEVICE: [APP]})
        self.assertEqual(changed, [(APP, DEVICE, "default", self.second)])
        self.assertEqual(accounts.resolve(APP, DEVICE), self.second)
        self.assertEqual(json.loads((self.root / "signing-accounts.json").read_text()),
                         {"version": 2, "devices": {DEVICE: self.second}, "apps": {}})
        self.assertEqual(accounts.migrate({DEVICE: [APP]}), [])

    def test_migration_adopts_the_apps_account_when_device_had_none(self):
        self.legacy_assignments({"devices": {}, "apps": {APP: {DEVICE: self.second}, "b.app": {DEVICE: self.second},
                                                         "c.app": {DEVICE: "default"}}})
        changed = accounts.migrate({DEVICE: [APP, "b.app", "c.app"]})
        self.assertEqual(accounts.device_account(DEVICE), self.second)
        self.assertEqual(changed, [("c.app", DEVICE, "default", self.second)])

    def test_migration_without_overrides_changes_nothing(self):
        accounts.assign(DEVICE, self.second)
        self.legacy_assignments({"devices": {DEVICE: self.second}, "apps": {}})
        self.assertEqual(accounts.migrate({DEVICE: [APP]}), [])
        self.assertEqual(accounts.resolve(APP, DEVICE), self.second)

    def test_removing_an_account_requires_no_device_to_use_it(self):
        accounts.assign(DEVICE, self.second)
        app = App(jobs.Jobs(lambda: None), None, None)
        with self.assertRaises(ValueError):
            app.remove_account({"account": self.second})
        with self.assertRaises(ValueError):
            app.remove_account({"account": "default"})
        accounts.assign(DEVICE, "default")
        accounts.set_verification(self.second, "verified")
        app.remove_account({"account": self.second})
        self.assertEqual(accounts.ids(), ["default"])
        self.assertFalse((self.root / "accounts" / self.second).exists())
        self.assertEqual(accounts.verification(self.second), {"status": "unverified"})

    def test_target_switch_keeps_separate_signature_state(self):
        legacy = accounts.state_folder(APP, DEVICE)
        legacy.mkdir(parents=True)
        (legacy / "expiry").write_text("2000000000")
        accounts.assign(DEVICE, self.second)
        second_state = accounts.state_folder(APP, DEVICE)
        self.assertNotEqual(second_state, legacy)
        self.assertIsNone(store.app_view(APP)["targets"][0]["signature"]["expiry"])
        # Not installed with this account, so not due; App.assign_account marks installed apps due.
        self.assertFalse(Watcher(None, None).due())
        context = accounts.shell_context(APP, DEVICE)
        self.assertIn("APPLE_ID=second@example.test", context)
        self.assertIn(str(self.root / "accounts" / self.second / "runtime"), context)
        accounts.assign(DEVICE, "default")
        self.assertEqual(accounts.state_folder(APP, DEVICE), legacy)
        self.assertFalse(Watcher(None, None).due())

    def test_removed_devices_do_not_leave_stale_assignments(self):
        accounts.assign(DEVICE, self.second)
        store.remove_app(APP)
        self.assertEqual(accounts.device_account(DEVICE), self.second)
        store.remove_device(DEVICE)
        self.assertEqual(accounts.device_account(DEVICE), "default")
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
            accounts.assign(DEVICE, "../escape")
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
            app.assign_account({"device": DEVICE, "account": self.second})
        with self.assertRaises(RuntimeError):
            app.remove_account({"account": self.second})
        with self.assertRaises(RuntimeError):
            app.save_account({"account": self.second, "apple_id": "second@example.test", "password": "new"})

    def test_additional_account_works_without_legacy_credentials(self):
        config.update({"APPLE_ID": "", "APPLE_PASSWORD": ""})
        accounts.assign(DEVICE, self.second)
        self.assertTrue(configured())
        self.assertIn("APPLE_PASSWORD=second-secret", accounts.shell_context(APP, DEVICE))

    def test_legacy_setup_remains_configured_when_apps_are_unassigned(self):
        store.set_app_devices(APP, [])
        self.assertTrue(configured())

    def test_shell_escaping_and_subprocess_persistence(self):
        password = "spaces ' quotes $(not-a-command); $HOME"
        accounts.save(self.second, "second@example.test", password)
        accounts.assign(DEVICE, self.second)
        context = accounts.shell_context(APP, DEVICE)
        result = subprocess.run(["bash", "-c", context + '\n printf "%s" "$APPLE_PASSWORD"'],
                                capture_output=True, text=True, check=True)
        self.assertEqual(result.stdout, password)
        env = {**os.environ, "DATA_DIR": str(self.root)}
        result = subprocess.run(["python3", "-m", "sideloop.accounts", "state", APP, DEVICE],
                                env=env, capture_output=True, text=True, check=True)
        self.assertEqual(result.stdout.strip(), str(accounts.state_folder(APP, DEVICE)))

    def test_partial_or_damaged_assignment_files_do_not_break_state(self):
        # Files written by other builds or damaged on disk: state reads, the startup
        # migration and the automatic re-sign loop must keep working.
        path = self.root / "signing-accounts.json"
        for content in (json.dumps({"devices": {DEVICE: "default"}}), json.dumps({"apps": None, "devices": 7}),
                        "[]", "{not json", json.dumps({"devices": {DEVICE: ["bad"]}, "apps": {APP: "bad"}})):
            with self.subTest(content=content):
                path.write_text(content)
                self.assertEqual(accounts.resolve(APP, DEVICE), "default")
                self.assertEqual(accounts.device_account(DEVICE), "default")
                self.assertTrue(store.app_view(APP)["targets"])
                self.assertFalse(watcher.Watcher(None, None).due() is None)
                App(jobs.Jobs(lambda: None), None, None)  # runs the startup migration
                self.assertEqual(json.loads(path.read_text())["apps"], {})
        path.write_text(json.dumps({"devices": {DEVICE: "default"}}))
        accounts.assign(DEVICE, self.second)
        self.assertEqual(accounts.resolve(APP, DEVICE), self.second)
        written = json.loads(path.read_text())
        # Builds that predate per-device accounts read "apps"; it stays present.
        self.assertEqual((written["devices"], written["apps"]), ({DEVICE: self.second}, {}))

    def test_watcher_loop_survives_a_failing_tick(self):
        w = watcher.Watcher(None, None)
        with patch.object(watcher.Watcher, "tick", side_effect=KeyError("apps")), \
             patch.object(watcher.time, "sleep", side_effect=[None, None, StopIteration]), \
             patch.object(watcher, "log") as logged:
            with self.assertRaises(StopIteration):
                w.loop()
        self.assertEqual(logged.call_count, 2)
        self.assertIn("KeyError", logged.call_args[0][0])
        self.assertGreater(w.next_run, time.time())

    def fake_tools(self):
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
        self.fake_tools_env = env
        return env

    def test_refresh_script_skips_apps_that_need_a_newer_ios(self):
        import plistlib, zipfile
        with zipfile.ZipFile(self.app_dir / "app.ipa", "w") as z:
            z.writestr("Payload/Test.app/Info.plist", plistlib.dumps(
                {"CFBundleIdentifier": APP, "CFBundleExecutable": "Test", "MinimumOSVersion": "16.0"}))
            z.writestr("Payload/Test.app/PlugIns/Share.appex/Info.plist", plistlib.dumps(
                {"CFBundleIdentifier": APP + ".share", "MinimumOSVersion": "17.0"}))
        self.assertEqual(store.app_view(APP)["info"]["min_ios"], "17.0")
        # The extension's requirement applies only when the extension is installed.
        store.set_keep_extensions(APP, True)
        env = {**self.fake_tools(), "TEST_IOS": "16.7.10"}
        r = subprocess.run(["bash", str(self.refresh_script), "--app", APP, "--device", DEVICE, "--force", '--install', '--confirm-replace'],
                           env=env, capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("needs iOS 17.0 or later, but Test iPhone runs iOS 16.7.10", r.stdout)
        self.assertFalse((self.root / "signing-records.jsonl").exists())
        self.assertEqual(store.app_view(APP)["targets"][0]["signature"]["last_run"]["result"], "fail")
        store.set_device_ios(DEVICE, "16.7.10")
        self.assertEqual(store.app_view(APP)["targets"][0]["needs_ios"], "17.0")
        store.set_device_ios(DEVICE, "17.1")
        self.assertEqual(store.app_view(APP)["targets"][0]["needs_ios"], "")
        self.assertEqual(store.device_name(DEVICE), "Test iPhone")

    def refresh(self, env, *args):
        install = ['--install', '--confirm-replace'] if '--force' in args else []
        return subprocess.run(["bash", str(self.refresh_script), "--app", APP, "--device", DEVICE, *args, *install],
                              env=env, capture_output=True, text=True, timeout=30)

    def signed(self):
        records = self.root / "signing-records.jsonl"
        return len(records.read_text().splitlines()) if records.exists() else 0

    def test_automatic_renewal_starts_exactly_at_the_configured_window(self):
        import time
        config.update({"RENEW_BEFORE_DAYS": "3"})
        env, state = self.fake_tools(), accounts.state_folder(APP, DEVICE)
        state.mkdir(parents=True)
        # 3.5 days left: outside a 3-day window. Whole-day rounding used to renew here.
        (state / "expiry").write_text(str(int(time.time() + 3.5 * 86400)))
        self.assertEqual(self.refresh(env).returncode, 0)
        self.assertEqual(self.signed(), 0)
        self.assertFalse(Watcher(None, None).due())
        watcher = Watcher(None, None)
        watcher.schedule()
        self.assertAlmostEqual(watcher.next_run, time.time() + 6 * 3600, delta=10)
        # Entering the window in 2.4 hours: wake then, not at the 6-hour idle check.
        (state / "expiry").write_text(str(int(time.time() + 3.1 * 86400)))
        watcher.schedule()
        self.assertAlmostEqual(watcher.next_run, time.time() + 0.1 * 86400 + 5, delta=10)
        # 2.9 days left: inside the window, so it renews without --force.
        (state / "expiry").write_text(str(int(time.time() + 2.9 * 86400)))
        self.assertTrue(Watcher(None, None).due())
        r = self.refresh(env)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("signature has 2d 21h left (threshold 3d)", r.stdout)
        self.assertEqual(self.signed(), 1)

    def test_automatic_checks_skip_apps_the_device_cannot_run(self):
        import plistlib, zipfile
        with zipfile.ZipFile(self.app_dir / "app.ipa", "w") as z:
            z.writestr("Payload/Test.app/Info.plist", plistlib.dumps(
                {"CFBundleIdentifier": APP, "CFBundleExecutable": "Test", "MinimumOSVersion": "17.0"}))
        store.set_device_ios(DEVICE, "16.7.16")
        self.assertFalse(Watcher(None, None).due())
        env = {**self.fake_tools(), "TEST_IOS": "16.7.16"}
        r = self.refresh(env)
        self.assertEqual((r.returncode, r.stdout), (0, ""))
        # A manual install still explains why it can't proceed.
        r = self.refresh(env, "--force")
        self.assertEqual(r.returncode, 1)
        self.assertIn("needs iOS 17.0 or later", r.stdout)
        # A failed live read falls back to the recorded version instead of attempting the install.
        r = self.refresh({**env, "TEST_IOS": ""}, "--force")
        self.assertIn("needs iOS 17.0 or later, but Test iPhone runs iOS 16.7.16", r.stdout)
        self.assertEqual(self.signed(), 0)

    def install_marker(self, seconds_left):
        import time
        state = accounts.state_folder(APP, DEVICE)
        state.mkdir(parents=True, exist_ok=True)
        (state / "expiry").write_text(str(int(time.time() + seconds_left)))

    def test_unreachable_device_is_logged_once_per_absence(self):
        self.install_marker(86400 - 600)  # installed and due within the 2-day window
        env = {**self.fake_tools(), "TEST_DEVICE": "ffffffffffffffffffffffffffffffffffffffff"}
        for _ in range(3):
            self.assertEqual(self.refresh(env).returncode, 0)
        log = (self.root / "state" / "refresh.log").read_text()
        self.assertEqual(log.count("not reachable"), 1)
        self.assertEqual(store.read_state(accounts.state_folder(APP, DEVICE))["last_run"]["result"], "offline")
        self.assertEqual(self.refresh(env, '--force').returncode, 1)
        r = self.refresh({**env, "TEST_DEVICE": DEVICE})
        self.assertIn("signature has 0d 23h left", r.stdout)
        self.assertEqual(self.signed(), 1)

    def test_new_devices_and_apps_are_never_installed_automatically(self):
        other = "abcdefabcdefabcdefabcdefabcdefabcdefabcd"
        store.add_device(other, "New iPad")
        self.assertEqual(store.app_devices(APP), [DEVICE])
        env = self.fake_tools()
        # Not installed yet: automatic checks and Re-sign Installed Apps skip it.
        self.assertFalse(Watcher(None, None).due())
        self.assertEqual(self.refresh(env).stdout, "")
        r = subprocess.run(["bash", str(self.refresh_script), "--force", "--resign-only"],
                           env=env, capture_output=True, text=True, timeout=30)
        self.assertEqual((r.returncode, self.signed()), (0, 0), r.stdout + r.stderr)
        # Tapping Install does install it.
        self.assertEqual(self.refresh(env, "--force").returncode, 0)
        self.assertEqual(self.signed(), 1)

    def test_auto_resign_can_be_turned_off_per_app_and_device(self):
        self.install_marker(3600)
        env, app = self.fake_tools(), App(jobs.Jobs(lambda: None), None, None)
        self.assertTrue(store.app_view(APP)["targets"][0]["auto"])
        app.set_auto_resign({"app": APP, "device": DEVICE, "auto": False})
        self.assertFalse(store.app_view(APP)["targets"][0]["auto"])
        self.assertFalse(Watcher(None, None).due())
        self.assertEqual((self.refresh(env).stdout, self.signed()), ("", 0))
        # Re-signing it by hand still works.
        self.assertEqual(self.refresh(env, "--force").returncode, 0)
        self.assertEqual(self.signed(), 1)
        app.set_auto_resign({"app": APP, "device": DEVICE, "auto": True})
        self.assertTrue(store.auto_resign(APP, DEVICE))
        self.assertEqual(store.device_name(DEVICE), "Test iPhone")
        with self.assertRaises(ValueError):
            app.set_auto_resign({"app": APP, "device": "abcdefabcdefabcdefabcdefabcdefabcdefabcd", "auto": False})

    def test_account_switch_keeps_installed_apps_due_for_re_signing(self):
        self.install_marker(5 * 86400)
        self.assertFalse(Watcher(None, None).due())
        App(jobs.Jobs(lambda: None), None, None).assign_account({"device": DEVICE, "account": self.second})
        self.assertEqual(store.read_state(accounts.state_folder(APP, DEVICE))["expiry"], 1)
        self.assertTrue(Watcher(None, None).due())

    def test_free_app_limit_is_explained_and_not_retried_automatically(self):
        env = {**self.fake_tools(), "TEST_APP_LIMIT": "1"}
        r = self.refresh(env, "--force")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("Test iPhone already has the 3 apps iOS allows with free developer profiles "
                      "(com.recsynq.recsynq, com.lavaamp.player, Test App). The limit counts apps from every Apple account, "
                      "so another account won't help; delete one from the device", r.stdout)
        log = (self.root / "state" / "refresh.log").read_text()
        self.assertNotIn("AltStore", log)
        self.assertIn(jobs.LIMIT_ADVICE, log)
        self.assertEqual(store.read_state(accounts.state_folder(APP, DEVICE))["last_run"]["result"], "limit")
        # Automatic checks wait for the user instead of signing and copying again.
        self.assertFalse(Watcher(None, None).due())
        self.assertEqual(self.refresh(env).stdout, "")
        attempts = (self.root / "limit-attempts").read_text().count("1")
        self.assertEqual(attempts, 1)
        # Tapping Install retries, and a success clears the limit state.
        r = self.refresh(self.fake_env_without_limit(env), "--force")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(store.read_state(accounts.state_folder(APP, DEVICE))["last_run"]["result"], "ok")
        job = jobs.Job("refresh", "test")
        job.add("Please deactivate a sideloaded app with AltStore in order to install another app.\n")
        self.assertEqual(job.lines, [jobs.LIMIT_ADVICE])

    def test_missing_mfa_with_error_line_is_tried_once_per_run(self):
        self.check_refused_account("mfa", "Apple is asking for a 2FA code")

    def test_refused_account_is_tried_once_per_run(self):
        self.check_refused_account("1", "Apple refused the sign-in from this signing service (-80045)")

    def check_refused_account(self, mode, hint):
        other = config.APPS / "other.app"
        other.mkdir()
        (other / "app.ipa").write_bytes(b"fake IPA")
        config.write_env(other / "meta.env", {"BUNDLE_ID": "other.app", "APP_NAME": "Other", "DEVICES": DEVICE})
        for app_id in (APP, "other.app"):
            state = accounts.state_folder(app_id, DEVICE)
            state.mkdir(parents=True, exist_ok=True)
            (state / "expiry").write_text(str(int(time.time() + 3600)))
        env = {**self.fake_tools(), "TEST_REFUSE": mode}
        r = subprocess.run(["bash", str(self.refresh_script)], env=env, capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertEqual((self.root / "refused-attempts").read_text().splitlines(), ["first@example.test"])
        self.assertIn(hint, r.stdout)
        self.assertIn("skipped: " + hint, r.stdout)
        results = {a: store.read_state(accounts.state_folder(a, DEVICE))["last_run"]["result"] for a in (APP, "other.app")}
        self.assertEqual(results, {APP: "fail", "other.app": "fail"})
        # A separate run, e.g. after the user fixed the account, tries again.
        subprocess.run(["bash", str(self.refresh_script)], env=env, capture_output=True, text=True, timeout=60)
        self.assertEqual(len((self.root / "refused-attempts").read_text().splitlines()), 2)

    def test_auth_503_pause_persists_but_manual_retry_and_other_accounts_work(self):
        self.install_marker(3600)
        env = {**self.fake_tools(), 'TEST_REFUSE': '503'}
        def run(*args):
            return self.refresh(env, *args)
        first = run()
        self.assertEqual(first.returncode, 1, first.stdout + first.stderr)
        pause = self.root / '.auth-retry-after'
        self.assertGreater(int(pause.read_text()), time.time() + 1700)
        self.assertEqual(run().returncode, 0)
        attempts = self.root / 'refused-attempts'
        self.assertEqual(len(attempts.read_text().splitlines()), 1)
        self.assertEqual(run('--force').returncode, 1)
        self.assertEqual(len(attempts.read_text().splitlines()), 2)
        pause.write_text(str(int(time.time()) - 1))
        self.assertEqual(run().returncode, 1)
        self.assertEqual(len(attempts.read_text().splitlines()), 3)
        accounts.assign(DEVICE, self.second)
        self.install_marker(3600)
        self.assertEqual(run().returncode, 1)
        self.assertEqual(attempts.read_text().splitlines()[-1], 'second@example.test')
        self.assertTrue((accounts._folder(self.second) / 'runtime' / '.auth-retry-after').exists())

    def test_generic_error_17_does_not_pause_automatic_signing(self):
        self.install_marker(3600)
        env = {**self.fake_tools(), 'TEST_REFUSE': '17'}
        self.assertEqual(self.refresh(env).returncode, 1)
        self.assertFalse((self.root / '.auth-retry-after').exists())
        self.assertEqual(self.refresh(env).returncode, 1)
        self.assertEqual(len((self.root / 'refused-attempts').read_text().splitlines()), 2)

    def test_runs_that_leave_apps_due_back_off(self):
        self.install_marker(3600)
        w = Watcher(None, None)
        waits = []
        for _ in range(6):
            w.schedule(ran=True)
            waits.append(round((w.next_run - time.time()) / 60))
        self.assertEqual(waits, [30, 60, 120, 240, 240, 240])
        # Checks that didn't run anything (automatic checks off) don't grow the delay.
        w.misses = 0
        w.schedule()
        self.assertEqual(round((w.next_run - time.time()) / 60), 30)
        # Changing the device's account retries soon and starts over.
        w.schedule(ran=True)
        w.schedule(ran=True)
        w.soon()
        self.assertLessEqual(w.next_run, time.time() + 30)
        w.schedule(ran=True)
        self.assertEqual(round((w.next_run - time.time()) / 60), 30)

    def test_backoff_keeps_the_next_apps_renewal_window(self):
        w = Watcher(None, None)
        w.misses = 4
        with patch.object(watcher.time, "time", return_value=10000), \
             patch.object(w, "renewals", return_value=iter([9900, 10600])):
            w.schedule(ran=True)
        self.assertEqual(w.next_run, 10605)
        self.assertEqual(w.misses, 4)

    def test_arrival_does_not_postpone_other_devices_or_increase_backoff(self):
        self.install_marker(3600)
        runner, health = Mock(), Mock()
        runner.claim_auto.return_value = jobs.Job("auto", "Automatic check")
        w = Watcher(runner, health)
        deadline = time.time() + 60
        w.next_run = deadline
        w.misses = 3
        w.queue.add(DEVICE)
        config.update({"AUTO_CHECK": "1"})
        with patch.object(watcher, "run_capture") as run:
            w.tick()
        self.assertEqual(w.next_run, deadline)
        self.assertEqual(w.misses, 3)
        self.assertEqual(run.call_args.args[1], ["refresh.sh", "--device", DEVICE])

    @staticmethod
    def fake_env_without_limit(env):
        return {k: v for k, v in env.items() if k != "TEST_APP_LIMIT"}

    def test_ipa_metadata_cannot_inject_commands_into_refresh(self):
        import plistlib, zipfile
        marker = self.root / "pwned"
        with zipfile.ZipFile(self.app_dir / "app.ipa", "w") as z:
            z.writestr("Payload/Test.app/Info.plist", plistlib.dumps(
                {"CFBundleIdentifier": APP, "CFBundleExecutable": "Test",
                 "MinimumOSVersion": f"1/e touch {marker} #"}))
        # The rejection path rewrites AltServer output with sed, using the app's minimum iOS.
        env = {**self.fake_tools(), "TEST_IOS": "", "TEST_IOS_REJECT": "1"}
        r = self.refresh(env, "--force")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertFalse(marker.exists())
        self.assertIn("This app needs iOS a newer version or later.", (self.root / "state" / "refresh.log").read_text())

    def test_ios_rejection_reports_the_apps_real_requirement(self):
        import plistlib, zipfile
        with zipfile.ZipFile(self.app_dir / "app.ipa", "w") as z:
            z.writestr("Payload/Test.app/Info.plist", plistlib.dumps(
                {"CFBundleIdentifier": APP, "CFBundleExecutable": "Test", "MinimumOSVersion": "17.0"}))
        # The device's version is unknown, so the pre-check can't stop the attempt.
        env = {**self.fake_tools(), "TEST_IOS": "", "TEST_IOS_REJECT": "1"}
        r = subprocess.run(["bash", str(self.refresh_script), "--app", APP, "--device", DEVICE, "--force", '--install', '--confirm-replace'],
                           env=env, capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("iOS refused Test App 1: it needs iOS 17.0 or later, and Test iPhone runs an older version",
                      r.stdout)
        log = (self.root / "state" / "refresh.log").read_text()
        self.assertNotIn("12.2", log)
        self.assertIn("This app needs iOS 17.0 or later.", log)
        job = jobs.Job("refresh", "test")
        job.add("    " + jobs.ALTSTORE_IOS + "\n")
        self.assertEqual(job.lines, ["    " + jobs.IOS_TOO_OLD])
        self.assertEqual(jobs.redact([jobs.ALTSTORE_IOS]), [jobs.IOS_TOO_OLD])

    def assert_minizip_readable(self, path):
        """AltSign's minizip requires each local header's sizes to match the central directory."""
        import struct, zipfile
        with zipfile.ZipFile(path) as z, open(path, "rb") as f:
            self.assertTrue(z.infolist())
            for info in z.infolist():
                f.seek(info.header_offset)
                *_, crc, csize, size, _, _ = struct.unpack("<IHHHHHIIIHH", f.read(30))
                self.assertEqual((crc, csize, size), (info.CRC, info.compress_size, info.file_size), info.filename)

    def test_stripped_copy_keeps_names_and_classic_zip_fields(self):
        import zipfile
        name = "Payload/Test.app/Français.lproj/Localizable.strings"
        with zipfile.ZipFile(self.app_dir / "app.ipa", "w") as z:
            z.writestr(name.replace("ç", "XX"), b"strings")
            z.writestr("Payload/Test.app/Big", b"x" * 5000)
            z.writestr("Payload/Test.app/PlugIns/Share.appex/Info.plist", b"extension")
        # macOS and most IPA tools store UTF-8 names without zip's UTF-8 flag.
        raw = (self.app_dir / "app.ipa").read_bytes()
        (self.app_dir / "app.ipa").write_bytes(raw.replace(name.replace("ç", "XX").encode(), name.encode()))
        with zipfile.ZipFile(self.app_dir / "app.ipa") as z:
            self.assertFalse(z.getinfo(name.encode().decode("cp437")).flag_bits & 0x800)
        # Shrunk stand-ins for zipfile's 2 GiB Zip64 switch and the 4 GiB classic limit.
        with patch.object(zipfile, "ZIP64_LIMIT", 1000), patch.object(ipa, "CLASSIC_LIMIT", 10 ** 6):
            copy = ipa.signing_copy(self.app_dir)
            self.assertEqual(zipfile.ZIP64_LIMIT, 1000)
        with zipfile.ZipFile(copy) as z:
            self.assertEqual(sorted(z.namelist()), ["Payload/Test.app/Big", name])
            self.assertEqual(z.read(name), b"strings")
            self.assertTrue(all(len(i.extra) == 0 for i in z.infolist()))
        self.assert_minizip_readable(copy)

    def test_extensions_are_removed_unless_kept(self):
        import plistlib, zipfile
        with zipfile.ZipFile(self.app_dir / "app.ipa", "w") as z:
            z.writestr("Payload/Test.app/Info.plist", plistlib.dumps(
                {"CFBundleIdentifier": APP, "CFBundleExecutable": "Test", "MinimumOSVersion": "16.0"}))
            z.writestr("Payload/Test.app/Test", b"binary")
            z.writestr("Payload/Test.app/PlugIns/Share.appex/Info.plist", plistlib.dumps(
                {"CFBundleIdentifier": APP + ".share", "MinimumOSVersion": "17.0"}))
            z.writestr("Payload/Test.app/Watch/Watch.app/Info.plist", b"watch")
        store.set_device_ios(DEVICE, "16.7.16")
        view = store.app_view(APP)
        self.assertEqual((view["keep_extensions"], view["min_ios"], view["targets"][0]["needs_ios"]),
                         (False, "16.0", ""))
        r = self.refresh(self.fake_tools(), "--force")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("removed the app's extensions", r.stdout)
        signed = json.loads((self.root / "signing-records.jsonl").read_text().splitlines()[-1])["ipa"]
        self.assertEqual(Path(signed).name, "app-noext.ipa")
        with zipfile.ZipFile(signed) as z:
            self.assertEqual(sorted(z.namelist()), ["Payload/Test.app/Info.plist", "Payload/Test.app/Test"])
        self.assert_minizip_readable(signed)
        with zipfile.ZipFile(self.app_dir / "app.ipa") as z:
            self.assertEqual(len(z.namelist()), 4)
        # A copy from the first builds (Zip64 local headers, Archive error 0) is made again.
        with zipfile.ZipFile(signed, "w") as z, z.open("Payload/Test.app/Test", "w", force_zip64=True) as f:
            f.write(b"binary")
        os.utime(signed, (time.time() + 60, time.time() + 60))
        self.assertEqual(ipa.signing_copy(self.app_dir), Path(signed))
        self.assert_minizip_readable(signed)
        # Keeping them signs the upload itself; the extension's iOS 17.0 then applies.
        App(jobs.Jobs(lambda: None), None, None).set_app_extensions({"app": APP, "keep": True})
        self.assertFalse((self.app_dir / "app-noext.ipa").exists())
        store.set_device_ios(DEVICE, "16.7.16")  # the install above recorded the fake device's 26.0
        view = store.app_view(APP)
        self.assertEqual((view["keep_extensions"], view["targets"][0]["needs_ios"]), (True, "17.0"))
        store.set_device_ios(DEVICE, "17.1")
        r = self.refresh({**self.fake_tools_env, "TEST_IOS": "17.1"}, "--force")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertNotIn("removed the app's extensions", r.stdout)
        signed = json.loads((self.root / "signing-records.jsonl").read_text().splitlines()[-1])["ipa"]
        self.assertEqual(Path(signed).name, "app.ipa")
        # A new upload keeps the app's choice.
        upload = self.root / "upload.ipa"
        upload.write_bytes((self.app_dir / "app.ipa").read_bytes())
        store.add_app(upload, {"bundle_id": APP, "name": "Test App", "version": "2"}, "new.ipa")
        self.assertTrue(store.app_view(APP)["keep_extensions"])

    def test_refresh_script_signs_and_renews_with_isolated_accounts(self):
        env = self.fake_tools()
        script = self.refresh_script
        def run(*args):
            install = ['--install', '--confirm-replace'] if '--force' in args else []
            r = subprocess.run(["bash", str(script), "--app", APP, "--device", DEVICE, *args, *install],
                               env=env, capture_output=True, text=True, timeout=30)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        run("--force")
        legacy = accounts.state_folder(APP, DEVICE)
        self.assertTrue((legacy / "expiry").is_file())
        accounts.assign(DEVICE, self.second)
        run("--force")
        second_state = accounts.state_folder(APP, DEVICE)
        self.assertTrue((second_state / "expiry").is_file())
        run("--recheck")
        run("--force")
        accounts.assign(DEVICE, "default")
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
