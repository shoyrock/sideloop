"""Real PTY and account state tests with a synthetic signing executable."""
import json
import os
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from sideloop import accounts, config, verification
from sideloop.jobs import Job, run_pty
from sideloop.server import App
from sideloop.jobs import Jobs


class VerificationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.old = {k: getattr(config, k) for k in ('DATA', 'CONFIG')}
        config.DATA, config.CONFIG = self.root, self.root / 'config.env'
        config.update({'APPLE_ID': 'test@example.test', 'APPLE_PASSWORD': 'synthetic-password'})
        self.signer = self.root / 'signer'
        self.signer.write_text('''#!/usr/bin/env python3
import os,sys,time
assert sys.argv[1:] == ['--verify-account']
assert os.environ['TZ'] == 'UTC'
assert os.environ['ALTSERVER_APPLE_PASSWORD'] == 'synthetic-password'
mode=os.getenv('TEST_AUTH','success')
print('Received auth response:')
print('<string>synthetic-session-token</string>')
if mode == 'timeout': time.sleep(30)
if mode in ('mfa','wrong','cancel'):
    print('Enter two factor code',flush=True)
    code=input()
    # Exercise redaction even if a signer echoes user input.
    print(code,flush=True)
    if code != '123456':
        print('Authentication failed: incorrect verification code (-21669).')
        sys.exit(1)
if mode == 'error':
    print('Authentication failed: This action cannot be completed at this time (-22411).')
    sys.exit(1)
if mode == 'echo':
    print('Authentication failed: ' + os.environ['ALTSERVER_APPLE_PASSWORD'])
    sys.exit(1)
if mode != 'silent':
    print('Account authentication succeeded.')
''')
        self.signer.chmod(0o755)

    def tearDown(self):
        for key, value in self.old.items():
            setattr(config, key, value)
        self.temp.cleanup()

    def launch(self, mode='success', account='default'):
        job = Job('verify', 'Verify Apple Account')
        def target():
            try:
                verification.verify(job, account)
            finally:
                job.ended = time.time()
        with patch.dict(os.environ, {'ALTSERVER_BIN': str(self.signer), 'TEST_AUTH': mode}):
            worker = threading.Thread(target=target, daemon=True)
            worker.start()
            if mode not in ('mfa', 'wrong', 'cancel'):
                worker.join(10)
                self.assertFalse(worker.is_alive())
            else:
                deadline = time.monotonic() + 10
                while not job.view()['needs_input']:
                    self.assertTrue(worker.is_alive(), job.view())
                    self.assertLess(time.monotonic(), deadline)
                    time.sleep(0.02)
        return job, worker

    def test_no_mfa_authentication_succeeds_without_a_code(self):
        job, _ = self.launch()
        self.assertEqual(job.rc, 0)
        self.assertFalse(job.view()['needs_input'])
        self.assertEqual(accounts.verification('default')['status'], 'verified')
        self.assertFalse((self.root / 'apps').exists())
        self.assertFalse((self.root / 'AltServerData').exists())

    def test_mfa_prompts_then_verifies_without_persisting_code(self):
        job, worker = self.launch('mfa')
        try:
            self.assertEqual(accounts.verification('default')['status'], 'checking')
            with self.assertRaises(ValueError): job.send('123')
            job.send('123456')
            worker.join(10)
            self.assertFalse(worker.is_alive())
            self.assertEqual(job.rc, 0)
            self.assertEqual(accounts.verification('default')['status'], 'verified')
            self.assertNotIn('123456', json.dumps(job.view(0)))
            self.assertNotIn('synthetic-session-token', json.dumps(job.view(0)))
            self.assertNotIn('123456', (self.root / 'account-verification.json').read_text())
            with self.assertRaises(ValueError): job.send('123456')
        finally:
            if worker.is_alive(): job.cancel(); worker.join(5)

    def test_incorrect_code_fails_and_does_not_mark_verified(self):
        job, worker = self.launch('wrong')
        try:
            job.send('654321')
            worker.join(10)
            self.assertFalse(worker.is_alive())
            self.assertEqual(job.rc, 1)
            self.assertEqual(accounts.verification('default')['status'], 'failed')
            self.assertNotIn('654321', json.dumps(job.view(0)))
        finally:
            if worker.is_alive(): job.cancel(); worker.join(5)

    def test_apple_rejection_and_exit_zero_without_confirmation_fail(self):
        for mode in ('error', 'silent'):
            job, _ = self.launch(mode)
            self.assertNotEqual(job.rc, 0)
            self.assertEqual(accounts.verification('default')['status'], 'failed')

    def test_cancelled_verification_does_not_mark_verified(self):
        job, worker = self.launch('cancel')
        job.cancel()
        worker.join(10)
        self.assertFalse(worker.is_alive())
        self.assertEqual(accounts.verification('default')['status'], 'unverified')

    def test_changed_credentials_clear_previous_verification(self):
        accounts.set_verification('default', 'verified')
        accounts.save('default', 'test@example.test', 'replacement-password')
        self.assertEqual(accounts.verification('default')['status'], 'unverified')

    def test_timeout_and_restart_clear_pending_verification(self):
        with patch.object(verification, 'AUTH_TIMEOUT', 1):
            job, _ = self.launch('timeout')
        self.assertEqual(job.rc, 124)
        self.assertEqual(accounts.verification('default')['status'], 'failed')
        accounts.set_verification('default', 'checking')
        App(Jobs(lambda: None), None, None)
        self.assertEqual(accounts.verification('default')['status'], 'unverified')

    def test_other_account_verification_does_not_change_default_status(self):
        other = accounts.save('new', 'other@example.test', 'synthetic-password')
        job, _ = self.launch(account=other)
        self.assertEqual(job.rc, 0)
        self.assertEqual(accounts.verification(other)['status'], 'verified')
        self.assertEqual(accounts.verification('default')['status'], 'unverified')

    def test_verification_is_available_without_a_device_or_app(self):
        jobs = Jobs(lambda: None)
        app = App(jobs, None, None)
        with patch.dict(os.environ, {'ALTSERVER_BIN': str(self.signer)}):
            result = app.verify_account({'account': 'default'})
            deadline = time.monotonic() + 10
            while jobs.current.running:
                self.assertLess(time.monotonic(), deadline)
                time.sleep(0.02)
        self.assertEqual(result['job'], jobs.current.id)
        self.assertEqual(jobs.current.rc, 0)

    def save_attempt(self, mode='success', account='new', email='new@example.test', legacy=False):
        jobs = Jobs(lambda: None)
        app = App(jobs, None, None)
        with patch.dict(os.environ, {'ALTSERVER_BIN': str(self.signer), 'TEST_AUTH': mode}):
            body = {'account': account, 'apple_id': email, 'password': 'synthetic-password'}
            result = app.apple_id(body) if legacy else app.save_account(body)
            job = jobs.current
            self.assertEqual(result, {'job': job.id})
            self.wait_saved(job, prompt=mode in ('mfa', 'wrong', 'cancel'))
        return job

    def wait_saved(self, job, prompt=False):
        deadline = time.monotonic() + 10
        while job.running and not (prompt and job.view()['needs_input']):
            self.assertLess(time.monotonic(), deadline, job.view(0))
            time.sleep(0.02)
        if prompt:
            self.assertTrue(job.view()['needs_input'], job.view(0))

    def test_new_account_is_added_only_after_mfa_succeeds(self):
        before = accounts.views()
        job = self.save_attempt('mfa')
        try:
            self.assertEqual(accounts.views(), before)
            self.assertFalse((self.root / 'accounts').exists())
            self.assertIsNone(job.saved_account)
            job.send('123456')
            self.wait_saved(job)
            self.assertEqual(job.rc, 0, job.view(0))
            self.assertEqual(accounts.credentials(job.saved_account)['APPLE_ID'], 'new@example.test')
            self.assertEqual(accounts.verification(job.saved_account)['status'], 'verified')
            self.assertNotIn('synthetic-password', json.dumps(job.view(0)))
            self.assertNotIn('123456', json.dumps(job.view(0)))
        finally:
            if job.running: job.cancel(); self.wait_saved(job)

    def test_rejected_silent_and_timed_out_saves_do_not_add_accounts(self):
        before = accounts.views()
        for mode in ('error', 'silent', 'timeout'):
            with self.subTest(mode=mode), patch.object(verification, 'AUTH_TIMEOUT', 1):
                job = self.save_attempt(mode)
            self.assertNotEqual(job.rc, 0)
            self.assertIsNone(job.saved_account)
            self.assertEqual(accounts.views(), before)
            self.assertFalse((self.root / 'accounts').exists())

    def test_cancelled_and_wrong_mfa_saves_do_not_add_accounts(self):
        before = accounts.views()
        for mode in ('wrong', 'cancel'):
            job = self.save_attempt(mode)
            if mode == 'wrong': job.send('654321')
            else: job.cancel()
            self.wait_saved(job)
            self.assertNotEqual(job.rc, 0)
            self.assertEqual(accounts.views(), before)
            self.assertFalse((self.root / 'accounts').exists())

    def test_failed_password_change_preserves_previous_credentials_and_status(self):
        config.update({'APPLE_PASSWORD': 'previous-password'})
        accounts.set_verification('default', 'verified')
        previous = config.CONFIG.read_bytes()
        status = accounts.verification('default')
        job = self.save_attempt('echo', account='default', email='test@example.test')
        self.assertNotEqual(job.rc, 0)
        self.assertEqual(config.CONFIG.read_bytes(), previous)
        self.assertEqual(accounts.verification('default'), status)
        self.assertNotIn('synthetic-password', json.dumps(job.view(0)))

    def test_successful_password_change_commits_verified_credentials(self):
        config.update({'APPLE_PASSWORD': 'previous-password'})
        job = self.save_attempt(account='default', email='test@example.test')
        self.assertEqual(job.rc, 0, job.view(0))
        self.assertEqual(job.saved_account, 'default')
        self.assertEqual(accounts.credentials('default')['APPLE_PASSWORD'], 'synthetic-password')
        self.assertEqual(accounts.verification('default')['status'], 'verified')

    def test_legacy_account_endpoint_also_verifies_before_saving(self):
        config.update({'APPLE_ID': '', 'APPLE_PASSWORD': ''})
        before = config.CONFIG.read_bytes()
        job = self.save_attempt('error', legacy=True)
        self.assertNotEqual(job.rc, 0)
        self.assertEqual(config.CONFIG.read_bytes(), before)
        job = self.save_attempt(legacy=True)
        self.assertEqual(job.rc, 0, job.view(0))
        self.assertEqual(job.saved_account, 'default')


if __name__ == '__main__':
    unittest.main()
