import json
import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sideloop import accounts, signing_auth


class AuthenticationRetryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)

    def test_repeated_failures_back_off_across_calls_and_survive_restart(self):
        for now, expected in ((100000, 101800), (101800, 105400), (105400, 186400)):
            with patch.object(signing_auth.time, 'time', return_value=now):
                state = signing_auth.failed(self.work, 'Error: com.rileytestut.AltServer.Localized (-80046).')
            self.assertEqual(state['retry_at'], expected)
            self.assertEqual(signing_auth.retry_at(self.work), expected)
            self.assertEqual(int((self.work / '.auth-retry-after').read_text()), expected)
        self.assertEqual(signing_auth.read(self.work)['kind'], 'service')
        self.assertEqual(signing_auth.read(self.work)['failures'], 3)
        with patch.object(signing_auth.time, 'time', return_value=193600):
            state = signing_auth.failed(self.work, 'Error (-80046)')
        self.assertEqual(state['failures'], 1)
        self.assertEqual(state['retry_at'], 195400)

    def test_success_clears_only_the_selected_accounts_pause(self):
        other = self.work / 'other'
        signing_auth.failed(self.work, 'Apple authentication HTTP status: 503')
        signing_auth.failed(other, 'Error: (-80046)')
        signing_auth.clear(self.work)
        self.assertEqual(signing_auth.read(self.work), {})
        self.assertEqual(signing_auth.retry_at(self.work), 0)
        self.assertGreater(signing_auth.retry_at(other), 0)
        with patch.object(signing_auth.time, 'time', return_value=200000):
            state = signing_auth.failed(self.work, 'Error: (-80046)')
        self.assertEqual(state['retry_at'], 201800)

    def test_locked_account_stays_blocked_after_days_and_manual_signing(self):
        with patch.object(signing_auth.time, 'time', return_value=100000):
            state = signing_auth.failed(
                self.work, 'Error: com.rileytestut.AltServer.Localized (-20209).'
            )
        self.assertEqual(state['kind'], 'locked')
        self.assertEqual(state['retry_at'], 0)
        with patch.object(signing_auth.time, 'time', return_value=10000000):
            self.assertEqual(signing_auth.pause_reason(self.work), state['message'])
        self.assertEqual(signing_auth.read(self.work), state)

    def test_failed_reverification_cannot_downgrade_lock_to_timed_retry(self):
        locked = signing_auth.failed(self.work, 'Error: (-20209)')
        for output in (
            'Apple authentication HTTP status: 503',
            'Authentication failed (-20101)',
            'unclassified error',
        ):
            with self.subTest(output=output):
                self.assertEqual(signing_auth.failed(self.work, output), locked)
        signing_auth.clear(self.work)
        self.assertEqual(signing_auth.pause_reason(self.work), '')

    def test_lock_does_not_block_another_account(self):
        signing_auth.failed(self.work, 'Error: (-20209)')
        self.assertEqual(signing_auth.pause_reason(self.work / 'other'), '')
        self.assertTrue(signing_auth.pause_reason(self.work))

    def test_transient_pause_expires(self):
        with patch.object(signing_auth.time, 'time', return_value=100000):
            signing_auth.failed(self.work, 'Apple authentication HTTP status: 503')
            self.assertIn('paused', signing_auth.pause_reason(self.work))
        with patch.object(signing_auth.time, 'time', return_value=101801):
            self.assertEqual(signing_auth.pause_reason(self.work), '')

    def test_credential_rejection_and_mfa_stop_automatic_attempts_until_verified(self):
        for output in ('Authentication failed (-20101)', 'Enter two factor code'):
            with self.subTest(output=output):
                signing_auth.clear(self.work)
                state = signing_auth.failed(self.work, output)
                self.assertEqual(state['retry_at'], 0)
                with patch.object(signing_auth.time, 'time', return_value=10**10):
                    self.assertEqual(signing_auth.pause_reason(self.work), state['message'])

    def test_unknown_authentication_error_uses_the_same_failure_budget(self):
        output = 'Apple account authentication failed.\nError: com.rileytestut.ALTAppleAPI (17).'
        for now in (100000, 101800, 105400):
            with patch.object(signing_auth.time, 'time', return_value=now):
                state = signing_auth.failed(self.work, output)
        self.assertEqual(state['kind'], 'service')
        self.assertEqual(state['failures'], 3)
        self.assertEqual(state['retry_at'], 186400)
        self.assertIn('attempt limit reached', state['message'])

    def test_rolling_limit_keeps_recent_failures_when_the_oldest_expires(self):
        for now in (100000, 101800, 105400, 186400):
            with patch.object(signing_auth.time, 'time', return_value=now):
                state = signing_auth.failed(self.work, 'Error (-80046)')
        self.assertEqual(state['failure_times'], [101800, 105400, 186400])
        self.assertEqual(state['failures'], 3)
        self.assertEqual(state['retry_at'], 193600)

    def test_timeout_during_authentication_is_limited_but_later_device_timeout_is_not(self):
        started = 'Apple account authentication started.\n'
        self.assertEqual(signing_auth.classify(started + 'process timed out')[0], 'service')
        self.assertEqual(signing_auth.classify(started + 'Account authentication succeeded.\nDevice timed out'), ('', ''))

    def test_lock_code_requires_exact_numeric_boundary_and_hides_raw_output(self):
        self.assertEqual(signing_auth.classify('Error (-202090)'), ('', ''))
        state = signing_auth.failed(self.work, 'private-password and private-token (-20209)')
        self.assertNotIn('private-', json.dumps(state))
        self.assertIn('https://iforgot.apple.com', state['message'])

    def test_reports_never_include_raw_credentials_or_session_material(self):
        raw = 'X-Apple-I-MD: secret-header\nValue : secret-session\nAuthentication failed: secret-password (-80046)'
        state = signing_auth.failed(self.work, raw)
        self.assertNotIn('secret-', json.dumps(state))
        self.assertNotIn('secret-', (self.work / 'authentication-state.json').read_text())

    def test_unrelated_install_errors_do_not_pause_authentication(self):
        for output in ('Error: com.rileytestut.ALTAppleAPI (17).', 'AFC write failed',
                       'Error: com.rileytestut.AltServer (9).', 'Error: com.rileytestut.AltServer (10).'):
            with self.subTest(output=output):
                self.assertEqual(signing_auth.failed(self.work, output), {})
                self.assertEqual(signing_auth.retry_at(self.work), 0)

    def test_rate_limit_mfa_and_account_failures_are_classified(self):
        for output, expected in (
                ('Apple authentication HTTP status: 429', 'service'),
                ('Apple authentication HTTP status: 503', 'service'),
                ('Error: (-80045)', 'service'), ('Error: (-80046)', 'service'),
                ('Authentication failed (-22411)', 'account'),
                ('Authentication failed (-20101)', 'account'),
                ('Enter two factor code\nError: verification cancelled', 'verification')):
            with self.subTest(output=output):
                self.assertEqual(signing_auth.failed(self.work, output)['kind'], expected)
        self.assertEqual(signing_auth.classify('Enter two factor code\nGot token for com.apple.gs.xcode.auth!'), ('', ''))

    def test_legacy_pause_survives_upgrade_and_malformed_state_is_tolerated(self):
        (self.work / '.auth-retry-after').write_text('2000000000')
        for raw in ('{', '[]', '{"kind":"service","retry_at":"bad"}',
                    '{"kind":"service","message":"x","failures":-10,"failed_at":1,"retry_at":2}'):
            (self.work / 'authentication-state.json').write_text(raw)
            self.assertEqual(signing_auth.read(self.work), {})
            self.assertEqual(signing_auth.retry_at(self.work), 2000000000)

    def test_token_without_completed_sign_in_does_not_clear_failed_account(self):
        signing_auth.failed(self.work, 'Error: (-80046)')
        output = self.work / 'signer-output'
        output.write_text('Got token for com.apple.gs.xcode.auth!\nError: com.rileytestut.ALTAppleAPI (17).')
        with patch.object(signing_auth.sys, 'argv', ['auth', 'failure', 'default', str(output)]), \
             patch.object(accounts, 'runtime_folder', return_value=self.work), \
             patch.object(accounts, 'set_verification') as status, contextlib.redirect_stdout(io.StringIO()):
            signing_auth.main()
        status.assert_not_called()
        self.assertEqual(signing_auth.read(self.work)['kind'], 'service')

    def test_install_failure_after_completed_sign_in_clears_old_authentication_failure(self):
        for confirmed in ('Fetching team...', 'Fetching renewal profiles...'):
            with self.subTest(confirmed=confirmed):
                signing_auth.failed(self.work, 'Error: (-80046)')
                output = self.work / 'signer-output'
                output.write_text(confirmed + '\nAFC write failed\n')
                with patch.object(signing_auth.sys, 'argv', ['auth', 'failure', 'default', str(output)]), \
                     patch.object(accounts, 'runtime_folder', return_value=self.work), \
                     patch.object(accounts, 'set_verification') as status, contextlib.redirect_stdout(io.StringIO()):
                    signing_auth.main()
                self.assertEqual(signing_auth.read(self.work), {})
                self.assertEqual(signing_auth.retry_at(self.work), 0)
                status.assert_called_once_with('default', 'verified')


if __name__ == '__main__':
    unittest.main()
